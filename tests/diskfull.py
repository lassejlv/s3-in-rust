#!/usr/bin/env python3
"""Disk-full test: fill a small filesystem through s3rs and check that it fails cleanly and
recovers without a restart.

    sudo mount -t tmpfs -o size=100m tmpfs /mnt/small
    python3 tests/diskfull.py ./target/release/s3rs /mnt/small

Two scenarios, each in a fresh data directory on that filesystem:

1. Default free-space reserve: uploads are refused with 507 StorageFull before the disk is full;
   nothing else fails, no temporary files are left behind, deletes work, and uploads resume once
   space is freed.
2. Reserve disabled (--min-free-space 0), and then another process fills the disk to the last
   byte, so the metadata database hits ENOSPC: the server gives up its ballast file so deletes
   can start, recovers the database without a restart, and once the other process's file is
   gone, deletes and uploads work again.

Both end with a graceful shutdown and a passing `s3rs fsck --deep`.
"""

import os
import shutil
import tempfile
import subprocess
import sys
import time
import urllib.request

import boto3
from botocore.config import Config

BIN, MOUNT = sys.argv[1], sys.argv[2]
PORT = 9320
LOGS = tempfile.mkdtemp(prefix="s3rs-diskfull-logs-")  # not on the small filesystem
ENDPOINT = f"http://127.0.0.1:{PORT}"


def client():
    return boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id="k", aws_secret_access_key="secretsecret",
                        region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))


def logfile(data):
    return os.path.join(LOGS, os.path.basename(data) + ".log")


def start(data, *extra, out=None):
    out = out or open(logfile(data), "w")
    p = subprocess.Popen([BIN, "-d", data, "-l", f"127.0.0.1:{PORT}", "--access-key", "k", "--secret-key", "secretsecret",
                          *extra], stdout=out, stderr=out)
    servers.append(p)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{ENDPOINT}/_health", timeout=1)
            return p
        except Exception:
            time.sleep(0.05)
    sys.exit("server did not start")


def fill(s3):
    """Upload until the server refuses; return (stored keys, error codes seen)."""
    stored, codes = [], set()
    for i in range(2000):
        size = [1000, 50_000, 1_000_000, 3_000_000][i % 4]
        try:
            s3.put_object(Bucket="full", Key=f"o{i}", Body=os.urandom(size))
            stored.append(f"o{i}")
        except s3.exceptions.ClientError as e:
            codes.add((e.response["Error"]["Code"], e.response["ResponseMetadata"]["HTTPStatusCode"]))
            if len(codes) and i > len(stored) + 20:
                break
    return stored, codes


def finish(p, data, label):
    p.terminate()
    p.wait()
    log = open(logfile(data)).read()
    assert "panicked" not in log, f"{label}: the server panicked:\n{log}"
    leftovers = os.listdir(os.path.join(data, "tmp"))
    assert not leftovers, f"{label}: temporary files left behind: {leftovers[:5]}"
    fsck = subprocess.run([BIN, "fsck", "-d", data, "--deep"], capture_output=True, text=True)
    assert fsck.returncode == 0, f"{label}: fsck failed:\n{fsck.stdout}{fsck.stderr}"
    print(f"{label}: OK ({fsck.stdout.strip().splitlines()[0]})")
    shutil.rmtree(data)


def fill_disk(path):
    """Another process fills the filesystem completely (it may be full already)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    except OSError:
        return
    try:
        for size in (1 << 20, 4096, 1):
            chunk = b"\0" * size
            try:
                while True:
                    os.write(fd, chunk)
            except OSError:
                pass
    finally:
        os.close(fd)


def scenario(label, extra, expect_ballast):
    data = os.path.join(MOUNT, label)
    shutil.rmtree(data, ignore_errors=True)
    p = start(data, *extra)
    s3 = client()
    s3.create_bucket(Bucket="full")
    stored, codes = fill(s3)
    assert stored, f"{label}: nothing could be stored"
    assert codes == {("StorageFull", 507)}, f"{label}: unexpected errors {codes}"
    filler = os.path.join(MOUNT, label + ".filler")
    if expect_ballast:
        fill_disk(filler)
    # With the reserve, deletes always work. On a disk another process filled to the last byte,
    # the ballast lets deletes start; once that process's file is gone, all of them must work.
    deleted = 0
    for key in stored:
        try:
            s3.delete_object(Bucket="full", Key=key)
            deleted += 1
        except s3.exceptions.ClientError as e:
            if not expect_ballast or e.response["Error"]["Code"] != "StorageFull":
                raise
    log = open(logfile(data)).read()
    if expect_ballast:
        assert "ballast file and retrying" in log, f"{label}: the disk never filled up:\n{log}"
        assert deleted > 0, f"{label}: no delete succeeded on the full disk"
        if os.path.exists(filler):
            os.remove(filler)
        for key in stored:
            s3.delete_object(Bucket="full", Key=key)
    else:
        assert deleted == len(stored)
        assert "metadata commit failed" not in log, f"{label}: the reserve did not protect the database:\n{log}"
    deadline = time.time() + 10
    while True:
        try:
            s3.put_object(Bucket="full", Key="after", Body=os.urandom(500_000))
            break
        except s3.exceptions.ClientError as e:
            if time.time() > deadline:
                sys.exit(f"{label}: uploads did not resume after freeing space: {e}")
            time.sleep(0.3)
    assert s3.get_object(Bucket="full", Key="after")["ContentLength"] == 500_000
    print(f"{label}: stored {len(stored)} objects before {sorted(codes)}; deletes and new uploads work")
    finish(p, data, label)


def unwritable_logs():
    """Diagnostics and access logs that cannot be written (stdout/stderr on /dev/full, as with
    logs on a full disk) must not crash anything."""
    data = os.path.join(MOUNT, "devfull")
    shutil.rmtree(data, ignore_errors=True)
    p = start(data, "--access-log", "json", "--min-free-space", "0", out=open("/dev/full", "w"))
    s3 = client()
    s3.create_bucket(Bucket="full")
    stored, _ = fill(s3)
    fill_disk(os.path.join(MOUNT, "devfull.filler"))
    for key in stored:
        try:
            s3.delete_object(Bucket="full", Key=key)
        except s3.exceptions.ClientError:
            pass
    os.remove(os.path.join(MOUNT, "devfull.filler"))
    for key in stored:
        s3.delete_object(Bucket="full", Key=key)
    deadline = time.time() + 10
    while True:  # uploads resume once the ballast is back
        try:
            s3.put_object(Bucket="full", Key="still-alive", Body=b"x" * 100_000)
            break
        except s3.exceptions.ClientError:
            if time.time() > deadline:
                raise
            time.sleep(0.3)
    assert s3.get_object(Bucket="full", Key="still-alive")["Body"].read() == b"x" * 100_000
    assert p.poll() is None, "the server exited"
    p.terminate()
    p.wait()
    shutil.rmtree(data)
    print("unwritable logs: OK (the server kept serving)")


servers = []
try:
    scenario("reserve", [], expect_ballast=False)
    scenario("no-reserve", ["--min-free-space", "0"], expect_ballast=True)
    unwritable_logs()
finally:
    for p in servers:
        if p.poll() is None:
            p.kill()
print("DISK-FULL TEST OK")
