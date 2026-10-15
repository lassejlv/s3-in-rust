#!/usr/bin/env python3
"""Backup and restore test.

    python3 tests/backup.py ./target/release/s3rs

Writes a mix of objects (inline, file-backed, multipart, SSE-S3, versioned), then downloads
GET /_admin/backup slowly while other clients overwrite and delete objects that the backup's
snapshot still refers to. The archive is extracted into an empty directory, which must pass
`s3rs fsck --deep`, and a server started on it must return every object written before the
backup with its content (and every key touched during the backup in a state it really had).
Also checks the admin API's access control, one-backup-at-a-time, and the offline
`s3rs backup -o` command.
"""

import hashlib
import os
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request

import boto3
from botocore.config import Config

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
PORT, PORT2 = 9330, 9331
TOKEN = "backup-admin-token"
work = tempfile.mkdtemp(prefix="s3rs-backup-")
key_file = os.path.join(work, "key")
with open(key_file, "w") as f:
    f.write(os.urandom(32).hex())
servers = []


def start(data, port, *extra):
    p = subprocess.Popen([BIN, "-d", data, "-l", f"127.0.0.1:{port}", "--access-key", "k", "--secret-key", "secretsecret",
                          "--encryption-key-file", key_file, *extra],
                         stdout=subprocess.DEVNULL, stderr=open(data + ".log", "w"))
    servers.append(p)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/_health", timeout=1)
            return p
        except Exception:
            time.sleep(0.05)
    sys.exit("server did not start")


def client(port):
    return boto3.client("s3", endpoint_url=f"http://127.0.0.1:{port}", aws_access_key_id="k",
                        aws_secret_access_key="secretsecret", region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))


def md5(b):
    return hashlib.md5(b).hexdigest()


def admin(port, token=TOKEN):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/_admin/backup",
                                 headers={"Authorization": f"Bearer {token}"} if token else {})
    return urllib.request.urlopen(req, timeout=30)


def check_restored(data, expected, versions, churn_allowed, label):
    fsck = subprocess.run([BIN, "fsck", "-d", data, "--deep", "--encryption-key-file", key_file],
                          capture_output=True, text=True)
    assert fsck.returncode == 0, f"{label}: fsck failed:\n{fsck.stdout}{fsck.stderr}"
    p = start(data, PORT2)
    s3 = client(PORT2)
    for (bucket, key), want in expected.items():
        got = md5(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
        assert got == want, f"{label}: {bucket}/{key}: {got} != {want}"
    for key, vs in versions.items():
        for vid, want in vs:
            got = md5(s3.get_object(Bucket="versioned", Key=key, VersionId=vid)["Body"].read())
            assert got == want, f"{label}: version {vid} of {key}"
    for key, allowed in churn_allowed.items():
        try:
            got = md5(s3.get_object(Bucket="data", Key=key)["Body"].read())
        except s3.exceptions.NoSuchKey:
            got = None
        assert got in allowed, f"{label}: churn/{key}: {got} not in {allowed}"
    p.terminate()
    p.wait()
    print(f"{label}: fsck OK, {len(expected)} objects and {sum(map(len, versions.values()))} versions restored")


def main():
    data = os.path.join(work, "data")
    p = start(data, PORT, "--admin-token", TOKEN)
    s3 = client(PORT)
    rng = random.Random(7)
    s3.create_bucket(Bucket="data")
    s3.create_bucket(Bucket="versioned")
    s3.put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})
    expected, versions = {}, {}
    for i in range(60):
        body = rng.randbytes(rng.choice([10, 3000, 70_000, 400_000, 1_500_000]))
        extra = {"ServerSideEncryption": "AES256"} if i % 5 == 0 else {}
        s3.put_object(Bucket="data", Key=f"static/{i}", Body=body, **extra)
        expected[("data", f"static/{i}")] = md5(body)
    parts = [rng.randbytes(5 << 20), rng.randbytes(123_456)]
    up = s3.create_multipart_upload(Bucket="data", Key="static/multipart")["UploadId"]
    etags = [s3.upload_part(Bucket="data", Key="static/multipart", UploadId=up, PartNumber=n + 1, Body=b)["ETag"]
             for n, b in enumerate(parts)]
    s3.complete_multipart_upload(Bucket="data", Key="static/multipart", UploadId=up, MultipartUpload={
        "Parts": [{"PartNumber": n + 1, "ETag": e} for n, e in enumerate(etags)]})
    expected[("data", "static/multipart")] = md5(b"".join(parts))
    for i in range(5):
        for _ in range(3):
            body = rng.randbytes(200_000)
            vid = s3.put_object(Bucket="versioned", Key=f"v{i}", Body=body)["VersionId"]
            versions.setdefault(f"v{i}", []).append((vid, md5(body)))
    # Objects that other clients will overwrite or delete while the backup streams.
    churn_allowed = {}
    for i in range(40):
        body = rng.randbytes(300_000)
        s3.put_object(Bucket="data", Key=f"churn/{i}", Body=body)
        churn_allowed[f"churn/{i}"] = {md5(body)}

    # Access control and one backup at a time.
    for token, want in ((None, 403), ("wrong", 403)):
        try:
            admin(PORT, token)
            sys.exit(f"backup with token {token!r} was allowed")
        except urllib.error.HTTPError as e:
            assert e.code == want, (token, e.code)

    stop = threading.Event()

    def churn():
        c = client(PORT)
        r = random.Random(11)
        while not stop.is_set():
            key = f"churn/{r.randrange(40)}"
            if r.random() < 0.5:
                body = r.randbytes(300_000)
                churn_allowed[key].add(md5(body))
                c.put_object(Bucket="data", Key=key, Body=body)
            else:
                churn_allowed[key].add(None)
                c.delete_object(Bucket="data", Key=key)

    archive = os.path.join(work, "online.tar")
    resp = admin(PORT)
    assert resp.headers["Content-Type"] == "application/x-tar"
    size = int(resp.headers["Content-Length"])
    try:
        admin(PORT)
        sys.exit("a second concurrent backup was allowed")
    except urllib.error.HTTPError as e:
        assert e.code == 409, e.code
    workers = [threading.Thread(target=churn) for _ in range(3)]
    for t in workers:
        t.start()
    got = 0
    with open(archive, "wb") as f:
        while chunk := resp.read(256 * 1024):
            f.write(chunk)
            got += len(chunk)
            time.sleep(0.02)  # a slow client: the churn runs while the archive streams
    stop.set()
    for t in workers:
        t.join()
    assert got == size, (got, size)
    log = open(data + ".log").read()
    assert "backup: done" in log, log
    restored = os.path.join(work, "restored")
    os.makedirs(restored)
    with tarfile.open(archive) as t:
        t.extractall(restored, filter="data")
    check_restored(restored, expected, versions, churn_allowed, "online backup")

    # Deletes held back during the backup happen afterwards: nothing is left orphaned.
    p.terminate()
    p.wait()
    fsck = subprocess.run([BIN, "fsck", "-d", data], capture_output=True, text=True)
    assert fsck.returncode == 0, f"source fsck after backup:\n{fsck.stdout}"

    # Offline backup of the stopped server.
    archive2 = os.path.join(work, "offline.tar")
    r = subprocess.run([BIN, "backup", "-d", data, "-o", archive2], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    restored2 = os.path.join(work, "restored2")
    os.makedirs(restored2)
    with tarfile.open(archive2) as t:
        t.extractall(restored2, filter="data")
    final = {}
    s3 = None
    p = start(data, PORT)
    s3 = client(PORT)
    for k in churn_allowed:
        try:
            final[k] = {md5(s3.get_object(Bucket="data", Key=k)["Body"].read())}
        except s3.exceptions.NoSuchKey:
            final[k] = {None}
    p.terminate()
    p.wait()
    check_restored(restored2, expected, versions, final, "offline backup")
    shutil.rmtree(work)
    print("BACKUP TEST OK")


try:
    main()
finally:
    for proc in servers:
        if proc.poll() is None:
            proc.kill()
