#!/usr/bin/env python3
"""Upgrade test: data written by an older s3rs must be fully readable by a newer one.

    python3 tests/upgrade.py OLD_BINARY NEW_BINARY

Starts the old binary on a fresh data directory and writes whatever it supports: small (inline)
and large (file-backed) objects with metadata, overwrites, deletes, multipart uploads (complete
and in progress), and, when the old version has them, versioned buckets, tags and SSE-S3/SSE-C
objects. Then it stops the old server gracefully, starts the new binary on the same directory and
checks that every object, version, tag and in-progress upload reads back exactly as written,
that new writes, overwrites and deletes work on the old data, and that `s3rs fsck --deep` is OK.
"""

import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

OLD, NEW = sys.argv[1], sys.argv[2]
PORT = int(os.environ.get("S3RS_UPGRADE_PORT", "9330"))
ENDPOINT = f"http://127.0.0.1:{PORT}"
KEY, SECRET = "upgradekey", "upgradesecret"

data_dir = tempfile.mkdtemp(prefix="s3rs-upgrade-")
key_file = data_dir + "-key"
with open(key_file, "w") as f:
    f.write(os.urandom(32).hex())
SSEC_KEY = os.urandom(32)
SSEC = {
    "SSECustomerAlgorithm": "AES256",
    "SSECustomerKey": SSEC_KEY,
}
rng = random.Random(7)


def client():
    return boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id=KEY, aws_secret_access_key=SECRET,
                        region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 2}))


def start(binary):
    helptext = subprocess.run([binary, "--help"], capture_output=True, text=True).stdout
    args = [binary, "-d", data_dir, "-l", f"127.0.0.1:{PORT}", "--access-key", KEY, "--secret-key", SECRET]
    if "--encryption-key-file" in helptext:
        args += ["--encryption-key-file", key_file]
    log = open(data_dir + ".log", "a")
    log.write(f"=== {binary}\n")
    log.flush()
    p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            urllib.request.urlopen(ENDPOINT + "/_health", timeout=1)
            return p, "--encryption-key-file" in helptext
        except Exception:
            if p.poll() is not None:
                break
            time.sleep(0.1)
    p.kill()
    print(open(data_dir + ".log").read())
    sys.exit(f"{binary} did not start")


def stop(p):
    p.terminate()
    if p.wait(timeout=30) != 0:
        print(open(data_dir + ".log").read())
        sys.exit(f"server exited with {p.returncode}")


def body(n):
    return rng.randbytes(n)


def supported(fn):
    """Run an operation the old version may not have; False if it answered 'not implemented'."""
    try:
        fn()
        return True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        if status in (400, 405, 501) or code in ("NotImplemented", "InvalidArgument", "MethodNotAllowed"):
            return False
        raise


# --- Write with the old version -----------------------------------------------------------------

old, old_sse = start(OLD)
s3 = client()
expect = {}  # (bucket, key) -> (bytes, metadata, content_type, extra get args)
s3.create_bucket(Bucket="plain")
for i in range(40):
    n = rng.choice([0, 1, 100, 4000, 70_000, 300_000, 2_000_000])
    data, meta = body(n), {"i": str(i), "note": "old"}
    s3.put_object(Bucket="plain", Key=f"dir{i % 4}/obj-{i}", Body=data, Metadata=meta, ContentType="application/x-test")
    expect[("plain", f"dir{i % 4}/obj-{i}")] = (data, meta, "application/x-test", {})
for i in range(0, 40, 5):  # overwrites
    data = body(rng.choice([10, 200_000]))
    s3.put_object(Bucket="plain", Key=f"dir{i % 4}/obj-{i}", Body=data)
    expect[("plain", f"dir{i % 4}/obj-{i}")] = (data, {}, None, {})
for i in range(1, 40, 7):  # deletes
    s3.delete_object(Bucket="plain", Key=f"dir{i % 4}/obj-{i}")
    del expect[("plain", f"dir{i % 4}/obj-{i}")]
# Odd keys.
for k in ["a b+c", "ünïcødé/😀", "x" * 900, "trailing/", "%2F/encoded"]:
    data = body(50)
    s3.put_object(Bucket="plain", Key=k, Body=data)
    expect[("plain", k)] = (data, {}, None, {})

# Multipart: one completed, one left in progress.
parts_data = [body(5 * 1024 * 1024), body(5 * 1024 * 1024), body(123)]
mp = s3.create_multipart_upload(Bucket="plain", Key="multi")
etags = [s3.upload_part(Bucket="plain", Key="multi", UploadId=mp["UploadId"], PartNumber=i + 1, Body=d)["ETag"]
         for i, d in enumerate(parts_data)]
s3.complete_multipart_upload(Bucket="plain", Key="multi", UploadId=mp["UploadId"],
                             MultipartUpload={"Parts": [{"ETag": e, "PartNumber": i + 1} for i, e in enumerate(etags)]})
expect[("plain", "multi")] = (b"".join(parts_data), {}, None, {})
pending = s3.create_multipart_upload(Bucket="plain", Key="pending")
pending_part = body(5 * 1024 * 1024)
pending_etag = s3.upload_part(Bucket="plain", Key="pending", UploadId=pending["UploadId"], PartNumber=1,
                              Body=pending_part)["ETag"]

etag_of = {k: s3.head_object(Bucket=k[0], Key=k[1])["ETag"] for k in expect}

# Versioning.
versions = []  # (key, version id, bytes)
s3.create_bucket(Bucket="versioned")
if supported(lambda: s3.put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})):
    for j in range(3):
        for k in ["v1", "v2"]:
            data = body(rng.choice([30, 150_000]))
            versions.append((k, s3.put_object(Bucket="versioned", Key=k, Body=data)["VersionId"], data))
    s3.delete_object(Bucket="versioned", Key="v2")  # leaves a delete marker
    print(f"old version: {len(versions)} object versions")

# Tags.
tagged = supported(lambda: s3.put_object_tagging(Bucket="plain", Key="multi",
                                                 Tagging={"TagSet": [{"Key": "t", "Value": "old"}]}))

# Encryption.
if old_sse:
    s3.create_bucket(Bucket="secret")
    for i, n in enumerate([5, 70_000, 1_000_000]):
        data = body(n)
        s3.put_object(Bucket="secret", Key=f"s3-{i}", Body=data, ServerSideEncryption="AES256")
        expect[("secret", f"s3-{i}")] = (data, {}, None, {})
        data = body(n)
        s3.put_object(Bucket="secret", Key=f"c-{i}", Body=data, **SSEC)
        expect[("secret", f"c-{i}")] = (data, {}, None, SSEC)
    etag_of.update({k: s3.head_object(Bucket=k[0], Key=k[1], **k_args)["ETag"]
                    for k, (_, _, _, k_args) in expect.items() if k[0] == "secret"})
    print("old version: encrypted objects written")

stop(old)

# --- Read with the new version ------------------------------------------------------------------

new, _ = start(NEW)
s3 = client()


def check(bucket, key, data, meta, ctype, extra):
    r = s3.get_object(Bucket=bucket, Key=key, **extra)
    got = r["Body"].read()
    assert got == data, f"{bucket}/{key}: content differs ({len(got)} vs {len(data)} bytes)"
    assert r["Metadata"] == meta, f"{bucket}/{key}: metadata {r['Metadata']} != {meta}"
    if ctype:
        assert r["ContentType"] == ctype, f"{bucket}/{key}: content type {r['ContentType']}"
    assert r["ETag"] == etag_of[(bucket, key)], f"{bucket}/{key}: ETag changed"
    if len(data) > 10:
        r = s3.get_object(Bucket=bucket, Key=key, Range="bytes=3-9", **extra)
        assert r["Body"].read() == data[3:10], f"{bucket}/{key}: range differs"


for (bucket, key), (data, meta, ctype, extra) in expect.items():
    check(bucket, key, data, meta, ctype, extra)
listed = {o["Key"] for p in s3.get_paginator("list_objects_v2").paginate(Bucket="plain") for o in p.get("Contents", [])}
assert listed == {k for b, k in expect if b == "plain"}, f"listing differs: {listed ^ {k for b, k in expect if b == 'plain'}}"

ups = s3.list_multipart_uploads(Bucket="plain").get("Uploads", [])
assert [u["UploadId"] for u in ups] == [pending["UploadId"]], ups
parts = s3.list_parts(Bucket="plain", Key="pending", UploadId=pending["UploadId"])["Parts"]
assert [(p["PartNumber"], p["ETag"]) for p in parts] == [(1, pending_etag)], parts
tail = body(77)
e2 = s3.upload_part(Bucket="plain", Key="pending", UploadId=pending["UploadId"], PartNumber=2, Body=tail)["ETag"]
s3.complete_multipart_upload(Bucket="plain", Key="pending", UploadId=pending["UploadId"],
                             MultipartUpload={"Parts": [{"ETag": pending_etag, "PartNumber": 1},
                                                        {"ETag": e2, "PartNumber": 2}]})
assert s3.get_object(Bucket="plain", Key="pending")["Body"].read() == pending_part + tail

for key, vid, data in versions:
    assert s3.get_object(Bucket="versioned", Key=key, VersionId=vid)["Body"].read() == data, f"version {key}/{vid}"
if versions:
    lv = s3.list_object_versions(Bucket="versioned")
    assert sorted(v["VersionId"] for v in lv.get("Versions", [])) == sorted(v for _, v, _ in versions)
    assert [m["Key"] for m in lv.get("DeleteMarkers", [])] == ["v2"]
    latest_v1 = [d for k, _, d in versions if k == "v1"][-1]
    assert s3.get_object(Bucket="versioned", Key="v1")["Body"].read() == latest_v1
if tagged:
    assert s3.get_object_tagging(Bucket="plain", Key="multi")["TagSet"] == [{"Key": "t", "Value": "old"}]

# New writes, overwrites and deletes on top of the old data.
for (bucket, key), (data, meta, ctype, extra) in list(expect.items())[::3]:
    if extra:
        continue
    s3.delete_object(Bucket=bucket, Key=key)
for i in range(10):
    s3.put_object(Bucket="plain", Key=f"dir0/obj-{i}", Body=body(rng.choice([5, 400_000])))
s3.create_bucket(Bucket="fresh")
s3.put_object(Bucket="fresh", Key="k", Body=b"new")
assert s3.get_object(Bucket="fresh", Key="k")["Body"].read() == b"new"
stop(new)

# Restart once more (usage counters, clean shutdown marker) and run fsck.
new, _ = start(NEW)
stop(new)
fsck = subprocess.run([NEW, "fsck", "--deep", "-d", data_dir, "--encryption-key-file", key_file],
                      capture_output=True, text=True)
print(fsck.stdout.strip()[-400:])
if fsck.returncode != 0:
    print(fsck.stderr)
    print(open(data_dir + ".log").read()[-4000:])
    sys.exit("fsck failed")
print(f"upgrade {os.path.basename(OLD)} -> {os.path.basename(NEW)}: OK "
      f"({len(expect)} objects, {len(versions)} versions)")
shutil.rmtree(data_dir)
os.remove(key_file)
os.remove(data_dir + ".log")
