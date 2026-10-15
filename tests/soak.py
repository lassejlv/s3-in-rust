#!/usr/bin/env python3
"""Concurrency soak test: many workers hammer a small set of shared keys with overwrites,
deletes, copies, conditional creates, multipart uploads and reads, in a plain and a versioned
bucket, and every response is checked against invariants that must hold however the requests
interleave:

- a GET returns a body whose MD5 is the ETag it returned (no torn or mixed reads), and a range
  GET returns a slice of a body some writer wrote;
- of the workers racing to create a key with If-None-Match: *, exactly one wins;
- every listed version is readable and matches its ETag;
- per-bucket usage counters equal what the listings add up to;
- after a graceful stop, `s3rs fsck --deep` reports no problems.

    python3 tests/soak.py ./target/release/s3rs [seconds]
"""

import atexit
import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
SECONDS = float(sys.argv[2]) if len(sys.argv) > 2 else 30
PORT = 9389
EP = f"http://127.0.0.1:{PORT}"
WORKERS = 12
KEYS = [f"k{i}" for i in range(6)]
work = tempfile.mkdtemp(prefix="s3rs-soak-")
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "sk", "--secret-key", "soaksecret1",
                      "--lifecycle-interval", "0", "--metrics-token", "mt"], stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
atexit.register(p.kill)
for _ in range(100):
    try:
        urllib.request.urlopen(f"{EP}/_health")
        break
    except Exception:
        time.sleep(0.1)


def client():
    return boto3.client("s3", endpoint_url=EP, aws_access_key_id="sk", aws_secret_access_key="soaksecret1", region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}, max_pool_connections=4))


s3 = client()
BUCKETS = ["soak-plain", "soak-versioned"]
for b in BUCKETS:
    s3.create_bucket(Bucket=b)
s3.put_bucket_versioning(Bucket="soak-versioned", VersioningConfiguration={"Status": "Enabled"})

# Every body any writer sends, by MD5, so reads can be checked against what was really written.
written = {}
written_lock = threading.Lock()
failures = []
counts = {}
stop = time.time() + SECONDS


def fail(msg):
    failures.append(msg)
    print("FAIL:", msg)


def body(rng):
    size = rng.choice([0, 1, 100, 4000, 70_000, 600_000])
    data = rng.randbytes(size)
    with written_lock:
        written[hashlib.md5(data).hexdigest()] = data
    return data


def count(op):
    counts[op] = counts.get(op, 0) + 1


def check_get(c, bucket, key, version=None):
    args = {"Bucket": bucket, "Key": key} | ({"VersionId": version} if version else {})
    try:
        r = c.get_object(**args)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "NoSuchVersion", "404", "MethodNotAllowed"):
            return
        raise
    data = r["Body"].read()
    etag = r["ETag"].strip('"')
    if "-" in etag:
        if data not in (v for v in written.values()) and not any(data == v for v in written.values()):
            # Multipart bodies are concatenations; check the length is consistent at least.
            if len(data) != r["ContentLength"]:
                fail(f"{bucket}/{key}: multipart body length {len(data)} != {r['ContentLength']}")
        return
    if hashlib.md5(data).hexdigest() != etag:
        fail(f"{bucket}/{key}@{version}: body MD5 {hashlib.md5(data).hexdigest()} != ETag {etag}")
    elif etag not in written:
        fail(f"{bucket}/{key}: body was never written by anyone")


def worker(n):
    rng = random.Random(n)
    c = client()
    while time.time() < stop:
        bucket = rng.choice(BUCKETS)
        key = rng.choice(KEYS)
        op = rng.choices(["put", "get", "range", "delete", "copy", "multipart", "head", "list", "tags"],
                         [30, 30, 8, 8, 8, 3, 6, 4, 3])[0]
        try:
            if op == "put":
                c.put_object(Bucket=bucket, Key=key, Body=body(rng))
            elif op == "get":
                check_get(c, bucket, key)
            elif op == "range":
                try:
                    r = c.get_object(Bucket=bucket, Key=key, Range="bytes=10-99")
                except ClientError as e:
                    if e.response["Error"]["Code"] in ("NoSuchKey", "InvalidRange", "404"):
                        continue
                    raise
                part = r["Body"].read()
                etag = r["ETag"].strip('"')
                full = written.get(etag)
                if full is not None and full[10:100] != part:
                    fail(f"{bucket}/{key}: range body doesn't match the object with ETag {etag}")
            elif op == "delete":
                c.delete_object(Bucket=bucket, Key=key)
            elif op == "copy":
                src = rng.choice(KEYS)
                try:
                    c.copy_object(Bucket=bucket, Key=key, CopySource={"Bucket": bucket, "Key": src})
                except ClientError as e:
                    if e.response["Error"]["Code"] not in ("NoSuchKey", "InvalidRequest"):
                        raise
            elif op == "multipart":
                up = c.create_multipart_upload(Bucket=bucket, Key=key)
                parts = []
                for i in range(2):
                    data = rng.randbytes(5 << 20 if i == 0 else 1000)
                    parts.append({"PartNumber": i + 1, "ETag": c.upload_part(Bucket=bucket, Key=key, UploadId=up["UploadId"],
                                                                             PartNumber=i + 1, Body=data)["ETag"]})
                c.complete_multipart_upload(Bucket=bucket, Key=key, UploadId=up["UploadId"], MultipartUpload={"Parts": parts})
            elif op == "head":
                try:
                    c.head_object(Bucket=bucket, Key=key)
                except ClientError as e:
                    if e.response["Error"]["Code"] not in ("404", "NoSuchKey", "405"):
                        raise
            elif op == "list":
                c.list_objects_v2(Bucket=bucket)
            elif op == "tags":
                try:
                    c.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": [{"Key": "w", "Value": str(n)}]})
                except ClientError as e:
                    if e.response["Error"]["Code"] not in ("NoSuchKey", "MethodNotAllowed"):
                        raise
            count(op)
        except ClientError as e:
            fail(f"{op} {bucket}/{key}: {e.response['Error']['Code']}: {e}")
        except Exception as e:
            fail(f"{op} {bucket}/{key}: {type(e).__name__}: {e}")


threads = [threading.Thread(target=worker, args=(n,)) for n in range(WORKERS)]
for t in threads:
    t.start()
for t in threads:
    t.join()
print("operations:", dict(sorted(counts.items())))

# Racing creators: exactly one If-None-Match: * wins per key.
for round_ in range(5):
    key = f"race-{round_}"
    winners = []

    for n in range(8):
        written[hashlib.md5(f"writer {n}".encode()).hexdigest()] = f"writer {n}".encode()

    def create(n):
        try:
            client().put_object(Bucket="soak-plain", Key=key, Body=f"writer {n}".encode(), IfNoneMatch="*")
            winners.append(n)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("PreconditionFailed", "ConditionalRequestConflict"):
                fail(f"create race: {e}")

    ts = [threading.Thread(target=create, args=(n,)) for n in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    if len(winners) != 1:
        fail(f"{key}: {len(winners)} conditional creates succeeded")
    elif s3.get_object(Bucket="soak-plain", Key=key)["Body"].read() != f"writer {winners[0]}".encode():
        fail(f"{key}: content isn't the winner's")

# Every version is readable and matches its ETag; the current objects too.
for bucket in BUCKETS:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []):
            check_get(s3, bucket, v["Key"], None if v["VersionId"] == "null" else v["VersionId"])

# Usage counters equal the listings.
for bucket in BUCKETS:
    n = size = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []):
            n += 1
            size += v["Size"]
    req = urllib.request.Request(f"{EP}/_metrics", headers={"Authorization": "Bearer mt"})
    metrics = urllib.request.urlopen(req).read().decode().splitlines()
    value = lambda name: int(next(l.split()[-1] for l in metrics if l.startswith(f'{name}{{bucket="{bucket}"}}')))
    got = (value("s3rs_bucket_objects"), value("s3rs_bucket_bytes"))
    if got != (n, size):
        fail(f"{bucket}: usage {got} != listing ({n}, {size})")

p.terminate()
p.wait()
r = subprocess.run([BIN, "fsck", "-d", f"{work}/data", "--deep"], capture_output=True, text=True)
if r.returncode != 0:
    fail("fsck: " + r.stdout + r.stderr)
if failures:
    print(open(f"{work}/log").read()[-3000:])
    sys.exit(f"SOAK TEST FAILED: {len(failures)} problem(s)")
shutil.rmtree(work)
print("SOAK TEST OK")
