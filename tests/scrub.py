#!/usr/bin/env python3
"""Online scrubbing: stored data is re-read in the background and checked against its ETag;
damage on disk is reported (log and metrics) without touching anything.

    python3 tests/scrub.py ./target/release/s3rs
"""

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import boto3
from botocore.config import Config

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
PORT = 9390
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-scrub-")
procs = []
atexit.register(lambda: [p.kill() for p in procs])
with open(f"{work}/key", "w") as f:
    f.write(os.urandom(32).hex())

p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "k", "--secret-key", "scrubsecret",
                      "--encryption-key-file", f"{work}/key", "--scrub-interval", "1s", "--scrub-rate", "64"],
                     stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
procs.append(p)
for _ in range(100):
    try:
        urllib.request.urlopen(f"{EP}/_health")
        break
    except Exception:
        time.sleep(0.1)
else:
    sys.exit("server did not start")


def metric(name):
    text = urllib.request.urlopen(f"{EP}/_metrics").read().decode()
    return sum(float(l.split()[-1]) for l in text.splitlines() if l.startswith(name + " "))


def wait_passes(n, timeout=30):
    deadline = time.time() + timeout
    while metric("s3rs_scrub_passes_total") < n:
        if time.time() > deadline:
            print(open(f"{work}/log").read()[-3000:])
            sys.exit(f"scrub pass {n} did not finish")
        time.sleep(0.2)


s3 = boto3.client("s3", endpoint_url=EP, aws_access_key_id="k", aws_secret_access_key="scrubsecret", region_name="us-east-1",
                  config=Config(s3={"addressing_style": "path"}))
s3.create_bucket(Bucket="plain")
s3.create_bucket(Bucket="versioned")
s3.put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})
s3.put_object(Bucket="plain", Key="small", Body=b"tiny")
big = os.urandom(3 << 20)
s3.put_object(Bucket="plain", Key="big", Body=big)
s3.put_object(Bucket="plain", Key="enc", Body=os.urandom(200_000), ServerSideEncryption="AES256")
s3.put_object(Bucket="plain", Key="empty", Body=b"")
up = s3.create_multipart_upload(Bucket="plain", Key="multi")
parts = [s3.upload_part(Bucket="plain", Key="multi", UploadId=up["UploadId"], PartNumber=i, Body=os.urandom(5 << 20 if i == 1 else 1000))["ETag"]
         for i in (1, 2)]
s3.complete_multipart_upload(Bucket="plain", Key="multi", UploadId=up["UploadId"],
                             MultipartUpload={"Parts": [{"PartNumber": i, "ETag": e} for i, e in enumerate(parts, 1)]})
for i in range(3):
    s3.put_object(Bucket="versioned", Key="v", Body=os.urandom(100_000))
s3.delete_object(Bucket="versioned", Key="v")

passes = metric("s3rs_scrub_passes_total")
wait_passes(passes + 2)
assert metric("s3rs_scrub_corrupt_total") == 0, open(f"{work}/log").read()[-3000:]
verified = metric("s3rs_scrub_verified_total")
assert verified >= 2 * 8, verified  # 5 objects + 3 versions per pass
print(f"clean data: {verified:.0f} versions verified over {metric('s3rs_scrub_passes_total'):.0f} passes")

# Flip one byte in the middle of the big object's data file.
files = [os.path.join(d, f) for d, _, fs in os.walk(f"{work}/data/data") for f in fs]
target = [f for f in files if os.path.getsize(f) == len(big)]
assert len(target) == 1, [(f, os.path.getsize(f)) for f in files]
with open(target[0], "r+b") as f:
    f.seek(len(big) // 2)
    b = f.read(1)
    f.seek(len(big) // 2)
    f.write(bytes([b[0] ^ 0xFF]))
passes = metric("s3rs_scrub_passes_total")
wait_passes(passes + 2)
log = open(f"{work}/log").read()
assert metric("s3rs_scrub_corrupt_total") >= 1, log[-3000:]
assert "scrub: DAMAGED plain/big: content does not match its ETag" in log, log[-3000:]
assert "DAMAGED plain/multi" not in log and "DAMAGED versioned" not in log
print("a flipped byte was found and reported")

# The read rate holds within large objects too: about 9 MiB at 2 MiB/s takes over 3 s.
p.terminate()
p.wait()
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "k", "--secret-key", "scrubsecret",
                      "--encryption-key-file", f"{work}/key", "--scrub-interval", "1h", "--scrub-rate", "2"],
                     stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
procs.append(p)
started = time.time()
for _ in range(100):
    try:
        urllib.request.urlopen(f"{EP}/_health")
        break
    except Exception:
        time.sleep(0.1)
wait_passes(1)
took = time.time() - started
assert took > 3, took
# Stopping doesn't wait for a pass (or a large object) to finish.
p = procs[-1]
t = time.time()
p.terminate()
p.wait()
print(f"a pass at 2 MiB/s took {took:.1f}s; shutdown took {time.time() - t:.1f}s")
shutil.rmtree(work)
print("SCRUB TEST OK")
