#!/usr/bin/env python3
"""Rate limit test: --rate-limit (per access key) and --rate-limit-anonymous (per address).

    python3 tests/ratelimit.py ./target/release/s3rs
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
PORT = 9350
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-rate-")
with open(f"{work}/creds", "w") as f:
    f.write("other:othersecret\n")
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "k", "--secret-key", "secretsecret",
                      "--credentials-file", f"{work}/creds", "--rate-limit", "5", "--rate-limit-anonymous", "10"],
                     stdout=open(f"{work}/log", "w"), stderr=subprocess.STDOUT)
for _ in range(100):
    try:
        urllib.request.urlopen(f"{EP}/_health")
        break
    except Exception:
        time.sleep(0.1)


def client(ak, sk, retries):
    return boto3.client("s3", endpoint_url=EP, aws_access_key_id=ak, aws_secret_access_key=sk, region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"total_max_attempts": retries, "mode": "standard"}))


try:
    s3 = client("k", "secretsecret", 1)
    s3.create_bucket(Bucket="pub")
    s3.put_object(Bucket="pub", Key="f", Body=b"public")
    s3.put_bucket_acl(Bucket="pub", ACL="public-read")
    time.sleep(2.5)  # refill

    # A burst beyond 2 s worth (10 requests) is refused with a retryable 503 SlowDown.
    codes = []
    for _ in range(60):
        try:
            s3.head_bucket(Bucket="pub")
            codes.append(200)
        except ClientError as e:
            codes.append(int(e.response["ResponseMetadata"]["HTTPStatusCode"]))
            retry_after = e.response["ResponseMetadata"]["HTTPHeaders"].get("retry-after")
    ok, slow = codes.count(200), codes.count(503)
    assert 10 <= ok <= 30 and slow >= 20 and ok + slow == 60, codes
    assert retry_after == "1", retry_after

    # Other keys have their own budget; the health endpoint is never limited.
    client("other", "othersecret", 1).list_buckets()
    for _ in range(50):
        urllib.request.urlopen(f"{EP}/_health")

    # Unsigned requests are limited per address.
    anon = []
    for _ in range(40):
        try:
            urllib.request.urlopen(f"{EP}/pub/f").read()
            anon.append(200)
        except urllib.error.HTTPError as e:
            anon.append(e.code)
            assert e.headers["retry-after"] == "1" and b"SlowDown" in e.read()
    assert 15 <= anon.count(200) <= 25 and anon.count(503) > 0, anon

    # Tokens come back, and SDK retries ride out the limit transparently.
    time.sleep(1)
    s3.head_bucket(Bucket="pub")
    retrying = client("k", "secretsecret", 10)
    start = time.time()
    for i in range(30):
        retrying.put_object(Bucket="pub", Key=f"k{i}", Body=b"x")
    took = time.time() - start
    assert took >= 3, took  # 30 requests at 5/s after a 10-request burst

    text = urllib.request.urlopen(f"{EP}/_metrics").read().decode()
    throttled = int(next(l for l in text.splitlines() if l.startswith("s3rs_throttled_requests_total")).split()[-1])
    assert throttled >= slow + anon.count(503), throttled
    print(f"key: {ok} of 60 passed, {slow} SlowDown; anonymous: {anon.count(200)} of 40; 30 PUTs with retries in {took:.1f}s")
    print("RATE LIMIT TEST OK")
finally:
    p.terminate()
    p.wait()
    shutil.rmtree(work)
