#!/usr/bin/env python3
"""Per-bucket metrics (served with --metrics-token): object counts and sizes, and requests and
traffic per bucket. Requests naming buckets that don't exist add no series.

    python3 tests/metrics.py ./target/release/s3rs
"""

import atexit
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
PORT = 9396
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-metrics-")
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "k", "--secret-key", "mbsecret1234",
                      "--metrics-token", "mtok"], stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
atexit.register(p.kill)
for _ in range(100):
    try:
        urllib.request.urlopen(f"{EP}/_health")
        break
    except Exception:
        time.sleep(0.1)


def metrics(token="mtok"):
    req = urllib.request.Request(f"{EP}/_metrics", headers={"Authorization": f"Bearer {token}"})
    return urllib.request.urlopen(req).read().decode()


def value(text, series):
    for line in text.splitlines():
        if line.startswith(series + " "):
            return float(line.split()[-1])
    return None


s3 = boto3.client("s3", endpoint_url=EP, aws_access_key_id="k", aws_secret_access_key="mbsecret1234", region_name="us-east-1",
                  config=Config(s3={"addressing_style": "path"}))
s3.create_bucket(Bucket="team-a")
s3.create_bucket(Bucket="team-b")
s3.put_object(Bucket="team-a", Key="x", Body=b"a" * 1000)
for _ in range(3):
    s3.get_object(Bucket="team-a", Key="x")["Body"].read()
try:
    s3.get_object(Bucket="team-a", Key="missing")
except ClientError:
    pass
s3.put_object(Bucket="team-b", Key="y", Body=b"b" * 10)
for i in range(20):
    try:
        s3.get_object(Bucket=f"made-up-{i}", Key="k")
    except ClientError:
        pass

t = metrics()
assert value(t, 's3rs_bucket_objects{bucket="team-a"}') == 1
assert value(t, 's3rs_bucket_bytes{bucket="team-a"}') == 1000
assert value(t, 's3rs_bucket_requests_total{bucket="team-a",method="GET",code="2xx"}') == 3, t
assert value(t, 's3rs_bucket_requests_total{bucket="team-a",method="GET",code="4xx"}') == 1, t
assert value(t, 's3rs_bucket_received_bytes_total{bucket="team-a"}') == 1000
assert value(t, 's3rs_bucket_sent_bytes_total{bucket="team-a"}') >= 3000
assert value(t, 's3rs_bucket_received_bytes_total{bucket="team-b"}') == 10
assert "made-up" not in t
# Without the token, nothing names a bucket.
try:
    metrics("wrong")
    sys.exit("metrics served with a wrong token")
except urllib.error.HTTPError as e:
    assert e.code in (401, 403), e.code
# A deleted bucket's series go away.
s3.delete_object(Bucket="team-b", Key="y")
s3.delete_bucket(Bucket="team-b")
assert "team-b" not in metrics()
p.terminate()
p.wait()
shutil.rmtree(work)
print("METRICS TEST OK")
