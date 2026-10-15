#!/usr/bin/env python3
"""Server access logging per bucket (PutBucketLogging).

    python3 tests/bucketlog.py ./target/release/s3rs
"""

import atexit
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
PORT = 9385
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-blog-")
procs = []
atexit.register(lambda: [p.kill() for p in procs])
with open(f"{work}/creds", "w") as f:
    f.write("scoped:scopedsecret123:rw:site\n")


def start():
    p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "root", "--secret-key", "rootsecret",
                          "--credentials-file", f"{work}/creds"], stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
    procs.append(p)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{EP}/_health")
            return p
        except Exception:
            time.sleep(0.1)
    sys.exit("server did not start")


def client(ak, sk):
    return boto3.client("s3", endpoint_url=EP, aws_access_key_id=ak, aws_secret_access_key=sk, region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}))


p = start()
s3 = client("root", "rootsecret")
for b in ("site", "logs", "other"):
    s3.create_bucket(Bucket=b)
assert s3.get_bucket_logging(Bucket="site").get("LoggingEnabled") is None

# A key limited to `site` can't send its logs into a bucket it can't write.
scoped = client("scoped", "scopedsecret123")
try:
    scoped.put_bucket_logging(Bucket="site", BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "x/"}})
    sys.exit("a scoped key enabled logging into another bucket")
except ClientError as e:
    assert e.response["Error"]["Code"] == "AccessDenied", e.response
try:
    s3.put_bucket_logging(Bucket="site", BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": "missing", "TargetPrefix": ""}})
    sys.exit("logging into a missing bucket was accepted")
except ClientError as e:
    assert e.response["Error"]["Code"] == "InvalidArgument", e.response

s3.put_bucket_logging(Bucket="site", BucketLoggingStatus={"LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "site/"}})
got = s3.get_bucket_logging(Bucket="site")["LoggingEnabled"]
assert got["TargetBucket"] == "logs" and got["TargetPrefix"] == "site/", got

s3.put_object(Bucket="site", Key="index.html", Body=b"<h1>hi</h1>")
s3.get_object(Bucket="site", Key="index.html")["Body"].read()
s3.list_objects_v2(Bucket="site")
try:
    s3.get_object(Bucket="site", Key="missing")
except ClientError:
    pass
s3.put_object(Bucket="other", Key="not-logged", Body=b"x")

# Buffered logs are written at the latest on shutdown.
p.send_signal(signal.SIGTERM)
p.wait()
p = start()
objs = s3.list_objects_v2(Bucket="logs", Prefix="site/").get("Contents", [])
assert len(objs) == 1, objs
text = s3.get_object(Bucket="logs", Key=objs[0]["Key"])["Body"].read().decode()
lines = text.splitlines()
assert len(lines) == 5, text  # get-bucket-logging, put, get, list, missing get
assert all(l.startswith("s3rs site [") for l in lines), text
assert any("REST.PUT.OBJECT index.html \"PUT /site/index.html HTTP/1.1\" 200" in l for l in lines), text
assert any("REST.GET.OBJECT index.html \"GET /site/index.html HTTP/1.1\" 200 - 11 " in l for l in lines), text
assert any("REST.GET.OBJECT missing" in l and " 404 NoSuchKey " in l for l in lines), text
assert any(" REST.GET.BUCKET - " in l for l in lines), text
assert all(" root " in l and " SigV4 " in l for l in lines), text
assert "not-logged" not in text
print(f"{len(lines)} log lines written to logs/{objs[0]['Key']}")

# Partitioned keys, and turning logging off.
s3.put_bucket_logging(Bucket="site", BucketLoggingStatus={"LoggingEnabled": {
    "TargetBucket": "logs", "TargetPrefix": "p/", "TargetObjectKeyFormat": {"PartitionedPrefix": {"PartitionDateSource": "EventTime"}}}})
s3.head_object(Bucket="site", Key="index.html")
s3.put_bucket_logging(Bucket="site", BucketLoggingStatus={})
assert s3.get_bucket_logging(Bucket="site").get("LoggingEnabled") is None
s3.head_object(Bucket="site", Key="index.html")
p.send_signal(signal.SIGTERM)
p.wait()
p = start()
part = s3.list_objects_v2(Bucket="logs", Prefix="p/").get("Contents", [])
assert len(part) == 1 and part[0]["Key"].startswith("p/s3rs/us-east-1/site/"), part
assert len(s3.list_objects_v2(Bucket="logs", Prefix="site/")["Contents"]) == 1, "logs were written after logging was turned off"
text = urllib.request.urlopen(f"{EP}/_metrics").read().decode()
assert "s3rs_bucket_log_objects_total" in text
p.terminate()
p.wait()
shutil.rmtree(work)
print("BUCKET LOGGING TEST OK")
