#!/usr/bin/env python3
"""--block-public-access: no bucket can be made public, whatever its ACL or policy says.

    python3 tests/publicblock.py ./target/release/s3rs
"""

import atexit
import json
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
PORT = 9395
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-pab-")
procs = []
atexit.register(lambda: [p.kill() for p in procs])


def start(*extra):
    p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "k", "--secret-key", "pabsecret123", *extra],
                         stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
    procs.append(p)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{EP}/_health")
            return p
        except Exception:
            time.sleep(0.1)
    sys.exit("server did not start")


def anon(path):
    try:
        return urllib.request.urlopen(f"{EP}{path}").status
    except urllib.error.HTTPError as e:
        return e.code


def code(fn):
    try:
        fn()
        return "OK"
    except ClientError as e:
        return e.response["Error"]["Code"]


s3 = boto3.client("s3", endpoint_url=EP, aws_access_key_id="k", aws_secret_access_key="pabsecret123", region_name="us-east-1",
                  config=Config(s3={"addressing_style": "path"}))
p = start()
s3.create_bucket(Bucket="acl", ACL="public-read")
s3.create_bucket(Bucket="pol")
s3.put_bucket_policy(Bucket="pol", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::pol/*"}]}))
for b in ("acl", "pol"):
    s3.put_object(Bucket=b, Key="f", Body=b"x")
    assert anon(f"/{b}/f") == 200
p.terminate()
p.wait()

p = start("--block-public-access")
assert anon("/acl/f") == 403 and anon("/pol/f") == 403
assert code(lambda: s3.put_bucket_acl(Bucket="acl", ACL="public-read-write")) == "AccessDenied"
assert code(lambda: s3.put_bucket_policy(Bucket="pol", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::pol/*"}]}))) == "AccessDenied"
# Removing a bucket's own block doesn't lift the server's.
s3.put_public_access_block(Bucket="acl", PublicAccessBlockConfiguration={"BlockPublicAcls": False})
assert anon("/acl/f") == 403
assert s3.get_object(Bucket="acl", Key="f")["Body"].read() == b"x"
p.terminate()
p.wait()
shutil.rmtree(work)
print("PUBLIC ACCESS BLOCK TEST OK")
