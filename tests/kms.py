#!/usr/bin/env python3
"""SSE-KMS: objects encrypted under KMS key ids whose keys are derived from the server's master
key (no external KMS).

    python3 tests/kms.py ./target/release/s3rs
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
PORT = 9394
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-kms-")
with open(f"{work}/key", "w") as f:
    f.write(os.urandom(32).hex())
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "root", "--secret-key", "rootsecret",
                      "--encryption-key-file", f"{work}/key", "--scrub-interval", "1s"],
                     stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
try:
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{EP}/_health")
            break
        except Exception:
            time.sleep(0.1)
    s3 = boto3.client("s3", endpoint_url=EP, aws_access_key_id="root", aws_secret_access_key="rootsecret", region_name="us-east-1",
                      config=Config(s3={"addressing_style": "path"}, retries={"total_max_attempts": 1}))

    def code(f):
        try:
            f()
        except ClientError as e:
            return e.response["Error"]["Code"]
        return "OK"

    s3.create_bucket(Bucket="kms")
    KEY = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    ctx = base64.b64encode(json.dumps({"team": "a"}).encode()).decode()
    big = os.urandom(9 << 20)
    r = s3.put_object(Bucket="kms", Key="small", Body=b"kms data", ServerSideEncryption="aws:kms", SSEKMSKeyId=KEY,
                      SSEKMSEncryptionContext=ctx, BucketKeyEnabled=True)
    assert r["ServerSideEncryption"] == "aws:kms" and r["SSEKMSKeyId"] == KEY and r["BucketKeyEnabled"], r
    s3.put_object(Bucket="kms", Key="big", Body=big, ServerSideEncryption="aws:kms")
    g = s3.get_object(Bucket="kms", Key="small")
    assert g["Body"].read() == b"kms data" and g["ServerSideEncryption"] == "aws:kms" and g["SSEKMSKeyId"] == KEY
    assert g["ResponseMetadata"]["HTTPHeaders"]["x-amz-server-side-encryption-context"] == ctx
    h = s3.head_object(Bucket="kms", Key="big")
    assert h["SSEKMSKeyId"] == "alias/aws/s3", h
    assert s3.get_object(Bucket="kms", Key="big", Range="bytes=5000000-5000099")["Body"].read() == big[5000000:5000100]
    print("PUT/GET/HEAD/range with SSE-KMS (named and default key)")

    # Data is really encrypted on disk, and with a different key per KMS key id.
    files = [os.path.join(d, f) for d, _, fs in os.walk(f"{work}/data/data") for f in fs]
    assert not any(big[:4096] in open(f, "rb").read() for f in files)

    # Multipart, copy (keeps KMS, or switches), invalid requests.
    up = s3.create_multipart_upload(Bucket="kms", Key="mp", ServerSideEncryption="aws:kms", SSEKMSKeyId="key-2")
    parts = [s3.upload_part(Bucket="kms", Key="mp", UploadId=up["UploadId"], PartNumber=i, Body=big[(i - 1) * (5 << 20):i * (5 << 20)])
             for i in (1, 2)]
    c = s3.complete_multipart_upload(Bucket="kms", Key="mp", UploadId=up["UploadId"], MultipartUpload={
        "Parts": [{"PartNumber": i, "ETag": x["ETag"]} for i, x in enumerate(parts, 1)]})
    assert c["ServerSideEncryption"] == "aws:kms" and c["SSEKMSKeyId"] == "key-2", c
    assert s3.get_object(Bucket="kms", Key="mp")["Body"].read() == big
    s3.copy_object(Bucket="kms", Key="copy", CopySource={"Bucket": "kms", "Key": "small"})
    cp = s3.head_object(Bucket="kms", Key="copy")
    assert cp["ServerSideEncryption"] == "aws:kms" and cp["SSEKMSKeyId"] == KEY, cp
    s3.copy_object(Bucket="kms", Key="copy2", CopySource={"Bucket": "kms", "Key": "small"}, ServerSideEncryption="aws:kms",
                   SSEKMSKeyId="key-3")
    assert s3.head_object(Bucket="kms", Key="copy2")["SSEKMSKeyId"] == "key-3"
    assert s3.get_object(Bucket="kms", Key="copy2")["Body"].read() == b"kms data"
    s3.copy_object(Bucket="kms", Key="copy3", CopySource={"Bucket": "kms", "Key": "small"}, ServerSideEncryption="AES256")
    assert s3.head_object(Bucket="kms", Key="copy3")["ServerSideEncryption"] == "AES256"
    assert code(lambda: s3.put_object(Bucket="kms", Key="x", Body=b"x", ServerSideEncryption="AES256", SSEKMSKeyId="k")) == "InvalidArgument"
    assert code(lambda: s3.put_object(Bucket="kms", Key="x", Body=b"x", ServerSideEncryption="aws:kms",
                                      SSEKMSEncryptionContext="not base64 json")) == "InvalidArgument"
    print("multipart, copies and invalid requests")

    # Bucket default encryption with a KMS key.
    s3.create_bucket(Bucket="kms-default")
    s3.put_bucket_encryption(Bucket="kms-default", ServerSideEncryptionConfiguration={"Rules": [{
        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "bucket-key"}, "BucketKeyEnabled": True}]})
    rule = s3.get_bucket_encryption(Bucket="kms-default")["ServerSideEncryptionConfiguration"]["Rules"][0]
    assert rule["ApplyServerSideEncryptionByDefault"] == {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "bucket-key"} and rule["BucketKeyEnabled"]
    s3.put_object(Bucket="kms-default", Key="d", Body=b"default")
    d = s3.head_object(Bucket="kms-default", Key="d")
    assert d["ServerSideEncryption"] == "aws:kms" and d["SSEKMSKeyId"] == "bucket-key", d
    assert s3.get_object(Bucket="kms-default", Key="d")["Body"].read() == b"default"
    print("bucket default SSE-KMS")

    # Scrubbing verifies KMS objects (it has the master key).
    deadline = time.time() + 30
    def metric(n):
        return sum(float(l.split()[-1]) for l in urllib.request.urlopen(f"{EP}/_metrics").read().decode().splitlines() if l.startswith(n + " "))
    while metric("s3rs_scrub_passes_total") < 1 and time.time() < deadline:
        time.sleep(0.2)
    assert metric("s3rs_scrub_corrupt_total") == 0 and metric("s3rs_scrub_skipped_total") == 0, open(f"{work}/log").read()[-2000:]
    print("scrub verified KMS objects")

    p.terminate()
    p.wait()
    r = subprocess.run([BIN, "fsck", "-d", f"{work}/data", "--deep", "--encryption-key-file", f"{work}/key"], capture_output=True, text=True)
    assert r.returncode == 0 and "0 skipped" in r.stdout, r.stdout + r.stderr
    print("KMS TEST OK")
finally:
    p.kill()
shutil.rmtree(work, ignore_errors=True)
