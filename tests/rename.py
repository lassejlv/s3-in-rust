#!/usr/bin/env python3
"""RenameObject: moving an object to another key without copying its data.

    python3 tests/rename.py ./target/release/s3rs
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
PORT, HOOK = 9392, 9393
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-rename-")
with open(f"{work}/key", "w") as f:
    f.write(os.urandom(32).hex())
with open(f"{work}/creds", "w") as f:
    f.write("limited:limitedsecret:policy=limited.json\n")
with open(f"{work}/limited.json", "w") as f:
    # May read and write everywhere, but delete only below tmp/.
    json.dump({"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], "Resource": "*"},
        {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::files/tmp/*"},
    ]}, f)

events = []


class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        events.extend((r["eventName"], r["s3"]["object"]["key"]) for r in body["Records"])
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


threading.Thread(target=HTTPServer(("127.0.0.1", HOOK), Hook).serve_forever, daemon=True).start()
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "root", "--secret-key", "rootsecret",
                      "--credentials-file", f"{work}/creds", "--encryption-key-file", f"{work}/key",
                      "--webhook", f"hook=http://127.0.0.1:{HOOK}/", "--metrics-token", "mt"],
                     stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
try:
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{EP}/_health")
            break
        except Exception:
            time.sleep(0.1)

    def client(ak="root", sk="rootsecret"):
        return boto3.client("s3", endpoint_url=EP, aws_access_key_id=ak, aws_secret_access_key=sk, region_name="us-east-1",
                            config=Config(s3={"addressing_style": "path"}, retries={"total_max_attempts": 1}))

    def code(f):
        try:
            f()
        except ClientError as e:
            return e.response["Error"]["Code"]
        return "OK"

    def usage(bucket):
        req = urllib.request.Request(f"{EP}/_metrics", headers={"Authorization": "Bearer mt"})
        text = urllib.request.urlopen(req).read().decode()
        get = lambda n: int(next(l.split()[-1] for l in text.splitlines() if l.startswith(f'{n}{{bucket="{bucket}"}}')))
        return get("s3rs_bucket_objects"), get("s3rs_bucket_bytes")

    s3 = client()
    s3.create_bucket(Bucket="files")
    s3.put_bucket_notification_configuration(Bucket="files", NotificationConfiguration={"QueueConfigurations": [
        {"QueueArn": "arn:s3rs:webhook::hook", "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]}]})
    big = os.urandom(12 << 20)
    s3.put_object(Bucket="files", Key="dir/big.bin", Body=big, ContentType="application/x-big", Metadata={"m": "1"},
                  Tagging="t=1")
    head = s3.head_object(Bucket="files", Key="dir/big.bin")

    # A rename moves data, metadata and tags, and takes no time whatever the size.
    t = time.time()
    s3.rename_object(Bucket="files", Key="moved/big.bin", RenameSource="files/dir/big.bin")
    took = time.time() - t
    assert code(lambda: s3.head_object(Bucket="files", Key="dir/big.bin")) == "404"
    got = s3.get_object(Bucket="files", Key="moved/big.bin")
    assert got["Body"].read() == big and got["ETag"] == head["ETag"] and got["ContentType"] == "application/x-big"
    assert got["Metadata"] == {"m": "1"} and got["LastModified"] == head["LastModified"]
    assert s3.get_object_tagging(Bucket="files", Key="moved/big.bin")["TagSet"] == [{"Key": "t", "Value": "1"}]
    assert [o["Key"] for o in s3.list_objects_v2(Bucket="files")["Contents"]] == ["moved/big.bin"]
    assert usage("files") == (1, len(big)), usage("files")
    print(f"renamed a 12 MiB object in {took * 1000:.1f} ms")

    # Small (inline) and encrypted objects, and a leading slash in the source.
    s3.put_object(Bucket="files", Key="small", Body=b"tiny")
    s3.put_object(Bucket="files", Key="enc", Body=b"secret stuff", ServerSideEncryption="AES256")
    s3.rename_object(Bucket="files", Key="small2", RenameSource="/files/small")
    s3.rename_object(Bucket="files", Key="enc2", RenameSource="files/enc")
    assert s3.get_object(Bucket="files", Key="small2")["Body"].read() == b"tiny"
    r = s3.get_object(Bucket="files", Key="enc2")
    assert r["Body"].read() == b"secret stuff" and r["ServerSideEncryption"] == "AES256"

    # Replacing an existing destination frees it; conditions on both sides.
    s3.put_object(Bucket="files", Key="a", Body=b"A" * 100)
    s3.put_object(Bucket="files", Key="b", Body=b"B" * 50)
    etag_a = s3.head_object(Bucket="files", Key="a")["ETag"]
    assert code(lambda: s3.rename_object(Bucket="files", Key="b", RenameSource="files/a", DestinationIfNoneMatch="*")) == "PreconditionFailed"
    assert code(lambda: s3.rename_object(Bucket="files", Key="b", RenameSource="files/a", SourceIfMatch='"0123"')) == "PreconditionFailed"
    assert code(lambda: s3.rename_object(Bucket="files", Key="b", RenameSource="files/a", DestinationIfMatch='"0123"')) == "PreconditionFailed"
    past = datetime.now(timezone.utc) - timedelta(days=1)
    assert code(lambda: s3.rename_object(Bucket="files", Key="b", RenameSource="files/a", SourceIfUnmodifiedSince=past)) == "PreconditionFailed"
    before = usage("files")
    s3.rename_object(Bucket="files", Key="b", RenameSource="files/a", SourceIfMatch=etag_a, SourceIfModifiedSince=past)
    assert s3.get_object(Bucket="files", Key="b")["Body"].read() == b"A" * 100
    assert usage("files") == (before[0] - 1, before[1] - 50), (before, usage("files"))
    assert code(lambda: s3.rename_object(Bucket="files", Key="c", RenameSource="files/b", DestinationIfNoneMatch="*")) == "OK"
    print("conditions on the source and destination hold; a replaced destination is freed")

    # Errors: missing source, another bucket, versioned buckets, missing header.
    assert code(lambda: s3.rename_object(Bucket="files", Key="x", RenameSource="files/nope")) == "NoSuchKey"
    s3.create_bucket(Bucket="other")
    s3.put_object(Bucket="other", Key="o", Body=b"o")
    assert code(lambda: s3.rename_object(Bucket="files", Key="x", RenameSource="other/o")) == "InvalidRequest"
    s3.create_bucket(Bucket="versioned")
    s3.put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket="versioned", Key="v", Body=b"v")
    assert code(lambda: s3.rename_object(Bucket="versioned", Key="w", RenameSource="versioned/v")) == "InvalidRequest"
    print("errors: missing source, other bucket, versioned bucket")

    # The source must be readable and deletable by the caller.
    lim = client("limited", "limitedsecret")
    s3.put_object(Bucket="files", Key="keep/k", Body=b"k")
    s3.put_object(Bucket="files", Key="tmp/t", Body=b"t")
    assert code(lambda: lim.rename_object(Bucket="files", Key="mine/k", RenameSource="files/keep/k")) == "AccessDenied"
    lim.rename_object(Bucket="files", Key="mine/t", RenameSource="files/tmp/t")
    print("the source needs s3:GetObject and s3:DeleteObject")

    # Readers of the old key see a complete object or none; usage still matches the listing.
    data = os.urandom(6 << 20)
    md5 = hashlib.md5(data).hexdigest()
    stop = time.time() + 3
    problems = []

    def reader():
        c = client()
        while time.time() < stop:
            for k in ("ping", "pong"):
                try:
                    if hashlib.md5(c.get_object(Bucket="files", Key=k)["Body"].read()).hexdigest() != md5:
                        problems.append("torn read")
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchKey":
                        problems.append(str(e))

    s3.put_object(Bucket="files", Key="ping", Body=data)
    readers = [threading.Thread(target=reader) for _ in range(4)]
    for t in readers:
        t.start()
    n = 0
    while time.time() < stop:
        src, dst = ("ping", "pong") if n % 2 == 0 else ("pong", "ping")
        s3.rename_object(Bucket="files", Key=dst, RenameSource=f"files/{src}")
        n += 1
    for t in readers:
        t.join()
    assert not problems, problems[:5]
    listed = [(o["Key"], o["Size"]) for o in s3.list_objects_v2(Bucket="files")["Contents"]]
    assert usage("files") == (len(listed), sum(s for _, s in listed)), (usage("files"), listed)
    print(f"{n} renames back and forth under concurrent reads")

    # Events: the new key is created, the old one removed.
    deadline = time.time() + 10
    while ("ObjectCreated:Copy", "moved/big.bin") not in events and time.time() < deadline:
        time.sleep(0.1)
    assert ("ObjectCreated:Copy", "moved/big.bin") in events and ("ObjectRemoved:Delete", "dir/big.bin") in events, events[:10]
    print("rename events delivered")

    p.terminate()
    p.wait()
    r = subprocess.run([BIN, "fsck", "-d", f"{work}/data", "--deep", "--encryption-key-file", f"{work}/key"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    print("RENAME TEST OK")
finally:
    p.kill()
shutil.rmtree(work, ignore_errors=True)
