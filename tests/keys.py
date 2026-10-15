#!/usr/bin/env python3
"""Access key management through the admin API (/_admin/keys).

    python3 tests/keys.py ./target/release/s3rs
"""

import json
import os
import shutil
import signal
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
PORT = 9360
EP = f"http://127.0.0.1:{PORT}"
TOKEN = "admin-token-for-tests"
work = tempfile.mkdtemp(prefix="s3rs-keys-")
with open(f"{work}/creds", "w") as f:
    f.write("filekey:filesecret123\n")


def start():
    p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "root",
                          "--secret-key", "rootsecret", "--credentials-file", f"{work}/creds", "--admin-token", TOKEN],
                         stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{EP}/_health")
            return p
        except Exception:
            time.sleep(0.1)
    sys.exit("server did not start")


def admin(method, path="", body=None, token=TOKEN):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{EP}/_admin/keys{path}", data=data, method=method,
                                 headers={"authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as r:
            text = r.read()
            return r.status, json.loads(text) if text else None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def client(ak, sk):
    return boto3.client("s3", endpoint_url=EP, aws_access_key_id=ak, aws_secret_access_key=sk, region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"total_max_attempts": 1}))


def denied(fn):
    try:
        fn()
        return False
    except ClientError as e:
        return e.response["Error"]["Code"] in ("AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "403")


p = start()
try:
    root = client("root", "rootsecret")
    root.create_bucket(Bucket="team-a")
    root.create_bucket(Bucket="team-b")

    assert admin("GET", token="wrong")[0] == 403
    status, listing = admin("GET")
    assert status == 200 and {k["access_key"] for k in listing["keys"]} == {"root", "filekey"}, listing
    assert all("secret" not in json.dumps(k) for k in listing["keys"])

    # A generated key, limited to one bucket.
    status, k = admin("POST", body={"buckets": ["team-a"], "description": "ci"})
    assert status == 201 and k["access_key"].startswith("S3RS") and len(k["secret_key"]) == 40, k
    a = client(k["access_key"], k["secret_key"])
    a.put_object(Bucket="team-a", Key="x", Body=b"1")
    assert denied(lambda: a.put_object(Bucket="team-b", Key="x", Body=b"1"))

    # A chosen key with a policy, and a read-only key.
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                                                      "Resource": "arn:aws:s3:::team-a/*"}]}
    status, _ = admin("POST", body={"access_key": "reader", "secret_key": "readersecret0123", "policy": policy})
    assert status == 201
    r = client("reader", "readersecret0123")
    assert r.get_object(Bucket="team-a", Key="x")["Body"].read() == b"1"
    assert denied(lambda: r.put_object(Bucket="team-a", Key="y", Body=b"1"))
    status, ro = admin("POST", body={"read_only": True})
    assert status == 201
    assert denied(lambda: client(ro["access_key"], ro["secret_key"]).put_object(Bucket="team-a", Key="z", Body=b"1"))

    # Conflicts and bad requests.
    assert admin("POST", body={"access_key": "reader"})[0] == 409
    assert admin("POST", body={"access_key": "filekey"})[0] == 409
    assert admin("POST", body={"secret_key": "short"})[0] == 400
    assert admin("POST", body={"policy": {"Statement": "nope"}})[0] == 400
    assert admin("DELETE", "/filekey")[0] == 409
    assert admin("DELETE", "/nope")[0] == 404

    # Keys survive a restart and a SIGHUP reload of the file keys.
    p.send_signal(signal.SIGHUP)
    time.sleep(0.5)
    a.head_bucket(Bucket="team-a")
    p.terminate()
    p.wait()
    p = start()
    a.head_bucket(Bucket="team-a")
    r.get_object(Bucket="team-a", Key="x")
    status, listing = admin("GET")
    api = [k for k in listing["keys"] if k["source"] == "api"]
    assert len(api) == 3 and any(x.get("description") == "ci" and x["buckets"] == ["team-a"] for x in api), api

    # Revoking takes effect at once.
    assert admin("DELETE", f"/{k['access_key']}")[0] == 204
    assert denied(lambda: a.head_bucket(Bucket="team-a"))
    assert len([x for x in admin("GET")[1]["keys"] if x["source"] == "api"]) == 2

    # A stored key hidden by a file key with the same name can still be revoked, so removing
    # the file key doesn't bring the old secret back.
    assert admin("POST", body={"access_key": "dup", "secret_key": "dupsecretA0123456"})[0] == 201
    with open(f"{work}/creds", "a") as f:
        f.write("dup:dupsecretB0123456:ro\n")
    p.send_signal(signal.SIGHUP)
    time.sleep(0.5)
    assert denied(lambda: client("dup", "dupsecretA0123456").list_buckets())
    client("dup", "dupsecretB0123456").list_buckets()
    assert admin("DELETE", "/dup")[0] == 204
    with open(f"{work}/creds", "w") as f:
        f.write("filekey:filesecret123\n")
    p.send_signal(signal.SIGHUP)
    time.sleep(0.5)
    assert denied(lambda: client("dup", "dupsecretA0123456").list_buckets())
    assert denied(lambda: client("dup", "dupsecretB0123456").list_buckets())

    # A temporary key works until it expires, is then refused with ExpiredToken (which makes SDKs
    # fetch new credentials), and is removed soon after.
    status, tmp = admin("POST", body={"expires_in": 2, "description": "short-lived"})
    assert status == 201 and "expires" in tmp, tmp
    t = client(tmp["access_key"], tmp["secret_key"])
    t.list_buckets()
    time.sleep(2.2)
    try:
        t.list_buckets()
        sys.exit("an expired key still works")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ExpiredToken", e.response
    for _ in range(100):
        if all(x["access_key"] != tmp["access_key"] for x in admin("GET")[1]["keys"]):
            break
        time.sleep(0.1)
    else:
        sys.exit("the expired key was not removed")
    assert admin("POST", body={"expires_in": 0})[0] == 400

    # Guessing the admin token is slowed down.
    codes = [admin("GET", token=f"guess{i}")[0] for i in range(14)]
    assert codes[0] == 403 and 503 in codes, codes
    # While throttled, even the right token is refused (else guessing would go on unhindered).
    assert admin("GET")[0] == 503
    time.sleep(1.5)
    assert admin("GET")[0] == 200

    log = open(f"{work}/log").read()
    assert k["secret_key"] not in log and "readersecret0123" not in log
    print("KEYS TEST OK")
finally:
    p.terminate()
    p.wait()
    shutil.rmtree(work)
