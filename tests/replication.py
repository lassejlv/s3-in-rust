#!/usr/bin/env python3
"""Bucket replication test with two servers.

    python3 tests/replication.py ./target/release/s3rs

Server A replicates bucket `src` to bucket `dst` on server B (and, at the end, B replicates
`dst` back to A, to check that two-way replication settles instead of looping). Checks:

- objects that existed before the configuration are replicated (ExistingObjectReplication);
- new objects of every kind arrive with the same content, ETag, metadata and tags: inline and
  file-backed objects, multipart objects (same ETag), SSE-S3 objects; SSE-C objects are skipped;
- tag changes and deletes (DeleteMarkerReplication) are replicated; prefix filters are honored;
- while B is down, changes queue up (s3rs_replication_pending) and are delivered once it is back,
  even if A was killed with SIGKILL in between;
- GetBucketReplication / DeleteBucketReplication, and invalid configurations are refused;
- `s3rs fsck --deep` passes on both servers.
"""

import atexit
import os
import random
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
PORT_A, PORT_B = 9340, 9341
KEY, SECRET = "replkey", "replsecret"
work = tempfile.mkdtemp(prefix="s3rs-repl-")
master = os.urandom(32).hex()
with open(f"{work}/master.key", "w") as f:
    f.write(master)
rng = random.Random(3)
procs = {}
# Don't leave servers behind when a check fails.
atexit.register(lambda: [p.kill() for p in procs.values()])


def targets(name, port):
    path = f"{work}/{name}.targets"
    with open(path, "w") as f:
        # `dead` never answers (nothing listens on port 9).
        f.write(f"# test target\n{name} http://127.0.0.1:{port} {KEY} {SECRET}\ndead http://127.0.0.1:9 {KEY} {SECRET}\n")
    return path


def start(name):
    port = PORT_A if name == "a" else PORT_B
    args = [BIN, "-d", f"{work}/{name}", "-l", f"127.0.0.1:{port}", "--access-key", KEY, "--secret-key", SECRET,
            "--encryption-key-file", f"{work}/master.key", "--lifecycle-interval", "0"]
    if name == "a":
        args += ["--replication-targets", targets("b", PORT_B)]
        with open(f"{work}/creds", "w") as f:
            f.write("scoped:scopedsecret:rw:src\n")
        args += ["--credentials-file", f"{work}/creds"]
    elif os.path.exists(f"{work}/a.targets"):
        args += ["--replication-targets", f"{work}/a.targets"]
    log = open(f"{work}/{name}.log", "a")
    p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/_health", timeout=1)
            procs[name] = p
            return p
        except Exception:
            if p.poll() is not None:
                break
            time.sleep(0.1)
    print(open(f"{work}/{name}.log").read())
    sys.exit(f"server {name} did not start")


def stop(name, sig=signal.SIGTERM):
    p = procs.pop(name)
    p.send_signal(sig)
    p.wait(timeout=30)


def client(port):
    return boto3.client("s3", endpoint_url=f"http://127.0.0.1:{port}", aws_access_key_id=KEY,
                        aws_secret_access_key=SECRET, region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 2}))


def metric(port, name):
    text = urllib.request.urlopen(f"http://127.0.0.1:{port}/_metrics").read().decode()
    vals = [float(l.split()[-1]) for l in text.splitlines() if l.startswith(name + " ") or l.startswith(name + "{")]
    return sum(vals)


def wait_for(cond, what, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if cond():
                return
        except ClientError:
            pass
        time.sleep(0.2)
    print(open(f"{work}/a.log").read()[-3000:])
    sys.exit(f"timed out waiting for: {what}")


def absent(s3, bucket, key):
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return False
    except ClientError as e:
        return e.response["Error"]["Code"] in ("404", "NoSuchKey")


def same(a, b, bucket_a, bucket_b, key, **extra):
    ra = a.get_object(Bucket=bucket_a, Key=key, **extra)
    rb = b.get_object(Bucket=bucket_b, Key=key)
    da, db = ra["Body"].read(), rb["Body"].read()
    assert da == db, f"{key}: content differs ({len(da)} vs {len(db)} bytes)"
    assert ra["ETag"] == rb["ETag"], f"{key}: ETag {ra['ETag']} vs {rb['ETag']}"
    assert ra["Metadata"] == rb["Metadata"], f"{key}: metadata {ra['Metadata']} vs {rb['Metadata']}"
    assert ra.get("ContentType") == rb.get("ContentType"), key
    ta = a.get_object_tagging(Bucket=bucket_a, Key=key)["TagSet"]
    tb = b.get_object_tagging(Bucket=bucket_b, Key=key)["TagSet"]
    assert sorted(map(str, ta)) == sorted(map(str, tb)), f"{key}: tags {ta} vs {tb}"
    return True


def config(dest, prefix="", existing=True, deletes=True, rule_id="all"):
    rule = {
        "ID": rule_id, "Status": "Enabled", "Priority": 1, "Filter": {"Prefix": prefix},
        "DeleteMarkerReplication": {"Status": "Enabled" if deletes else "Disabled"},
        "Destination": {"Bucket": dest},
    }
    if existing:
        rule["ExistingObjectReplication"] = {"Status": "Enabled"}
    return {"Role": "", "Rules": [rule]}


start("b")
start("a")
a, b = client(PORT_A), client(PORT_B)
a.create_bucket(Bucket="src")
b.create_bucket(Bucket="dst")

# Objects that exist before replication is configured.
before = {f"old/{i}": rng.randbytes(rng.choice([10, 100_000])) for i in range(25)}
for k, v in before.items():
    a.put_object(Bucket="src", Key=k, Body=v)

# Invalid configurations are refused.
for bad in ["arn:aws:s3:::dst", "arn:s3rs:replication::nope:dst", "arn:s3rs:replication::b:Bad_Name"]:
    try:
        a.put_bucket_replication(Bucket="src", ReplicationConfiguration=config(bad))
        sys.exit(f"configuration with destination {bad} was accepted")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "InvalidArgument", e.response
try:
    a.get_bucket_replication(Bucket="src")
    sys.exit("GetBucketReplication without a configuration succeeded")
except ClientError as e:
    assert e.response["Error"]["Code"] == "ReplicationConfigurationNotFoundError"

# A key limited to some buckets can't make the server write elsewhere with its target credentials.
scoped = boto3.client("s3", endpoint_url=f"http://127.0.0.1:{PORT_A}", aws_access_key_id="scoped",
                      aws_secret_access_key="scopedsecret", region_name="us-east-1",
                      config=Config(s3={"addressing_style": "path"}))
try:
    scoped.put_bucket_replication(Bucket="src", ReplicationConfiguration=config("arn:s3rs:replication::b:dst"))
    sys.exit("a bucket-limited key configured replication")
except ClientError as e:
    assert e.response["Error"]["Code"] == "AccessDenied", e.response

a.put_bucket_replication(Bucket="src", ReplicationConfiguration=config("arn:s3rs:replication::b:dst"))
got = a.get_bucket_replication(Bucket="src")["ReplicationConfiguration"]["Rules"][0]
assert got["Destination"]["Bucket"] == "arn:s3rs:replication::b:dst", got

wait_for(lambda: all(not absent(b, "dst", k) for k in before), "existing objects replicated")
for k in before:
    same(a, b, "src", "dst", k)
print(f"backfill: {len(before)} existing objects replicated")

# New objects of every kind.
a.put_object(Bucket="src", Key="small", Body=b"hello", ContentType="text/plain", Metadata={"m": "1"})
a.put_object(Bucket="src", Key="big", Body=rng.randbytes(300_000), CacheControl="max-age=60",
             ContentDisposition="attachment", Tagging="env=prod&team=a%20b")
a.put_object(Bucket="src", Key="dir/ünï cødé+%.txt", Body=b"odd key")
a.put_object(Bucket="src", Key="secret", Body=rng.randbytes(80_000), ServerSideEncryption="AES256")
mp = a.create_multipart_upload(Bucket="src", Key="multi", Metadata={"kind": "mp"}, ChecksumAlgorithm="SHA256")
parts = [rng.randbytes(5 * 1024 * 1024), rng.randbytes(5 * 1024 * 1024), rng.randbytes(1234)]
ups = [a.upload_part(Bucket="src", Key="multi", UploadId=mp["UploadId"], PartNumber=i + 1, Body=d, ChecksumAlgorithm="SHA256")
       for i, d in enumerate(parts)]
a.complete_multipart_upload(Bucket="src", Key="multi", UploadId=mp["UploadId"], MultipartUpload={"Parts": [
    {"ETag": u["ETag"], "ChecksumSHA256": u["ChecksumSHA256"], "PartNumber": i + 1} for i, u in enumerate(ups)]})
ssec = {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": os.urandom(32)}
a.put_object(Bucket="src", Key="customer-key", Body=b"only the client has the key", **ssec)
keys = ["small", "big", "dir/ünï cødé+%.txt", "secret", "multi"]
wait_for(lambda: all(not absent(b, "dst", k) for k in keys), "new objects replicated")
for k in keys:
    same(a, b, "src", "dst", k)
assert b.head_object(Bucket="dst", Key="secret").get("ServerSideEncryption") == "AES256"
assert b.head_object(Bucket="dst", Key="big")["CacheControl"] == "max-age=60"
# Multipart checksums are replicated too.
src_ck = a.head_object(Bucket="src", Key="multi", ChecksumMode="ENABLED")["ChecksumSHA256"]
assert src_ck.endswith("-3") and b.head_object(Bucket="dst", Key="multi", ChecksumMode="ENABLED").get("ChecksumSHA256") == src_ck
wait_for(lambda: metric(PORT_A, "s3rs_replication_pending") == 0, "queue drained")
assert absent(b, "dst", "customer-key"), "an SSE-C object was replicated"
assert metric(PORT_A, 's3rs_replication_total{result="skipped"}') >= 1
print("new objects: content, ETags (also multipart), metadata, tags and SSE-S3 replicated; SSE-C skipped")

# Changes: overwrite, tags, delete.
a.put_object(Bucket="src", Key="small", Body=b"hello again", ContentType="text/plain")
a.put_object_tagging(Bucket="src", Key="big", Tagging={"TagSet": [{"Key": "env", "Value": "dev"}]})
a.delete_object(Bucket="src", Key="old/0")
wait_for(lambda: b.get_object(Bucket="dst", Key="small")["Body"].read() == b"hello again", "overwrite replicated")
wait_for(lambda: b.get_object_tagging(Bucket="dst", Key="big")["TagSet"] == [{"Key": "env", "Value": "dev"}],
         "tag change replicated")
wait_for(lambda: absent(b, "dst", "old/0"), "delete replicated")
print("overwrites, tag changes and deletes replicated")

# Target down: changes queue up durably, survive a SIGKILL of the source, and arrive later.
stop("b")
queued = {f"queued/{i}": rng.randbytes(rng.choice([50, 200_000])) for i in range(30)}
for k, v in queued.items():
    a.put_object(Bucket="src", Key=k, Body=v)
a.delete_object(Bucket="src", Key="old/1")
wait_for(lambda: metric(PORT_A, "s3rs_replication_pending") >= 31, "changes queued while the target is down")
time.sleep(1.5)
assert metric(PORT_A, 's3rs_replication_total{result="failed"}') > 0
stop("a", signal.SIGKILL)
start("a")
start("b")
wait_for(lambda: all(not absent(b, "dst", k) for k in queued) and absent(b, "dst", "old/1"),
         "queued changes delivered after the outage", timeout=60)
for k in list(queued)[:5]:
    same(a, b, "src", "dst", k)
wait_for(lambda: metric(PORT_A, "s3rs_replication_pending") == 0, "queue drained after the outage", timeout=60)
print(f"outage: {len(queued) + 1} changes queued, kept across SIGKILL, delivered when the target came back")

# Prefix filters and removing the configuration.
a.create_bucket(Bucket="partial")
b.create_bucket(Bucket="partial-copy")
a.put_bucket_replication(Bucket="partial", ReplicationConfiguration=config(
    "arn:s3rs:replication::b:partial-copy", prefix="logs/", existing=False, deletes=False))
a.put_object(Bucket="partial", Key="logs/1", Body=b"yes")
a.put_object(Bucket="partial", Key="other/1", Body=b"no")
wait_for(lambda: not absent(b, "partial-copy", "logs/1"), "prefix-filtered object replicated")
wait_for(lambda: metric(PORT_A, "s3rs_replication_pending") == 0, "queue drained")
assert absent(b, "partial-copy", "other/1"), "an object outside the prefix was replicated"
a.delete_object(Bucket="partial", Key="logs/1")
a.delete_bucket_replication(Bucket="partial")
a.put_object(Bucket="partial", Key="logs/2", Body=b"after removal")
time.sleep(2)
assert not absent(b, "partial-copy", "logs/1"), "a delete was replicated although delete replication is off"
assert absent(b, "partial-copy", "logs/2"), "replication continued after DeleteBucketReplication"
print("prefix filters, disabled delete replication and DeleteBucketReplication honored")

# Two-way replication settles: B replicates dst back to A.
targets("a", PORT_A)
stop("b")
start("b")
b.put_bucket_replication(Bucket="dst", ReplicationConfiguration=config("arn:s3rs:replication::a:src", existing=False))
# boto3 refuses non-ASCII metadata (S3 accepts it as UTF-8); other clients send it.
from botocore.handlers import validate_ascii_metadata
a.meta.events.unregister("before-parameter-build.s3.PutObject", validate_ascii_metadata)
a.put_object(Bucket="src", Key="ping", Body=b"from a", Metadata={"author": "José"})
b.put_object(Bucket="dst", Key="pong", Body=b"from b")
wait_for(lambda: not absent(b, "dst", "ping") and not absent(a, "src", "pong"), "two-way replication")
wait_for(lambda: metric(PORT_A, "s3rs_replication_pending") == 0 and metric(PORT_B, "s3rs_replication_pending") == 0,
         "both queues drained")
counts = (metric(PORT_A, 's3rs_replication_total{result="replicated"}'),
          metric(PORT_B, 's3rs_replication_total{result="replicated"}'))
time.sleep(3)
assert counts == (metric(PORT_A, 's3rs_replication_total{result="replicated"}'),
                  metric(PORT_B, 's3rs_replication_total{result="replicated"}')), "two-way replication keeps going"
same(a, b, "src", "dst", "multi")
assert b.head_object(Bucket="dst", Key="ping")["ResponseMetadata"]["HTTPHeaders"]["x-amz-replication-status"] == "REPLICA"
print("two-way replication settles (no ping-pong, also with non-ASCII metadata)")

# Two-way replication never brings back older data: while B is away, A overwrites and deletes;
# when B is back, both sides have A's latest state.
a.put_object(Bucket="src", Key="doc", Body=b"v1")
a.put_object(Bucket="src", Key="gone", Body=b"x")
wait_for(lambda: not absent(b, "dst", "doc") and not absent(b, "dst", "gone"), "replicated before the partition")
stop("b")
a.put_object(Bucket="src", Key="doc", Body=b"v2")
a.delete_object(Bucket="src", Key="gone")
start("b")
wait_for(lambda: b.get_object(Bucket="dst", Key="doc")["Body"].read() == b"v2" and absent(b, "dst", "gone"),
         "the latest state reached B", timeout=60)
wait_for(lambda: metric(PORT_A, "s3rs_replication_pending") == 0 and metric(PORT_B, "s3rs_replication_pending") == 0,
         "both queues drained")
assert a.get_object(Bucket="src", Key="doc")["Body"].read() == b"v2" and absent(a, "src", "gone")
print("two-way replication after a partition keeps the latest writes and deletes")

# A destination that is down doesn't hold up the other destinations of a key, or other buckets.
a.create_bucket(Bucket="fanout")
b.create_bucket(Bucket="fanout-copy")
fan = config("arn:s3rs:replication::dead:fanout", existing=False, rule_id="dead")
fan["Rules"].append({"ID": "live", "Status": "Enabled", "Priority": 2, "Filter": {"Prefix": ""},
                     "DeleteMarkerReplication": {"Status": "Disabled"},
                     "Destination": {"Bucket": "arn:s3rs:replication::b:fanout-copy"}})
a.put_bucket_replication(Bucket="fanout", ReplicationConfiguration=fan)
for i in range(20):
    a.put_object(Bucket="fanout", Key=f"f{i}", Body=b"x")
a.put_object(Bucket="src", Key="after-fanout", Body=b"y")
wait_for(lambda: all(not absent(b, "fanout-copy", f"f{i}") for i in range(20)), "the live destination got everything")
wait_for(lambda: not absent(b, "dst", "after-fanout"), "other buckets keep replicating")
assert metric(PORT_A, "s3rs_replication_pending") >= 20, "keys for the dead destination should stay queued"
a.delete_bucket_replication(Bucket="fanout")
print("a dead destination doesn't block the others")

stop("a")
stop("b")
for name in ("a", "b"):
    r = subprocess.run([BIN, "fsck", "--deep", "-d", f"{work}/{name}", "--encryption-key-file", f"{work}/master.key"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        sys.exit(f"fsck failed on server {name}")
log = open(f"{work}/a.log").read() + open(f"{work}/b.log").read()
assert "panicked" not in log, log
shutil.rmtree(work)
print("REPLICATION TEST OK")
