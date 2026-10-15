#!/usr/bin/env python3
"""Replication under crashes: writers change keys on server A (puts, overwrites, deletes,
multipart) while A and B are killed with SIGKILL and restarted at random. Once everything is
running again and A's queue has drained, B must hold exactly A's state: the same keys with the
same ETags and content.

    python3 tests/replication_chaos.py ./target/release/s3rs [rounds]
"""

import atexit
import hashlib
import os
import random
import shutil
import signal
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
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 6
PORT_A, PORT_B = 9370, 9371
KEY, SECRET = "chaoskey", "chaossecret"
work = tempfile.mkdtemp(prefix="s3rs-chaos-")
procs = {}
atexit.register(lambda: [p.kill() for p in procs.values()])
with open(f"{work}/targets", "w") as f:
    f.write(f"b http://127.0.0.1:{PORT_B} {KEY} {SECRET}\n")


def start(name):
    port = PORT_A if name == "a" else PORT_B
    args = [BIN, "-d", f"{work}/{name}", "-l", f"127.0.0.1:{port}", "--access-key", KEY, "--secret-key", SECRET,
            "--lifecycle-interval", "0"]
    if name == "a":
        args += ["--replication-targets", f"{work}/targets"]
    p = subprocess.Popen(args, stdout=open(f"{work}/{name}.log", "a"), stderr=subprocess.STDOUT)
    for _ in range(200):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/_health", timeout=1)
            procs[name] = p
            return
        except Exception:
            time.sleep(0.05)
    sys.exit(f"{name} did not start")


def kill(name):
    p = procs.pop(name)
    p.send_signal(signal.SIGKILL)
    p.wait()


def client(port):
    return boto3.client("s3", endpoint_url=f"http://127.0.0.1:{port}", aws_access_key_id=KEY,
                        aws_secret_access_key=SECRET, region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"total_max_attempts": 1},
                                      connect_timeout=2, read_timeout=20))


def metric(port, name):
    text = urllib.request.urlopen(f"http://127.0.0.1:{port}/_metrics", timeout=5).read().decode()
    return sum(float(l.split()[-1]) for l in text.splitlines() if l.startswith(name + " "))


start("a")
start("b")
client(PORT_A).create_bucket(Bucket="src")
client(PORT_B).create_bucket(Bucket="dst")
client(PORT_A).put_bucket_replication(Bucket="src", ReplicationConfiguration={"Role": "", "Rules": [{
    "ID": "all", "Status": "Enabled", "Priority": 1, "Filter": {"Prefix": ""},
    "DeleteMarkerReplication": {"Status": "Enabled"},
    "Destination": {"Bucket": "arn:s3rs:replication::b:dst"}}]})

stop_writers = threading.Event()
ops = {"ok": 0, "failed": 0}


def writer(seed):
    rng = random.Random(seed)
    s3 = client(PORT_A)
    while not stop_writers.is_set():
        key = f"k{rng.randrange(60)}"
        try:
            r = rng.random()
            if r < 0.55:
                s3.put_object(Bucket="src", Key=key, Body=rng.randbytes(rng.choice([10, 3000, 200_000])))
            elif r < 0.8:
                s3.delete_object(Bucket="src", Key=key)
            elif r < 0.9:
                s3.put_object_tagging(Bucket="src", Key=key, Tagging={"TagSet": [{"Key": "n", "Value": str(rng.random())}]})
            else:
                mp = s3.create_multipart_upload(Bucket="src", Key=key)
                parts = [rng.randbytes(5 * 1024 * 1024), rng.randbytes(100)]
                etags = [s3.upload_part(Bucket="src", Key=key, UploadId=mp["UploadId"], PartNumber=i + 1, Body=d)["ETag"]
                         for i, d in enumerate(parts)]
                s3.complete_multipart_upload(Bucket="src", Key=key, UploadId=mp["UploadId"], MultipartUpload={
                    "Parts": [{"ETag": e, "PartNumber": i + 1} for i, e in enumerate(etags)]})
            ops["ok"] += 1
        except Exception:
            ops["failed"] += 1
            time.sleep(0.05)


threads = [threading.Thread(target=writer, args=(i,)) for i in range(6)]
for t in threads:
    t.start()
rng = random.Random(42)
for rnd in range(ROUNDS):
    time.sleep(rng.uniform(1.0, 3.0))
    victim = rng.choice(["a", "b", "both"])
    for v in (["a", "b"] if victim == "both" else [victim]):
        kill(v)
    time.sleep(rng.uniform(0.2, 1.5))
    for v in (["a", "b"] if victim == "both" else [victim]):
        start(v)
    print(f"round {rnd + 1}: killed {victim}", flush=True)
time.sleep(2)
stop_writers.set()
for t in threads:
    t.join()
print(f"writer operations: {ops['ok']} acknowledged, {ops['failed']} failed (server down)")

deadline = time.time() + 120
while time.time() < deadline and metric(PORT_A, "s3rs_replication_pending") > 0:
    time.sleep(0.5)
assert metric(PORT_A, "s3rs_replication_pending") == 0, "the queue did not drain"


def state(port, bucket):
    s3 = client(port)
    out = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for o in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read()
            tags = sorted((t["Key"], t["Value"]) for t in s3.get_object_tagging(Bucket=bucket, Key=o["Key"])["TagSet"])
            out[o["Key"]] = (o["ETag"], hashlib.md5(body).hexdigest(), tags)
    return out


sa, sb = state(PORT_A, "src"), state(PORT_B, "dst")
diff = {k: (sa.get(k), sb.get(k)) for k in set(sa) | set(sb) if sa.get(k) != sb.get(k)}
assert not diff, f"B differs from A for {len(diff)} key(s): {list(diff.items())[:5]}"
print(f"converged: {len(sa)} keys identical on both servers after {ROUNDS} crash rounds")
for name in ("a", "b"):
    p = procs.pop(name)
    p.terminate()
    p.wait()
for name in ("a", "b"):
    r = subprocess.run([BIN, "fsck", "-d", f"{work}/{name}"], capture_output=True, text=True)
    assert r.returncode == 0, (name, r.stdout, r.stderr)
assert "panicked" not in open(f"{work}/a.log").read() + open(f"{work}/b.log").read()
shutil.rmtree(work)
print("REPLICATION CHAOS TEST OK")
