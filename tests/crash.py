#!/usr/bin/env python3
"""Crash-consistency test: SIGKILL the server under concurrent writes, restart it, and check that
every acknowledged write survived and nothing else appeared.

    python3 tests/crash.py ./target/release/s3rs [rounds]

Each round starts s3rs on the same data directory, runs writers (PUTs of inline and file-backed
sizes, overwrites, deletes, multipart uploads, and versioned PUTs) for a random time, kills the
server with SIGKILL, restarts it and verifies:

- every key holds a value it could legitimately hold: the last acknowledged one, or the value of
  the operation that was in flight when the server died (which may or may not have committed);
- every acknowledged version in the versioned bucket is still readable with its content;
- listings agree with the per-key checks (no unexpected keys).

After the last round the server is stopped gracefully and `s3rs fsck --deep` must report OK.
"""

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

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 8
PORT = int(os.environ.get("S3RS_CRASH_PORT", "9310"))
ENDPOINT = f"http://127.0.0.1:{PORT}"
WORKERS = 8
KEY = "crashkey"
SECRET = "crashsecret"
ABSENT = None

data_dir = tempfile.mkdtemp(prefix="s3rs-crash-")
key_file = os.path.join(data_dir + "-key")
with open(key_file, "w") as f:
    f.write(os.urandom(32).hex())


def client():
    return boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id=KEY, aws_secret_access_key=SECRET,
                        region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1},
                                      connect_timeout=2, read_timeout=30, max_pool_connections=WORKERS * 2))


def start():
    log = open(data_dir + ".log", "a")
    p = subprocess.Popen([BIN, "-d", data_dir, "-l", f"127.0.0.1:{PORT}", "--access-key", KEY, "--secret-key", SECRET,
                          "--encryption-key-file", key_file, "--lifecycle-interval", "0"],
                         stdout=log, stderr=subprocess.STDOUT)
    for _ in range(200):
        try:
            urllib.request.urlopen(f"{ENDPOINT}/_health", timeout=1)
            return p
        except Exception:
            if p.poll() is not None:
                sys.exit(f"server exited with {p.returncode}; see {data_dir}.log")
            time.sleep(0.05)
    sys.exit("server did not become healthy")


def md5(b):
    return hashlib.md5(b).hexdigest()


def body(rng):
    # Inline-sized, file-backed and multi-megabyte bodies.
    size = rng.choice([0, 17, 900, 4096, 70_000, 300_000, 2_500_000])
    return rng.randbytes(size)


class Model:
    """What each key may hold: the acknowledged value plus, for an operation that was in flight
    when the server died, the value it would have produced."""

    def __init__(self):
        self.acked = {}       # (bucket, key) -> md5 or ABSENT
        self.pending = {}     # (bucket, key) -> md5 or ABSENT of an unacknowledged operation
        self.versions = {}    # key -> [(version_id, md5)] acknowledged in the versioned bucket
        self.lock = threading.Lock()

    def allowed(self, k):
        out = {self.acked.get(k, ABSENT)}
        if k in self.pending:
            out.add(self.pending[k])
        return out


def worker(n, model, stop, seed):
    rng = random.Random(seed)
    s3 = client()
    while not stop.is_set():
        # Each worker owns its keys, so operations on a key never race each other.
        key = f"w{n}/k{rng.randrange(40)}"
        op = rng.choices(["put", "delete", "multipart", "versioned"], weights=[60, 15, 5, 20])[0]
        bucket = "versioned" if op == "versioned" else "plain"
        k = (bucket, key)
        try:
            if op in ("put", "versioned"):
                b = body(rng)
                with model.lock:
                    model.pending[k] = md5(b)
                r = s3.put_object(Bucket=bucket, Key=key, Body=b)
                with model.lock:
                    model.acked[k] = md5(b)
                    del model.pending[k]
                    if op == "versioned":
                        model.versions.setdefault(key, []).append((r["VersionId"], md5(b)))
            elif op == "delete":
                with model.lock:
                    model.pending[k] = ABSENT
                s3.delete_object(Bucket=bucket, Key=key)
                with model.lock:
                    model.acked[k] = ABSENT
                    del model.pending[k]
            else:
                parts = [rng.randbytes(5 * 1024 * 1024), rng.randbytes(rng.randrange(1, 300_000))]
                up = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
                etags = [s3.upload_part(Bucket=bucket, Key=key, UploadId=up, PartNumber=i + 1, Body=p)["ETag"]
                         for i, p in enumerate(parts)]
                whole = md5(b"".join(parts))
                with model.lock:
                    model.pending[k] = whole
                s3.complete_multipart_upload(Bucket=bucket, Key=key, UploadId=up, MultipartUpload={
                    "Parts": [{"PartNumber": i + 1, "ETag": e} for i, e in enumerate(etags)]})
                with model.lock:
                    model.acked[k] = whole
                    del model.pending[k]
        except Exception:
            if stop.is_set():
                return  # the server was killed; the pending entry stays ambiguous
            raise


def verify(model):
    s3 = client()
    problems = []
    for (bucket, key) in sorted(set(model.acked) | set(model.pending)):
        allowed = model.allowed((bucket, key))
        try:
            got = md5(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
        except s3.exceptions.NoSuchKey:
            got = ABSENT
        if got not in allowed:
            problems.append(f"{bucket}/{key}: got {got}, allowed {allowed}")
        # Settle the model: whatever survived is now the acknowledged state.
        model.acked[(bucket, key)] = got
    model.pending.clear()
    for key, versions in model.versions.items():
        for vid, want in versions:
            try:
                got = md5(s3.get_object(Bucket="versioned", Key=key, VersionId=vid)["Body"].read())
            except Exception as e:
                got = f"error {e}"
            if got != want:
                problems.append(f"versioned/{key} version {vid}: got {got}, want {want}")
    for bucket in ("plain", "versioned"):
        listed = set()
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            listed |= {o["Key"] for o in page.get("Contents", [])}
        expected = {key for (b, key), v in model.acked.items() if b == bucket and v is not ABSENT}
        if listed != expected:
            problems.append(f"{bucket}: listing differs: extra {sorted(listed - expected)[:5]}, "
                            f"missing {sorted(expected - listed)[:5]}")
    return problems


def main():
    model = Model()
    rng = random.Random(int(os.environ.get("S3RS_CRASH_SEED", time.time())))
    p = start()
    s3 = client()
    s3.create_bucket(Bucket="plain")
    s3.create_bucket(Bucket="versioned")
    s3.put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})
    total_ops = 0
    for rnd in range(ROUNDS):
        stop = threading.Event()
        errors = []

        def run(n):
            try:
                worker(n, model, stop, rng.random())
            except Exception as e:  # an error while the server was alive is a failure
                errors.append(f"worker {n}: {e!r}")

        threads = [threading.Thread(target=run, args=(n,)) for n in range(WORKERS)]
        for t in threads:
            t.start()
        time.sleep(rng.uniform(0.5, 4.0))
        stop.set()
        p.send_signal(signal.SIGKILL)
        p.wait()
        for t in threads:
            t.join()
        if errors:
            sys.exit("FAILED before the kill: " + "; ".join(errors))
        pending = len(model.pending)
        p = start()
        problems = verify(model)
        total_ops += len(model.acked)
        print(f"round {rnd + 1}: killed with {pending} operation(s) in flight; "
              f"{sum(v is not ABSENT for v in model.acked.values())} keys, "
              f"{sum(len(v) for v in model.versions.values())} versions verified"
              + (f"; {len(problems)} PROBLEM(S)" if problems else ""))
        if problems:
            for pr in problems[:20]:
                print("  ", pr)
            p.kill()
            sys.exit(f"FAILED (data directory kept at {data_dir})")
    p.send_signal(signal.SIGTERM)
    p.wait()
    fsck = subprocess.run([BIN, "fsck", "-d", data_dir, "--deep", "--encryption-key-file", key_file],
                          capture_output=True, text=True)
    print(fsck.stdout.strip().splitlines()[-1] if fsck.stdout else fsck.stderr)
    if fsck.returncode != 0:
        print(fsck.stdout, fsck.stderr)
        sys.exit(f"FAILED: fsck (data directory kept at {data_dir})")
    shutil.rmtree(data_dir)
    os.remove(key_file)
    print("CRASH TEST OK")


if __name__ == "__main__":
    main()
