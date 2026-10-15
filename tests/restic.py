#!/usr/bin/env python3
"""restic backups on s3rs: init a repository, back up a tree twice, verify every pack
(`check --read-data`), restore and compare, then forget and prune.

    python3 tests/restic.py ./target/release/s3rs [restic]
"""

import atexit
import filecmp
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
RESTIC = sys.argv[2] if len(sys.argv) > 2 else "restic"
PORT = 9398
work = tempfile.mkdtemp(prefix="s3rs-restic-")
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "rk", "--secret-key", "resticsecret1"],
                     stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
atexit.register(p.kill)
for _ in range(100):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_health")
        break
    except Exception:
        time.sleep(0.1)

env = dict(os.environ, AWS_ACCESS_KEY_ID="rk", AWS_SECRET_ACCESS_KEY="resticsecret1", AWS_DEFAULT_REGION="us-east-1",
           RESTIC_PASSWORD="correct horse", RESTIC_REPOSITORY=f"s3:http://127.0.0.1:{PORT}/backups/host1",
           RESTIC_CACHE_DIR=f"{work}/cache")


def restic(*args):
    r = subprocess.run([RESTIC, *args], env=env, capture_output=True, text=True)
    if r.returncode != 0:
        print(open(f"{work}/log").read()[-2000:])
        sys.exit(f"restic {' '.join(args)} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout


src = f"{work}/src"
rng = random.Random(3)
for d in range(5):
    os.makedirs(f"{src}/d{d}", exist_ok=True)
    for i in range(20):
        with open(f"{src}/d{d}/f{i}.bin", "wb") as f:
            f.write(rng.randbytes(rng.choice([0, 100, 5000, 300_000])))
with open(f"{src}/large.bin", "wb") as f:
    f.write(rng.randbytes(40 << 20))

subprocess.run(["aws", "--endpoint-url", f"http://127.0.0.1:{PORT}", "s3", "mb", "s3://backups"], env=env, check=True, capture_output=True)
restic("init")
restic("backup", src)
# A second backup after changes: mostly deduplicated.
with open(f"{src}/d0/f0.bin", "wb") as f:
    f.write(b"changed")
os.remove(f"{src}/d1/f1.bin")
restic("backup", src)
import json
assert len(json.loads(restic("snapshots", "--json"))) == 2
restic("check", "--read-data")
restic("restore", "latest", "--target", f"{work}/restore")
restored = f"{work}/restore{src}"
cmp = filecmp.dircmp(src, restored)


def same(c):
    if c.left_only or c.right_only or c.diff_files or c.funny_files:
        sys.exit(f"restore differs: {c.left_only} {c.right_only} {c.diff_files}")
    for sub in c.subdirs.values():
        same(sub)


same(cmp)
# filecmp's shallow comparison trusts size and mtime; compare one large file fully.
assert filecmp.cmp(f"{src}/large.bin", f"{restored}/large.bin", shallow=False)
restic("forget", "--keep-last", "1", "--prune")
assert len(json.loads(restic("snapshots", "--json"))) == 1
restic("check")
p.terminate()
p.wait()
shutil.rmtree(work)
print("RESTIC TEST OK")
