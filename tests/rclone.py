#!/usr/bin/env python3
"""rclone against s3rs: sync a tree (with multipart uploads), check it byte for byte, server-side
copies and moves, listing, versions and purge.

    python3 tests/rclone.py ./target/release/s3rs [rclone]
"""

import atexit
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
RCLONE = sys.argv[2] if len(sys.argv) > 2 else "rclone"
PORT = 9397
work = tempfile.mkdtemp(prefix="s3rs-rclone-")
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "rk", "--secret-key", "rclonesecret1"],
                     stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
atexit.register(p.kill)
for _ in range(100):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_health")
        break
    except Exception:
        time.sleep(0.1)

env = dict(os.environ, RCLONE_CONFIG_S3RS_TYPE="s3", RCLONE_CONFIG_S3RS_PROVIDER="Other",
           RCLONE_CONFIG_S3RS_ACCESS_KEY_ID="rk", RCLONE_CONFIG_S3RS_SECRET_ACCESS_KEY="rclonesecret1",
           RCLONE_CONFIG_S3RS_ENDPOINT=f"http://127.0.0.1:{PORT}", RCLONE_CONFIG_S3RS_REGION="us-east-1",
           # Small chunks so modest files use multipart uploads.
           RCLONE_S3_UPLOAD_CUTOFF="6M", RCLONE_S3_CHUNK_SIZE="5M", RCLONE_CONFIG="/dev/null")


def rc(*args, check=True):
    r = subprocess.run([RCLONE, *args], env=env, capture_output=True, text=True)
    if check and r.returncode != 0:
        print(open(f"{work}/log").read()[-2000:])
        sys.exit(f"rclone {' '.join(args)} failed:\n{r.stdout}\n{r.stderr}")
    return r


# A tree with empty, small, multipart-sized and oddly named files.
src = f"{work}/src"
rng = random.Random(7)
files = {"empty": b"", "small.txt": b"hello\n", "dir/a.bin": rng.randbytes(200_000), "dir/sub/big.bin": rng.randbytes(13 << 20),
         "ünï cødé/[x] & y+z.txt": b"odd names", "dir/sub/deeper/file with spaces.txt": b"spaces"}
for name, data in files.items():
    os.makedirs(os.path.dirname(f"{src}/{name}") or src, exist_ok=True)
    with open(f"{src}/{name}", "wb") as f:
        f.write(data)

rc("mkdir", "s3rs:tree")
rc("sync", src, "s3rs:tree", "--checksum")
rc("check", src, "s3rs:tree")                 # sizes and hashes (MD5 / ETag, multipart included)
rc("check", src, "s3rs:tree", "--download")   # byte for byte
listing = json.loads(rc("lsjson", "-R", "--hash", "s3rs:tree").stdout)
by_path = {e["Path"]: e for e in listing if not e["IsDir"]}
assert set(by_path) == set(files), sorted(by_path)
assert by_path["small.txt"]["Hashes"]["md5"] == hashlib.md5(b"hello\n").hexdigest()
assert by_path["dir/sub/big.bin"]["Size"] == 13 << 20
print(f"synced and checked {len(files)} files (one multipart)")

# Changes are synced: a modified file, a deleted file, a new one.
with open(f"{src}/small.txt", "wb") as f:
    f.write(b"changed\n")
os.remove(f"{src}/dir/a.bin")
with open(f"{src}/new.txt", "wb") as f:
    f.write(b"new")
rc("sync", src, "s3rs:tree", "--checksum")
rc("check", src, "s3rs:tree", "--download")
print("incremental sync ok")

# Server-side copy and move (CopyObject; multipart copy for the big file).
rc("copyto", "s3rs:tree/dir/sub/big.bin", "s3rs:tree/copy/big.bin")
rc("moveto", "s3rs:tree/new.txt", "s3rs:tree/moved/new.txt")
assert rc("cat", "s3rs:tree/moved/new.txt").stdout == "new"
assert rc("md5sum", "s3rs:tree/copy/big.bin").stdout.split()[0] == hashlib.md5(files["dir/sub/big.bin"]).hexdigest()
assert "new.txt" not in rc("lsf", "s3rs:tree").stdout
print("server-side copy and move ok")

# Versions: an overwrite in a versioned bucket keeps the old version.
rc("mkdir", "s3rs:vers")
subprocess.run(["aws", "--endpoint-url", f"http://127.0.0.1:{PORT}", "s3api", "put-bucket-versioning", "--bucket", "vers",
                "--versioning-configuration", "Status=Enabled"], check=True, capture_output=True,
               env=dict(os.environ, AWS_ACCESS_KEY_ID="rk", AWS_SECRET_ACCESS_KEY="rclonesecret1", AWS_DEFAULT_REGION="us-east-1"))
subprocess.run([RCLONE, "rcat", "s3rs:vers/f.txt"], input=b"one", env=env, check=True)
subprocess.run([RCLONE, "rcat", "s3rs:vers/f.txt"], input=b"two", env=env, check=True)
versions = [e["Path"] for e in json.loads(rc("lsjson", "--s3-versions", "s3rs:vers").stdout)]
assert len(versions) == 2 and "f.txt" in versions, versions
print("versions listed:", versions)

# Purge removes everything, including the bucket.
rc("purge", "s3rs:tree")
assert "tree" not in rc("lsd", "s3rs:").stdout
p.terminate()
p.wait()
shutil.rmtree(work)
print("RCLONE TEST OK")
