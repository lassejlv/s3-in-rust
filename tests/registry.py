#!/usr/bin/env python3
"""A container registry (distribution) storing its data in s3rs: push an image with a large
layer (uploaded in chunks, i.e. multipart), copy it, pull it back and compare digests, delete
a manifest and garbage-collect.

    python3 tests/registry.py ./target/release/s3rs [registry] [crane]
"""

import atexit
import io
import os
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
REGISTRY = sys.argv[2] if len(sys.argv) > 2 else "registry"
CRANE = sys.argv[3] if len(sys.argv) > 3 else "crane"
PORT, REG = 9388, 5055
work = tempfile.mkdtemp(prefix="s3rs-registry-")
procs = []
atexit.register(lambda: [p.kill() for p in procs])


def wait(url):
    for _ in range(200):
        try:
            urllib.request.urlopen(url)
            return
        except urllib.error.HTTPError:
            return
        except Exception:
            time.sleep(0.1)
    sys.exit(f"{url} did not come up")


procs.append(subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "regkey", "--secret-key", "registrysecret"],
                              stdout=open(f"{work}/s3rs.log", "a"), stderr=subprocess.STDOUT))
wait(f"http://127.0.0.1:{PORT}/_health")
env = dict(os.environ, AWS_ACCESS_KEY_ID="regkey", AWS_SECRET_ACCESS_KEY="registrysecret", AWS_DEFAULT_REGION="us-east-1")
subprocess.run(["aws", "--endpoint-url", f"http://127.0.0.1:{PORT}", "s3", "mb", "s3://registry"], env=env, check=True, capture_output=True)

with open(f"{work}/config.yml", "w") as f:
    f.write(f"""version: 0.1
log:
  level: warn
storage:
  s3:
    accesskey: regkey
    secretkey: registrysecret
    region: us-east-1
    regionendpoint: http://127.0.0.1:{PORT}
    forcepathstyle: true
    bucket: registry
    secure: false
    chunksize: 5242880
    rootdirectory: /r
  delete:
    enabled: true
  redirect:
    disable: true
http:
  addr: 127.0.0.1:{REG}
""")
reg = subprocess.Popen([REGISTRY, "serve", f"{work}/config.yml"], stdout=open(f"{work}/registry.log", "a"), stderr=subprocess.STDOUT)
procs.append(reg)
wait(f"http://127.0.0.1:{REG}/v2/")


def crane(*args):
    r = subprocess.run([CRANE, *args, "--insecure"], capture_output=True, text=True)
    if r.returncode != 0:
        print(open(f"{work}/registry.log").read()[-3000:])
        sys.exit(f"crane {' '.join(args)} failed:\n{r.stderr}")
    return r.stdout.strip()


# An image with a small layer and a 24 MiB one (pushed in 5 MiB chunks).
rng = random.Random(5)
for name, size in (("small", 1000), ("big", 24 << 20)):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo(f"{name}.bin")
        info.size = size
        t.addfile(info, io.BytesIO(rng.randbytes(size)))
    with open(f"{work}/{name}.tar", "wb") as f:
        f.write(buf.getvalue())
img = f"127.0.0.1:{REG}/demo/app"
crane("append", "-f", f"{work}/small.tar", "-f", f"{work}/big.tar", "-t", f"{img}:v1")
digest = crane("digest", f"{img}:v1")
crane("copy", f"{img}:v1", f"{img}:v2")
assert crane("digest", f"{img}:v2") == digest
assert sorted(crane("ls", img).split()) == ["v1", "v2"]
crane("pull", f"{img}:v1", f"{work}/pulled.tar")
assert os.path.getsize(f"{work}/pulled.tar") > 24 << 20
# Re-pushing the same image uploads nothing new (blobs already exist: HEAD on S3).
crane("append", "-f", f"{work}/small.tar", "-f", f"{work}/big.tar", "-t", f"{img}:v3")
crane("delete", f"{img}@{digest}")
reg.terminate()
reg.wait()
r = subprocess.run([REGISTRY, "garbage-collect", "--delete-untagged", f"{work}/config.yml"], capture_output=True, text=True)
assert r.returncode == 0, r.stdout + r.stderr
for p in procs:
    p.terminate()
    p.wait()
shutil.rmtree(work)
print(f"pushed, copied, pulled and garbage-collected {digest[:19]}…")
print("REGISTRY TEST OK")
