#!/usr/bin/env python3
"""Event notifications to real NATS and Redis servers (CI starts them in containers):
the events of a few uploads must arrive on the subject, list and channel.

    python3 tests/eventtargets_real.py ./target/release/s3rs NATS_PORT REDIS_PORT

The servers require passwords: NATS user `alice` / `natspw`, Redis `redispw`.
"""

import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import boto3
from botocore.config import Config

BIN, NATS, REDIS = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
PORT = 9401
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-targets-real-")


def redis(*args):
    """One command over a fresh connection; returns the raw reply."""
    with socket.create_connection(("127.0.0.1", REDIS)) as s:
        enc = lambda c: f"*{len(c)}\r\n".encode() + b"".join(f"${len(a)}\r\n".encode() + a.encode() + b"\r\n" for a in c)
        s.sendall(enc(("AUTH", "redispw")) + enc(args))
        s.settimeout(5)
        data = b""
        time.sleep(0.2)
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(chunk) < 65536:
                break
        return data


# Subscribe on NATS and on the Redis channel before anything is published.
nats_got, chan_got = [], []


def nats_sub():
    s = socket.create_connection(("127.0.0.1", NATS))
    f = s.makefile("rb")
    f.readline()  # INFO
    s.sendall(b'CONNECT {"verbose":false,"user":"alice","pass":"natspw"}\r\nSUB s3.events 1\r\nPING\r\n')
    while True:
        line = f.readline()
        if not line:
            return
        if line.startswith(b"PING"):
            s.sendall(b"PONG\r\n")
        elif line.startswith(b"MSG"):
            n = int(line.split()[-1])
            nats_got.append(json.loads(f.read(n)))
            f.read(2)


def redis_sub():
    s = socket.create_connection(("127.0.0.1", REDIS))
    s.sendall(b"*2\r\n$4\r\nAUTH\r\n$7\r\nredispw\r\n*2\r\n$9\r\nSUBSCRIBE\r\n$10\r\ns3-channel\r\n")
    f = s.makefile("rb")
    while True:
        line = f.readline()
        if not line:
            return
        if line.startswith(b"*3"):
            parts = []
            for _ in range(3):
                head = f.readline()
                if head.startswith(b"$"):
                    parts.append(f.read(int(head[1:]) + 2)[:-2])
                else:
                    parts.append(head.strip())
            if parts[0] == b"message":
                chan_got.append(json.loads(parts[2]))


threading.Thread(target=nats_sub, daemon=True).start()
threading.Thread(target=redis_sub, daemon=True).start()
time.sleep(1)
redis("DEL", "s3-events")

p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "root", "--secret-key", "rootsecret",
                      "--webhook", f"n=nats://alice:natspw@127.0.0.1:{NATS}/s3.events",
                      "--webhook", f"r=redis://:redispw@127.0.0.1:{REDIS}/s3-events",
                      "--webhook", f"p=redis://:redispw@127.0.0.1:{REDIS}/s3-channel?publish"],
                     stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
try:
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{EP}/_health")
            break
        except OSError:
            time.sleep(0.1)
    s3 = boto3.client("s3", endpoint_url=EP, aws_access_key_id="root", aws_secret_access_key="rootsecret", region_name="us-east-1",
                      config=Config(s3={"addressing_style": "path"}))
    s3.create_bucket(Bucket="events")
    s3.put_bucket_notification_configuration(Bucket="events", NotificationConfiguration={"QueueConfigurations": [
        {"QueueArn": f"arn:s3rs:webhook::{t}", "Events": ["s3:ObjectCreated:*"]} for t in ("n", "r", "p")]})
    for i in range(3):
        s3.put_object(Bucket="events", Key=f"k{i}", Body=b"x")
    want = ["k0", "k1", "k2"]
    deadline = time.time() + 20
    while time.time() < deadline:
        listed = redis("LRANGE", "s3-events", "0", "-1")
        if len(nats_got) >= 3 and len(chan_got) >= 3 and listed.count(b'"Records"') >= 3:
            break
        time.sleep(0.3)
    key = lambda r: r["Records"][0]["s3"]["object"]["key"]
    assert [key(r) for r in nats_got] == want, nats_got
    assert [key(r) for r in chan_got] == want, chan_got
    assert all(f'"key":"{k}"'.encode() in listed for k in want), listed[:500]
    print("REAL EVENT TARGETS TEST OK")
except BaseException:
    print(open(f"{work}/log").read()[-3000:])
    raise
finally:
    p.kill()
shutil.rmtree(work, ignore_errors=True)
