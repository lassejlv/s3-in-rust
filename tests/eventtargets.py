#!/usr/bin/env python3
"""Event notifications to NATS subjects and Redis lists / channels (minimal fake servers that
speak each protocol), including authentication, ordering and redelivery after an outage.

    python3 tests/eventtargets.py ./target/release/s3rs
"""

import json
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import boto3
from botocore.config import Config

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
PORT, NATS, REDIS = 9397, 9398, 9399
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-targets-")
nats_msgs, redis_lists, redis_pubs, nats_connects = [], {}, [], []
lock = threading.Lock()


class Nats(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b'INFO {"server_id":"fake","version":"2.10.0","max_payload":1048576}\r\n')
        authed = False
        while True:
            line = self.rfile.readline()
            if not line:
                return
            parts = line.decode().strip().split(" ", 1)
            if parts[0] == "CONNECT":
                opts = json.loads(parts[1])
                nats_connects.append(opts)
                if opts.get("user") != "alice" or opts.get("pass") != "s3cret!":
                    self.wfile.write(b"-ERR 'Authorization Violation'\r\n")
                    return
                authed = True
            elif parts[0] == "PING":
                self.wfile.write(b"PONG\r\n")
            elif parts[0] == "PUB" and authed:
                subject, n = parts[1].split(" ")
                payload = self.rfile.read(int(n))
                self.rfile.read(2)
                with lock:
                    nats_msgs.append((subject, json.loads(payload)))


class Redis(socketserver.StreamRequestHandler):
    def handle(self):
        authed = False
        while True:
            line = self.rfile.readline()
            if not line:
                return
            n = int(line[1:])
            args = []
            for _ in range(n):
                size = int(self.rfile.readline()[1:])
                args.append(self.rfile.read(size))
                self.rfile.read(2)
            cmd = args[0].decode().upper()
            if cmd == "AUTH":
                authed = args[-1] == b"pw"
                self.wfile.write(b"+OK\r\n" if authed else b"-WRONGPASS invalid password\r\n")
            elif cmd == "SELECT":
                self.wfile.write(b"+OK\r\n")
            elif not authed:
                self.wfile.write(b"-NOAUTH Authentication required.\r\n")
            elif cmd == "RPUSH":
                with lock:
                    lst = redis_lists.setdefault(args[1].decode(), [])
                    lst.append(json.loads(args[2]))
                    self.wfile.write(f":{len(lst)}\r\n".encode())
            elif cmd == "PUBLISH":
                with lock:
                    redis_pubs.append((args[1].decode(), json.loads(args[2])))
                self.wfile.write(b":1\r\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(handler, port):
    srv = Server(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


nats = serve(Nats, NATS)
redis = serve(Redis, REDIS)
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "root", "--secret-key", "rootsecret",
                      "--webhook", f"n=nats://alice:s3cret%21@127.0.0.1:{NATS}/s3.events",
                      "--webhook", f"r=redis://:pw@127.0.0.1:{REDIS}/s3-events?db=1",
                      "--webhook", f"p=redis://:pw@127.0.0.1:{REDIS}/s3-channel?publish"],
                     stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)


def wait_for(cond, what, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return
        time.sleep(0.1)
    print(open(f"{work}/log").read()[-3000:])
    sys.exit(f"timed out waiting for {what}")


def keys(records):
    return [r["Records"][0]["s3"]["object"]["key"] for r in records]


try:
    def up():
        try:
            return urllib.request.urlopen(f"{EP}/_health").status == 200
        except OSError:
            return False

    wait_for(up, "the server")
    s3 = boto3.client("s3", endpoint_url=EP, aws_access_key_id="root", aws_secret_access_key="rootsecret", region_name="us-east-1",
                      config=Config(s3={"addressing_style": "path"}))
    s3.create_bucket(Bucket="events")
    s3.put_bucket_notification_configuration(Bucket="events", NotificationConfiguration={"QueueConfigurations": [
        {"QueueArn": f"arn:s3rs:webhook::{t}", "Events": ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]} for t in ("n", "r", "p")]})
    for i in range(5):
        s3.put_object(Bucket="events", Key=f"k{i}", Body=b"x")
    s3.delete_object(Bucket="events", Key="k0")
    want = [f"k{i}" for i in range(5)] + ["k0"]
    wait_for(lambda: len(nats_msgs) == 6 and len(redis_lists.get("s3-events", [])) == 6 and len(redis_pubs) == 6, "events")
    assert all(s == "s3.events" for s, _ in nats_msgs) and keys(m for _, m in nats_msgs) == want, nats_msgs
    assert keys(redis_lists["s3-events"]) == want
    assert all(c == "s3-channel" for c, _ in redis_pubs) and keys(m for _, m in redis_pubs) == want
    assert nats_msgs[-1][1]["Records"][0]["eventName"] == "ObjectRemoved:Delete"
    assert nats_connects[0]["user"] == "alice" and nats_connects[0]["name"] == "s3rs"
    print("events reach NATS (PUB), a Redis list (RPUSH) and a Redis channel (PUBLISH), in order")

    # An outage: events queue up and arrive, in order, once the servers are back.
    redis.shutdown()
    redis.server_close()
    nats.shutdown()
    nats.server_close()
    for i in range(5, 10):
        s3.put_object(Bucket="events", Key=f"k{i}", Body=b"x")
    time.sleep(1.5)
    redis = serve(Redis, REDIS)
    nats = serve(Nats, NATS)
    want += [f"k{i}" for i in range(5, 10)]
    wait_for(lambda: len(redis_lists["s3-events"]) == 11 and len(nats_msgs) >= 11, "redelivery", timeout=40)
    assert keys(redis_lists["s3-events"]) == want
    got = keys(m for _, m in nats_msgs)
    # At least once: an event in flight when the server went away may arrive twice.
    assert [k for i, k in enumerate(got) if i == 0 or k != got[i - 1]] == want, got
    print("after an outage, queued events arrive in order")

    log = open(f"{work}/log").read()
    assert "event target n: nats://alice:***@127.0.0.1" in log and "s3cret" not in log and ":pw@" not in log, log[:2000]
    print("EVENT TARGETS TEST OK")
finally:
    p.kill()
shutil.rmtree(work, ignore_errors=True)
