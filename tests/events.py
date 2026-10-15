#!/usr/bin/env python3
"""Durable event notifications: events wait in a queue on disk while the webhook is down or
failing, survive a restart, and are then delivered completely and in order.

    python3 tests/events.py ./target/release/s3rs
"""

import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import boto3
from botocore.config import Config

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
PORT, HOOK = 9380, 9381
KEY, SECRET = "evkey", "evsecret"
work = tempfile.mkdtemp(prefix="s3rs-events-")
procs = []
atexit.register(lambda: [p.kill() for p in procs])

received = []
mode = {"status": 200}


class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["content-length"]))
        status = mode["status"]
        if status == 200:
            received.append(json.loads(body))
        self.send_response(status)
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


hook = None


def hook_up():
    global hook
    hook = HTTPServer(("127.0.0.1", HOOK), Hook)
    threading.Thread(target=hook.serve_forever, daemon=True).start()


def hook_down():
    hook.shutdown()
    hook.server_close()


def start():
    p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", KEY, "--secret-key", SECRET,
                          "--webhook", f"t=http://127.0.0.1:{HOOK}/hook"], stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
    procs.append(p)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_health")
            return p
        except Exception:
            time.sleep(0.1)
    sys.exit("server did not start")


def metric(name):
    text = urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_metrics").read().decode()
    return sum(float(l.split()[-1]) for l in text.splitlines() if l.startswith(name))


def wait_for(cond, what, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return
        time.sleep(0.2)
    print(open(f"{work}/log").read()[-2000:])
    sys.exit(f"timed out: {what}")


def keys():
    return [r["Records"][0]["s3"]["object"]["key"] for r in received]


p = start()
s3 = boto3.client("s3", endpoint_url=f"http://127.0.0.1:{PORT}", aws_access_key_id=KEY, aws_secret_access_key=SECRET,
                  region_name="us-east-1", config=Config(s3={"addressing_style": "path"}))
s3.create_bucket(Bucket="events")
s3.put_bucket_notification_configuration(Bucket="events", NotificationConfiguration={"QueueConfigurations": [
    {"Id": "all", "QueueArn": "arn:s3rs:webhook::t", "Events": ["s3:ObjectCreated:*"]}]})

# 1. Receiver down: events queue up.
for i in range(40):
    s3.put_object(Bucket="events", Key=f"a{i:03d}", Body=b"x")
wait_for(lambda: metric("s3rs_notifications_pending") == 40, "40 events queued")

# 2. They survive a restart.
p.send_signal(signal.SIGTERM)
p.wait()
p = start()
assert metric("s3rs_notifications_pending") == 40, metric("s3rs_notifications_pending")
assert "40 queued event(s) from before the restart" in open(f"{work}/log").read()

# 3. A receiver that answers 500 gets retries; nothing is lost or skipped.
mode["status"] = 500
hook_up()
for i in range(10):
    s3.put_object(Bucket="events", Key=f"b{i:03d}", Body=b"x")
time.sleep(3)
assert not received and metric('s3rs_notifications_total{result="failed"}') > 0
mode["status"] = 200
wait_for(lambda: len(received) >= 50, "all 50 events delivered")
time.sleep(1)
expected = [f"a{i:03d}" for i in range(40)] + [f"b{i:03d}" for i in range(10)]
assert keys() == expected, keys()
assert metric("s3rs_notifications_pending") == 0
print(f"delivered {len(received)} events in order after an outage, a restart and HTTP 500s")

# 4. Normal operation is still prompt.
start_t = time.time()
s3.put_object(Bucket="events", Key="c", Body=b"x")
wait_for(lambda: keys()[-1:] == ["c"], "a new event", timeout=10)
print(f"a new event arrives in {time.time() - start_t:.2f}s")
hook_down()
p.terminate()
p.wait()
shutil.rmtree(work)
print("EVENTS TEST OK")
