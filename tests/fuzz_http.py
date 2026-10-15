#!/usr/bin/env python3
"""HTTP-level fuzzing: send mutated S3 requests to a server and require that it never answers
500 or panics, and stays healthy.

    python3 tests/fuzz_http.py ./target/release/s3rs [requests]

The server runs with --anonymous so requests reach the handlers instead of stopping at
authentication. Requests mix every method, odd paths and encodings, every subresource, hostile
headers (ranges, copy sources, checksums, SSE and Object Lock headers, conditionals) and mutated
XML/JSON bodies, sent over raw sockets so nothing is normalised on the way.
"""

import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
PORT = 9340
SEED = int(os.environ.get("S3RS_FUZZ_SEED", "1"))

METHODS = ["GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS", "PATCH", "PROPFIND", "get"]
BUCKETS = ["fz", "fzv", "nope", "FZ", "f", "a" * 70, "fz..x", "-fz", "xn--fz", "_admin", "_metrics", "_console", ""]
KEYS = ["k", "dir/k", "a%2Fb", "%00", "..", "../x", "%2e%2e/x", "a b", "%E2%82%AC", "%ff%fe", "k" * 1100, "?x", "#f",
        "%", "%zz", "x/" * 300, "ascii", "big"]
SUBRESOURCES = ["acl", "cors", "lifecycle", "policy", "policyStatus", "tagging", "versioning", "versions", "uploads",
                "delete", "website", "notification", "object-lock", "retention", "legal-hold", "encryption", "quota",
                "usage", "attributes", "location", "events", "list-type", "uploadId", "partNumber", "versionId",
                "prefix", "delimiter", "max-keys", "marker", "continuation-token", "start-after", "encoding-type",
                "key-marker", "version-id-marker", "max-parts", "part-number-marker", "max-uploads", "response-content-type",
                "X-Amz-Signature", "Signature", "x-id"]
VALUES = ["", "1", "0", "-1", "2", "10000", "10001", "99999999999999999999", "null", "abc", "%00", "%ff", "*", "/",
          "url", "Enabled", "Suspended", "a" * 2000, "s3:ObjectCreated:*", "1a13d51a78c00000b68965e8ab71d7e6"]
HEADERS = {
    "range": ["bytes=0-0", "bytes=-1", "bytes=5-", "bytes=9-1", "bytes=0-99999999999999999999", "bytes=a-b", "bytes=0-1,2-3",
              "items=0-1", "bytes=-0"],
    "x-amz-copy-source": ["/fz/k", "fz/k", "/fz/k?versionId=null", "/nope/k", "/fz/%ff", "/", "//", "/fz/" + "a" * 2000,
                          "/fz/big?versionId=x"],
    "x-amz-copy-source-range": ["bytes=0-1", "bytes=1-0", "bytes=0-99999999999"],
    "x-amz-metadata-directive": ["COPY", "REPLACE", "BOGUS"],
    "x-amz-tagging-directive": ["COPY", "REPLACE", "x"],
    "x-amz-tagging": ["a=b", "a=b&a=c", "%zz=1", "=", "a" * 300 + "=b", "&&&"],
    "x-amz-meta-x": ["v", "é", "a" * 3000],
    "content-md5": ["1B2M2Y8AsgTpgAmY7PhCfg==", "bad", "", "AAAA"],
    "x-amz-content-sha256": ["UNSIGNED-PAYLOAD", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "zz"],
    "x-amz-decoded-content-length": ["5", "-1", "99999999999999999999", "x"],
    "x-amz-checksum-crc32": ["AAAAAA==", "x", ""],
    "x-amz-checksum-sha256": ["47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "?"],
    "x-amz-sdk-checksum-algorithm": ["CRC32", "CRC64NVME", "MD5", "x"],
    "x-amz-trailer": ["x-amz-checksum-crc32", "x-amz-checksum-zz", ""],
    "x-amz-server-side-encryption": ["AES256", "aws:kms", "x"],
    "x-amz-server-side-encryption-customer-algorithm": ["AES256", "x"],
    "x-amz-server-side-encryption-customer-key": ["MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "short", ""],
    "x-amz-server-side-encryption-customer-key-md5": ["x", ""],
    "x-amz-object-lock-mode": ["GOVERNANCE", "COMPLIANCE", "x"],
    "x-amz-object-lock-retain-until-date": ["2030-01-01T00:00:00Z", "yesterday", "1970-01-01T00:00:00Z"],
    "x-amz-object-lock-legal-hold": ["ON", "OFF", "x"],
    "x-amz-bypass-governance-retention": ["true", "x"],
    "x-amz-bucket-object-lock-enabled": ["true", "x"],
    "x-amz-acl": ["private", "public-read", "public-read-write", "x"],
    "x-amz-website-redirect-location": ["/a", "https://e.com/", "javascript:x", "//evil"],
    "x-amz-object-attributes": ["ETag", "ObjectParts,ObjectSize", "x", ""],
    "x-amz-max-parts": ["1", "-1", "x"],
    "if-match": ["*", "\"x\"", ""],
    "if-none-match": ["*", "\"x\""],
    "if-modified-since": ["Wed, 21 Oct 2015 07:28:00 GMT", "x"],
    "if-unmodified-since": ["Wed, 21 Oct 2035 07:28:00 GMT", "x"],
    "origin": ["https://a.example", "null", ""],
    "access-control-request-method": ["PUT", "x"],
    "content-type": ["multipart/form-data; boundary=xyz", "application/xml", "text/plain", "multipart/form-data"],
    "expect": ["100-continue"],
    "authorization": ["AWS4-HMAC-SHA256 Credential=x", "AWS x:y", "Bearer x", "x"],
}
BODIES = [
    b"<Delete><Object><Key>k</Key></Object><Object><Key>dir/k</Key><VersionId>null</VersionId></Object></Delete>",
    b"<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>",
    b"<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Prefix>a</Prefix></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
    b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>",
    b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>x</ETag></Part></CompleteMultipartUpload>",
    b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>",
    b"<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>",
    b"<LegalHold><Status>ON</Status></LegalHold>",
    b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>",
    b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>",
    b"<BucketQuota><MaxBytes>100000000</MaxBytes></BucketQuota>",
    b"<NotificationConfiguration/>",
    b"<AccessControlPolicy/>",
    b'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::fz/*"}]}',
    b"5\r\nhello\r\n0\r\n\r\n",
    b"--xyz\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--xyz\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n\r\ndata\r\n--xyz--\r\n",
    b"",
    b"plain body",
]


def mutate(rng, b):
    b = bytearray(b)
    for _ in range(rng.randrange(0, 4)):
        op = rng.randrange(5)
        pos = rng.randrange(len(b) + 1)
        if op == 0 and b:
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        elif op == 1:
            del b[pos:]
        elif op == 2:
            b[pos:pos] = rng.choice([b"<", b">", b"</a>", b"&", b"&#0;", b"\xff", b"\x00", b"<a>" * 50, b"]]>"])
        elif op == 3 and b:
            a = rng.randrange(len(b))
            b[pos:pos] = b[a:a + rng.randrange(1, 40)] * rng.randrange(1, 30)
        else:
            b[pos:pos] = rng.randbytes(rng.randrange(1, 20))
    return bytes(b)


def request(rng):
    method = rng.choice(METHODS)
    bucket = rng.choice(BUCKETS)
    path = "/" + bucket
    if rng.random() < 0.6:
        path += "/" + rng.choice(KEYS)
    if rng.random() < 0.05:
        path = rng.choice(["*", "//", "/%", "http://x/fz", "/fz/k?x"])
    q = []
    for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
        name = rng.choice(SUBRESOURCES)
        q.append(name if rng.random() < 0.3 else f"{name}={rng.choice(VALUES)}")
    if q:
        path += "?" + "&".join(q)
    headers = {"host": rng.choice(["localhost", "fz.localhost", "", "x" * 300, "[::1]:9340"])}
    for _ in range(rng.randrange(0, 6)):
        name = rng.choice(list(HEADERS))
        headers[name] = rng.choice(HEADERS[name])
    body = mutate(rng, rng.choice(BODIES)) if rng.random() < 0.7 else b""
    chunked = rng.random() < 0.1
    lines = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in headers.items()]
    if chunked:
        lines.append("transfer-encoding: chunked")
        body = (f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n") if body else b"0\r\n\r\n"
    else:
        lines.append(f"content-length: {len(body)}")
    lines.append("connection: close")
    head = "\r\n".join(lines).encode("utf-8", "surrogateescape") + b"\r\n\r\n"
    return head + body, f"{method} {path[:120]}"


def send(raw):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    try:
        s.sendall(raw)
        data = b""
        while b"\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\r\n", 1)[0].decode("latin-1")
        return int(line.split()[1]) if line.startswith("HTTP/") and len(line.split()) > 1 else 0
    except (ConnectionResetError, BrokenPipeError):
        return 0
    finally:
        s.close()


def main():
    work = tempfile.mkdtemp(prefix="s3rs-fuzz-")
    data = os.path.join(work, "data")
    key = os.path.join(work, "key")
    with open(key, "w") as f:
        f.write(os.urandom(32).hex())
    log = open(os.path.join(work, "server.log"), "w")
    p = subprocess.Popen([BIN, "-d", data, "-l", f"127.0.0.1:{PORT}", "--anonymous", "--encryption-key-file", key,
                          "--domain", "localhost"], stdout=subprocess.DEVNULL, stderr=log)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_health", timeout=1)
                break
            except Exception:
                time.sleep(0.05)
        # Some state for the requests to work on.
        for raw in (b"PUT /fz HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\r\n",
                    b"PUT /fzv HTTP/1.1\r\nhost: x\r\ncontent-length: 0\r\n\r\n",
                    b"PUT /fzv?versioning HTTP/1.1\r\nhost: x\r\ncontent-length: 70\r\n\r\n<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"[:200],
                    b"PUT /fz/k HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nhello",
                    b"PUT /fz/big HTTP/1.1\r\nhost: x\r\ncontent-length: 200000\r\n\r\n" + b"b" * 200000,
                    b"PUT /fzv/k HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nhello"):
            send(raw)
        rng = random.Random(SEED)
        lock = threading.Lock()
        counts, failures = {}, []

        def worker(n):
            r = random.Random(SEED * 1000 + n)
            for _ in range(N // 8):
                raw, desc = request(r)
                status = send(raw)
                with lock:
                    counts[status] = counts.get(status, 0) + 1
                    if status >= 500 and status not in (501, 503, 507):
                        failures.append((status, desc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        del rng
        alive = p.poll() is None
        healthy = alive and urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_health", timeout=5).status == 200
    finally:
        p.terminate()
        p.wait()
    server_log = open(os.path.join(work, "server.log")).read()
    print("status counts:", dict(sorted(counts.items())))
    panics = [line for line in server_log.splitlines() if "panicked" in line]
    errors = [line for line in server_log.splitlines() if line.startswith("error:")]
    for status, desc in failures[:15]:
        print(f"  {status}: {desc}")
    for line in (panics + errors)[:15]:
        print("  log:", line[:300])
    if failures or panics or not healthy:
        sys.exit(f"FAILED: {len(failures)} server errors, {len(panics)} panics, healthy={healthy} (logs in {work})")
    fsck = subprocess.run([BIN, "fsck", "-d", data, "--encryption-key-file", key], capture_output=True, text=True)
    if fsck.returncode != 0:
        sys.exit(f"FAILED: fsck after fuzzing:\n{fsck.stdout}")
    print(f"HTTP FUZZ OK ({N} requests)")


main()
