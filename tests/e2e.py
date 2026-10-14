#!/usr/bin/env python3
"""End-to-end compatibility tests against a running s3rs using boto3.

Usage:
    S3RS_ENDPOINT=http://127.0.0.1:9000 S3RS_ACCESS_KEY=... S3RS_SECRET_KEY=... python3 tests/e2e.py
"""

import hashlib
import io
import os
import sys
import time
import urllib.request
import uuid

import boto3
from boto3.s3.transfer import TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = os.environ.get("S3RS_ENDPOINT", "http://127.0.0.1:9000")
AK = os.environ.get("S3RS_ACCESS_KEY", "testkey")
SK = os.environ.get("S3RS_SECRET_KEY", "testsecret")
# Optional read-only credential (configured via --credentials-file with `key:secret:ro`).
RO_AK = os.environ.get("S3RS_RO_ACCESS_KEY")
RO_SK = os.environ.get("S3RS_RO_SECRET_KEY")


def client(**cfg):
    cfg.setdefault("s3", {"addressing_style": "path"})
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        aws_access_key_id=AK,
        aws_secret_access_key=SK,
        region_name="us-east-1",
        config=Config(retries={"max_attempts": 1}, **cfg),
    )


s3 = client()
failures = []


def check(name, fn):
    try:
        fn()
        print(f"  ok    {name}")
    except Exception as e:  # noqa: BLE001
        failures.append(name)
        print(f"  FAIL  {name}: {type(e).__name__}: {e}")


def expect_error(code, fn):
    try:
        fn()
    except ClientError as e:
        got = e.response["Error"]["Code"]
        assert got == code, f"expected {code}, got {got}"
        return
    raise AssertionError(f"expected error {code}")


B = "e2e-" + uuid.uuid4().hex[:8]
MB = 1024 * 1024


def t_buckets():
    s3.create_bucket(Bucket=B)
    names = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    assert B in names
    s3.head_bucket(Bucket=B)
    expect_error("BucketAlreadyOwnedByYou", lambda: s3.create_bucket(Bucket=B))
    expect_error("InvalidBucketName", lambda: s3.create_bucket(Bucket="Bad_Name"))
    expect_error("404", lambda: s3.head_bucket(Bucket="does-not-exist-xyz"))
    loc = s3.get_bucket_location(Bucket=B)
    assert loc.get("LocationConstraint") in (None, "")


def t_small_object():
    s3.put_object(Bucket=B, Key="hello.txt", Body=b"hello world", ContentType="text/plain",
                  Metadata={"color": "blue"}, CacheControl="max-age=60")
    r = s3.get_object(Bucket=B, Key="hello.txt")
    assert r["Body"].read() == b"hello world"
    assert r["ContentType"] == "text/plain"
    assert r["Metadata"] == {"color": "blue"}, r["Metadata"]
    assert r["CacheControl"] == "max-age=60"
    assert r["ETag"] == '"%s"' % hashlib.md5(b"hello world").hexdigest()
    h = s3.head_object(Bucket=B, Key="hello.txt")
    assert h["ContentLength"] == 11, h["ContentLength"]


def t_empty_object():
    s3.put_object(Bucket=B, Key="empty", Body=b"")
    assert s3.get_object(Bucket=B, Key="empty")["Body"].read() == b""
    assert s3.head_object(Bucket=B, Key="empty")["ContentLength"] == 0


def t_large_object():
    data = os.urandom(3 * MB + 123)
    s3.put_object(Bucket=B, Key="big.bin", Body=data)
    assert s3.get_object(Bucket=B, Key="big.bin")["Body"].read() == data
    r = s3.get_object(Bucket=B, Key="big.bin", Range="bytes=1000-1999")
    assert r["Body"].read() == data[1000:2000]
    assert r["ContentRange"] == f"bytes 1000-1999/{len(data)}"
    assert s3.get_object(Bucket=B, Key="big.bin", Range="bytes=-10")["Body"].read() == data[-10:]
    expect_error("InvalidRange", lambda: s3.get_object(Bucket=B, Key="big.bin", Range=f"bytes={len(data)}-"))


def t_signed_payload():
    c = client(s3={"addressing_style": "path", "payload_signing_enabled": True})
    data = os.urandom(200_000)
    c.put_object(Bucket=B, Key="signed.bin", Body=data)
    assert c.get_object(Bucket=B, Key="signed.bin")["Body"].read() == data


def t_checksums():
    for algo in ["CRC32", "CRC32C", "SHA1", "SHA256", "CRC64NVME"]:
        data = os.urandom(100_000)
        try:
            r = s3.put_object(Bucket=B, Key=f"ck-{algo}", Body=data, ChecksumAlgorithm=algo)
        except Exception as e:
            if "CRT" in str(e) or "crt" in str(e):
                continue  # algorithm needs awscrt, not installed
            raise
        assert f"Checksum{algo}" in r, r.keys()
        g = s3.get_object(Bucket=B, Key=f"ck-{algo}", ChecksumMode="ENABLED")
        assert g["Body"].read() == data
        assert g.get(f"Checksum{algo}") == r[f"Checksum{algo}"]


def t_bad_md5():
    import base64
    bad = base64.b64encode(hashlib.md5(b"other").digest()).decode()
    expect_error("BadDigest", lambda: s3.put_object(Bucket=B, Key="badmd5", Body=b"data", ContentMD5=bad))
    expect_error("NoSuchKey", lambda: s3.get_object(Bucket=B, Key="badmd5"))


def t_conditionals():
    etag = s3.head_object(Bucket=B, Key="hello.txt")["ETag"]
    s3.get_object(Bucket=B, Key="hello.txt", IfMatch=etag)
    expect_error("PreconditionFailed", lambda: s3.get_object(Bucket=B, Key="hello.txt", IfMatch='"nope"'))
    expect_error("304", lambda: s3.get_object(Bucket=B, Key="hello.txt", IfNoneMatch=etag))
    expect_error("PreconditionFailed", lambda: s3.put_object(Bucket=B, Key="hello.txt", Body=b"x", IfNoneMatch="*"))
    s3.put_object(Bucket=B, Key="cond-new", Body=b"x", IfNoneMatch="*")


def t_not_found():
    expect_error("NoSuchKey", lambda: s3.get_object(Bucket=B, Key="missing"))
    expect_error("NoSuchBucket", lambda: s3.get_object(Bucket="no-such-bucket-xyz", Key="k"))
    expect_error("404", lambda: s3.head_object(Bucket=B, Key="missing"))


def t_listing():
    for k in ["dir/a", "dir/b", "dir/sub/c", "dir/sub/d", "other/e", "top", "space key", "plus+key", "uni/ä€"]:
        s3.put_object(Bucket=B, Key=k, Body=k.encode())
    r = s3.list_objects_v2(Bucket=B, Prefix="dir/", Delimiter="/")
    assert [c["Key"] for c in r["Contents"]] == ["dir/a", "dir/b"], r.get("Contents")
    assert [p["Prefix"] for p in r["CommonPrefixes"]] == ["dir/sub/"]
    r = s3.list_objects_v2(Bucket=B, Delimiter="/")
    prefixes = [p["Prefix"] for p in r["CommonPrefixes"]]
    assert prefixes == ["dir/", "other/", "uni/"], prefixes
    keys = [c["Key"] for c in r["Contents"]]
    assert "space key" in keys and "plus+key" in keys and "top" in keys, keys
    # Pagination with v2 and v1
    pag = s3.get_paginator("list_objects_v2")
    all_keys = [o["Key"] for page in pag.paginate(Bucket=B, PaginationConfig={"PageSize": 2}) for o in page.get("Contents", [])]
    assert all_keys == sorted(all_keys) and len(all_keys) == len(set(all_keys))
    full = [o["Key"] for o in s3.list_objects_v2(Bucket=B)["Contents"]]
    assert all_keys == full, (all_keys, full)
    pag1 = s3.get_paginator("list_objects")
    v1 = [o["Key"] for page in pag1.paginate(Bucket=B, PaginationConfig={"PageSize": 3}) for o in page.get("Contents", [])]
    assert v1 == full
    # Paginating with a delimiter must not repeat common prefixes.
    seen = []
    for page in pag.paginate(Bucket=B, Delimiter="/", PaginationConfig={"PageSize": 1}):
        seen += [p["Prefix"] for p in page.get("CommonPrefixes", [])] + [c["Key"] for c in page.get("Contents", [])]
    assert len(seen) == len(set(seen)), seen
    r = s3.list_objects_v2(Bucket=B, StartAfter="dir/sub/c")
    assert r["Contents"][0]["Key"] == "dir/sub/d"
    assert s3.list_objects_v2(Bucket=B, Prefix="uni/")["Contents"][0]["Key"] == "uni/ä€"
    v = s3.list_object_versions(Bucket=B, Prefix="dir/")
    assert len(v["Versions"]) == 4


def t_copy():
    s3.copy_object(Bucket=B, Key="hello-copy", CopySource={"Bucket": B, "Key": "hello.txt"})
    r = s3.get_object(Bucket=B, Key="hello-copy")
    assert r["Body"].read() == b"hello world" and r["Metadata"] == {"color": "blue"}
    s3.copy_object(Bucket=B, Key="big-copy", CopySource={"Bucket": B, "Key": "big.bin"},
                   MetadataDirective="REPLACE", Metadata={"x": "y"}, ContentType="application/x-test")
    a = s3.get_object(Bucket=B, Key="big.bin")["Body"].read()
    r = s3.get_object(Bucket=B, Key="big-copy")
    assert r["Body"].read() == a and r["Metadata"] == {"x": "y"} and r["ContentType"] == "application/x-test"
    # Deleting the source must not affect the copy.
    s3.put_object(Bucket=B, Key="src-tmp", Body=b"z" * 200_000)
    s3.copy_object(Bucket=B, Key="dst-tmp", CopySource=f"{B}/src-tmp")
    s3.delete_object(Bucket=B, Key="src-tmp")
    assert s3.get_object(Bucket=B, Key="dst-tmp")["Body"].read() == b"z" * 200_000
    expect_error("InvalidRequest", lambda: s3.copy_object(Bucket=B, Key="hello.txt", CopySource=f"{B}/hello.txt"))


def t_multipart():
    key = "mp/object.bin"
    parts_data = [os.urandom(5 * MB), os.urandom(5 * MB), os.urandom(1234)]
    up = s3.create_multipart_upload(Bucket=B, Key=key, ContentType="video/mp4", Metadata={"m": "1"})
    uid = up["UploadId"]
    ups = s3.list_multipart_uploads(Bucket=B)
    assert any(u["UploadId"] == uid for u in ups.get("Uploads", []))
    etags = []
    for i, d in enumerate(parts_data, 1):
        etags.append(s3.upload_part(Bucket=B, Key=key, UploadId=uid, PartNumber=i, Body=d)["ETag"])
    lp = s3.list_parts(Bucket=B, Key=key, UploadId=uid)
    assert [p["PartNumber"] for p in lp["Parts"]] == [1, 2, 3]
    expect_error("InvalidPart", lambda: s3.complete_multipart_upload(
        Bucket=B, Key=key, UploadId=uid,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": '"0000"'}]}))
    r = s3.complete_multipart_upload(Bucket=B, Key=key, UploadId=uid, MultipartUpload={
        "Parts": [{"PartNumber": i, "ETag": e} for i, e in enumerate(etags, 1)]})
    md5s = b"".join(hashlib.md5(d).digest() for d in parts_data)
    assert r["ETag"] == '"%s-3"' % hashlib.md5(md5s).hexdigest(), r["ETag"]
    whole = b"".join(parts_data)
    g = s3.get_object(Bucket=B, Key=key)
    assert g["Body"].read() == whole and g["ContentType"] == "video/mp4" and g["Metadata"] == {"m": "1"}
    off = 5 * MB - 10
    assert s3.get_object(Bucket=B, Key=key, Range=f"bytes={off}-{off + 19}")["Body"].read() == whole[off:off + 20]
    p2 = s3.get_object(Bucket=B, Key=key, PartNumber=2)
    assert p2["Body"].read() == parts_data[1] and p2["PartsCount"] == 3
    expect_error("NoSuchUpload", lambda: s3.list_parts(Bucket=B, Key=key, UploadId=uid))


def t_multipart_small_part():
    key = "mp/small"
    uid = s3.create_multipart_upload(Bucket=B, Key=key)["UploadId"]
    e1 = s3.upload_part(Bucket=B, Key=key, UploadId=uid, PartNumber=1, Body=b"a" * 100)["ETag"]
    e2 = s3.upload_part(Bucket=B, Key=key, UploadId=uid, PartNumber=2, Body=b"b" * 100)["ETag"]
    expect_error("EntityTooSmall", lambda: s3.complete_multipart_upload(Bucket=B, Key=key, UploadId=uid, MultipartUpload={
        "Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}]}))
    s3.abort_multipart_upload(Bucket=B, Key=key, UploadId=uid)
    expect_error("NoSuchUpload", lambda: s3.abort_multipart_upload(Bucket=B, Key=key, UploadId=uid))


def t_upload_part_copy():
    key = "mp/copied"
    src = s3.get_object(Bucket=B, Key="big.bin")["Body"].read()
    uid = s3.create_multipart_upload(Bucket=B, Key=key)["UploadId"]
    p1 = s3.upload_part_copy(Bucket=B, Key=key, UploadId=uid, PartNumber=1,
                             CopySource={"Bucket": B, "Key": "big.bin"}, CopySourceRange="bytes=0-5242879"
                             ) if len(src) > 5 * MB else None
    if p1 is None:
        p1 = s3.upload_part_copy(Bucket=B, Key=key, UploadId=uid, PartNumber=1,
                                 CopySource={"Bucket": B, "Key": "mp/object.bin"}, CopySourceRange="bytes=0-5242879")
        first = s3.get_object(Bucket=B, Key="mp/object.bin", Range="bytes=0-5242879")["Body"].read()
    else:
        first = src[:5 * MB]
    p2 = s3.upload_part_copy(Bucket=B, Key=key, UploadId=uid, PartNumber=2, CopySource={"Bucket": B, "Key": "hello.txt"})
    s3.complete_multipart_upload(Bucket=B, Key=key, UploadId=uid, MultipartUpload={"Parts": [
        {"PartNumber": 1, "ETag": p1["CopyPartResult"]["ETag"]},
        {"PartNumber": 2, "ETag": p2["CopyPartResult"]["ETag"]}]})
    assert s3.get_object(Bucket=B, Key=key)["Body"].read() == first + b"hello world"


def t_transfer_manager():
    data = os.urandom(23 * MB + 7)
    cfg = TransferConfig(multipart_threshold=8 * MB, multipart_chunksize=8 * MB, max_concurrency=4)
    s3.upload_fileobj(io.BytesIO(data), B, "tm/file.bin", Config=cfg)
    out = io.BytesIO()
    s3.download_fileobj(B, "tm/file.bin", out, Config=cfg)
    assert out.getvalue() == data


def t_presigned_v2():
    _presigned(s3)


def t_presigned_v4():
    _presigned(client(signature_version="s3v4"))


def t_sigv2_header():
    c = client(signature_version="s3")
    c.put_object(Bucket=B, Key="v2 key+x", Body=b"sigv2", Metadata={"a": "b"})
    assert c.get_object(Bucket=B, Key="v2 key+x")["Body"].read() == b"sigv2"
    assert any(o["Key"] == "v2 key+x" for o in c.list_objects(Bucket=B, Prefix="v2")["Contents"])


def _presigned(s3):
    url = s3.generate_presigned_url("get_object", Params={"Bucket": B, "Key": "hello.txt"}, ExpiresIn=60)
    assert urllib.request.urlopen(url).read() == b"hello world"
    put_url = s3.generate_presigned_url("put_object", Params={"Bucket": B, "Key": "presigned-put"}, ExpiresIn=60)
    req = urllib.request.Request(put_url, data=b"via presigned", method="PUT", headers={"Content-Type": ""})
    urllib.request.urlopen(req).read()
    assert s3.get_object(Bucket=B, Key="presigned-put")["Body"].read() == b"via presigned"
    bad = url.replace("Signature=", "Signature=0")
    try:
        urllib.request.urlopen(bad)
        raise AssertionError("tampered URL accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 403


def t_bad_credentials():
    bad = boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id=AK, aws_secret_access_key="wrong",
                       region_name="us-east-1", config=Config(retries={"max_attempts": 1}))
    expect_error("SignatureDoesNotMatch", lambda: bad.list_buckets())
    worse = boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id="nobody", aws_secret_access_key="x",
                         region_name="us-east-1", config=Config(retries={"max_attempts": 1}))
    expect_error("InvalidAccessKeyId", lambda: worse.list_buckets())
    try:
        urllib.request.urlopen(f"{ENDPOINT}/{B}/hello.txt")
        raise AssertionError("anonymous request accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 403


def http(method, path, headers=None, data=None):
    """Raw unauthenticated HTTP request; returns (status, headers, body)."""
    req = urllib.request.Request(f"{ENDPOINT}{path}", data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def t_object_tagging():
    s3.put_object(Bucket=B, Key="tagged", Body=b"t", Tagging="env=prod&team=a%20b")
    tags = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=B, Key="tagged")["TagSet"]}
    assert tags == {"env": "prod", "team": "a b"}, tags
    assert s3.get_object(Bucket=B, Key="tagged")["TagCount"] == 2
    s3.put_object_tagging(Bucket=B, Key="tagged", Tagging={"TagSet": [{"Key": "x", "Value": "1"}]})
    assert s3.get_object_tagging(Bucket=B, Key="tagged")["TagSet"] == [{"Key": "x", "Value": "1"}]
    s3.copy_object(Bucket=B, Key="tagged-copy", CopySource=f"{B}/tagged")
    assert s3.get_object_tagging(Bucket=B, Key="tagged-copy")["TagSet"] == [{"Key": "x", "Value": "1"}]
    s3.copy_object(Bucket=B, Key="tagged-copy", CopySource=f"{B}/tagged", TaggingDirective="REPLACE", Tagging="y=2")
    assert s3.get_object_tagging(Bucket=B, Key="tagged-copy")["TagSet"] == [{"Key": "y", "Value": "2"}]
    s3.delete_object_tagging(Bucket=B, Key="tagged")
    assert s3.get_object_tagging(Bucket=B, Key="tagged")["TagSet"] == []
    expect_error("InvalidTag", lambda: s3.put_object(Bucket=B, Key="bad-tags", Body=b"", Tagging="a=1&a=2"))
    uid = s3.create_multipart_upload(Bucket=B, Key="mp-tagged", Tagging="mp=yes")["UploadId"]
    e = s3.upload_part(Bucket=B, Key="mp-tagged", UploadId=uid, PartNumber=1, Body=b"z")["ETag"]
    s3.complete_multipart_upload(Bucket=B, Key="mp-tagged", UploadId=uid, MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e}]})
    assert s3.get_object_tagging(Bucket=B, Key="mp-tagged")["TagSet"] == [{"Key": "mp", "Value": "yes"}]


def t_bucket_tagging():
    expect_error("NoSuchTagSet", lambda: s3.get_bucket_tagging(Bucket=B))
    s3.put_bucket_tagging(Bucket=B, Tagging={"TagSet": [{"Key": "owner", "Value": "me"}]})
    assert s3.get_bucket_tagging(Bucket=B)["TagSet"] == [{"Key": "owner", "Value": "me"}]
    s3.delete_bucket_tagging(Bucket=B)
    expect_error("NoSuchTagSet", lambda: s3.get_bucket_tagging(Bucket=B))


def t_public_read_acl():
    pb = B + "-pub"
    s3.create_bucket(Bucket=pb)
    s3.put_object(Bucket=pb, Key="file.txt", Body=b"public data")
    assert http("GET", f"/{pb}/file.txt")[0] == 403
    s3.put_bucket_acl(Bucket=pb, ACL="public-read")
    grants = s3.get_bucket_acl(Bucket=pb)["Grants"]
    assert any(g["Grantee"].get("URI", "").endswith("AllUsers") and g["Permission"] == "READ" for g in grants), grants
    st, _, body = http("GET", f"/{pb}/file.txt")
    assert (st, body) == (200, b"public data"), st
    assert http("HEAD", f"/{pb}/file.txt")[0] == 200
    st, _, body = http("GET", f"/{pb}?list-type=2")
    assert st == 200 and b"<Key>file.txt</Key>" in body
    assert http("PUT", f"/{pb}/new.txt", data=b"nope")[0] == 403
    assert http("DELETE", f"/{pb}/file.txt")[0] == 403
    assert http("GET", f"/{pb}?acl")[0] == 403
    s3.put_bucket_acl(Bucket=pb, ACL="private")
    assert http("GET", f"/{pb}/file.txt")[0] == 403
    # Canned ACL at creation time.
    pb2 = B + "-pub2"
    s3.create_bucket(Bucket=pb2, ACL="public-read")
    s3.put_object(Bucket=pb2, Key="k", Body=b"v")
    assert http("GET", f"/{pb2}/k")[2] == b"v"
    for b in (pb, pb2):
        for o in s3.list_objects_v2(Bucket=b).get("Contents", []):
            s3.delete_object(Bucket=b, Key=o["Key"])
        s3.delete_bucket(Bucket=b)


def t_bucket_policy():
    import json
    expect_error("NoSuchBucketPolicy", lambda: s3.get_bucket_policy(Bucket=B))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{B}/public/*"},
            {"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{B}/public/secret*"},
            {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{B}/dropbox/*"},
        ],
    }
    s3.put_bucket_policy(Bucket=B, Policy=json.dumps(policy))
    assert json.loads(s3.get_bucket_policy(Bucket=B)["Policy"]) == policy
    assert s3.get_bucket_policy_status(Bucket=B)["PolicyStatus"]["IsPublic"] is True
    s3.put_object(Bucket=B, Key="public/page.html", Body=b"<h1>hi</h1>")
    s3.put_object(Bucket=B, Key="public/secret.txt", Body=b"s")
    assert http("GET", f"/{B}/public/page.html")[2] == b"<h1>hi</h1>"
    assert http("GET", f"/{B}/public/secret.txt")[0] == 403
    assert http("GET", f"/{B}/hello.txt")[0] == 403
    assert http("GET", f"/{B}?list-type=2")[0] == 403
    assert http("PUT", f"/{B}/dropbox/upload.bin", data=b"anon upload")[0] == 200
    assert s3.get_object(Bucket=B, Key="dropbox/upload.bin")["Body"].read() == b"anon upload"
    assert http("PUT", f"/{B}/elsewhere.bin", data=b"x")[0] == 403
    bad = dict(policy, Statement=[{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::other/*"}])
    expect_error("MalformedPolicy", lambda: s3.put_bucket_policy(Bucket=B, Policy=json.dumps(bad)))
    expect_error("MalformedPolicy", lambda: s3.put_bucket_policy(Bucket=B, Policy="{not json"))
    s3.delete_bucket_policy(Bucket=B)
    assert http("GET", f"/{B}/public/page.html")[0] == 403


def t_cors():
    expect_error("NoSuchCORSConfiguration", lambda: s3.get_bucket_cors(Bucket=B))
    rules = [{"AllowedOrigins": ["https://*.example.com"], "AllowedMethods": ["GET", "PUT"],
              "AllowedHeaders": ["*"], "ExposeHeaders": ["ETag"], "MaxAgeSeconds": 600}]
    s3.put_bucket_cors(Bucket=B, CORSConfiguration={"CORSRules": rules})
    got = s3.get_bucket_cors(Bucket=B)["CORSRules"]
    assert got[0]["AllowedOrigins"] == ["https://*.example.com"] and got[0]["MaxAgeSeconds"] == 600, got
    st, h, _ = http("OPTIONS", f"/{B}/some/key", headers={
        "Origin": "https://app.example.com", "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "content-type, x-amz-meta-foo"})
    assert st == 200, st
    assert h["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert "PUT" in h["Access-Control-Allow-Methods"] and h["Access-Control-Max-Age"] == "600"
    assert "x-amz-meta-foo" in h["Access-Control-Allow-Headers"]
    st, _, _ = http("OPTIONS", f"/{B}/k", headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"})
    assert st == 403
    st, _, _ = http("OPTIONS", f"/{B}/k", headers={"Origin": "https://app.example.com", "Access-Control-Request-Method": "DELETE"})
    assert st == 403
    # Actual requests (signed) get CORS headers too.
    c = client()
    def add_origin(request, **kw):
        request.headers["Origin"] = "https://app.example.com"
    c.meta.events.register("before-sign.s3.GetObject", add_origin)
    r = c.get_object(Bucket=B, Key="hello.txt")
    hdrs = r["ResponseMetadata"]["HTTPHeaders"]
    assert hdrs.get("access-control-allow-origin") == "https://app.example.com", hdrs
    assert hdrs.get("access-control-expose-headers") == "ETag"
    s3.delete_bucket_cors(Bucket=B)
    expect_error("NoSuchCORSConfiguration", lambda: s3.get_bucket_cors(Bucket=B))


def t_read_only_key():
    if not RO_AK:
        print("        (skipped: S3RS_RO_ACCESS_KEY not set)")
        return
    ro = boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id=RO_AK, aws_secret_access_key=RO_SK,
                      region_name="us-east-1", config=Config(retries={"max_attempts": 1}, s3={"addressing_style": "path"}))
    assert ro.get_object(Bucket=B, Key="hello.txt")["Body"].read() == b"hello world"
    assert any(o["Key"] == "hello.txt" for o in ro.list_objects_v2(Bucket=B)["Contents"])
    expect_error("AccessDenied", lambda: ro.put_object(Bucket=B, Key="ro-write", Body=b"x"))
    expect_error("AccessDenied", lambda: ro.delete_object(Bucket=B, Key="hello.txt"))
    expect_error("AccessDenied", lambda: ro.create_bucket(Bucket=B + "-ro"))


def t_metrics_and_health():
    st, _, body = http("GET", "/_health")
    assert st == 200 and body == b"ok\n"
    st, h, body = http("GET", "/_metrics")
    text = body.decode()
    assert st == 200 and "s3rs_requests_total{method=\"GET\",code=\"2xx\"}" in text, text[:500]
    assert "s3rs_request_duration_seconds_bucket" in text and "s3rs_buckets" in text


def t_lifecycle():
    # Needs a server started with --lifecycle-interval 1 and S3RS_LIFECYCLE_DAY_SECS=2.
    if not os.environ.get("S3RS_FAST_LIFECYCLE"):
        print("        (skipped: set S3RS_FAST_LIFECYCLE=1 with a fast-sweeping server)")
        return
    lb = B + "-lc"
    s3.create_bucket(Bucket=lb)
    expect_error("NoSuchLifecycleConfiguration", lambda: s3.get_bucket_lifecycle_configuration(Bucket=lb))
    rules = [
        {"ID": "tmp", "Status": "Enabled", "Filter": {"Prefix": "tmp/"}, "Expiration": {"Days": 1}},
        {"ID": "dated", "Status": "Enabled", "Filter": {"Prefix": "dated/"}, "Expiration": {"Date": "2020-01-01T00:00:00Z"}},
        {"ID": "tagged", "Status": "Enabled",
         "Filter": {"And": {"Prefix": "tagged/", "Tags": [{"Key": "ttl", "Value": "short"}]}}, "Expiration": {"Days": 1}},
        {"ID": "off", "Status": "Disabled", "Filter": {"Prefix": "keep/"}, "Expiration": {"Days": 1}},
        {"ID": "mpu", "Status": "Enabled", "Filter": {"Prefix": ""}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}},
    ]
    s3.put_bucket_lifecycle_configuration(Bucket=lb, LifecycleConfiguration={"Rules": rules})
    got = s3.get_bucket_lifecycle_configuration(Bucket=lb)["Rules"]
    assert [r["ID"] for r in got] == ["tmp", "dated", "tagged", "off", "mpu"], got
    for k in ["tmp/a", "dated/b", "keep/c", "other/d", "tagged/untagged"]:
        s3.put_object(Bucket=lb, Key=k, Body=b"x")
    s3.put_object(Bucket=lb, Key="tagged/short", Body=b"x", Tagging="ttl=short")
    s3.create_multipart_upload(Bucket=lb, Key="stale-upload")
    deadline = time.time() + 15
    gone = {"tmp/a", "dated/b", "tagged/short"}
    while time.time() < deadline:
        keys = {o["Key"] for o in s3.list_objects_v2(Bucket=lb).get("Contents", [])}
        if not (keys & gone) and not s3.list_multipart_uploads(Bucket=lb).get("Uploads"):
            break
        time.sleep(0.5)
    keys = {o["Key"] for o in s3.list_objects_v2(Bucket=lb).get("Contents", [])}
    assert keys == {"keep/c", "other/d", "tagged/untagged"}, keys
    assert not s3.list_multipart_uploads(Bucket=lb).get("Uploads")
    st, _, body = http("GET", "/_metrics")
    assert b"s3rs_lifecycle_expired_objects_total" in body
    s3.delete_bucket_lifecycle(Bucket=lb)
    expect_error("NoSuchLifecycleConfiguration", lambda: s3.get_bucket_lifecycle_configuration(Bucket=lb))
    expect_error("InvalidRequest", lambda: s3.put_bucket_lifecycle_configuration(
        Bucket=lb, LifecycleConfiguration={"Rules": [{"ID": "x", "Status": "Enabled", "Filter": {"Prefix": ""}}]}))
    for k in keys:
        s3.delete_object(Bucket=lb, Key=k)
    s3.delete_bucket(Bucket=lb)


def _form_post(url, fields, file_bytes, filename="upload.bin", file_type="application/octet-stream"):
    """Send a multipart/form-data POST with the file as the last part."""
    boundary = "----s3rs" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                 f"Content-Type: {file_type}\r\n\r\n".encode() + file_bytes + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return http("POST", url[len(ENDPOINT):], data=b"".join(parts),
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})


def t_presigned_post():
    for sigver in ["s3v4", "s3"]:
        c = client(signature_version=sigver)
        post = c.generate_presigned_post(
            B, "forms/${filename}",
            Fields={"success_action_status": "201", "x-amz-meta-origin": "browser"},
            Conditions=[["starts-with", "$key", "forms/"], ["content-length-range", 1, 1_000_000],
                        {"success_action_status": "201"}, {"x-amz-meta-origin": "browser"}],
            ExpiresIn=300)
        data = os.urandom(150_000)
        st, h, body = _form_post(post["url"], post["fields"], data, filename=f"photo-{sigver}.jpg", file_type="image/jpeg")
        assert st == 201, (sigver, st, body)
        assert b"<Key>forms/photo-%s.jpg</Key>" % sigver.encode() in body, body
        r = s3.get_object(Bucket=B, Key=f"forms/photo-{sigver}.jpg")
        assert r["Body"].read() == data and r["ContentType"] == "image/jpeg" and r["Metadata"] == {"origin": "browser"}
        assert r["ETag"] == h["ETag"]
        # Too large for the policy's content-length-range.
        st, _, body = _form_post(post["url"], post["fields"], b"x" * 1_000_001)
        assert st == 400 and b"EntityTooLarge" in body, (st, body)
        # Tampered signature / extra field / policy violation.
        bad = dict(post["fields"])
        sig_field = "x-amz-signature" if "x-amz-signature" in bad else "signature"
        bad[sig_field] = ("0" + bad[sig_field])[: len(bad[sig_field])]
        assert _form_post(post["url"], bad, b"data")[0] == 403
        extra = dict(post["fields"], **{"x-amz-meta-sneaky": "1"})
        st, _, body = _form_post(post["url"], extra, b"data")
        assert st == 403 and b"Extra input fields" in body, body
        wrong = dict(post["fields"], key="elsewhere/${filename}")
        assert _form_post(post["url"], wrong, b"data")[0] == 403
    # Default response (204) and redirect.
    post = s3.generate_presigned_post(B, "forms/plain.txt", ExpiresIn=60)
    st, _, _ = _form_post(post["url"], post["fields"], b"plain")
    assert st == 204, st
    assert s3.get_object(Bucket=B, Key="forms/plain.txt")["Body"].read() == b"plain"
    post = s3.generate_presigned_post(B, "forms/r.txt", Fields={"success_action_redirect": "https://app.example/done"},
                                      Conditions=[{"success_action_redirect": "https://app.example/done"}], ExpiresIn=60)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    boundary = "b" + uuid.uuid4().hex
    body = b"".join(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in post["fields"].items())
    body += f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="r.txt"\r\n\r\nR\r\n--{boundary}--\r\n'.encode()
    req = urllib.request.Request(post["url"], data=body, method="POST", headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        urllib.request.build_opener(NoRedirect).open(req)
        raise AssertionError("expected redirect")
    except urllib.error.HTTPError as e:
        assert e.code == 303 and e.headers["Location"].startswith("https://app.example/done?bucket="), (e.code, e.headers["Location"])
    # Unsigned form to a private bucket is refused.
    st, _, _ = _form_post(f"{ENDPOINT}/{B}", {"key": "anon.txt"}, b"x")
    assert st == 403


def _all_versions(bucket, **kw):
    out = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, **kw):
        out += [("v", v["Key"], v["VersionId"], v["IsLatest"]) for v in page.get("Versions", [])]
        out += [("dm", d["Key"], d["VersionId"], d["IsLatest"]) for d in page.get("DeleteMarkers", [])]
    return out


def _wipe_versioned(bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
    s3.delete_bucket(Bucket=bucket)


def t_versioning():
    vb = B + "-ver"
    s3.create_bucket(Bucket=vb)
    assert "Status" not in s3.get_bucket_versioning(Bucket=vb)
    s3.put_object(Bucket=vb, Key="k", Body=b"v0")  # pre-versioning "null" version
    s3.put_bucket_versioning(Bucket=vb, VersioningConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_versioning(Bucket=vb)["Status"] == "Enabled"
    v1 = s3.put_object(Bucket=vb, Key="k", Body=b"v1")["VersionId"]
    v2 = s3.put_object(Bucket=vb, Key="k", Body=b"v2")["VersionId"]
    assert v1 != v2 and v1 != "null"
    g = s3.get_object(Bucket=vb, Key="k")
    assert g["Body"].read() == b"v2" and g["VersionId"] == v2
    assert s3.get_object(Bucket=vb, Key="k", VersionId=v1)["Body"].read() == b"v1"
    assert s3.get_object(Bucket=vb, Key="k", VersionId="null")["Body"].read() == b"v0"
    assert s3.head_object(Bucket=vb, Key="k", VersionId=v1)["ContentLength"] == 2
    assert _all_versions(vb) == [("v", "k", v2, True), ("v", "k", v1, False), ("v", "k", "null", False)], _all_versions(vb)
    expect_error("NoSuchVersion", lambda: s3.get_object(Bucket=vb, Key="k", VersionId="0" * 32))

    # Delete creates a marker; the key disappears from normal listings.
    d = s3.delete_object(Bucket=vb, Key="k")
    assert d["DeleteMarker"] is True and d["VersionId"] not in (v1, v2)
    dm = d["VersionId"]
    try:
        s3.get_object(Bucket=vb, Key="k")
        raise AssertionError("expected 404")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "NoSuchKey"
        assert e.response["ResponseMetadata"]["HTTPHeaders"].get("x-amz-delete-marker") == "true"
    expect_error("405", lambda: s3.head_object(Bucket=vb, Key="k", VersionId=dm))
    assert "Contents" not in s3.list_objects_v2(Bucket=vb)
    assert ("dm", "k", dm, True) in _all_versions(vb)
    expect_error("BucketNotEmpty", lambda: s3.delete_bucket(Bucket=vb))

    # Removing the delete marker restores the object; removing the latest version promotes the previous one.
    s3.delete_object(Bucket=vb, Key="k", VersionId=dm)
    assert s3.get_object(Bucket=vb, Key="k")["Body"].read() == b"v2"
    s3.delete_object(Bucket=vb, Key="k", VersionId=v2)
    g = s3.get_object(Bucket=vb, Key="k")
    assert g["Body"].read() == b"v1" and g["VersionId"] == v1

    # Copy from an old version.
    c = s3.copy_object(Bucket=vb, Key="copy", CopySource={"Bucket": vb, "Key": "k", "VersionId": "null"})
    assert c["CopySourceVersionId"] == "null" and c["VersionId"]
    assert s3.get_object(Bucket=vb, Key="copy")["Body"].read() == b"v0"

    # Tagging a specific version.
    s3.put_object_tagging(Bucket=vb, Key="k", VersionId="null", Tagging={"TagSet": [{"Key": "old", "Value": "yes"}]})
    assert s3.get_object_tagging(Bucket=vb, Key="k", VersionId="null")["TagSet"] == [{"Key": "old", "Value": "yes"}]
    assert s3.get_object_tagging(Bucket=vb, Key="k")["TagSet"] == []

    # Multipart uploads create versions too.
    uid = s3.create_multipart_upload(Bucket=vb, Key="mp")["UploadId"]
    e = s3.upload_part(Bucket=vb, Key="mp", UploadId=uid, PartNumber=1, Body=b"m")["ETag"]
    r = s3.complete_multipart_upload(Bucket=vb, Key="mp", UploadId=uid, MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e}]})
    assert r.get("VersionId")

    # Batch delete with and without versions.
    many = [s3.put_object(Bucket=vb, Key=f"batch/{i}", Body=b"x")["VersionId"] for i in range(3)]
    res = s3.delete_objects(Bucket=vb, Delete={"Objects": [{"Key": "batch/0", "VersionId": many[0]}, {"Key": "batch/1"}]})
    by_key = {d["Key"]: d for d in res["Deleted"]}
    assert by_key["batch/0"]["VersionId"] == many[0] and "DeleteMarker" not in by_key["batch/0"]
    assert by_key["batch/1"]["DeleteMarker"] is True and by_key["batch/1"]["DeleteMarkerVersionId"]
    assert [o["Key"] for o in s3.list_objects_v2(Bucket=vb, Prefix="batch/")["Contents"]] == ["batch/2"]

    # Paginated version listing (MaxKeys=1) matches the full listing.
    full = _all_versions(vb)
    paged = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=vb, PaginationConfig={"PageSize": 1}):
        paged += [("v", v["Key"], v["VersionId"], v["IsLatest"]) for v in page.get("Versions", [])]
        paged += [("dm", d["Key"], d["VersionId"], d["IsLatest"]) for d in page.get("DeleteMarkers", [])]
    assert sorted(paged) == sorted(full) and len(paged) == len(set(paged)), (paged, full)

    # Regression: a key-marker shorter than the prefix must not crash the server.
    r = s3.list_object_versions(Bucket=vb, Prefix="abc", Delimiter="/", KeyMarker="b/")
    assert "Versions" not in r
    r = s3.list_object_versions(Bucket=vb, Prefix="a", Delimiter="/", KeyMarker="\u00e9/")
    assert http("GET", "/_health")[0] == 200
    # Keys containing NUL are rejected (they would alias other keys' versions).
    assert http("PUT", f"/{vb}/a%00b", data=b"x")[0] in (400, 403)
    res = s3.delete_objects(Bucket=vb, Delete={"Objects": [{"Key": "a\x00b"}]})
    assert res.get("Errors") and not res.get("Deleted"), res
    # Deleting a delete marker by version id reports DeleteMarkerVersionId.
    s3.put_object(Bucket=vb, Key="dmk", Body=b"x")
    m = s3.delete_object(Bucket=vb, Key="dmk")["VersionId"]
    res = s3.delete_objects(Bucket=vb, Delete={"Objects": [{"Key": "dmk", "VersionId": m}]})
    assert res["Deleted"][0]["DeleteMarker"] is True and res["Deleted"][0]["DeleteMarkerVersionId"] == m, res

    # Suspended: new writes replace the single "null" version, older versions stay.
    s3.put_bucket_versioning(Bucket=vb, VersioningConfiguration={"Status": "Suspended"})
    s3.put_object(Bucket=vb, Key="k", Body=b"s1")
    s3.put_object(Bucket=vb, Key="k", Body=b"s2")
    ks = [x for x in _all_versions(vb, Prefix="k") if x[1] == "k"]
    assert [x[2] for x in ks] == ["null", v1], ks
    assert s3.get_object(Bucket=vb, Key="k")["Body"].read() == b"s2"
    _wipe_versioned(vb)


def t_lifecycle_versions():
    if not os.environ.get("S3RS_FAST_LIFECYCLE"):
        print("        (skipped: set S3RS_FAST_LIFECYCLE=1 with a fast-sweeping server)")
        return
    lb = B + "-lcv"
    s3.create_bucket(Bucket=lb)
    s3.put_bucket_versioning(Bucket=lb, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_lifecycle_configuration(Bucket=lb, LifecycleConfiguration={"Rules": [{
        "ID": "nc", "Status": "Enabled", "Filter": {"Prefix": ""},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
        "Expiration": {"ExpiredObjectDeleteMarker": True}}]})
    s3.put_object(Bucket=lb, Key="k", Body=b"old")
    keep = s3.put_object(Bucket=lb, Key="k", Body=b"new")["VersionId"]
    s3.put_object(Bucket=lb, Key="solo", Body=b"x")
    s3.delete_object(Bucket=lb, Key="solo")
    deadline = time.time() + 20
    while time.time() < deadline and _all_versions(lb) != [("v", "k", keep, True)]:
        time.sleep(0.5)
    assert _all_versions(lb) == [("v", "k", keep, True)], _all_versions(lb)
    _wipe_versioned(lb)


def t_encryption():
    if not os.environ.get("S3RS_ENCRYPTION"):
        print("        (skipped: set S3RS_ENCRYPTION=1 with a server started with --encryption-key)")
        return
    import base64
    eb = B + "-enc"
    s3.create_bucket(Bucket=eb)
    data_dir = os.environ.get("S3RS_DATA_DIR")

    def on_disk_contains(needle):
        if not data_dir:
            return False
        for root, _, files in os.walk(data_dir):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    if needle in fh.read():
                        return True
        return False

    # SSE-S3: large (file) and small (inline) objects, ranges across chunk boundaries.
    big = os.urandom(300_000) + b"PLAINTEXT-MARKER-BIG" + os.urandom(100)
    r = s3.put_object(Bucket=eb, Key="sse/big", Body=big, ServerSideEncryption="AES256")
    assert r["ServerSideEncryption"] == "AES256"
    g = s3.get_object(Bucket=eb, Key="sse/big")
    assert g["Body"].read() == big and g["ServerSideEncryption"] == "AES256"
    for a, b in [(0, 0), (65535, 65537), (131000, 200000), (len(big) - 5, len(big) - 1)]:
        assert s3.get_object(Bucket=eb, Key="sse/big", Range=f"bytes={a}-{b}")["Body"].read() == big[a:b + 1]
    small = b"tiny secret PLAINTEXT-MARKER-SMALL"
    s3.put_object(Bucket=eb, Key="sse/small", Body=small, ServerSideEncryption="AES256")
    assert s3.get_object(Bucket=eb, Key="sse/small")["Body"].read() == small
    s3.put_object(Bucket=eb, Key="plain/control", Body=b"PLAINTEXT-MARKER-PLAIN")
    if data_dir:
        assert on_disk_contains(b"PLAINTEXT-MARKER-PLAIN"), "control marker should be visible on disk"
        assert not on_disk_contains(b"PLAINTEXT-MARKER-BIG") and not on_disk_contains(b"PLAINTEXT-MARKER-SMALL")
    expect_error("NotImplemented", lambda: s3.put_object(Bucket=eb, Key="kms", Body=b"x", ServerSideEncryption="aws:kms"))

    # Bucket default encryption.
    expect_error("ServerSideEncryptionConfigurationNotFoundError", lambda: s3.get_bucket_encryption(Bucket=eb))
    s3.put_bucket_encryption(Bucket=eb, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    rule = s3.get_bucket_encryption(Bucket=eb)["ServerSideEncryptionConfiguration"]["Rules"][0]
    assert rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"
    assert s3.put_object(Bucket=eb, Key="default/x", Body=b"d")["ServerSideEncryption"] == "AES256"
    assert s3.head_object(Bucket=eb, Key="default/x")["ServerSideEncryption"] == "AES256"
    s3.delete_bucket_encryption(Bucket=eb)
    assert "ServerSideEncryption" not in s3.put_object(Bucket=eb, Key="default/y", Body=b"d")

    # SSE-C.
    key = os.urandom(32)
    other = os.urandom(32)
    ck = {"SSECustomerAlgorithm": "AES256", "SSECustomerKey": key}
    data = os.urandom(150_000)
    r = s3.put_object(Bucket=eb, Key="ssec/obj", Body=data, **ck)
    assert r["SSECustomerAlgorithm"] == "AES256"
    expect_error("InvalidRequest", lambda: s3.get_object(Bucket=eb, Key="ssec/obj"))
    expect_error("AccessDenied", lambda: s3.get_object(Bucket=eb, Key="ssec/obj", SSECustomerAlgorithm="AES256", SSECustomerKey=other))
    expect_error("400", lambda: s3.head_object(Bucket=eb, Key="ssec/obj"))
    g = s3.get_object(Bucket=eb, Key="ssec/obj", **ck)
    assert g["Body"].read() == data and g["SSECustomerKeyMD5"]
    # The ETag of an SSE-C object must not reveal the plaintext MD5, and conditional requests
    # must not work without the key.
    plain_md5 = '"%s"' % hashlib.md5(data).hexdigest()
    assert g["ETag"] != plain_md5 and r["ETag"] == g["ETag"]
    listed = {o["Key"]: o["ETag"] for o in s3.list_objects_v2(Bucket=eb, Prefix="ssec/")["Contents"]}
    assert listed["ssec/obj"] != plain_md5
    expect_error("400", lambda: s3.head_object(Bucket=eb, Key="ssec/obj", IfNoneMatch="*"))
    expect_error("400", lambda: s3.head_object(Bucket=eb, Key="ssec/obj", IfMatch=plain_md5))
    assert s3.get_object(Bucket=eb, Key="ssec/obj", Range="bytes=70000-70009", **ck)["Body"].read() == data[70000:70010]
    assert s3.head_object(Bucket=eb, Key="ssec/obj", **ck)["ContentLength"] == len(data)

    # Multipart with SSE-C (parts must carry the key) and part copy from an SSE-C source.
    uid = s3.create_multipart_upload(Bucket=eb, Key="ssec/mp", **ck)["UploadId"]
    p1 = os.urandom(5 * MB)
    e1 = s3.upload_part(Bucket=eb, Key="ssec/mp", UploadId=uid, PartNumber=1, Body=p1, **ck)["ETag"]
    assert e1 != '"%s"' % hashlib.md5(p1).hexdigest()
    expect_error("InvalidRequest", lambda: s3.upload_part(Bucket=eb, Key="ssec/mp", UploadId=uid, PartNumber=2, Body=b"x"))
    e2 = s3.upload_part_copy(Bucket=eb, Key="ssec/mp", UploadId=uid, PartNumber=2, CopySource={"Bucket": eb, "Key": "sse/big"},
                             CopySourceRange="bytes=0-999", **ck)["CopyPartResult"]["ETag"]
    s3.complete_multipart_upload(Bucket=eb, Key="ssec/mp", UploadId=uid,
                                 MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}]})
    whole = p1 + big[:1000]
    assert s3.get_object(Bucket=eb, Key="ssec/mp", **ck)["Body"].read() == whole
    assert s3.get_object(Bucket=eb, Key="ssec/mp", Range=f"bytes={5 * MB - 3}-{5 * MB + 2}", **ck)["Body"].read() == whole[5 * MB - 3:5 * MB + 3]

    # Copies between encryption modes.
    s3.copy_object(Bucket=eb, Key="copy/plain", CopySource={"Bucket": eb, "Key": "ssec/obj"},
                   CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=key)
    g = s3.get_object(Bucket=eb, Key="copy/plain")
    assert g["Body"].read() == data and "ServerSideEncryption" not in g
    s3.copy_object(Bucket=eb, Key="copy/sse", CopySource={"Bucket": eb, "Key": "copy/plain"}, ServerSideEncryption="AES256")
    assert s3.get_object(Bucket=eb, Key="copy/sse")["Body"].read() == data
    s3.copy_object(Bucket=eb, Key="copy/ssec2", CopySource={"Bucket": eb, "Key": "copy/sse"},
                   SSECustomerAlgorithm="AES256", SSECustomerKey=other)
    assert s3.get_object(Bucket=eb, Key="copy/ssec2", SSECustomerAlgorithm="AES256", SSECustomerKey=other)["Body"].read() == data
    s3.copy_object(Bucket=eb, Key="copy/sse-small", CopySource={"Bucket": eb, "Key": "sse/small"}, ServerSideEncryption="AES256")
    assert s3.get_object(Bucket=eb, Key="copy/sse-small")["Body"].read() == small
    # Copying an SSE-S3 object without encryption headers keeps it encrypted (as S3 does today).
    c = s3.copy_object(Bucket=eb, Key="copy/kept", CopySource={"Bucket": eb, "Key": "sse/big"})
    assert c["ServerSideEncryption"] == "AES256"
    assert s3.head_object(Bucket=eb, Key="copy/kept")["ServerSideEncryption"] == "AES256"
    if data_dir:
        assert not on_disk_contains(b"PLAINTEXT-MARKER-BIG")
    # Changing an object's encryption in place is allowed.
    s3.copy_object(Bucket=eb, Key="copy/plain", CopySource={"Bucket": eb, "Key": "copy/plain"}, ServerSideEncryption="AES256")
    assert s3.head_object(Bucket=eb, Key="copy/plain")["ServerSideEncryption"] == "AES256"
    assert s3.get_object(Bucket=eb, Key="copy/plain")["Body"].read() == data
    # A copy that re-encrypts with SSE-C gets a keyed ETag, not the plaintext MD5.
    c = s3.copy_object(Bucket=eb, Key="copy/to-ssec", CopySource={"Bucket": eb, "Key": "copy/plain"}, **ck)
    assert c["CopyObjectResult"]["ETag"] != plain_md5

    # Form upload with SSE.
    post = s3.generate_presigned_post(eb, "form/enc", Fields={"x-amz-server-side-encryption": "AES256"},
                                      Conditions=[{"x-amz-server-side-encryption": "AES256"}], ExpiresIn=60)
    assert _form_post(post["url"], post["fields"], b"form secret")[0] == 204
    g = s3.get_object(Bucket=eb, Key="form/enc")
    assert g["Body"].read() == b"form secret" and g["ServerSideEncryption"] == "AES256"

    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=eb):
        for o in page.get("Contents", []):
            s3.delete_object(Bucket=eb, Key=o["Key"])
    s3.delete_bucket(Bucket=eb)


def t_scoped_key():
    # Needs a credential `scoped:scopedsecret:rw:scoped-*,shared-scope` (see --credentials-file).
    ak, sk = os.environ.get("S3RS_SCOPED_ACCESS_KEY"), os.environ.get("S3RS_SCOPED_SECRET_KEY")
    if not ak:
        print("        (skipped: S3RS_SCOPED_ACCESS_KEY not set)")
        return
    sc = boto3.client("s3", endpoint_url=ENDPOINT, aws_access_key_id=ak, aws_secret_access_key=sk, region_name="us-east-1",
                      config=Config(retries={"max_attempts": 1}, s3={"addressing_style": "path"}))
    mine = "scoped-" + uuid.uuid4().hex[:8]
    sc.create_bucket(Bucket=mine)
    sc.put_object(Bucket=mine, Key="k", Body=b"mine")
    assert sc.get_object(Bucket=mine, Key="k")["Body"].read() == b"mine"
    names = [b["Name"] for b in sc.list_buckets()["Buckets"]]
    assert mine in names and B not in names, names
    expect_error("AccessDenied", lambda: sc.create_bucket(Bucket="other-" + uuid.uuid4().hex[:8]))
    expect_error("AccessDenied", lambda: sc.get_object(Bucket=B, Key="hello.txt"))
    expect_error("AccessDenied", lambda: sc.list_objects_v2(Bucket=B))
    expect_error("AccessDenied", lambda: sc.copy_object(Bucket=mine, Key="stolen", CopySource={"Bucket": B, "Key": "hello.txt"}))
    post = sc.generate_presigned_post(B, "x", ExpiresIn=60)
    assert _form_post(post["url"], post["fields"], b"x")[0] == 403
    # The full-access key still sees everything.
    assert mine in [b["Name"] for b in s3.list_buckets()["Buckets"]]
    sc.delete_object(Bucket=mine, Key="k")
    sc.delete_bucket(Bucket=mine)


def t_object_lock():
    import datetime

    now = lambda: datetime.datetime.now(datetime.timezone.utc)  # noqa: E731
    lb = B + "-lock"
    s3.create_bucket(Bucket=lb, ObjectLockEnabledForBucket=True)
    assert s3.get_bucket_versioning(Bucket=lb)["Status"] == "Enabled"
    cfg = s3.get_object_lock_configuration(Bucket=lb)["ObjectLockConfiguration"]
    assert cfg["ObjectLockEnabled"] == "Enabled" and "Rule" not in cfg, cfg
    expect_error(
        "InvalidBucketState",
        lambda: s3.put_bucket_versioning(Bucket=lb, VersioningConfiguration={"Status": "Suspended"}),
    )

    # GOVERNANCE: protected unless the caller bypasses it.
    until = now() + datetime.timedelta(hours=1)
    g = s3.put_object(Bucket=lb, Key="gov", Body=b"g", ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=until)
    h = s3.head_object(Bucket=lb, Key="gov")
    assert h["ObjectLockMode"] == "GOVERNANCE" and abs((h["ObjectLockRetainUntilDate"] - until).total_seconds()) < 1, h
    r = s3.get_object_retention(Bucket=lb, Key="gov", VersionId=g["VersionId"])["Retention"]
    assert r["Mode"] == "GOVERNANCE", r
    expect_error("AccessDenied", lambda: s3.delete_object(Bucket=lb, Key="gov", VersionId=g["VersionId"]))
    # Shortening needs the bypass too; extending does not.
    expect_error(
        "AccessDenied",
        lambda: s3.put_object_retention(
            Bucket=lb, Key="gov", Retention={"Mode": "GOVERNANCE", "RetainUntilDate": now() + datetime.timedelta(minutes=5)}
        ),
    )
    s3.put_object_retention(
        Bucket=lb, Key="gov", Retention={"Mode": "GOVERNANCE", "RetainUntilDate": until + datetime.timedelta(hours=1)}
    )
    # Deleting without a version id just adds a delete marker.
    assert s3.delete_object(Bucket=lb, Key="gov")["DeleteMarker"]
    s3.delete_object(Bucket=lb, Key="gov", VersionId=g["VersionId"], BypassGovernanceRetention=True)

    # COMPLIANCE: nobody can delete or shorten it until it expires.
    comp_until = now() + datetime.timedelta(seconds=3)
    c = s3.put_object(Bucket=lb, Key="comp", Body=b"c", ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=comp_until)
    expect_error(
        "AccessDenied",
        lambda: s3.delete_object(Bucket=lb, Key="comp", VersionId=c["VersionId"], BypassGovernanceRetention=True),
    )
    expect_error(
        "AccessDenied",
        lambda: s3.put_object_retention(
            Bucket=lb,
            Key="comp",
            Retention={"Mode": "GOVERNANCE", "RetainUntilDate": now() + datetime.timedelta(hours=1)},
            BypassGovernanceRetention=True,
        ),
    )

    # Legal hold: blocks deletion regardless of retention or bypass.
    lh = s3.put_object(Bucket=lb, Key="hold", Body=b"h", ObjectLockLegalHoldStatus="ON")
    assert s3.get_object_legal_hold(Bucket=lb, Key="hold")["LegalHold"]["Status"] == "ON"
    r = s3.delete_objects(
        Bucket=lb, Delete={"Objects": [{"Key": "hold", "VersionId": lh["VersionId"]}]}, BypassGovernanceRetention=True
    )
    assert [e["Code"] for e in r.get("Errors", [])] == ["AccessDenied"], r
    s3.put_object_legal_hold(Bucket=lb, Key="hold", LegalHold={"Status": "OFF"})
    s3.delete_object(Bucket=lb, Key="hold", VersionId=lh["VersionId"])

    # Bucket default retention applies to plain PUTs, multipart uploads and copies.
    s3.put_object_lock_configuration(
        Bucket=lb,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}},
        },
    )
    rule = s3.get_object_lock_configuration(Bucket=lb)["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]
    assert rule == {"Mode": "GOVERNANCE", "Days": 1}, rule
    d = s3.put_object(Bucket=lb, Key="def", Body=b"d")
    h = s3.head_object(Bucket=lb, Key="def")
    left = (h["ObjectLockRetainUntilDate"] - now()).total_seconds()
    assert h["ObjectLockMode"] == "GOVERNANCE" and 86_000 < left <= 86_400, h
    up = s3.create_multipart_upload(Bucket=lb, Key="mp")
    e = s3.upload_part(Bucket=lb, Key="mp", UploadId=up["UploadId"], PartNumber=1, Body=b"m")["ETag"]
    mp = s3.complete_multipart_upload(
        Bucket=lb, Key="mp", UploadId=up["UploadId"], MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e}]}
    )
    assert s3.head_object(Bucket=lb, Key="mp")["ObjectLockMode"] == "GOVERNANCE"
    cp = s3.copy_object(Bucket=lb, Key="cp", CopySource={"Bucket": lb, "Key": "def"})
    assert s3.head_object(Bucket=lb, Key="cp")["ObjectLockMode"] == "GOVERNANCE"
    for key, vid in [("def", d["VersionId"]), ("mp", mp["VersionId"]), ("cp", cp["VersionId"])]:
        expect_error("AccessDenied", lambda: s3.delete_object(Bucket=lb, Key=key, VersionId=vid))

    # Buckets without Object Lock reject lock settings.
    expect_error(
        "InvalidRequest",
        lambda: s3.put_object(Bucket=B, Key="nolock", Body=b"x", ObjectLockLegalHoldStatus="ON"),
    )
    expect_error("ObjectLockConfigurationNotFoundError", lambda: s3.get_object_lock_configuration(Bucket=B))
    expect_error(
        "InvalidBucketState",
        lambda: s3.put_object_lock_configuration(Bucket=B, ObjectLockConfiguration={"ObjectLockEnabled": "Enabled"}),
    )

    # A presigned URL holder cannot add an unsigned bypass header.
    url = s3.generate_presigned_url("delete_object", Params={"Bucket": lb, "Key": "def", "VersionId": d["VersionId"]})
    req = urllib.request.Request(url, method="DELETE", headers={"x-amz-bypass-governance-retention": "true"})
    try:
        urllib.request.urlopen(req)
        raise AssertionError("unsigned bypass header was accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 403, e.code
    assert s3.get_object(Bucket=lb, Key="def", VersionId=d["VersionId"])["Body"].read() == b"d"
    # Anonymous writers (public-read-write) cannot set locks, also not through multipart uploads.
    s3.put_bucket_acl(Bucket=lb, ACL="public-read-write")
    lock_hdrs = {"x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": "2099-01-01T00:00:00Z"}
    assert http("POST", f"/{lb}/anon?uploads", headers=lock_hdrs)[0] == 403
    assert http("PUT", f"/{lb}/anon", headers=lock_hdrs, data=b"x")[0] == 403
    s3.put_bucket_acl(Bucket=lb, ACL="private")

    # Clean up: wait out the COMPLIANCE retention, then bypass the GOVERNANCE ones.
    time.sleep(max(0.0, (comp_until - now()).total_seconds() + 1.1))
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=lb):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            r = s3.delete_objects(Bucket=lb, Delete={"Objects": objs, "Quiet": True}, BypassGovernanceRetention=True)
            assert not r.get("Errors"), r["Errors"]
    s3.delete_bucket(Bucket=lb)


WEBSITE = os.environ.get("S3RS_WEBSITE_ENDPOINT")  # e.g. http://127.0.0.1:9001
WEBSITE_DOMAIN = os.environ.get("S3RS_WEBSITE_DOMAIN")


def web(host, path, method="GET", headers=None):
    """Request to the website endpoint (no redirect following): (status, headers, body)."""
    import http.client
    import urllib.parse

    u = urllib.parse.urlparse(WEBSITE)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    conn.request(method, path, headers={"Host": host, **(headers or {})})
    r = conn.getresponse()
    body = r.read()
    conn.close()
    return r.status, r.headers, body


def t_website():
    if not WEBSITE:
        print("        (skipped: set S3RS_WEBSITE_ENDPOINT)")
        return
    wb = B + "-site"
    host = f"{wb}.{WEBSITE_DOMAIN}" if WEBSITE_DOMAIN else wb
    s3.create_bucket(Bucket=wb)
    html = {"ContentType": "text/html"}
    s3.put_object(Bucket=wb, Key="index.html", Body=b"<h1>home</h1>", **html)
    s3.put_object(Bucket=wb, Key="about/index.html", Body=b"about", **html)
    s3.put_object(Bucket=wb, Key="404.html", Body=b"custom not found", **html)
    s3.put_object(Bucket=wb, Key="moved", Body=b"", WebsiteRedirectLocation="/about/")
    s3.put_bucket_acl(Bucket=wb, ACL="public-read")

    st, _, body = web(host, "/")
    assert st == 404 and b"NoSuchWebsiteConfiguration" in body, (st, body)
    expect_error("NoSuchWebsiteConfiguration", lambda: s3.get_bucket_website(Bucket=wb))
    s3.put_bucket_website(
        Bucket=wb,
        WebsiteConfiguration={
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "404.html"},
            "RoutingRules": [{"Condition": {"KeyPrefixEquals": "old/"}, "Redirect": {"ReplaceKeyPrefixWith": "new/"}}],
        },
    )
    assert s3.get_bucket_website(Bucket=wb)["IndexDocument"]["Suffix"] == "index.html"

    st, h, body = web(host, "/")
    assert (st, body, h["Content-Type"]) == (200, b"<h1>home</h1>", "text/html"), (st, body)
    st, h, _ = web(host, "/about")
    assert st == 302 and h["Location"] == f"http://{host}/about/", (st, h["Location"])
    assert web(host, "/about/")[2] == b"about"
    st, _, body = web(host, "/nope.html")
    assert (st, body) == (404, b"custom not found"), (st, body)
    st, h, _ = web(host, "/old/page.html")
    assert st == 301 and h["Location"] == f"http://{host}/new/page.html", h["Location"]
    st, h, _ = web(host, "/moved")
    assert st == 301 and h["Location"] == "/about/", (st, h["Location"])
    expect_error(
        "InvalidRedirectLocation", lambda: s3.put_object(Bucket=wb, Key="bad", Body=b"", WebsiteRedirectLocation="//evil.example")
    )
    # A key starting with "/" must not turn the directory redirect into a protocol-relative URL.
    s3.put_object(Bucket=wb, Key="/evil.example/index.html", Body=b"x")
    st, h, _ = web(host, "//evil.example")
    assert st == 302 and h["Location"] == f"http://{host}//evil.example/", (st, h["Location"])
    s3.delete_object(Bucket=wb, Key="/evil.example/index.html")
    st, h, body = web(host, "/", method="HEAD")
    assert st == 200 and body == b"" and h["Content-Length"] == "13", (st, h)
    etag = h["ETag"]
    assert web(host, "/", headers={"If-None-Match": etag})[0] == 304
    st, _, body = web(host, "/", headers={"Range": "bytes=4-7"})
    assert (st, body) == (206, b"home"), (st, body)
    assert web(host, "/", method="POST")[0] == 405
    st, h, body = web("no-such-bucket-xyz", "/")
    assert st == 404 and b"NoSuchBucket" in body and h["Content-Type"].startswith("text/html"), (st, body)
    if WEBSITE_DOMAIN:  # CNAME style: a bucket named like the host
        assert web(wb, "/")[2] == b"<h1>home</h1>"
    # Only publicly readable objects are served.
    s3.put_bucket_acl(Bucket=wb, ACL="private")
    assert web(host, "/")[0] == 403
    # Redirect everything.
    s3.put_bucket_website(
        Bucket=wb, WebsiteConfiguration={"RedirectAllRequestsTo": {"HostName": "example.com", "Protocol": "https"}}
    )
    st, h, _ = web(host, "/a/b?c=1")
    assert st == 301 and h["Location"] == "https://example.com/a/b?c=1", h["Location"]
    s3.delete_bucket_website(Bucket=wb)
    assert web(host, "/")[0] == 404
    for k in ["index.html", "about/index.html", "404.html", "moved"]:
        s3.delete_object(Bucket=wb, Key=k)
    s3.delete_bucket(Bucket=wb)


def t_console():
    st, h, body = http("GET", "/_console/")
    assert st == 200 and h["Content-Type"].startswith("text/html") and b"s3rs console" in body, (st, body[:100])
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"] and h["X-Frame-Options"] == "DENY", dict(h)
    assert http("GET", "/_console/app.js")[0] == 200
    assert http("GET", "/_console/nope")[0] == 404
    assert http("POST", "/_console/")[0] == 405
    # Browsers opening the endpoint without credentials land on the console; API clients don't.
    st, _, body = http("GET", "/", headers={"Accept": "text/html,application/xhtml+xml"})
    assert st == 200 and b"s3rs console" in body, st
    assert http("GET", "/")[0] == 403


def t_overwrite():
    s3.put_object(Bucket=B, Key="ow", Body=b"x" * 300_000)
    s3.put_object(Bucket=B, Key="ow", Body=b"small")
    assert s3.get_object(Bucket=B, Key="ow")["Body"].read() == b"small"
    s3.put_object(Bucket=B, Key="ow", Body=b"y" * 300_000)
    assert s3.get_object(Bucket=B, Key="ow")["Body"].read() == b"y" * 300_000


def t_delete():
    s3.delete_object(Bucket=B, Key="hello-copy")
    expect_error("NoSuchKey", lambda: s3.get_object(Bucket=B, Key="hello-copy"))
    s3.delete_object(Bucket=B, Key="never-existed")
    r = s3.delete_objects(Bucket=B, Delete={"Objects": [{"Key": "dir/a"}, {"Key": "dir/b"}, {"Key": "nope"}]})
    assert sorted(d["Key"] for d in r["Deleted"]) == ["dir/a", "dir/b", "nope"]
    expect_error("BucketNotEmpty", lambda: s3.delete_bucket(Bucket=B))


def t_cleanup():
    pag = s3.get_paginator("list_objects_v2")
    for page in pag.paginate(Bucket=B):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=B, Delete={"Objects": objs, "Quiet": True})
    for u in s3.list_multipart_uploads(Bucket=B).get("Uploads", []):
        s3.abort_multipart_upload(Bucket=B, Key=u["Key"], UploadId=u["UploadId"])
    s3.delete_bucket(Bucket=B)
    expect_error("NoSuchBucket", lambda: s3.list_objects_v2(Bucket=B))


if __name__ == "__main__":
    start = time.time()
    print(f"s3rs e2e against {ENDPOINT} (bucket {B})")
    for name, fn in list(globals().items()):
        if name.startswith("t_") and callable(fn):
            check(name[2:], fn)
    print(f"{'FAILED' if failures else 'passed'} in {time.time() - start:.1f}s; failures: {failures}")
    sys.exit(1 if failures else 0)
