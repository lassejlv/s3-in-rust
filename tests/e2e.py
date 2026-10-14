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
