#!/usr/bin/env python3
"""Per-object canned ACLs: public-read objects in private buckets, as apps that upload with
`x-amz-acl: public-read` expect.

    python3 tests/objacl.py ./target/release/s3rs
"""

import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BIN = sys.argv[1] if len(sys.argv) > 1 else "./target/release/s3rs"
PORT, WEB = 9395, 9396
EP = f"http://127.0.0.1:{PORT}"
work = tempfile.mkdtemp(prefix="s3rs-objacl-")
p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "root", "--secret-key", "rootsecret",
                      "--website-listen", f"127.0.0.1:{WEB}", "--website-domain", "web.localhost"],
                     stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
try:
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{EP}/_health")
            break
        except Exception:
            time.sleep(0.1)
    s3 = boto3.client("s3", endpoint_url=EP, aws_access_key_id="root", aws_secret_access_key="rootsecret", region_name="us-east-1",
                      config=Config(s3={"addressing_style": "path"}, retries={"total_max_attempts": 1}))

    def anon(path, method="GET", host=None, base=EP):
        req = urllib.request.Request(base + path, method=method, headers={"host": host} if host else {})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def code(f):
        try:
            f()
        except ClientError as e:
            return e.response["Error"]["Code"]
        return "OK"

    s3.create_bucket(Bucket="media")
    s3.put_object(Bucket="media", Key="avatar.png", Body=b"public image", ACL="public-read")
    s3.put_object(Bucket="media", Key="secret.txt", Body=b"private")
    assert anon("/media/avatar.png") == (200, b"public image")
    assert anon("/media/avatar.png", "HEAD")[0] == 200
    assert anon("/media/secret.txt")[0] == 403
    assert anon("/media")[0] == 403  # listing stays private
    assert anon("/media/avatar.png?acl")[0] == 403
    acl = s3.get_object_acl(Bucket="media", Key="avatar.png")
    assert any(g["Grantee"].get("URI", "").endswith("AllUsers") for g in acl["Grants"]), acl
    print("public-read objects are readable by anyone in a private bucket; others are not")

    # Multipart uploads, copies and browser POST uploads carry their ACL; copies don't inherit it.
    up = s3.create_multipart_upload(Bucket="media", Key="video.mp4", ACL="public-read")
    part = s3.upload_part(Bucket="media", Key="video.mp4", UploadId=up["UploadId"], PartNumber=1, Body=b"v" * 1000)
    s3.complete_multipart_upload(Bucket="media", Key="video.mp4", UploadId=up["UploadId"],
                                 MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part["ETag"]}]})
    assert anon("/media/video.mp4")[0] == 200
    s3.copy_object(Bucket="media", Key="copy-private", CopySource={"Bucket": "media", "Key": "avatar.png"})
    s3.copy_object(Bucket="media", Key="copy-public", CopySource={"Bucket": "media", "Key": "secret.txt"}, ACL="public-read")
    assert anon("/media/copy-private")[0] == 403 and anon("/media/copy-public") == (200, b"private")
    post = s3.generate_presigned_post("media", "posted.txt", Fields={"acl": "public-read"}, Conditions=[{"acl": "public-read"}])
    boundary = "xyzboundary"
    body = "".join(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n' for k, v in post["fields"].items())
    body = body.encode() + f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="f"\r\n\r\nposted\r\n--{boundary}--\r\n'.encode()
    r = urllib.request.urlopen(urllib.request.Request(post["url"], data=body, method="POST",
                                                      headers={"content-type": f"multipart/form-data; boundary={boundary}"}))
    assert r.status == 204 and anon("/media/posted.txt") == (200, b"posted")
    print("multipart uploads, copies and POST uploads take an ACL")

    # PutObjectAcl makes an object public or private again.
    s3.put_object_acl(Bucket="media", Key="secret.txt", ACL="public-read")
    assert anon("/media/secret.txt")[0] == 200
    s3.put_object_acl(Bucket="media", Key="secret.txt", ACL="private")
    assert anon("/media/secret.txt")[0] == 403
    assert code(lambda: s3.put_object_acl(Bucket="media", Key="missing", ACL="public-read")) == "NoSuchKey"
    print("PutObjectAcl changes an object's ACL")

    # Versions have their own ACLs.
    s3.create_bucket(Bucket="vers")
    s3.put_bucket_versioning(Bucket="vers", VersioningConfiguration={"Status": "Enabled"})
    v1 = s3.put_object(Bucket="vers", Key="k", Body=b"one", ACL="public-read")["VersionId"]
    v2 = s3.put_object(Bucket="vers", Key="k", Body=b"two")["VersionId"]
    assert anon("/vers/k")[0] == 403 and anon(f"/vers/k?versionId={v1}") == (200, b"one")
    s3.put_object_acl(Bucket="vers", Key="k", VersionId=v2, ACL="public-read")
    assert anon("/vers/k") == (200, b"two")
    print("each version has its own ACL")

    # A bucket policy Deny wins; IgnorePublicAcls and BlockPublicAcls apply to objects.
    s3.put_bucket_policy(Bucket="media", Policy=json.dumps({"Statement": [{"Effect": "Deny", "Principal": "*",
                         "Action": "s3:GetObject", "Resource": "arn:aws:s3:::media/avatar.png"}]}))
    assert anon("/media/avatar.png")[0] == 403 and anon("/media/video.mp4")[0] == 200
    s3.delete_bucket_policy(Bucket="media")
    s3.put_public_access_block(Bucket="media", PublicAccessBlockConfiguration={"IgnorePublicAcls": True})
    assert anon("/media/avatar.png")[0] == 403
    s3.put_public_access_block(Bucket="media", PublicAccessBlockConfiguration={"BlockPublicAcls": True})
    assert anon("/media/avatar.png")[0] == 200
    assert code(lambda: s3.put_object(Bucket="media", Key="new", Body=b"x", ACL="public-read")) == "AccessDenied"
    assert code(lambda: s3.put_object_acl(Bucket="media", Key="secret.txt", ACL="public-read")) == "AccessDenied"
    s3.delete_public_access_block(Bucket="media")
    print("bucket policies and public access blocks apply")

    # In a public-read bucket, objects can't be made private with an ACL (only with a policy).
    s3.create_bucket(Bucket="open", ACL="public-read")
    s3.put_object(Bucket="open", Key="o", Body=b"o")
    assert code(lambda: s3.put_object_acl(Bucket="open", Key="o", ACL="private")) == "NotImplemented"

    # The website endpoint serves public objects of a private bucket.
    s3.put_bucket_website(Bucket="media", WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
    s3.put_object(Bucket="media", Key="index.html", Body=b"<p>home</p>", ContentType="text/html", ACL="public-read")
    web = f"http://127.0.0.1:{WEB}"
    assert anon("/", host="media.web.localhost", base=web) == (200, b"<p>home</p>")
    assert anon("/secret.txt", host="media.web.localhost", base=web)[0] == 403
    print("the website endpoint serves public objects")
    print("OBJECT ACL TEST OK")
finally:
    p.kill()
shutil.rmtree(work, ignore_errors=True)
