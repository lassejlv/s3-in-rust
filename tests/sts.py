#!/usr/bin/env python3
"""STS AssumeRole: temporary credentials with session tokens, limited by the key they were
issued for and by an optional session policy.

    python3 tests/sts.py ./target/release/s3rs
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
PORT = 9391
EP = f"http://127.0.0.1:{PORT}"
TOKEN = "sts-admin-token"
work = tempfile.mkdtemp(prefix="s3rs-sts-")
with open(f"{work}/creds", "w") as f:
    f.write("reader:readersecret1:ro\n")
procs = []


def start():
    p = subprocess.Popen([BIN, "-d", f"{work}/data", "-l", f"127.0.0.1:{PORT}", "--access-key", "root",
                          "--secret-key", "rootsecret", "--credentials-file", f"{work}/creds", "--admin-token", TOKEN],
                         stdout=open(f"{work}/log", "a"), stderr=subprocess.STDOUT)
    procs.append(p)
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{EP}/_health")
            return p
        except Exception:
            time.sleep(0.1)
    sys.exit("server did not start")


def cfg():
    # No client-side validation, so the server's checks are what is tested.
    return Config(s3={"addressing_style": "path"}, retries={"total_max_attempts": 1}, parameter_validation=False)


def s3(ak, sk, token=None):
    return boto3.client("s3", endpoint_url=EP, aws_access_key_id=ak, aws_secret_access_key=sk, aws_session_token=token,
                        region_name="us-east-1", config=cfg())


def sts(ak, sk, token=None):
    return boto3.client("sts", endpoint_url=EP, aws_access_key_id=ak, aws_secret_access_key=sk, aws_session_token=token,
                        region_name="us-east-1", config=cfg())


def session(c, **kw):
    return c.assume_role(RoleArn="arn:aws:iam::000000000000:role/any", RoleSessionName=kw.pop("name", "test"), **kw)["Credentials"]


def as_client(creds):
    return s3(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"])


def code(f):
    try:
        f()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return "OK"


def admin(method, path="", body=None):
    req = urllib.request.Request(f"{EP}/_admin/keys{path}", data=json.dumps(body).encode() if body is not None else None,
                                 method=method, headers={"authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req) as r:
        text = r.read()
        return json.loads(text) if text else None


try:
    start()
    root = s3("root", "rootsecret")
    root.create_bucket(Bucket="data")
    root.put_object(Bucket="data", Key="pub/a.txt", Body=b"public")
    root.put_object(Bucket="data", Key="private/b.txt", Body=b"secret")

    # A session acts as the key it was issued for.
    creds = session(sts("root", "rootsecret"), DurationSeconds=900)
    assert creds["AccessKeyId"].startswith("ASIA") and creds["SessionToken"], creds
    left = creds["Expiration"].timestamp() - time.time()
    assert 800 < left <= 900, left
    tmp = as_client(creds)
    tmp.put_object(Bucket="data", Key="by-session.txt", Body=b"hi")
    assert tmp.get_object(Bucket="data", Key="by-session.txt")["Body"].read() == b"hi"
    assert [b["Name"] for b in tmp.list_buckets()["Buckets"]] == ["data"]
    print("a session can do what its key can")

    # The token is required and must be the one issued with the key.
    assert code(lambda: s3(creds["AccessKeyId"], creds["SecretAccessKey"]).list_buckets()) == "InvalidAccessKeyId"
    other = session(sts("root", "rootsecret"))
    assert code(lambda: s3(creds["AccessKeyId"], creds["SecretAccessKey"], other["SessionToken"]).list_buckets()) == "InvalidToken"
    assert code(lambda: s3(creds["AccessKeyId"], "wrong-secret", creds["SessionToken"]).list_buckets()) == "SignatureDoesNotMatch"
    tampered = creds["SessionToken"][:-4] + ("AAAA" if not creds["SessionToken"].endswith("AAAA") else "BBBB")
    assert code(lambda: s3(creds["AccessKeyId"], creds["SecretAccessKey"], tampered).list_buckets()) == "InvalidToken"
    print("the session token is checked")

    # Presigned URLs and browser POST uploads carry the token too.
    v4 = boto3.client("s3", endpoint_url=EP, aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                      aws_session_token=creds["SessionToken"], region_name="us-east-1",
                      config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))
    for c in (tmp, v4):  # SigV2 and SigV4 presigned URLs
        url = c.generate_presigned_url("get_object", Params={"Bucket": "data", "Key": "pub/a.txt"}, ExpiresIn=60)
        assert "x-amz-security-token=" in url.lower(), url
        assert urllib.request.urlopen(url).read() == b"public"
    post = tmp.generate_presigned_post("data", "posted.txt", ExpiresIn=60)
    assert "x-amz-security-token" in post["fields"]
    import uuid
    boundary = uuid.uuid4().hex
    parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n' for k, v in post["fields"].items()]
    form = "".join(parts).encode() + f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="x"\r\n\r\nposted\r\n--{boundary}--\r\n'.encode()
    r = urllib.request.urlopen(urllib.request.Request(post["url"], data=form, method="POST",
                                                      headers={"content-type": f"multipart/form-data; boundary={boundary}"}))
    assert r.status == 204, r.status
    assert root.get_object(Bucket="data", Key="posted.txt")["Body"].read() == b"posted"
    print("presigned URLs and POST uploads work with session credentials")

    # A session policy narrows what the session may do.
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data/pub/*"},
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::data",
         "Condition": {"StringLike": {"s3:prefix": "pub/*"}}},
    ]}
    narrow = as_client(session(sts("root", "rootsecret"), Policy=json.dumps(policy), name="narrow"))
    assert narrow.get_object(Bucket="data", Key="pub/a.txt")["Body"].read() == b"public"
    assert code(lambda: narrow.get_object(Bucket="data", Key="private/b.txt")) == "AccessDenied"
    assert code(lambda: narrow.put_object(Bucket="data", Key="pub/new", Body=b"x")) == "AccessDenied"
    assert [o["Key"] for o in narrow.list_objects_v2(Bucket="data", Prefix="pub/")["Contents"]] == ["pub/a.txt"]
    assert code(lambda: narrow.list_objects_v2(Bucket="data")) == "AccessDenied"
    assert code(lambda: narrow.list_buckets()) == "AccessDenied"
    print("a session policy narrows the session")

    # A session can't do more than its key: a read-only key's sessions are read-only.
    ro = as_client(session(sts("reader", "readersecret1")))
    assert ro.get_object(Bucket="data", Key="pub/a.txt")["Body"].read() == b"public"
    assert code(lambda: ro.put_object(Bucket="data", Key="x", Body=b"x")) == "AccessDenied"
    print("a read-only key's sessions are read-only")

    # Sessions can't assume roles themselves.
    assert code(lambda: session(sts(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]))) == "AccessDenied"

    # Invalid requests get STS errors that SDKs understand.
    assert code(lambda: session(sts("root", "rootsecret"), DurationSeconds=60)) == "ValidationError"
    assert code(lambda: session(sts("root", "rootsecret"), Policy="{not json")) == "MalformedPolicyDocument"
    assert code(lambda: session(sts("root", "wrongsecret"))) == "SignatureDoesNotMatch"
    assert code(lambda: sts("nobody", "x").get_caller_identity()) == "InvalidAccessKeyId"
    assert sts("root", "rootsecret").get_caller_identity()["Arn"].endswith(":user/root")
    me = sts(creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]).get_caller_identity()
    assert me["Arn"].endswith(":assumed-role/root/test") and me["UserId"] == "root:test", me
    print("errors come in STS's format")

    # Deleting the key ends its sessions; a temporary key's sessions end with it.
    k = admin("POST", body={"description": "for sts"})
    kc = as_client(session(sts(k["access_key"], k["secret_key"])))
    kc.list_buckets()
    admin("DELETE", f"/{k['access_key']}")
    assert code(lambda: kc.list_buckets()) == "InvalidToken"
    # Rotating a key (re-created under the same name with a new secret) ends its old sessions.
    admin("POST", body={"access_key": "ROTATEDKEY1", "secret_key": "first-secret-123"})
    rc = as_client(session(sts("ROTATEDKEY1", "first-secret-123")))
    rc.list_buckets()
    admin("DELETE", "/ROTATEDKEY1")
    admin("POST", body={"access_key": "ROTATEDKEY1", "secret_key": "second-secret-456"})
    assert code(lambda: rc.list_buckets()) == "InvalidToken"
    t = admin("POST", body={"expires_in": 2})
    tc = session(sts(t["access_key"], t["secret_key"]))
    assert tc["Expiration"].timestamp() - time.time() < 3
    as_client(tc).list_buckets()
    time.sleep(2.5)
    assert code(lambda: as_client(tc).list_buckets()) == "ExpiredToken"
    print("sessions end with their key")

    # The admin API can end every session at once.
    ended = session(sts("root", "rootsecret"))
    as_client(ended).list_buckets()
    req = urllib.request.Request(f"{EP}/_admin/sessions", method="DELETE", headers={"authorization": f"Bearer {TOKEN}"})
    assert urllib.request.urlopen(req).status == 204
    assert code(lambda: as_client(ended).list_buckets()) == "InvalidToken"
    creds = session(sts("root", "rootsecret"))
    tmp = as_client(creds)
    tmp.put_object(Bucket="data", Key="by-session.txt", Body=b"hi")
    print("all sessions can be ended at once")

    # Sessions survive a restart (the signing key is kept with the data).
    procs[-1].terminate()
    procs[-1].wait()
    start()
    assert as_client(creds).get_object(Bucket="data", Key="by-session.txt")["Body"].read() == b"hi"
    print("sessions survive a restart")
    print("STS TEST OK")
finally:
    for p in procs:
        p.kill()
shutil.rmtree(work, ignore_errors=True)
