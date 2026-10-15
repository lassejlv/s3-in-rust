# s3rs

A fast, lightweight, S3-compatible object storage server written in pure Rust.

- **Single self-contained binary** (~4.5 MB, linked only against the system C library), no C code
  in the dependency tree.
  Native HTTPS is an optional build feature (see [HTTPS](#https-tls)).
- **Works with standard S3 clients**: AWS CLI, boto3, and other SDKs (SigV4 and SigV2 auth, presigned
  URLs, streaming/chunked uploads, multipart uploads, checksums).
- **Fast**: about 110k small GETs/s, about 35k durable small PUTs/s, and multiple GB/s of large-object reads on a
  4-core VM (see [Performance](#performance)).
- **Safe by default**: data and metadata are fsynced before a write is acknowledged. Group commit keeps that
  cheap.

## Quick start

```bash
cargo build --release

./target/release/s3rs --data-dir ./data --access-key mykey --secret-key mysecret
# s3rs 0.1.0 listening on http://0.0.0.0:9000 (data: ./data, region: us-east-1, auth: sigv4, ...)
```

```bash
export AWS_ACCESS_KEY_ID=mykey AWS_SECRET_ACCESS_KEY=mysecret AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://localhost:9000 s3 mb s3://photos
aws --endpoint-url http://localhost:9000 s3 sync ./pictures s3://photos/2024/
aws --endpoint-url http://localhost:9000 s3 ls --recursive s3://photos
```

```python
import boto3
s3 = boto3.client("s3", endpoint_url="http://localhost:9000",
                  aws_access_key_id="mykey", aws_secret_access_key="mysecret", region_name="us-east-1")
s3.put_object(Bucket="photos", Key="hello.txt", Body=b"hi")
```

Or open `http://localhost:9000` in a browser to use the [web console](#web-console).

### Docker

```bash
docker build -t s3rs .
docker run -p 9000:9000 -v $PWD/data:/data -e S3RS_ACCESS_KEY=mykey -e S3RS_SECRET_KEY=mysecret s3rs
```

Add `--build-arg FEATURES=tls` for an image with [native HTTPS](#https-tls).

### Releases

Pushing a `vX.Y.Z` tag that matches `Cargo.toml`'s version runs `.github/workflows/release.yml`:
- Linux binaries for x86_64 and arm64 (glibc 2.35+), each as a default and a `tls` build, are
  smoke-tested and published to a GitHub release with a `SHA256SUMS` file.
- Multi-arch container images are pushed to `ghcr.io/<owner>/s3rs:<version>` and `:latest`, plus
  `-tls` variants.

The release images run as an unprivileged user (uid 10001) and keep data in the `/data` volume:

```bash
docker run -p 9000:9000 -v s3rs-data:/data -e S3RS_ACCESS_KEY=mykey -e S3RS_SECRET_KEY=mysecret ghcr.io/<owner>/s3rs:0.1.0
```

`s3rs --version` prints the version, and `/_metrics` exports it as `s3rs_build_info`.

## Web console

Open the server's address in a browser (it redirects to `/_console/`) and sign in with an access
key. From the console you can:
- Create and delete buckets, with versioning or Object Lock.
- Browse folders, upload files by drag and drop (with progress), and create folders.
- Preview text and images, download objects, and create time-limited share links (presigned
  URLs).
- Delete objects and whole folders, and change a bucket's versioning, public access and website
  settings.

The console is three static files compiled into the binary. Every request is signed with SigV4
inside the browser tab, so the server keeps no sessions and the console can do nothing an S3
client with the same key couldn't. Signing needs a secure context, so use HTTPS or `localhost`. The pages are served with a
strict Content-Security-Policy and refuse to be framed. The key stays in the page's memory unless you
tick "Stay signed in", which keeps it in `sessionStorage` until the tab closes.

The console shares its origin with the S3 API, so while it is enabled, objects downloaded from the
API endpoint are sent with `Content-Security-Policy: sandbox`. HTML or SVG stored in a bucket then
renders in an isolated origin and can't read the console's storage. Serve websites from the
[website endpoint](#static-websites), which is a separate origin. Turn the console off with
`--no-console`.

## Configuration

Each flag can also be set with the environment variable shown (switches take `1`/`true`/`yes`/`on`).

| Flag | Env | Default | |
|---|---|---|---|
| `-l, --listen` | `S3RS_LISTEN` | `0.0.0.0:9000` | Listen address |
| `-d, --data-dir` | `S3RS_DATA_DIR` | `./data` | Storage directory |
| `--access-key` | `S3RS_ACCESS_KEY` | | Access key ID |
| `--secret-key` | `S3RS_SECRET_KEY` | | Secret access key |
| `--credentials-file` | `S3RS_CREDENTIALS_FILE` | | More keys, one `access_key:secret_key[:ro\|rw[:bucket-patterns]]` per line (see [Access control](#access-control)) |
| `--anonymous` | | off | Turns off authentication. Use it only on trusted networks. |
| `--cors-origins` | `S3RS_CORS_ORIGINS` | | Comma-separated origins (e.g. `*`) allowed for buckets that have no CORS configuration of their own |
| `--metrics-token` | `S3RS_METRICS_TOKEN` | | Requires `Authorization: Bearer <token>` on `/_metrics` |
| `--admin-token` | `S3RS_ADMIN_TOKEN` | | Enables the admin API (`GET /_admin/backup`) for `Authorization: Bearer <token>` |
| `--no-console` | `S3RS_NO_CONSOLE` | off | Turns off the web console at `/_console/` |
| `--tls-cert`, `--tls-key` | `S3RS_TLS_CERT`, `S3RS_TLS_KEY` | | Serves HTTPS with this PEM certificate chain and key (needs a `--features tls` build; see [HTTPS](#https-tls)) |
| `--behind-proxy` | `S3RS_BEHIND_PROXY` | off | Trusts `X-Forwarded-For` / `X-Forwarded-Proto` for policy conditions |
| `--webhook ID=URL` | `S3RS_WEBHOOKS` (comma-separated) | | Event notification target (repeatable); see [Event notifications](#event-notifications) |
| `--webhook-secret` | `S3RS_WEBHOOK_SECRET` | | Signs webhook bodies with HMAC-SHA256 |
| `--webhook-ca` | `S3RS_WEBHOOK_CA` | | Extra PEM CA certificates trusted for `https://` webhooks |
| `--lifecycle-interval` | `S3RS_LIFECYCLE_INTERVAL` | `3600` | Seconds between lifecycle sweeps. `0` turns lifecycle off. |
| `--encryption-key` | `S3RS_ENCRYPTION_KEY` | | Master key for SSE-S3, as 64 hex characters or base64 (e.g. `openssl rand -hex 32`) |
| `--encryption-key-file` | `S3RS_ENCRYPTION_KEY_FILE` | | Reads the master key from a file |
| `--encrypt-by-default` | `S3RS_ENCRYPT_BY_DEFAULT` | off | Encrypts every new object with the master key |
| `--region` | `S3RS_REGION` | `us-east-1` | Region reported to clients |
| `--domain` | `S3RS_DOMAIN` | | Turns on virtual-hosted-style requests (`<bucket>.<domain>`) |
| `--website-listen` | `S3RS_WEBSITE_LISTEN` | | Serves static websites on this address (see [Static websites](#static-websites)) |
| `--website-domain` | `S3RS_WEBSITE_DOMAIN` | | On the website endpoint, `<bucket>.<domain>` serves that bucket |
| `--inline-threshold` | `S3RS_INLINE_THRESHOLD` | `65536` | Objects up to this many bytes are stored inside the metadata DB |
| `--cache-mb` | `S3RS_CACHE_MB` | `256` | Metadata cache size |
| `--max-connections` | `S3RS_MAX_CONNECTIONS` | from the fd limit, ≤ 10000 | Stops accepting beyond this many open connections (see [Limits and timeouts](#limits-and-timeouts)) |
| `--rate-limit` | `S3RS_RATE_LIMIT` | off | Requests per second per access key |
| `--rate-limit-anonymous` | `S3RS_RATE_LIMIT_ANONYMOUS` | off | Requests per second per client address for unsigned requests |
| `--replication-targets` | `S3RS_REPLICATION_TARGETS` | | Remote servers for bucket replication (see [Replication](#replication)) |
| `--min-free-space` | `S3RS_MIN_FREE_SPACE` | 2% of the disk (16M–256M) | Refuses uploads when the data disk's free space would drop below this (e.g. `512M`, `2G`; `0` turns the reserve off, but after the ballast file was used, uploads still wait until it can be recreated). See [Disk space](#disk-space). |
| `--no-fsync` | `S3RS_NO_FSYNC` | off | Skips fsync. Faster, but a crash or power loss can lose about the last second of acknowledged writes. |
| `--access-log` | `S3RS_ACCESS_LOG` | off | Logs every request to stdout as `json` or `text` (see [Access logs](#access-logs)) |
| `-v, --verbose` | `S3RS_VERBOSE` | off | Same as `--access-log text` |

The server refuses to start without credentials unless you pass `--anonymous`.

`GET /_health` returns `200 ok` while the metadata database is readable and its writer
responds, and `503` otherwise. A full disk does not make the server unhealthy: reads and deletes
still work. `s3rs healthcheck` probes it from the same host, for container health checks (the
images define a `HEALTHCHECK` with it). `GET /_metrics` serves Prometheus metrics: request counts by method
and status, a latency histogram, bytes in and out, lifecycle activity, and the bucket count. Both
endpoints are public unless you set `--metrics-token`, which applies to `/_metrics` only. Per-bucket
series (which name every bucket) are included only when `/_metrics` is protected by a token.

### Limits and timeouts

Slow or stalled clients cost only memory, never a thread. Uploads and downloads wait for the
network asynchronously and use the blocking thread pool just for each chunk's disk work, so
thousands of slow transfers don't starve anything else. On top of that:

| What | Limit |
|---|---|
| New connection sends nothing | closed after 30 s |
| Request headers (also the next request on a kept-alive connection) | 30 s |
| TLS handshake | 10 s |
| Request body sends nothing | `400 RequestTimeout` after 60 s |
| Request body too slow | `400 RequestTimeout` once the body averages under 500 bytes/s (after a 20 s grace period). This also covers POST form uploads, which authenticate only after their fields arrive. |
| Client accepts no response data | connection closed after 120 s with no progress (a slow but steady reader is fine) |
| HTTP/2 peer stops answering pings | closed (pinged every 30 s) |
| Open connections | `--max-connections`. Beyond it s3rs stops accepting and new connections wait in the kernel's queue. |
| Request rate (optional) | `--rate-limit` per access key and `--rate-limit-anonymous` per client address for unsigned requests: public reads, websites and browser uploads. Bursts of two seconds' worth pass. Beyond that, requests get `503 SlowDown` with `Retry-After`, which AWS SDKs retry automatically. `/_health` and `/_metrics` are never limited. |

At startup s3rs raises its open-file limit to the hard limit. The default connection limit is half
of that (each transfer needs a socket and a file), at most 10,000. `/_metrics` exports
`s3rs_connections` and `s3rs_connections_max`.

### Access logs

`--access-log json` writes one JSON object per request to stdout. Diagnostics go to stderr, so the
two streams can be collected separately:

```json
{"time":"2026-10-15T01:57:54.775Z","request_id":"5B15702C99B7AB0A","endpoint":"api","remote_ip":"10.0.4.7",
 "user":"mykey","method":"GET","path":"/photos/missing","bucket":"photos","key":"missing",
 "error":"NoSuchKey","user_agent":"aws-cli/2.17","status":404,"duration_ms":0.040}
```

- `endpoint` is `api` or `website`.
- `remote_ip` honours `--behind-proxy`.
- `user` is the access key of a signed request.
- `error` is the S3 error code. `bytes_in` and `bytes_out` come from the request and response
  lengths.
- Signatures and session tokens in presigned URLs are replaced by `REDACTED`.
- `request_id` is the `x-amz-request-id` the client received.

Lines are written by a separate thread, so logging never slows requests down: small GETs still run
at about 85k requests/s with JSON logs on. If stdout can't keep up, lines are dropped and counted
in `s3rs_access_log_dropped_total`. `--access-log text` (or `-v`) prints a compact human-readable
line instead.

### Bucket logging

Bucket owners can turn on S3 server access logging for their buckets with PutBucketLogging. No
operator setup is needed:

```bash
aws s3api put-bucket-logging --bucket site --bucket-logging-status \
  '{"LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "site/"}}'
```

- **Format:** S3's server access log format, one line per request: time, client address,
  requester (access key), request id, operation (`REST.GET.OBJECT`), key, request line, status,
  error code, bytes sent, duration, user agent, signature and authentication type.
- **Delivery:** lines are written as log objects (`site/2024-05-01-12-00-03-<id>`) in the target
  bucket, about once a minute, or as soon as 1 MiB of lines accumulates.
  - `TargetObjectKeyFormat` with `PartitionedPrefix` writes
    `<prefix>s3rs/<region>/<bucket>/YYYY/MM/DD/<name>` instead.
  - Log objects get the target bucket's default encryption and retention.
  - Delivery is best effort, as in S3: lines still buffered when the server dies are lost.
    A graceful shutdown writes them.
- **Permissions:** whoever turns logging on must be allowed to `s3:PutObject` into the target
  bucket and prefix.
- **Monitoring:** `s3rs_bucket_log_objects_total` counts log objects written;
  `s3rs_bucket_log_dropped_total` counts writes that failed.

### Disk space

A full disk must never take the metadata database down with it, because deleting data is how you
recover from one. So s3rs keeps a free-space reserve on the data disk (`--min-free-space`, by
default 2% of the disk, between 16 MiB and 256 MiB):

- Uploads, parts and copies are refused with `507 StorageFull` when they would eat into the
  reserve. The check runs before any data is received and again every 8 MiB while it arrives.
  Deletes and other metadata changes are always allowed.
- The data directory also holds a ballast file (0.5% of the disk, 8–64 MiB). If the disk fills up
  anyway, for example because another process wrote to it, the server deletes the ballast to give
  pending writes and deletes room to commit. If even that is not enough, free space outside s3rs.
  Uploads stay refused until there is room to recreate the ballast.
- If the database still hits an I/O error, the server reopens it in place and recovers without a
  restart once space is available.
- `/_metrics` exports `s3rs_disk_free_bytes` and `s3rs_disk_reserve_bytes`. Alert well before the
  first reaches the second.

CI fills a 100 MB filesystem through the server, with and without the reserve
(`tests/diskfull.py`).

On `SIGTERM` or Ctrl-C the server stops accepting connections and waits up to 30 seconds for
in-flight requests to finish. It then flushes metadata and records a clean shutdown. If a run
crashes, the next start scans the store before serving and removes orphaned data files.

## HTTPS (TLS)

s3rs can serve HTTPS itself, without a reverse proxy. TLS uses [rustls](https://github.com/rustls/rustls)
with the ring crypto provider. ring contains C and assembly, so TLS is an optional build feature,
and the default build stays pure Rust:

```bash
cargo build --release --features tls
./target/release/s3rs --data-dir ./data --access-key mykey --secret-key mysecret \
  --tls-cert /etc/s3rs/fullchain.pem --tls-key /etc/s3rs/privkey.pem
# s3rs listening on https://0.0.0.0:9000 ...
```

- The certificate file holds the PEM chain (leaf first). The key is an unencrypted PEM key (PKCS#8,
  PKCS#1 or SEC1) for RSA, ECDSA P-256/P-384 or Ed25519. The server refuses to start if the key
  doesn't match the certificate.
- The same certificate serves the S3 API, the console and the `--website-listen` endpoint. Use one
  with names (or a wildcard) for each of them.
- TLS 1.2 and 1.3 are supported. ALPN offers HTTP/2 and HTTP/1.1.
- `SIGHUP` re-reads the certificate and key (for example after a Let's Encrypt renewal), together
  with the access keys. Open connections keep the old certificate. New ones get the new certificate.
  If the new files can't be loaded, the old certificate stays in use and the log says so.
- Clients get 10 seconds to complete the handshake. Handshakes still in progress at shutdown are
  dropped.
- Policies see `aws:SecureTransport` as `true`, and website redirects use `https://`.

A default build refuses to start when given `--tls-cert`. Behind a TLS-terminating proxy (or on
platforms such as Railway that terminate TLS for you) you don't need the feature: use `--behind-proxy`.

## Access control

Keys without a policy have full access, unless the credentials file limits them:

```text
# access_key:secret_key[:ro|rw|policy=<file.json>[:bucket-patterns]]
admin:s3cr3t
reporting:r3p0rt:ro                    # read-only, all buckets
team-a:t34m4:rw:team-a-*,shared-assets # read-write, only matching buckets
alice:al1c3:policy=policies/home.json  # only what the IAM-style policy allows
```

A key restricted to some buckets only sees those buckets in ListBuckets. It cannot create other
buckets, cannot copy from other buckets, and cannot sign form uploads to other buckets. Send the
server `SIGHUP` to reload the credentials file and policies without a restart. If the new file is
invalid, the server logs `RELOAD FAILED` and keeps the previous keys, including any you meant to
remove. A valid but empty file revokes every key in it.

**Keys through the admin API.** With `--admin-token`, keys can also be created and revoked at
runtime, without editing files. They are stored in the metadata database, so backups contain
them. They take effect immediately and survive restarts:

```bash
H="Authorization: Bearer $S3RS_ADMIN_TOKEN"
# Create a key (generated, or choose "access_key"/"secret_key"). The secret is shown only here.
curl -fsS -H "$H" -X POST https://s3.example.com/_admin/keys \
  -d '{"buckets": ["team-a-*"], "description": "team A deploys"}'
# {"access_key":"S3RSK7Q2...","secret_key":"...","source":"api","read_only":false,"buckets":["team-a-*"],...}

# Read-only, or limited by an IAM-style policy (the same format as policy files):
curl -fsS -H "$H" -X POST https://s3.example.com/_admin/keys -d '{"read_only": true}'
curl -fsS -H "$H" -X POST https://s3.example.com/_admin/keys -d '{"policy": {"Version": "2012-10-17", "Statement": [...]}}'

curl -fsS -H "$H" https://s3.example.com/_admin/keys                       # list (no secrets)
curl -fsS -H "$H" -X DELETE https://s3.example.com/_admin/keys/S3RSK7Q2...  # revoke
```

Keys from the command line and the credentials file are listed with `"source": "file"`. They can
only be changed there. If both define the same access key, the file wins.

**Per-key policies** use IAM's JSON format. Paths are relative to the credentials file. For example,
this policy gives every key using it a private home prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::home",
     "Condition": {"StringLike": {"s3:prefix": ["${aws:username}/*"]}}},
    {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
     "Resource": "arn:aws:s3:::home/${aws:username}/*"},
    {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::home/${aws:username}/keep/*"}
  ]
}
```

**Bucket policies** apply to every caller. Use `"Principal": "*"` for everyone (including anonymous
requests) or `{"AWS": ["alice", "arn:aws:iam::123456789012:user/alice"]}` for named keys. To
make public data, use an ACL or a policy:

```bash
# Public read: anyone can GET objects and list the bucket
aws --endpoint-url $E s3api put-bucket-acl --bucket site --acl public-read      # or create-bucket --acl public-read

# Finer control with a bucket policy: public prefix, a denied subfolder, an upload drop-box for one network
aws --endpoint-url $E s3api put-bucket-policy --bucket site --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::site/public/*"},
    {"Effect": "Deny",  "Principal": "*", "Action": "s3:*",         "Resource": "arn:aws:s3:::site/public/private/*"},
    {"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::site/uploads/*",
     "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}
  ]}'
```

Evaluation follows AWS:
1. An explicit `Deny` in the key's policy or the bucket policy always wins, even for full-access keys.
2. Otherwise a key with a policy needs an `Allow` from its own policy or from the bucket policy.
3. Keys without a policy are allowed, within their `ro` and bucket limits.
4. Anonymous callers need an ACL grant or an `Allow` in the bucket policy, and only for object
   operations and listings: managing the bucket itself (its policy, ACL, configuration, creating or
   deleting it) always needs a key, as on S3.

Every request is checked against its IAM action, such as `s3:GetObject`, `s3:GetObjectVersion`,
`s3:PutBucketPolicy` or `s3:ListBucketVersions`. Some operations need more than one action:
- CopyObject also needs read access to the source.
- DeleteObjects checks each key separately and reports refused keys as `AccessDenied` errors.
- Uploads that set tags, retention or a legal hold also need `s3:PutObjectTagging`,
  `s3:PutObjectRetention` or `s3:PutObjectLegalHold`.
- Bypassing GOVERNANCE retention needs `s3:BypassGovernanceRetention`.

Supported policy elements:
- `Effect`, `Principal` / `NotPrincipal` (bucket policies), `Action` / `NotAction`,
  `Resource` / `NotResource`, and `Condition`.
- Condition operators: `String*` (including `Like` and `IgnoreCase`), `Numeric*`, `Date*`, `Bool`,
  `IpAddress` / `NotIpAddress` and `Null`, plus `...IfExists` and `ForAnyValue:` / `ForAllValues:`.
- Condition keys: `aws:SourceIp`, `aws:SecureTransport`, `aws:username`, `aws:userid`,
  `aws:PrincipalType`, `aws:UserAgent`, `aws:Referer`, `aws:CurrentTime`, `aws:EpochTime`,
  `s3:prefix`, `s3:delimiter`, `s3:max-keys`, `s3:VersionId`, `s3:authType`, `s3:x-amz-acl`,
  `s3:x-amz-server-side-encryption`, `s3:x-amz-copy-source`, `s3:x-amz-metadata-directive`,
  `s3:object-lock-*` and `s3:RequestObjectTagKeys`.
- Policy variables such as `${aws:username}` work in resources and condition values.
- Unknown operators and condition keys, and malformed CIDR blocks, are rejected with
  `MalformedPolicy`, so a policy never silently means less than it says. If a stored policy stops
  parsing (e.g. after an upgrade), the bucket fails closed: everything except managing the policy
  is denied until it is replaced.

Requests that name more than one subresource (such as `?versions&acl`) are rejected, as are
methods a subresource doesn't support. Every request maps to exactly one operation, which decides
both the permission that is checked and the code that runs.

Behind a reverse proxy (Railway, Fly, nginx), pass `--behind-proxy` so `aws:SourceIp` and
`aws:SecureTransport` use the client's address and scheme from the proxy's `X-Forwarded-For`
(the last entry, which the proxy adds itself) and `X-Forwarded-Proto` headers. Without it, those
headers are ignored.

The `public-read` ACL lets anonymous callers GET objects and list the bucket. `public-read-write`
also lets them upload and delete. Objects have no ACLs of their own: they have their bucket's
ACL. GetObjectAcl reports it, `x-amz-acl` on uploads is ignored, and PutObjectAcl refuses
(`NotImplemented`) to set anything else.

**CORS.** `PutBucketCors`, `GetBucketCors` and `DeleteBucketCors` are supported. `OPTIONS` preflight
requests are answered without authentication. Matching responses get `Access-Control-*` headers, and
error responses get them too, so browsers can read the error. Use `--cors-origins` to set a
server-wide default for buckets that have no CORS configuration.

## Lifecycle rules

`PutBucketLifecycleConfiguration` supports:
- `Expiration` with `Days` or `Date`.
- `AbortIncompleteMultipartUpload`.
- `NoncurrentVersionExpiration` (`NoncurrentDays`) and `Expiration` with `ExpiredObjectDeleteMarker`,
  for versioned buckets.
- Filters by `Prefix`, `Tag`, `And`, `ObjectSizeGreaterThan` and `ObjectSizeLessThan`.

A background task applies the rules every `--lifecycle-interval` seconds. As on S3, a `Days` rule
expires an object at the first midnight (UTC) after its age reaches that many days. Expiration is a
compare-and-delete: an object overwritten after the sweeper looked at it is kept. In a
versioning-enabled bucket, expiring the current version adds a delete marker, as S3 does.
`Transition` actions are accepted but have no effect, since there is only one storage class.

## Encryption at rest

s3rs supports two kinds of server-side encryption.

**SSE-S3** uses a server master key, set with `--encryption-key`:
- A client requests it per object with `x-amz-server-side-encryption: AES256`.
- `PutBucketEncryption` makes it the default for a bucket.
- `--encrypt-by-default` makes it the default for every bucket.

**SSE-C** uses a key the client supplies with every request
(`x-amz-server-side-encryption-customer-*`):
- The server never stores the key, only its MD5, which it uses to check later requests.
- Reads without the key, or with a different key, are refused.
- SSE-C works without a master key.

How it works:
- Every encrypted data file (or inline object) has its own random 256-bit data key, encrypted
  under the master or customer key and stored in a header in the file. Hard-linked copies,
  multipart parts and old versions therefore need no extra bookkeeping.
- Data is encrypted in 64 KiB AES-256-GCM chunks. The last chunk is authenticated as last, so
  truncation, tampering and wrong keys are detected.
- Range reads decrypt only the chunks they overlap.
- Checksums are computed on the plaintext. Plain and SSE-S3 objects use the plaintext MD5 as
  their ETag, as S3 does. SSE-C ETags (and part ETags) are keyed with the customer key, so
  nobody without the key can learn or confirm the plaintext MD5. Requests on SSE-C objects need
  the key before any condition (`If-Match` and so on) is evaluated.
- Copying an SSE-S3 object keeps it encrypted unless the request asks for something else, and an
  object's encryption can be changed in place by copying it onto itself.
- Copies and UploadPartCopy decrypt with the source's key (`x-amz-copy-source-server-side-encryption-customer-*`
  for SSE-C sources) and re-encrypt for the destination. When the source and destination keys
  match, a copy just shares the stored bytes.
- SSE-KMS is not supported.

Costs on the benchmark machine: 1 MiB GETs run at about 2.4 GiB/s instead of 4.4 GiB/s, and
small objects lose under 10%. **Keep the master key safe:** without it, SSE-S3 objects cannot be
read. The key is not stored in the data directory.

Threat model: encryption protects data at rest against someone who can read the disk or backups.
Encrypted files are not bound to a particular object. Someone with *write* access to the data
directory could swap or roll back whole files between objects encrypted under the same key, and
the server would not notice.

## Versioning

`PutBucketVersioning` and `GetBucketVersioning` support `Enabled` and `Suspended`, with S3's
semantics:
- Every write creates a new version, and plain DELETEs add delete markers.
- `versionId` works on GET, HEAD, DELETE, CopyObject/UploadPartCopy sources, tagging, and
  DeleteObjects.
- Deleting a delete marker restores the object.
- A suspended bucket keeps a single `null` version per key.
- `ListObjectVersions` lists every version and delete marker, with key and version-id pagination.

Unversioned buckets pay nothing for this. The latest version of every key stays in the same table as
before, and old versions live in a separate one. Reading or listing current objects never touches
old versions, and a lookup by version id is a single key read. Versioning-enabled buckets keep
every version, so small objects in them are stored as files rather than inline. That keeps the
metadata database from growing without bound.

## Object Lock

Object Lock makes versions write-once (WORM), as on S3:
- Create the bucket with Object Lock (`create_bucket(..., ObjectLockEnabledForBucket=True)`), or
  enable it later on a bucket that already has versioning enabled. Versioning then cannot be
  suspended and Object Lock cannot be turned off.
- **Retention** per version, set on upload (`x-amz-object-lock-mode` and
  `x-amz-object-lock-retain-until-date`), with `PutObjectRetention`, or from the bucket's default
  retention (`PutObjectLockConfiguration` with `Days` or `Years`).
  - `GOVERNANCE`: the version can't be deleted or have its retention shortened, unless the
    request sends `x-amz-bypass-governance-retention: true`.
  - `COMPLIANCE`: nobody can delete it or shorten its retention until the date passes.
- **Legal hold** (`ON`/`OFF`) blocks deletion regardless of retention, until it is removed.
- Retention and legal hold apply to PUT, CopyObject (the copy gets its own settings, not the
  source's), multipart uploads and form uploads, and are returned on GET/HEAD.

Deleting a key without a version id still works: it adds a delete marker, and the protected
versions stay. Lifecycle rules never remove a protected version, and a bucket with versions can't
be deleted. All checks run on the single metadata writer, atomically with the change.

Every authenticated read-write key may bypass GOVERNANCE retention. Anonymous requests never can.
Locks protect data from S3 API clients. Anyone with access to the data directory can still remove
files, so use storage-level protection if that matters.

## Static websites

With `--website-listen` (e.g. `0.0.0.0:8080`), s3rs runs a second, website-only endpoint like S3's
`s3-website` endpoints:
- Configure a bucket with `PutBucketWebsite` (`aws s3 website s3://site --index-document
  index.html --error-document 404.html`).
- Make it publicly readable with a `public-read` ACL or a bucket policy. Only objects that anonymous
  users may read are served.
- The bucket is chosen by the `Host` header. `<bucket>.<website-domain>` works when
  `--website-domain` is set. Otherwise, name the bucket after the host (e.g. a bucket called
  `www.example.com` serves `http://www.example.com`).

Supported: index documents (`/` and `/dir/`, and `/dir` redirects to `/dir/`), error documents
(served with the original 404/403 status), routing rules (`KeyPrefixEquals` /
`HttpErrorCodeReturnedEquals` conditions; `ReplaceKeyPrefixWith`, `ReplaceKeyWith`, `HostName`,
`Protocol` and `HttpRedirectCode` redirects), `RedirectAllRequestsTo`, per-object
`x-amz-website-redirect-location`, ranges and conditional GETs. Errors are HTML pages. The endpoint
accepts only anonymous GET and HEAD, and never lists buckets. Redirects use `https://` when s3rs
serves TLS, and with `--behind-proxy` they use the scheme from `X-Forwarded-Proto`.

## Running in production

[OPERATIONS.md](OPERATIONS.md) has a go-live checklist and covers the rest of running s3rs:
- a hardened systemd unit ([`deploy/s3rs.service`](deploy/s3rs.service)) and its configuration
  template
- sizing, plus Prometheus alert rules ([`deploy/prometheus-alerts.yml`](deploy/prometheus-alerts.yml))
- backup schedules, upgrades and downgrades, and incident runbooks

[SECURITY.md](SECURITY.md) has the threat model and how to report a vulnerability.

## Usage and quotas

The server keeps a running count of each bucket's stored object versions and bytes. It is updated
in the same transaction as every write, so it is always exact and costs no scans. Delete markers
don't count, and noncurrent versions do. Parts of unfinished multipart uploads are counted
separately. With `--metrics-token` set, `/_metrics` exports the counts as
`s3rs_bucket_objects{bucket=...}` and `s3rs_bucket_bytes{bucket=...}`. The console shows them too.

The counters are recomputed at startup after a crash, or after the data directory was used by a
release without usage tracking. `s3rs fsck --repair` also rebuilds them.

Quotas cap a bucket's size and/or object count. Writes that would exceed them fail with
`403 QuotaExceeded`:
- Uploads and parts with a known length are refused before any data is received.
- Bytes in unfinished multipart uploads count towards the byte quota until the upload completes
  or is aborted.
- An overwrite that replaces a stored version (unversioned, or versioning suspended) counts only
  the size difference.

These are s3rs extensions (bucket subresources, signed like any S3 request):

```bash
# usage: <BucketUsage><Objects>…</Objects><Bytes>…</Bytes><MultipartBytes>…</MultipartBytes>
#        [<MaxObjects/MaxBytes>]</BucketUsage>
GET    /photos?usage
# set a quota (0 or a missing element = unlimited)
PUT    /photos?quota      <BucketQuota><MaxBytes>10737418240</MaxBytes><MaxObjects>100000</MaxObjects></BucketQuota>
GET    /photos?quota
DELETE /photos?quota
```

Reading usage needs `s3:GetBucketUsage`, and changing quotas needs `s3:PutBucketQuota`. Keys without
a policy have both (read-only keys only the first). The console's bucket settings include quota
fields.

## Backup and restore

Copying the data directory of a running server doesn't give a usable backup, because the metadata
database changes underneath the copy. s3rs makes consistent backups itself, as a tar archive:

```bash
# A running server (needs --admin-token):
curl -fsS -H "Authorization: Bearer $S3RS_ADMIN_TOKEN" -o backup.tar https://s3.example.com/_admin/backup

# A stopped server:
s3rs backup --data-dir /data -o backup.tar

# Restore: extract into an empty directory and start the server on it.
mkdir /data-restored && tar -xf backup.tar -C /data-restored
s3rs fsck --data-dir /data-restored --deep --encryption-key-file /etc/s3rs.key   # optional
s3rs --data-dir /data-restored ...
```

How it works:
- The archive holds a snapshot of the metadata database, taken from a single read transaction
  without blocking writes, plus exactly the data files that snapshot refers to.
- Data files are immutable. While a backup streams, the server holds back deleting any of them, so
  the archive matches the snapshot however long the download takes. The held-back deletes run
  afterwards.
- The response has an exact `Content-Length`. If the server hits an error midway, it aborts the
  transfer, so a truncated download never looks complete (`curl -f` exits non-zero).
- Only one backup runs at a time. A second request gets `409 BackupInProgress`.
- The backup is written by one background thread.
- If the client stops reading for 120 seconds, the connection is closed and the backup aborted.
  The held-back deletes then run.
- The snapshot needs free space the size of the metadata database, and is refused (`507`) if
  taking it would eat into the free-space reserve.

Encrypted objects stay encrypted in the archive. Restoring them needs the same `--encryption-key`,
and SSE-C objects need their customer keys as before. Treat archives like the data itself: they
include everything stored, including inline object contents, configurations and policies.

CI takes a backup over a deliberately slow connection while other clients overwrite and delete the
objects it contains. It then restores the backup, runs `fsck --deep` and compares every object
(`tests/backup.py`).

## Integrity checks (`s3rs fsck`)

Run `s3rs fsck` while the server is stopped. It refuses to run while the data directory is in
use:

```bash
s3rs fsck --data-dir /data                          # fast: metadata vs. data files
s3rs fsck --data-dir /data --deep --encryption-key-file /etc/s3rs.key
s3rs fsck --data-dir /data --repair                 # remove orphans, rebuild usage counters
```

The fast check confirms:
- Every object version's data (files or inline blobs) exists with exactly the expected size.
- Multipart upload parts exist with the expected size.
- There are no orphaned data files or inline blobs.
- Usage counters match the stored objects and parts.

It also works on a data directory from a release before usage tracking. Its counters are then
reported as missing, and the server computes them on its next start.

`--deep` also reads all data back:
- Each ETag is verified: the MD5 for single-part objects, and the composite `md5-of-part-md5s-N`
  for multipart objects and their copies.
- SSE-S3 objects are decrypted with the given key, which authenticates every 64 KiB chunk.
- SSE-C objects can't be verified without their customer keys and are counted as skipped.

`--repair` only removes orphaned files and inline blobs and rebuilds usage counters. It never
modifies or deletes object data. If some metadata records can't be read, it removes nothing: the
files those records refer to are unknown. The exit status is 0 when everything is consistent, and 1 when it found problems.
CI runs `fsck --deep` on the data left by the full test suite after a graceful shutdown.

## Replication

s3rs can copy a bucket's changes to a bucket on another server: a second s3rs (for example in
another data center), AWS S3, MinIO or any other S3-compatible server. Replication is
asynchronous: writes return as soon as they are stored locally, and are sent to the destination
in the background, normally within a second.

**Targets.** The operator lists the remote servers in a file, one per line (`#` starts a
comment), and passes it with `--replication-targets` (reloaded on `SIGHUP`):

```
# ID  URL                          ACCESS_KEY  SECRET_KEY  [REGION]
dr    https://s3-dr.example.com    AKIA...     ...         us-east-1
```

The credentials are the target's own keys. They decide what replication can write there, so give
them access to the replica buckets only (s3rs: a key limited to those buckets). Only keys that are
not limited to some buckets or by a policy can configure replication.

**Configuration.** Buckets opt in with the standard PutBucketReplication call. A destination is
`arn:s3rs:replication::<TARGET>:<BUCKET>`:

```bash
aws s3api put-bucket-replication --bucket photos --replication-configuration '{
  "Role": "",
  "Rules": [{
    "ID": "dr", "Status": "Enabled", "Priority": 1,
    "Filter": {"Prefix": ""},
    "DeleteMarkerReplication": {"Status": "Enabled"},
    "ExistingObjectReplication": {"Status": "Enabled"},
    "Destination": {"Bucket": "arn:s3rs:replication::dr:photos-replica"}
  }]
}'
```

- **What is replicated:**
  - New and overwritten objects arrive with their content, ETag, content type and other
    headers, user metadata and tags. Multipart objects are uploaded in the same parts, so they
    keep their ETag.
  - Tag changes are replicated too.
  - SSE-S3 objects are decrypted and stored with `x-amz-server-side-encryption: AES256` at the
    destination, which therefore needs SSE-S3 too.
  - SSE-C objects are skipped: the server never has their key.
- **Deletes** are replicated only with `DeleteMarkerReplication` enabled. That isn't possible in
  rules with tag filters.
  - Not replicated, as in S3: deletes of specific versions, and lifecycle expirations (each
    server applies its own lifecycle rules).
- **Existing objects** are copied when `ExistingObjectReplication` is enabled. The copy runs in the
  background and resumes after a restart.
- **Rules** filter by prefix and/or tags. Each destination gets the state of the highest-priority
  rule that matches.
- **Versioned buckets:** the current version of each key is replicated, not its history.
  Versioning is not required.
- **Object Lock** settings are not replicated.
- **Replicas:** writes made by replication carry `x-amz-replication-status: REPLICA`, are stored
  with it, and are never replicated onwards. Two servers can therefore replicate to each other.
  Each one sends only its own clients' changes, so neither ever overwrites newer data with an
  older copy.
  - The destination honors the marker only for keys allowed the `s3:ReplicateObject`,
    `s3:ReplicateDelete` and `s3:ReplicateTags` actions.
  - Keys without a policy have them for the buckets they can use. Keys with a policy need them
    granted explicitly.

**How it works.** Every change to a replicated key is recorded in a queue in the metadata
database, in the same transaction as the change itself, so no change is lost to a crash or a
restart. Several changes to the same key before it is sent collapse into one. A background worker
sends each queued key's current state to its destinations and removes the entry once all of them
have it.
- **Unchanged objects:** a destination that already holds an identical object (same ETag,
  metadata and tags) is not sent it again. This also lets two servers replicate to each other
  without bouncing changes back and forth.
- **Retries:** a key that fails is set aside and retried after a delay that grows with how long
  it has been waiting (up to 5 minutes). Failing keys don't hold up anything else, even
  thousands of them. A target that stops answering is probed every few seconds, and when it comes
  back the whole backlog is sent at once.
- **Several destinations:** if one fails, the others still get the change.

**Tested** with two servers (`tests/replication.py`) and under crashes: SIGKILL of either or both
servers while clients write, overwrite, tag and delete (`tests/replication_chaos.py`). Once the
queue drains, the destination always matches the source exactly.

**Monitoring.** `s3rs_replication_pending` counts queued keys, and `s3rs_replication_lag_seconds`
is the age of the oldest change not yet replicated. `s3rs_replication_total{result}` counts keys
that were replicated, unchanged, skipped (SSE-C) or failed. The log says why keys fail, at most
every 10 seconds.

## Event notifications

s3rs can tell other services when objects are created or removed, in S3's event format.

**Webhooks.** The operator defines the targets, so bucket owners can't make the server call
arbitrary URLs:

```bash
s3rs ... --webhook thumbnails=http://worker.internal:8080/s3-events --webhook-secret "$(openssl rand -hex 16)"
```

Buckets then subscribe with the standard API, using the target's ARN `arn:s3rs:webhook::<id>`:

```python
s3.put_bucket_notification_configuration(Bucket="photos", NotificationConfiguration={"QueueConfigurations": [{
    "Id": "new-images", "QueueArn": "arn:s3rs:webhook::thumbnails",
    "Events": ["s3:ObjectCreated:*"],
    "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": "uploads/"}, {"Name": "suffix", "Value": ".jpg"}]}}}]})
```

How delivery works:
- **Body:** each event is POSTed as `{"Records":[...]}`, the same JSON S3 sends to SQS/SNS/Lambda.
  Object keys are URL-encoded, and the body includes the size, ETag, version id and a sequencer.
- **Signature:** with `--webhook-secret`, the `X-S3rs-Signature: sha256=<HMAC-SHA256 of the body>`
  header lets receivers verify it.
- **Delivery is durable and at least once:**
  - Events are queued on disk, per target.
  - An event is removed from the queue only after the target answered `2xx`.
  - Until then it is retried with backoff (up to a minute), and the events behind it wait. Each
    target therefore gets its events in order, also across outages and restarts.
  - A crash between a delivery and its removal from the queue can deliver an event twice; the
    sequencer identifies duplicates.
  - Writes never wait for deliveries.
- **Full queue:** a target that is down long enough to collect 100,000 events gets no new ones
  until it catches up. Dropped events are counted.
- **Removed targets:** queued events for a target that is no longer configured are dropped at
  startup.
- **Monitoring:**
  - `s3rs_notifications_total{result="delivered|failed|dropped"}` counts outcomes;
  - `s3rs_notifications_pending` counts queued events.

With a `--features tls` build, webhook URLs can be `https://`. Receivers' certificates are verified
against the Mozilla root certificates, plus any CA certificates in `--webhook-ca` (for receivers with
certificates from a private CA). The default build supports `http://` only: point those at services
on a private network (such as `*.railway.internal`).

Supported events:
- `s3:ObjectCreated:*`: `Put`, `Post`, `Copy`, `CompleteMultipartUpload`.
- `s3:ObjectRemoved:*`: `Delete`, `DeleteMarkerCreated`.
- `s3:LifecycleExpiration:*`: `Delete`, `DeleteMarkerCreated`.

**Live streams.** `GET /<bucket>?events=s3:ObjectCreated:*&prefix=...&suffix=...` (or `GET /?events=...`
for all buckets) is MinIO's ListenBucketNotification API. It is a signed request that keeps the
connection open and sends one JSON event per line, plus a space every 10 seconds to keep idle
connections alive. MinIO clients use it directly, e.g. `ListenBucketNotification` in minio-go or
`mc watch`. It needs the `s3:ListenBucketNotification` (or, for all buckets,
`s3:ListenNotification`) permission. Every event is checked against the subscriber's access to
that event's bucket (its bucket limits, its policy and the bucket policy), so a stream for all
buckets only carries events the caller could otherwise see.

Each record's `sequencer` follows the order in which changes were committed, so for a given key the
event with the highest sequencer describes its latest state, even when concurrent writes deliver
events out of order. Deletes that remove nothing (a missing key or version) emit no event. If a
webhook target is removed from the server's configuration, bucket rules that point to it are
skipped with a warning, and the bucket's other rules keep working.

## Browser uploads (POST policy)

`POST /<bucket>` with `multipart/form-data` accepts browser form uploads, including those made with
`generate_presigned_post` from boto3 and the equivalent helpers in other SDKs. Supported:
- SigV4 and SigV2 policy signatures.
- Policy conditions `eq`, `starts-with` and `content-length-range`. Every form field must be
  covered by a condition, as on S3.
- `${filename}` in the key.
- The `success_action_status` (200/201/204) and `success_action_redirect` responses.
- Metadata, `Content-Type` and `tagging` fields.

The file is streamed straight to storage and never buffered in memory. A form without a policy is
only accepted when the bucket allows anonymous `s3:PutObject`. Combine form uploads with CORS for
direct uploads from web apps.

## S3 API coverage

| Area | Operations |
|---|---|
| Buckets | ListBuckets, CreateBucket (with canned ACL), DeleteBucket, HeadBucket, GetBucketLocation, Get/PutBucketVersioning, Get/PutBucketAcl, Get/Put/DeleteBucketPolicy, GetBucketPolicyStatus, Get/Put/DeleteBucketCors, Get/Put/DeleteBucketTagging, Get/Put/DeleteBucketEncryption, Get/PutObjectLockConfiguration, Get/Put/DeleteBucketWebsite, Get/PutBucketNotificationConfiguration, Get/Put/DeleteBucketReplication, Get/PutBucketLogging, ListenBucketNotification (MinIO) |
| Objects | PutObject, GetObject, HeadObject, GetObjectAttributes, DeleteObject, DeleteObjects, CopyObject (COPY/REPLACE for metadata and tags), Get/Put/DeleteObjectTagging, `x-amz-tagging` on upload, GetObjectAcl, Get/PutObjectRetention, Get/PutObjectLegalHold, SSE-S3 and SSE-C on every read/write/copy path |
| Listing | ListObjects (v1), ListObjectsV2, ListObjectVersions (versions and delete markers); prefix, delimiter, pagination, `start-after`, `encoding-type=url` |
| Multipart | CreateMultipartUpload, UploadPart, UploadPartCopy (with ranges), CompleteMultipartUpload, AbortMultipartUpload, ListParts, ListMultipartUploads |
| Lifecycle | Get/Put/DeleteBucketLifecycleConfiguration (expiration, abort incomplete uploads) |
| Forms | POST Object (browser uploads with POST policies) |
| Reads | Single `Range` requests, `partNumber` reads, `If-Match` / `If-None-Match` / `If-Modified-Since` / `If-Unmodified-Since`, `response-*` header overrides |
| Writes | Conditional writes (`If-None-Match: *`, `If-Match`), `Content-MD5`, `x-amz-content-sha256` verification, user metadata (`x-amz-meta-*`) and standard headers |
| Checksums | CRC32, CRC32C, CRC64NVME, SHA1 and SHA256, sent as headers or as aws-chunked trailers. They are verified on upload and returned with `x-amz-checksum-mode: ENABLED`. |
| Auth | SigV4 headers, SigV4 presigned URLs, SigV4 streaming (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]`, `STREAMING-UNSIGNED-PAYLOAD-TRAILER`), SigV2 headers and presigned URLs |
| Transport | HTTP/1.1 keep-alive, HTTP/2 (h2c), path-style and virtual-hosted-style addressing |

Not implemented: SSE-KMS, storage class transitions and SigV4A. These
requests return `NotImplemented` or the matching "not found" configuration error.

## Architecture

```
            ┌──────────────── tokio + hyper (HTTP/1.1, h2c) ────────────────┐
request ──▶ │ SigV4/V2 auth → router → handler                             │
            └──────┬──────────────────────────────┬────────────────────────┘
                   │ bytes (bounded channels)      │ metadata ops
                   ▼                               ▼
      blocking I/O threads                 single writer thread
      hash (MD5 + checksums) + write       group commit → redb (one fsync per batch)
                   │                               │
                   ▼                               ▼
        data/<xx>/<id>  (immutable files)   meta.redb (buckets, objects, inline data, uploads, parts)
```

- **Immutable data files.** Object bytes are written once to a temp file, verified, and renamed into
  `data/<xx>/<id>`. Files are never changed after that. An overwrite writes a new file and swaps the
  metadata atomically, so readers never see a partial object. A garbage-collector thread deletes the
  old file after the metadata commit.
- **Small objects inline.** Objects up to 64 KiB by default are stored in the metadata database. A
  small PUT then needs only a metadata commit, not a file create, an fsync, and a rename.
- **Group commit.** All metadata changes go through one writer thread. It collects the operations
  that are waiting and commits them in a single redb transaction, so many concurrent PUTs share one
  fsync.
- **Multipart without copying.** A completed multipart object is the list of its part files.
  Completing an upload only updates metadata, even for a 5 TB object. Range reads use that list to find
  the right file and offset.
- **Copy without copying.** CopyObject hard-links the source files. It falls back to a real copy only
  when hard links are not supported.
- **Sorted metadata.** Listing walks a B-tree range. A delimiter listing skips past each common prefix
  with one seek, so its cost does not depend on how many keys are under the prefix.
- **Streaming everywhere.** Uploads and downloads move through small bounded channels. Hashing and disk
  I/O happen on blocking threads, so a large transfer never blocks the async runtime, and memory per
  transfer stays at a few MB.

## Performance

These numbers come from a 4-vCPU cloud VM, with the load generator ([oha](https://github.com/hatoo/oha))
running on the same machine. Treat them as rough indications.

| Workload | Result |
|---|---|
| GET 4 KiB object, 64 connections | ~110,000 req/s, p99 1.8 ms |
| HEAD, 64 connections | ~109,000 req/s |
| GET 1 MiB object, 16 connections | ~4,500 req/s (~4.4 GiB/s) |
| PUT 4 KiB, 64 connections, **fsync on** | ~35,000 req/s, p99 4.2 ms |
| PUT 4 KiB, 64 connections, `--no-fsync` | ~50,000 req/s |
| PUT 1 KiB to 200k distinct keys, fsync on | ~27,000 req/s |
| PUT 1 MiB, 16 connections, fsync on / off | ~480 / ~860 req/s |
| ListObjectsV2, 1000 keys per page | ~3,300 pages/s (~3.3M keys/s) |

Server memory use stays around 100–200 MB under load, and most of that is the metadata cache
(`--cache-mb`). Large uploads are limited by MD5, which S3 requires for ETags and which cannot be
parallelized within a single stream.

## Testing

```bash
cargo test                        # unit tests, including the AWS SigV4 test vectors

# end-to-end compatibility suite (needs boto3)
./target/release/s3rs -d /tmp/s3rs-test --access-key testkey --secret-key testsecret &
S3RS_ACCESS_KEY=testkey S3RS_SECRET_KEY=testsecret python3 tests/e2e.py

# MinIO Go SDK (exercises signed aws-chunked uploads)
cd tests/minio-go && S3RS_ACCESS_KEY=testkey S3RS_SECRET_KEY=testsecret go run .
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy, the unit tests, the boto3 suite, an AWS CLI sync
round-trip, the minio-go suite and a Playwright test of the web console (`tests/console.js`) on
every push. It also runs two durability tests:
- `tests/crash.py` SIGKILLs the server repeatedly during concurrent writes. It checks that every
  acknowledged write survives and that `fsck --deep` passes afterwards.
- `tests/diskfull.py` fills a small filesystem through the server (see [Disk space](#disk-space)).

Two fuzzers run as well:
- `cargo test` mutates valid seed inputs for every parser that sees client input or on-disk
  records: XML configurations, policies and JSON, POST policies, aws-chunked bodies, SigV4/SigV2
  headers, ranges, dates, query strings and metadata records. None may panic or abort.
  `S3RS_FUZZ_ITERS=1000000 cargo test --release fuzz` runs longer.
- `tests/fuzz_http.py` sends mutated requests over raw sockets to a server running with
  `--anonymous`, so they reach every handler. It covers odd methods, paths and encodings, every
  subresource, hostile headers and mutated bodies, and fails on any 500 or panic.

A second job builds with `--features tls` and runs the boto3 and minio-go suites over
HTTPS, with an `https://` webhook, using a throwaway CA from `tests/tls/gen-certs.sh`.

## Limitations and notes

- Keys are configured in a file (reloaded on `SIGHUP`), not through an IAM API: there are no
  users, groups or roles to create at runtime, and no STS temporary credentials.
- Each object can be at most 5 GiB on a single PUT. A multipart upload can have up to 10,000 parts of
  5 GiB each, the same limits as S3.
- Only one `s3rs` process can use a data directory at a time.
- Parts of a completed multipart object are numbered 1..N in order, for `GET ?partNumber=` and
  GetObjectAttributes, even if the upload used non-consecutive part numbers (S3 keeps the
  original numbers). Clients and SDKs that upload consecutive parts see no difference.
- GetObjectAttributes needs `s3:GetObject` (or `s3:GetObjectVersion`) as well as
  `s3:GetObjectAttributes`, as in S3.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
s3rs by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
