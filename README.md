# s3rs

A fast, lightweight, S3-compatible object storage server written in pure Rust.

- **Single static binary** (~2.6 MB), no runtime dependencies, no C code in the dependency tree.
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
# s3rs listening on http://0.0.0.0:9000 (data: ./data, region: us-east-1, auth: sigv4, fsync: true)
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

### Docker

```bash
docker build -t s3rs .
docker run -p 9000:9000 -v $PWD/data:/data -e S3RS_ACCESS_KEY=mykey -e S3RS_SECRET_KEY=mysecret s3rs
```

## Configuration

Each flag can also be set with the environment variable shown.

| Flag | Env | Default | |
|---|---|---|---|
| `-l, --listen` | `S3RS_LISTEN` | `0.0.0.0:9000` | Listen address |
| `-d, --data-dir` | `S3RS_DATA_DIR` | `./data` | Storage directory |
| `--access-key` | `S3RS_ACCESS_KEY` | | Access key ID |
| `--secret-key` | `S3RS_SECRET_KEY` | | Secret access key |
| `--anonymous` | | off | Turns off authentication. Use it only on trusted networks. |
| `--region` | `S3RS_REGION` | `us-east-1` | Region reported to clients |
| `--domain` | `S3RS_DOMAIN` | | Turns on virtual-hosted-style requests (`<bucket>.<domain>`) |
| `--inline-threshold` | `S3RS_INLINE_THRESHOLD` | `65536` | Objects up to this many bytes are stored inside the metadata DB |
| `--cache-mb` | `S3RS_CACHE_MB` | `256` | Metadata cache size |
| `--no-fsync` | | off | Skips fsync. Faster, but a power loss can lose up to ~1s of acknowledged writes. |
| `-v, --verbose` | | off | Logs every request |

The server refuses to start without credentials unless you pass `--anonymous`. `GET /_health` returns
`200 ok` without authentication.

## S3 API coverage

| Area | Operations |
|---|---|
| Buckets | ListBuckets, CreateBucket, DeleteBucket, HeadBucket, GetBucketLocation, GetBucketVersioning, GetBucketAcl/PutBucketAcl (fixed owner-only ACL) |
| Objects | PutObject, GetObject, HeadObject, DeleteObject, DeleteObjects, CopyObject (COPY/REPLACE metadata), GetObjectAcl, GetObjectTagging (empty) |
| Listing | ListObjects (v1), ListObjectsV2, ListObjectVersions (one `null` version per key); prefix, delimiter, pagination, `start-after`, `encoding-type=url` |
| Multipart | CreateMultipartUpload, UploadPart, UploadPartCopy (with ranges), CompleteMultipartUpload, AbortMultipartUpload, ListParts, ListMultipartUploads |
| Reads | Single `Range` requests, `partNumber` reads, `If-Match` / `If-None-Match` / `If-Modified-Since` / `If-Unmodified-Since`, `response-*` header overrides |
| Writes | Conditional writes (`If-None-Match: *`, `If-Match`), `Content-MD5`, `x-amz-content-sha256` verification, user metadata (`x-amz-meta-*`) and standard headers |
| Checksums | CRC32, CRC32C, CRC64NVME, SHA1 and SHA256, sent as headers or as aws-chunked trailers. They are verified on upload and returned with `x-amz-checksum-mode: ENABLED`. |
| Auth | SigV4 headers, SigV4 presigned URLs, SigV4 streaming (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]`, `STREAMING-UNSIGNED-PAYLOAD-TRAILER`), SigV2 headers and presigned URLs |
| Transport | HTTP/1.1 keep-alive, HTTP/2 (h2c), path-style and virtual-hosted-style addressing |

Not implemented: versioning, bucket policies/IAM (one credential, full access), server-side encryption,
object lock, lifecycle rules, tagging writes, CORS, website hosting, and SigV4A. These requests return
`NotImplemented` or the matching "not found" configuration error.

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
```

## Limitations and notes

- There is one set of credentials, and it has full access to everything.
- If the server crashes between renaming a data file into place and committing its metadata, that
  file is left behind as an orphan. It wastes space but cannot be reached.
- Each object can be at most 5 GiB on a single PUT. A multipart upload can have up to 10,000 parts of
  5 GiB each, the same limits as S3.
- Only one `s3rs` process can use a data directory at a time.
