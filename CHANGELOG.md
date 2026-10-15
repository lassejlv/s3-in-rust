# Changelog

## 0.1.0 (unreleased)

First release.

**Storage**
- A single binary with no runtime dependencies. Metadata is in redb, with group-committed
  durable writes, and small objects are stored inline.
- Objects larger than that are immutable data files. A crash never loses an acknowledged write:
  the next start removes orphaned files and recomputes usage counters.
- Versioning (enabled and suspended), lifecycle rules (expiration, noncurrent versions, incomplete
  uploads) and Object Lock (governance and compliance retention, legal holds).
- Server-side encryption with SSE-S3 (master key) and SSE-C, using chunked AES-256-GCM.
- Per-bucket usage accounting and quotas, including bytes in unfinished multipart uploads.
- `s3rs fsck` checks a data directory, deeply with `--deep`, and `--repair` fixes it.
- Consistent online backups (`GET /_admin/backup`) and offline backups (`s3rs backup`) as tar
  archives.
- Bucket replication to other S3-compatible servers (PutBucketReplication):
  - asynchronous, from a durable queue written with each change;
  - prefix and tag filters, delete replication, and copying of existing objects;
  - retries with backoff, and two-way replication that settles instead of looping;
  - backlog and lag metrics.
- Full-disk safety: a free-space reserve (507 StorageFull), a ballast file, and in-place recovery
  of the metadata database.
- The data directory records its format version: a release refuses to open data written in a
  newer format than it understands, rather than misreading it.

**S3 API**
- Buckets, objects, multipart uploads, copies, listings (v1, v2, versions), tagging, ACLs (canned),
  bucket policies, CORS, website hosting, notifications, ranges, conditional requests, checksums
  (CRC32/CRC32C/CRC64NVME/SHA1/SHA256, also for multipart uploads as COMPOSITE or FULL_OBJECT
  checksums, with per-part checksums), POST uploads, GetObjectAttributes.
- CompleteMultipartUpload is idempotent: a client retrying after a lost response gets the same
  result.
- Authentication: SigV4 (headers, presigned URLs, streaming and trailers) and SigV2.

**Access control**
- Several access keys from a credentials file (reloaded on SIGHUP): read-only keys,
  bucket-limited keys, and IAM-style policies per key or bucket (conditions, variables, explicit
  Deny).
- Keys can also be created, listed and revoked at runtime through the admin API
  (`/_admin/keys`).

**Operations**
- Web console at `/_console/`.
- Per-bucket server access logs in S3's format (PutBucketLogging), written to a target bucket.
- Prometheus metrics, JSON access logs, event notifications (webhooks and live streams). Webhook
  events are queued on disk with the write they describe and delivered in order, at least once,
  across outages and restarts. A receiver's `4xx` drops the event instead of blocking the queue.
- `/_health` checks that the metadata database and its writer respond. `s3rs healthcheck` and a
  Docker `HEALTHCHECK` use it.
- Native HTTPS with certificate reload, as the optional `tls` build feature.
- Idle timeouts, a connection limit, and slow clients that never hold threads.
- Optional request rate limits per access key and per client address (`503 SlowDown`).
- Release binaries for Linux x86_64 and arm64, container images, a hardened systemd unit and
  Prometheus alert rules.

**Testing**
- Unit tests, including AWS SigV4 test vectors and parser fuzzing.
- Compatibility suites: boto3, aws-cli, minio-go and a Playwright console test, all also over HTTPS.
- A SIGKILL crash-consistency test, a disk-full test, a backup/restore test, an upgrade test
  (data written by older builds), a two-server replication test and HTTP-level fuzzing, all in CI.
