# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting
(**Security → Report a vulnerability** on the repository), not in a public issue. Include the
version (`s3rs --version`), the configuration involved and a reproduction if you have one.

Fixes go into the latest release. There are no long-term support branches.

## Threat model

s3rs is a single-node server meant to be exposed to untrusted networks. It defends against
clients that are anonymous, that hold valid keys with limited permissions, or that are slow or
malicious. It does not defend against someone who controls the host.

**In scope:**
- **Authentication:** every request is authenticated with SigV4 (headers, presigned URLs,
  streaming chunk signatures) or SigV2, unless a bucket policy or canned ACL allows anonymous
  access. Signatures are compared in constant time. Presigned URLs expire, and request dates
  outside a 15-minute skew are refused.
- **Authorization:** read-only keys, bucket-scoped keys and IAM-style policies are enforced on
  every operation, including the source of copies and part copies, listings, versions,
  notifications and the console API. `aws:SecureTransport` lets a policy require HTTPS.
- **Integrity:**
  - Signed payloads, `Content-MD5` and the `x-amz-checksum-*` checksums are verified before an
    upload commits. A failed upload leaves nothing behind.
  - A crash never loses an acknowledged write.
  - `s3rs fsck --deep` re-verifies stored data.
- **Confidentiality at rest (optional):**
  - SSE-S3 and SSE-C use AES-256-GCM with a per-object data key. SSE-C keys are never stored.
  - Encryption protects against someone who can read the disk or the backups. It does not
    protect against someone who can write to them (see [Encryption at rest](README.md#encryption-at-rest)).
- **Resource exhaustion by one client:**
  - Request headers, bodies and XML documents are size-limited.
  - Idle and slow connections are closed: header, body-rate and write-stall timeouts.
  - The number of connections is capped.
  - The access log queue is bounded.
  - A full disk refuses writes (507) but keeps serving reads and deletes.
- **Replication** writes to other servers with credentials the operator puts in the targets
  file. Only keys that are not limited to some buckets or by a policy can configure it, and the
  target credentials should be limited to the replica buckets.
- **Operator endpoints:** `/_metrics` can require a token, and the admin API (`/_admin/backup`,
  `/_admin/keys`) is off unless `--admin-token` is set. The admin token can read every object (via
  backups) and create keys, so treat it like the root key. Keys created through the API are stored
  in the metadata database, so backups contain their secrets. Empty tokens and the `change-me` placeholders are refused at startup.
  Wrong admin tokens are limited to about one per second per client address after a burst of ten
  (then `503 SlowDown`, also for the right token).
- **STS sessions** can never do more than the key they came from, and stop working when it is
  revoked or expires. Their tokens are signed with a random key kept in the metadata database
  (so backups contain it): anyone with that database can mint sessions for existing keys, just
  as they can read the keys' secrets.
- **Public buckets:** `--block-public-access` makes sure no bucket can be made public by mistake
  (public ACLs and public bucket policies are refused, and existing ones have no effect).
- **Secrets in logs:** access logs redact signatures, credentials and tokens in query strings.

**Out of scope:**
- **Network attackers when TLS is off:** run s3rs behind TLS (native `--features tls` or a
  proxy). Over plain HTTP, signatures stop request tampering but not eavesdropping.
- **Anyone with access to the host, the data directory or the master key file:** root, the s3rs
  user, or someone with backup storage write access.
- **Distributed denial of service:** many clients together can exhaust bandwidth or connections.
  Put a load balancer or rate limiter in front if this matters.
- **Availability beyond one machine:** a single server is a single point of failure.
  [Replication](README.md#replication) keeps an asynchronous copy of chosen buckets on another
  server. A failover is manual, and the copy can miss the last changes before a failure. Use
  backups too (see [OPERATIONS.md](OPERATIONS.md#backups)).

## Hardening

The go-live checklist in [OPERATIONS.md](OPERATIONS.md#before-going-live) and the systemd unit
in `deploy/s3rs.service` cover the recommended setup:
- an unprivileged user, a read-only system and a syscall filter;
- TLS;
- separate least-privilege keys per application;
- a metrics token;
- encrypted backups.

Testing includes:
- AWS SigV4 test vectors;
- policy evaluation tests;
- fuzzing of every parser (`src/fuzz.rs`) and of raw HTTP requests (`tests/fuzz_http.py`);
- crash, disk-full and upgrade tests, all in CI.
