# Running s3rs in production

This guide covers deploying, monitoring, backing up, upgrading and recovering an s3rs server.
Every option it mentions is documented in the [README](README.md).

## Before going live

- [ ] **Credentials:** a long random secret for the admin key, and separate keys for each
  application. Give applications read-only keys, bucket-limited keys or policy keys
  ([Access control](README.md#access-control)) instead of the admin key.
- [ ] **TLS:** native HTTPS (`--features tls` build, `--tls-cert/--tls-key`), or a TLS-terminating
  proxy with `--behind-proxy`. Without TLS, SigV4 still protects requests from tampering, but
  object contents and presigned URLs travel in clear text.
- [ ] **Encryption at rest:** an SSE-S3 master key (`S3RS_ENCRYPTION_KEY_FILE`), if the disk or its
  backups could fall into the wrong hands. Store the key separately from the data and back it up:
  without it, encrypted objects can't be recovered.
- [ ] **`--metrics-token`:** set it if `/_metrics` is reachable from outside. Per-bucket series are
  only served with a token.
- [ ] **`--admin-token`:** set it to take online backups and manage keys at runtime. Without it the admin API is off.
- [ ] **A dedicated data disk.** The free-space reserve (`--min-free-space`) keeps the server working
  when it fills up. Other software sharing the disk can still fill it.
- [ ] **Backups** are scheduled and a restore has been tried ([below](#backups)).
- [ ] **Monitoring** scrapes `/_metrics` and the alerts are wired up ([below](#monitoring)).
- [ ] **Access logs** (`--access-log json`) go to your log pipeline if you need an audit trail.

## Deploying

### systemd

[`deploy/s3rs.service`](deploy/s3rs.service) is a hardened unit, and
[`deploy/s3rs.env`](deploy/s3rs.env) is its configuration template. Installation steps are at the
top of the unit file.
- The server runs as an unprivileged user with a read-only view of the system. It can write only
  its data directory (`/var/lib/s3rs`), through a syscall filter.
- `systemctl reload s3rs` re-reads the credentials file and the TLS certificate without dropping
  connections.
- `systemctl stop` drains in-flight requests for up to 30 seconds.

### Containers

Release images (`ghcr.io/<owner>/s3rs:<version>`, with `-tls` variants) run as uid 10001 and keep
data in the `/data` volume. Configure them with the same `S3RS_*` environment variables, and mount
secrets as files (`S3RS_ENCRYPTION_KEY_FILE`, `S3RS_CREDENTIALS_FILE`, `S3RS_TLS_CERT`/`KEY`).
Give the container time to drain: `docker stop -t 60`, or `terminationGracePeriodSeconds: 60` on
Kubernetes. Use `GET /_health` for liveness and readiness (an `httpGet` probe, with
`scheme: HTTPS` for native TLS). The images define a Docker `HEALTHCHECK` that runs
`s3rs healthcheck`. Allow for the start after a crash, which scans the data directory: about 1 s
per million objects.

### Sizing

- **Memory:** about 100–200 MB under load, most of it the metadata cache (`--cache-mb`, default
  256). A larger cache helps when there are millions of objects. In a 7-minute soak test (16
  clients of mixed PUT/GET/DELETE/LIST/multipart traffic plus a GET flood, `--cache-mb 64`), memory
  levelled off at about 120 MB, with constant thread and file counts.
- **Scale:** measured with 1.1 million objects in one bucket (1M of 100 bytes and 100k of 20 KB,
  default settings, 4 cores):
  - The metadata database is about 400 MB, roughly 370 bytes per object including the inline data.
  - A listing page of 1000 keys takes 2 ms, with a prefix 3 ms, and with a delimiter (1000 common
    prefixes) 7 ms. Paging through all 1.1M keys takes 3.4 s.
  - A clean restart takes 0.05 s. A restart after SIGKILL takes 1.2 s: it scans for orphaned files
    and recounts usage. `fsck` takes 3.8 s.
  - Memory peaked at 350 MB, with the 256 MiB cache full.
  - With fsync on, 16 clients wrote about 4300 small objects/s; more concurrent clients share each
    commit.
- **Disk:** objects are stored as-is. Encryption adds 16 bytes per 64 KiB plus 73 bytes per
  object. Objects up to
  `--inline-threshold` (64 KiB) live in the metadata database, larger ones in data files. Versioned
  buckets keep every version until lifecycle rules expire them. Leave room for the reserve and the
  ballast file (about 2.5% of the disk).
- **File descriptors:** each open transfer needs a socket and a file. s3rs raises its soft limit to
  the hard limit and derives `--max-connections` from it (the unit sets `LimitNOFILE=65536`).
- **CPU:** small requests are cheap (100k GETs/s on 4 cores). Each upload is hashed (MD5, plus
  SHA-256 for signed payloads) and possibly encrypted (AES-GCM), which costs a few hundred MB/s to
  1 GB/s of throughput per core.
- **fsync:** keep it on (the default). Group commit keeps durable writes cheap. `--no-fsync` makes
  metadata commits durable only about once a second:
  - A crash, a power loss, or a database reopen after a full disk rolls back about the last second
    of acknowledged writes. Each key returns to an earlier, consistent state.
  - A power loss can also leave recently written objects incomplete. `s3rs fsck --deep` finds
    those objects.

## Monitoring

Scrape `/_metrics` (Prometheus text format) and load
[`deploy/prometheus-alerts.yml`](deploy/prometheus-alerts.yml).

| Metric | Watch for |
|---|---|
| `s3rs_disk_free_bytes`, `s3rs_disk_reserve_bytes` | free space approaching the reserve. Below it, uploads fail with `507`. |
| `s3rs_requests_total{method,code}` | a rising `5xx` rate (details are in the server log on stderr) |
| `s3rs_request_duration_seconds` | latency histogram |
| `s3rs_connections`, `s3rs_connections_max` | approaching the connection limit |
| `s3rs_requests_in_flight` | stuck or piling-up requests |
| `s3rs_notifications_total{result}` | `failed`/`dropped` webhook deliveries |
| `s3rs_access_log_dropped_total` | stdout not keeping up with the access log |
| `s3rs_throttled_requests_total` | clients hitting `--rate-limit` / `--rate-limit-anonymous` |
| `s3rs_replication_pending`, `s3rs_replication_lag_seconds` | a growing replication backlog (target down, or writes outpacing it) |
| `s3rs_replication_total{result}` | `failed` replication attempts (the log says why) |
| `s3rs_bucket_objects`, `s3rs_bucket_bytes` | growth per bucket (served only with a metrics token) |
| `s3rs_build_info{version,tls}`, `s3rs_uptime_seconds` | what is running, and unexpected restarts |

Server diagnostics (startup, reloads, recovery, lifecycle, errors) go to stderr. Access logs go to
stdout. Every response carries `x-amz-request-id`, which matches `request_id` in the access log.

## Backups

Back up with `GET /_admin/backup` while the server runs
([Backup and restore](README.md#backup-and-restore)). For example, nightly from cron or a systemd
timer, keeping two weeks:

```bash
#!/bin/sh
set -eu
out=/backups/s3rs-$(date +%Y%m%d-%H%M).tar
curl -fsS -H "Authorization: Bearer $S3RS_ADMIN_TOKEN" -o "$out.partial" http://127.0.0.1:9000/_admin/backup
mv "$out.partial" "$out"
find /backups -name 's3rs-*.tar' -mtime +14 -delete
```

- `curl -f` exits non-zero if the server aborts the backup. The archive length is checked against
  `Content-Length`.
- Keep backups on a different disk, and preferably a different machine. Back up the encryption key
  separately.
- **Test restores.** Extract an archive into an empty directory, run
  `s3rs fsck --deep --data-dir <dir>` (with the encryption key), then start a server on it and read
  a few objects.

A backup holds the state at the moment it started. Writes made during the backup are not in it.

## Upgrading

1. Read the release notes.
2. Take a backup.
3. Replace the binary (or image) and restart. A graceful stop drains in-flight requests, and the
   new version starts in seconds.

- New releases read data directories written by older ones. Some new features compute data on
  their first start: for example, usage counters were computed from existing objects when they
  were introduced. The start log reports this.
- **Downgrading** works as long as the older release understands the data directory. The data
  directory records a format version, raised only by changes an older release would misread or
  mishandle (the release notes say so). A release refuses to start, and `s3rs fsck` and
  `s3rs backup` refuse to run, on a data directory with a newer format than its own (`the data
  directory has format version N, which only a newer release of s3rs understands`); restore the
  backup taken before the upgrade to go back. Within one format version, individual records also
  carry a version, and an older release refuses a record it doesn't know instead of misreading
  it. After running an older release, the next start of a newer one recomputes the counters that
  the older release didn't maintain.
- Upgrades are tested: `tests/upgrade.py OLD NEW` writes every kind of data with an older binary
  (objects of all sizes, metadata, multipart uploads in progress, versions, delete markers, tags,
  SSE-S3 and SSE-C) and checks that the newer one reads it back exactly, keeps working on it and
  passes `fsck --deep`.
- `s3rs fsck` runs on a stopped server and checks a data directory after any upgrade or incident.

## Incidents

| Symptom | What to do |
|---|---|
| Uploads fail with `507 StorageFull` | The disk is below the reserve. Delete objects (deletes always work), shorten lifecycle rules, abort stale multipart uploads (their parts count too), or grow the disk. Uploads resume on their own. A backup that is streaming holds back the deletion of data files until it finishes. |
| `disk full: released the ballast file` in the log | The disk filled up despite the reserve, usually because another process wrote to it. Free space. The ballast is recreated automatically. |
| The server crashed or was killed | Just start it again. The next start finds no clean-shutdown marker, scans for orphaned data files and recomputes usage counters. Acknowledged writes are never lost (see `tests/crash.py`). |
| Suspected corruption (bad disk, restored from a filesystem snapshot) | Stop the server and run `s3rs fsck --deep --encryption-key-file …`. `--repair` removes orphaned files and rebuilds counters. It never deletes object data, and it does nothing at all if some metadata can't be read. |
| A key or certificate must be revoked | Edit the credentials file or replace the certificate, then `systemctl reload s3rs` (SIGHUP). If the reload fails, the old keys and certificate stay in use and the log says so loudly. |
| Replication lag grows | The log names the failing target and the reason. `unreachable` or a connection error means the target is down or blocked: changes stay queued on disk and are sent when it is back. `403` means the target's credentials can't write to the destination bucket. `404 NoSuchBucket` means the destination bucket doesn't exist. Fix the targets file and `systemctl reload s3rs`. |
| Webhook deliveries fail | Check `s3rs_notifications_total` and the log. While a target is down, events get one attempt each and are then dropped. Events are not queued on disk. |
| Many slow clients, connections at the limit | Slow clients don't tie up threads, but each holds a connection. Raise `LimitNOFILE` and `--max-connections`, or put a proxy in front. |
