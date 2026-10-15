//! Storage engine.
//!
//! * Object bytes live in immutable data files (`data/<xx>/<id>`) or, for small objects, inline
//!   in the metadata database. Files are never modified after they are written, so overwrites,
//!   copies (hard links) and multipart completion never rewrite data.
//! * All metadata lives in a single redb database. Reads run concurrently on any thread; all
//!   mutations go through one writer thread that group-commits batches of operations so a burst
//!   of small PUTs costs one fsync instead of one each.

pub mod backup;
pub mod fsck;
pub mod meta;
pub mod space;

use crate::error::{S3Error, S3Result, err};
use crate::lock;
use crate::util::{self, now_ms};
use bytes::Bytes;
use meta::{ChecksumAlgo, ObjectMeta, ObjectSummary, PartMeta, Storage, UploadMeta};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const BUCKETS: TableDefinition<&str, u64> = TableDefinition::new("buckets");
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
const INLINE: TableDefinition<u128, &[u8]> = TableDefinition::new("inline");
const UPLOADS: TableDefinition<u128, &[u8]> = TableDefinition::new("uploads");
const PARTS: TableDefinition<(u128, u32), &[u8]> = TableDefinition::new("parts");
/// Per-bucket configuration documents: (bucket, kind) -> raw document.
const CONFIG: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("bucket_config");

/// Kinds of bucket configuration stored in `CONFIG`.
pub const CONFIG_KINDS: &[&str] = &[
    "acl",
    "policy",
    "cors",
    "tagging",
    "lifecycle",
    "versioning",
    "encryption",
    "object-lock",
    "website",
    "notification",
    "quota",
    "replication",
    "logging",
    "public-access-block",
    "ownership",
    // Where the backfill of a new replication configuration has got to (see Op::ReplBackfill).
    "replication-backfill",
];
/// Per-bucket usage: bucket -> (stored object versions, bytes). Delete markers don't count.
const USAGE: TableDefinition<&str, (u64, u64)> = TableDefinition::new("usage");
/// Small server-wide state values (e.g. the usage bookkeeping version).
const STATE: TableDefinition<&str, u64> = TableDefinition::new("state");

/// Version of the data directory format, stored in STATE as "format". Raise it with any change
/// that an older release would misread or mishandle (say, a new table whose rules it would not
/// enforce, or a record it would decode wrongly); changes that older releases can safely ignore
/// don't need it. A release refuses to open a data directory with a newer format than its own
/// instead of serving wrong data or dropping what it doesn't know.
pub(crate) const FORMAT: u64 = 1;

/// Whether this release can open a data directory whose stored format is `stored`.
pub(crate) fn check_format(stored: Option<u64>) -> Result<(), String> {
    match stored {
        Some(v) if v > FORMAT => Err(format!(
            "the data directory has format version {v}, which only a newer release of s3rs understands \
             (this release reads version {FORMAT} and older)"
        )),
        _ => Ok(()),
    }
}

/// `check_format` for tools that open the database read-only (fsck, offline backup).
pub(crate) fn check_format_read(txn: &redb::ReadTransaction) -> Result<(), String> {
    let stored = match txn.open_table(STATE) {
        Ok(t) => t.get("format").map_err(|e| e.to_string())?.map(|v| v.value()),
        Err(redb::TableError::TableDoesNotExist(_)) => None,
        Err(e) => return Err(e.to_string()),
    };
    check_format(stored)
}
/// Per-bucket bytes held by multipart upload parts that are not part of an object yet.
const PART_BYTES: TableDefinition<&str, u64> = TableDefinition::new("part_bytes");
/// Keys waiting to be replicated: bucket \0 key -> (sequence number of the latest change,
/// time in ms of the oldest change not yet replicated). Written in the same transaction as the
/// change, so a crash never loses one; see crate::replication.
const REPL: TableDefinition<&[u8], (u64, u64)> = TableDefinition::new("replication_queue");
/// Replication keys that failed and wait to be retried: retry time (ms, big-endian) + queue key
/// -> (sequence number, time of the oldest change not yet replicated). They go back to REPL when
/// their time comes (Op::ReplRequeue).
const REPL_WAIT: TableDefinition<&[u8], (u64, u64)> = TableDefinition::new("replication_wait");
/// Event notifications waiting to be delivered: webhook target id \0 sequence number (u64,
/// big-endian, so each target's events are in order) -> the request body (see crate::events).
const EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("event_queue");
/// Access keys created through the admin API: access key -> record (see crate::keys).
const KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("access_keys");
const USAGE_VERSION: u64 = 2;
/// Contents of the clean-shutdown marker. Older releases wrote an empty marker without
/// maintaining usage, so any other content (or none) makes the next start recompute usage.
const CLEAN_TAG: &[u8] = b"usage-v2\n";

/// A bucket quota; 0 means unlimited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Quota {
    pub max_objects: u64,
    pub max_bytes: u64,
}

impl Quota {
    pub fn encode(self) -> Vec<u8> {
        let mut v = self.max_objects.to_le_bytes().to_vec();
        v.extend_from_slice(&self.max_bytes.to_le_bytes());
        v
    }
    pub fn decode(v: &[u8]) -> Option<Quota> {
        let (a, b) = (v.get(..8)?, v.get(8..16)?);
        Some(Quota { max_objects: u64::from_le_bytes(a.try_into().ok()?), max_bytes: u64::from_le_bytes(b.try_into().ok()?) })
    }
}

pub fn quota_exceeded() -> S3Error {
    S3Error::new("QuotaExceeded", hyper::StatusCode::FORBIDDEN, "The bucket's quota does not allow this upload.")
}
/// Noncurrent object versions and delete markers: `bucket \0 key \0 (u64::MAX - seq)` -> meta.
/// Keys sort newest-first within an object. The current version of a key always lives in
/// OBJECTS (if it is not a delete marker), so unversioned reads never touch this table.
const VERSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("versions");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Versioning {
    #[default]
    Unversioned,
    Enabled,
    Suspended,
}

impl Versioning {
    pub fn parse(v: Option<&[u8]>) -> Self {
        match v {
            Some(b"Enabled") => Versioning::Enabled,
            Some(b"Suspended") => Versioning::Suspended,
            _ => Versioning::Unversioned,
        }
    }
}

/// Why the lifecycle sweeper wants a noncurrent entry removed.
#[derive(Debug, Clone, Copy)]
pub enum PurgeRule {
    /// The entry became noncurrent at or before this unix time (seconds).
    NoncurrentBefore(u64),
    /// The entry is a delete marker with no other versions left.
    LoneDeleteMarker,
}

/// Result of deleting a key or a specific version.
#[derive(Debug, Clone, Default)]
pub struct DeleteOutcome {
    /// Version id that was removed, or of the delete marker that was created.
    pub version_id: Option<String>,
    pub delete_marker: bool,
    /// Something was actually removed or a delete marker was created (deleting a missing key
    /// or version succeeds without changing anything).
    pub removed: bool,
    /// Commit order of the change (for event sequencers); 0 when nothing changed.
    pub seq: u64,
}

/// The next write sequence number (monotonic across the whole store).
fn next_seq(last: &mut u64) -> u64 {
    *last = (*last + 1).max(now_ms() << 20);
    *last
}

fn ver_prefix(bucket: &str, key: &str) -> Vec<u8> {
    let mut k = obj_key(bucket, key);
    k.push(0);
    k
}

fn ver_key(bucket: &str, key: &str, seq: u64) -> Vec<u8> {
    let mut k = ver_prefix(bucket, key);
    k.extend_from_slice(&(u64::MAX - seq).to_be_bytes());
    k
}

/// Object keys may not contain NUL: it separates the key from the sequence number in
/// VERSIONS keys, so a NUL would let one key's range cover another key's versions.
pub fn check_key_chars(key: &str) -> S3Result<()> {
    if key.contains('\0') {
        return Err(err::InvalidArgument().with_message("Object keys may not contain NUL characters"));
    }
    Ok(())
}

/// Version ids are `<seq as 16 hex><16 random hex>`, so a lookup by id needs no index.
fn new_version_id(seq: u64) -> String {
    format!("{seq:016x}{:016x}", util::new_id() as u64)
}

/// The sequence number encoded in a version id (`None` for "null" or malformed ids).
pub fn version_seq(vid: &str) -> Option<u64> {
    if vid.len() != 32 || !vid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(&vid[..16], 16).ok()
}

/// Validate a client-supplied version id: "null" or one of ours.
pub fn valid_version_id(vid: &str) -> bool {
    vid == "null" || version_seq(vid).is_some()
}

pub const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
const MAX_BATCH: usize = 1024;

/// redb errors are internal errors, except a full disk, which clients should see as such.
macro_rules! redb_from {
    ($($t:ty),*) => {$(
        impl From<$t> for S3Error {
            fn from(e: $t) -> Self {
                match redb::Error::from(e) {
                    redb::Error::Io(io) => S3Error::from(io),
                    e => S3Error::internal(e),
                }
            }
        }
    )*};
}
redb_from!(redb::Error, redb::DatabaseError, redb::TransactionError, redb::TableError, redb::StorageError, redb::CommitError);

pub struct StoreConfig {
    pub root: PathBuf,
    pub fsync: bool,
    pub inline_threshold: usize,
    pub cache_bytes: usize,
    /// Free space (bytes) to keep on the data filesystem; None picks a default.
    pub min_free: Option<u64>,
}

pub struct Store {
    root: PathBuf,
    pub fsync: bool,
    pub inline_threshold: usize,
    db: Arc<DbCell>,
    writer: mpsc::Sender<Job>,
    deleter: mpsc::Sender<Gc>,
    /// Free-space reserve for uploads.
    pub space: Arc<space::Space>,
    /// While non-zero (a backup is streaming), data files are not deleted.
    gc_paused: Arc<std::sync::atomic::AtomicUsize>,
    /// Signalled when a commit added keys to the replication queue.
    pub repl_wake: Arc<tokio::sync::Notify>,
    /// Counts commits that queued event notifications (delivery tasks watch it).
    pub events_committed: tokio::sync::watch::Sender<u64>,
}

/// A key waiting to be replicated (see crate::replication).
#[derive(Debug, Clone)]
pub struct ReplEntry {
    /// The queue key (bucket \0 key), for resuming a scan.
    pub raw: Vec<u8>,
    pub bucket: String,
    pub key: String,
    pub seq: u64,
    /// When the oldest change not yet replicated was made.
    pub since_ms: u64,
}

/// A backup in progress: the plan, its snapshot file, and a hold on data file deletion.
pub struct Backup {
    pub plan: backup::Plan,
    _snapshot: backup::SnapshotFile,
    _pause: GcPause,
}

struct GcPause(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for GcPause {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The metadata database. If an I/O error (typically a full disk) poisons it, the writer
/// reopens it in place, so the server recovers without a restart once the cause is gone.
struct DbCell {
    path: PathBuf,
    cache_bytes: usize,
    db: std::sync::RwLock<Option<Arc<Database>>>,
    /// Set once the database was reopened: commits that were not yet durable are lost, so
    /// their new data files are orphans for the next start's recovery scan.
    reopened: std::sync::atomic::AtomicBool,
}

impl DbCell {
    fn get(&self) -> S3Result<Arc<Database>> {
        self.db.read().unwrap_or_else(|e| e.into_inner()).clone().ok_or_else(|| {
            S3Error::new(
                "ServiceUnavailable",
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "The metadata database is being reopened after an I/O error. Please retry.",
            )
        })
    }

    /// Close and reopen the database. The handle is taken out first, so requests fail fast with
    /// a retryable 503 meanwhile instead of blocking; then this waits (without holding the lock)
    /// for in-flight reads that still use the old handle.
    fn reopen(&self) -> S3Result<()> {
        let old = self.db.write().unwrap_or_else(|e| e.into_inner()).take();
        self.reopened.store(true, std::sync::atomic::Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(30);
        if let Some(mut old) = old {
            loop {
                match Arc::try_unwrap(old) {
                    Ok(db) => {
                        drop(db);
                        break;
                    }
                    Err(still_shared) if Instant::now() < deadline => {
                        old = still_shared;
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(still_shared) => {
                        *self.db.write().unwrap_or_else(|e| e.into_inner()) = Some(still_shared);
                        return Err(S3Error::internal("cannot reopen the metadata database: still in use"));
                    }
                }
            }
        }
        // Read transactions that outlive their handle keep the file locked for a moment.
        loop {
            match Database::builder().set_cache_size(self.cache_bytes).create(&self.path) {
                Ok(db) => {
                    *self.db.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(db));
                    return Ok(());
                }
                Err(redb::DatabaseError::DatabaseAlreadyOpen) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                // Left closed; the next write tries again.
                Err(e) => return Err(e.into()),
            }
        }
    }
}

/// Has an earlier I/O error left the database unusable until it is reopened?
fn poisoned(db: &Database) -> bool {
    match db.begin_write() {
        Ok(txn) => {
            let _ = txn.abort();
            false
        }
        Err(e) => matches!(redb::Error::from(e), redb::Error::PreviousIo),
    }
}

/// What an upload is for (see `Store::quota_allows`).
pub enum Incoming<'a> {
    Object(&'a str),
    Part { upload: u128, part: u32 },
}

/// Work for the file deletion thread.
enum Gc {
    Remove(Vec<u128>),
    /// Reply once every earlier removal is done.
    Sync(mpsc::Sender<()>),
}

/// Conditions on a delete (`If-Match`, and S3's `x-amz-if-match-size` and
/// `x-amz-if-match-last-modified-time`): the delete fails with 412 unless the object or
/// version it removes matches them. Deleting something that doesn't exist still succeeds.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DeleteCond {
    pub etag: Option<String>,
    pub size: Option<u64>,
    /// Unix seconds.
    pub mtime: Option<u64>,
}

impl DeleteCond {
    fn check(&self, m: &ObjectMeta) -> S3Result<()> {
        let etag_ok = self.etag.as_ref().is_none_or(|e| e.trim() == "*" || norm_etag(e) == norm_etag(&m.etag));
        let size_ok = self.size.is_none_or(|s| s == m.size);
        let mtime_ok = self.mtime.is_none_or(|t| t == m.mtime_ms / 1000);
        if etag_ok && size_ok && mtime_ok { Ok(()) } else { Err(err::PreconditionFailed()) }
    }
}

#[derive(Debug, Clone)]
pub enum WriteCond {
    /// `If-None-Match: *` — only create.
    NotExists,
    /// `If-Match: "etag"` — only overwrite this version.
    Matches(String),
    /// `If-None-Match: "etag"[, "etag"...]` — don't overwrite these versions.
    NotMatches(String),
    /// Several conditions (`If-Match` and `If-None-Match` together), all of which must hold.
    All(Vec<WriteCond>),
}

/// Builds the event queue rows (key, body) for an operation's result. It runs inside the
/// operation's own transaction, so the events are committed together with the change they
/// describe, and their queue keys follow commit order.
pub type EventRows = Arc<dyn Fn(&OpOut) -> Vec<(Vec<u8>, Vec<u8>)> + Send + Sync>;

#[derive(Clone)]
pub enum Op {
    /// `op`, plus the event notifications for its result.
    WithEvents(Box<Op>, EventRows),
    CreateBucket(String),
    DeleteBucket(String),
    PutObject {
        bucket: String,
        key: String,
        meta: ObjectMeta,
        inline: Option<Bytes>,
        cond: Option<WriteCond>,
    },
    /// Delete keys (current version, possibly creating delete markers) or specific versions.
    /// `bypass` lets GOVERNANCE-mode retention be overridden.
    DeleteObjects {
        bucket: String,
        items: Vec<(String, Option<String>)>,
        /// Conditions per item (none when shorter than `items`).
        conds: Vec<Option<DeleteCond>>,
        bypass: bool,
        /// Made by replication from another server: not replicated again.
        replica: bool,
    },
    CreateUpload {
        id: u128,
        meta: UploadMeta,
    },
    PutPart {
        upload: u128,
        bucket: String,
        key: String,
        part: u32,
        meta: PartMeta,
    },
    Complete {
        bucket: String,
        key: String,
        upload: u128,
        /// (part number, ETag, checksum the client listed for it).
        parts: Vec<(u32, String, Option<String>)>,
        /// The whole object's checksum, if the client sent one.
        checksum: Option<(ChecksumAlgo, String)>,
        cond: Option<WriteCond>,
    },
    Abort {
        bucket: String,
        key: String,
        upload: u128,
    },
    SetBucketConfig {
        bucket: String,
        kind: &'static str,
        value: Option<Vec<u8>>,
    },
    SetObjectTags {
        bucket: String,
        key: String,
        version: Option<String>,
        tags: Vec<(String, String)>,
        /// Made by replication from another server: not replicated again.
        replica: bool,
    },
    /// Change a version's Object Lock retention (`Some(None)` removes it) and/or legal hold.
    SetObjectLock {
        bucket: String,
        key: String,
        version: Option<String>,
        retention: Option<Option<lock::Retention>>,
        legal_hold: Option<bool>,
        bypass: bool,
    },
    /// Lifecycle: permanently remove noncurrent entries (key, seq, rule). Each item is
    /// re-checked against the current state, so concurrent writes never cause early deletion.
    PurgeVersions {
        bucket: String,
        items: Vec<(String, u64, PurgeRule)>,
    },
    /// Lifecycle expiration: delete each (key, mtime_ms) only if the object still has that
    /// mtime, so an object overwritten after the sweeper looked at it is left alone.
    Expire {
        bucket: String,
        items: Vec<(String, u64)>,
    },
    /// Remove a replication queue entry if it still has sequence number `seq` (a newer change
    /// keeps it queued).
    ReplDone {
        bucket: String,
        key: String,
        seq: u64,
    },
    /// A replication attempt for a key failed: unless the key changed meanwhile, move it from the
    /// queue to the waiting table until `retry_ms`.
    ReplFailed {
        bucket: String,
        key: String,
        seq: u64,
        retry_ms: u64,
    },
    /// Move up to `limit` waiting keys whose retry time is before `before_ms` back to the queue.
    /// Returns `OpOut::More(true)` while more are due.
    ReplRequeue {
        before_ms: u64,
        limit: usize,
    },
    /// Queue up to `limit` existing objects of a bucket for replication, continuing from the
    /// bucket's "replication-backfill" cursor (empty: from the start) and advancing it, or
    /// removing it once the whole bucket is queued. Returns `OpOut::More(true)` while objects
    /// remain.
    ReplBackfill {
        bucket: String,
        limit: usize,
    },
    /// Remove delivered (or abandoned) event notifications.
    DeleteEvents(Vec<Vec<u8>>),
    /// Store an access key created through the admin API (refused if it exists).
    CreateKey {
        access_key: String,
        record: Vec<u8>,
    },
    /// Remove an access key created through the admin API.
    DeleteKey(String),
    /// Remove an access key if its record is still exactly this one (expiry clean-up, which
    /// must not remove a key re-created under the same name meanwhile).
    DeleteKeyIf {
        access_key: String,
        record: Vec<u8>,
    },
    Flush,
    /// Answered by the writer without touching the database (health checks).
    Ping,
}

pub enum OpOut {
    Done,
    More(bool),
    Object(ObjectMeta),
    Deleted(Vec<S3Result<DeleteOutcome>>),
    /// What lifecycle operations removed.
    Removed(Vec<Removed>),
}

/// An object version (or delete marker) removed by lifecycle, or the delete marker it created.
#[derive(Debug, Clone)]
pub struct Removed {
    pub key: String,
    pub version: Option<String>,
    /// A delete marker was created (current objects in versioned buckets).
    pub marker_created: bool,
    pub size: u64,
    pub etag: String,
    /// Commit order of the removal.
    pub seq: u64,
}

struct Job {
    op: Op,
    reply: oneshot::Sender<S3Result<OpOut>>,
}

pub struct ListResult {
    pub contents: Vec<(String, ObjectSummary)>,
    pub prefixes: Vec<String>,
    pub truncated: bool,
    pub next_marker: Option<String>,
}

#[derive(Default)]
pub struct VersionList {
    pub entries: Vec<VersionEntry>,
    pub prefixes: Vec<String>,
    pub truncated: bool,
    /// (key marker, version id marker) to resume from.
    pub next: Option<(String, Option<String>)>,
}

pub struct VersionEntry {
    pub key: String,
    pub is_latest: bool,
    pub meta: ObjectMeta,
}

#[derive(Default)]
pub struct NoncurrentPage {
    pub items: Vec<NoncurrentItem>,
    /// Raw table key to continue after.
    pub last: Option<Vec<u8>>,
}

pub struct NoncurrentItem {
    pub key: String,
    pub meta: ObjectMeta,
    pub noncurrent_since_ms: Option<u64>,
    pub only_version: bool,
}

pub struct UploadEntry {
    pub id: u128,
    pub meta: UploadMeta,
}

fn obj_key(bucket: &str, key: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(bucket.len() + 1 + key.len());
    k.extend_from_slice(bucket.as_bytes());
    k.push(0);
    k.extend_from_slice(key.as_bytes());
    k
}

/// Smallest byte string greater than every string with prefix `p`.
fn prefix_successor(p: &[u8]) -> Option<Vec<u8>> {
    let mut v = p.to_vec();
    while let Some(last) = v.pop() {
        if last < 0xff {
            v.push(last + 1);
            return Some(v);
        }
    }
    None
}

/// Normalize an ETag for comparison: strip quotes / weak prefix, lowercase.
pub fn norm_etag(s: &str) -> String {
    s.trim().trim_start_matches("W/").trim_matches('"').to_ascii_lowercase()
}

impl Store {
    pub fn open(cfg: StoreConfig) -> S3Result<Arc<Store>> {
        let root = cfg.root;
        std::fs::create_dir_all(root.join("data"))?;
        for i in 0..=255u8 {
            let d = root.join("data").join(format!("{i:02x}"));
            if !d.exists() {
                std::fs::create_dir(&d)?;
            }
        }
        // Anything left in tmp/ belongs to uploads that never committed.
        let tmp = root.join("tmp");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;

        // The marker exists only between a clean shutdown and the next start. If the database
        // exists but the marker does not, the last run crashed and may have left orphaned files.
        let marker = root.join(CLEAN_MARKER);
        let existed = root.join("meta.redb").exists();
        let unclean = existed && !marker.exists();
        let tagged = std::fs::read(&marker).is_ok_and(|m| m == CLEAN_TAG);
        let _ = std::fs::remove_file(&marker);

        let db = Database::builder().set_cache_size(cfg.cache_bytes).create(root.join("meta.redb"))?;
        {
            let txn = db.begin_write()?;
            {
                let mut state = txn.open_table(STATE)?;
                let stored = state.get("format")?.map(|v| v.value());
                check_format(stored).map_err(S3Error::internal)?;
                if stored != Some(FORMAT) {
                    state.insert("format", FORMAT)?;
                }
            }
            txn.open_table(BUCKETS)?;
            txn.open_table(OBJECTS)?;
            txn.open_table(INLINE)?;
            txn.open_table(UPLOADS)?;
            txn.open_table(PARTS)?;
            txn.open_table(CONFIG)?;
            txn.open_table(VERSIONS)?;
            txn.open_table(USAGE)?;
            txn.open_table(STATE)?;
            txn.open_table(PART_BYTES)?;
            txn.open_table(REPL)?;
            txn.open_table(REPL_WAIT)?;
            txn.open_table(EVENTS)?;
            txn.open_table(KEYS)?;
            txn.commit()?;
        }
        // After a crash or a run of an older release, the counters may not match the data.
        rebuild_usage_if_needed(&db, existed && !tagged)?;
        if unclean {
            let started = std::time::Instant::now();
            match collect_orphans(&db, &root) {
                Ok((n, bytes)) => elog!(
                    "recovery: removed {n} orphaned data file(s), {bytes} bytes, in {:.1}s",
                    started.elapsed().as_secs_f64()
                ),
                Err(e) => elog!("recovery: orphan scan failed: {e}"),
            }
        }
        let db = Arc::new(DbCell {
            path: root.join("meta.redb"),
            cache_bytes: cfg.cache_bytes,
            db: std::sync::RwLock::new(Some(Arc::new(db))),
            reopened: std::sync::atomic::AtomicBool::new(false),
        });
        let space = Arc::new(space::Space::new(&root, cfg.min_free));
        if let Err(e) = space.restore_ballast() {
            elog!("warning: cannot create the ballast file: {e}");
        }

        let (del_tx, del_rx) = mpsc::channel::<Gc>();
        let del_root = root.clone();
        let gc_space = space.clone();
        let gc_paused = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let paused = gc_paused.clone();
        std::thread::Builder::new().name("s3rs-gc".into()).spawn(move || {
            for msg in del_rx {
                let ids = match msg {
                    Gc::Remove(ids) => ids,
                    Gc::Sync(done) => {
                        let _ = done.send(());
                        continue;
                    }
                };
                // A backup in progress may still need these files; they wait in the queue.
                while paused.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                    std::thread::sleep(Duration::from_millis(50));
                }
                for id in ids {
                    if let Err(e) = std::fs::remove_file(data_path(&del_root, id))
                        && e.kind() != std::io::ErrorKind::NotFound
                    {
                        elog!("gc: failed to remove {}: {e}", util::id_hex(id));
                    }
                }
                // Deletes free space: put the ballast back once there is room.
                if !gc_space.ballast.present() && matches!(gc_space.restore_ballast(), Ok(true)) {
                    elog!("disk space recovered: recreated the ballast file");
                }
            }
        })?;

        let (tx, rx) = mpsc::channel::<Job>();
        let wdb = db.clone();
        let wdel = del_tx.clone();
        let durable = cfg.fsync;
        let repl_wake = Arc::new(tokio::sync::Notify::new());
        let events_committed = tokio::sync::watch::Sender::new(0u64);
        std::thread::Builder::new().name("s3rs-writer".into()).spawn({
            let space = space.clone();
            let wake = repl_wake.clone();
            let events = events_committed.clone();
            move || writer_loop(wdb, rx, wdel, durable, space, wake, events)
        })?;

        Ok(Arc::new(Store {
            root,
            fsync: cfg.fsync,
            inline_threshold: cfg.inline_threshold,
            db,
            writer: tx,
            deleter: del_tx,
            space,
            gc_paused,
            repl_wake,
            events_committed,
        }))
    }

    /// Record that the store shut down cleanly (all metadata flushed, nothing in flight). Waits
    /// for pending file deletions first, so the data directory has no orphans; if they don't
    /// finish in time, no marker is written and the next start runs the recovery scan.
    pub fn mark_clean_shutdown(&self) {
        if self.db.reopened.load(std::sync::atomic::Ordering::SeqCst) {
            elog!("shutdown: the metadata database was reopened after an I/O error; the next start will run a recovery scan");
            return;
        }
        let (done, wait) = mpsc::channel();
        if self.deleter.send(Gc::Sync(done)).is_ok() && wait.recv_timeout(Duration::from_secs(60)).is_ok() {
            let _ = std::fs::write(self.root.join(CLEAN_MARKER), CLEAN_TAG);
        } else {
            elog!("shutdown: file deletions did not finish; the next start will run a recovery scan");
        }
    }

    pub fn data_path(&self, id: u128) -> PathBuf {
        data_path(&self.root, id)
    }

    pub fn tmp_path(&self, id: u128) -> PathBuf {
        self.root.join("tmp").join(util::id_hex(id))
    }

    /// Start a consistent backup: data file deletion is held back (before the snapshot, so no
    /// file the snapshot refers to can disappear) until the returned `Backup` is dropped.
    pub fn begin_backup(&self) -> S3Result<Backup> {
        // The snapshot is at most as large as the live database; it must not eat the reserve.
        let db_len = std::fs::metadata(self.root.join("meta.redb")).map(|m| m.len()).unwrap_or(0);
        self.space.check(db_len)?;
        self.gc_paused.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let pause = GcPause(self.gc_paused.clone());
        let snapshot = backup::SnapshotFile(self.root.join("tmp").join(format!("backup-{}.redb", util::id_hex(util::new_id()))));
        let plan = backup::snapshot(&*self.db.get()?, &self.root, &snapshot.0)?;
        Ok(Backup { plan, _snapshot: snapshot, _pause: pause })
    }

    /// Schedule data files for deletion (used to clean up after failed writes).
    pub fn discard(&self, ids: Vec<u128>) {
        if !ids.is_empty() {
            let _ = self.deleter.send(Gc::Remove(ids));
        }
    }

    pub async fn submit(&self, op: Op) -> S3Result<OpOut> {
        let (reply, rx) = oneshot::channel();
        self.writer.send(Job { op, reply }).map_err(|_| S3Error::internal("writer stopped"))?;
        rx.await.map_err(|_| S3Error::internal("writer stopped"))?
    }

    /// Like `submit`, but deletes `files` if the operation fails (they were never referenced).
    pub async fn submit_owning(&self, op: Op, files: Vec<u128>) -> S3Result<OpOut> {
        let r = self.submit(op).await;
        if r.is_err() {
            self.discard(files);
        }
        r
    }

    /// Whether the store can serve requests: the metadata database is open and readable and
    /// the writer answers within a few seconds. A full disk does not make the store unhealthy.
    pub async fn health(&self) -> S3Result<()> {
        drop(self.db.get()?.begin_read()?);
        match tokio::time::timeout(Duration::from_secs(5), self.submit(Op::Ping)).await {
            Ok(r) => r.map(|_| ()),
            Err(_) => Err(S3Error::new(
                "ServiceUnavailable",
                hyper::StatusCode::SERVICE_UNAVAILABLE,
                "the metadata writer is not responding",
            )),
        }
    }

    // ---------------------------------------------------------------- replication queue

    /// Up to `limit` replication queue entries after `after` (a previous entry's `raw` key).
    pub fn repl_scan(&self, after: Option<&[u8]>, limit: usize) -> S3Result<Vec<ReplEntry>> {
        let txn = self.db.get()?.begin_read()?;
        let t = txn.open_table(REPL)?;
        let lo = match after {
            Some(a) => Bound::Excluded(a),
            None => Bound::Unbounded,
        };
        let mut out = Vec::new();
        for e in t.range::<&[u8]>((lo, Bound::Unbounded))?.take(limit) {
            let (k, v) = e?;
            let raw = k.value().to_vec();
            let sep = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            let (seq, since_ms) = v.value();
            out.push(ReplEntry {
                bucket: String::from_utf8_lossy(&raw[..sep]).into_owned(),
                key: String::from_utf8_lossy(raw.get(sep + 1..).unwrap_or_default()).into_owned(),
                raw,
                seq,
                since_ms,
            });
        }
        Ok(out)
    }

    /// Queue an operation without waiting for it (event notifications are recorded this way, so
    /// requests don't wait for them).
    pub fn submit_detached(&self, op: Op) {
        let (reply, _) = oneshot::channel();
        let _ = self.writer.send(Job { op, reply });
    }

    /// Up to `limit` queued event notifications for a webhook target, oldest first: (queue key,
    /// body).
    pub fn events(&self, target: &str, limit: usize) -> S3Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let txn = self.db.get()?.begin_read()?;
        let lo = obj_key(target, "");
        let hi = prefix_successor(&lo).expect("prefix ends with 0");
        let mut out = Vec::new();
        for e in txn.open_table(EVENTS)?.range::<&[u8]>(lo.as_slice()..hi.as_slice())?.take(limit) {
            let (k, v) = e?;
            out.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(out)
    }

    /// Queued event notifications per webhook target: (events, bytes, highest queue
    /// sequence number).
    pub fn event_queues(&self) -> S3Result<HashMap<String, (u64, u64, u64)>> {
        let txn = self.db.get()?.begin_read()?;
        let mut out: HashMap<String, (u64, u64, u64)> = HashMap::new();
        for e in txn.open_table(EVENTS)?.iter()? {
            let (k, v) = e?;
            let k = k.value();
            let sep = k.iter().position(|b| *b == 0).unwrap_or(k.len());
            let target = String::from_utf8_lossy(&k[..sep]).into_owned();
            let seq = k.get(sep + 1..).and_then(|s| <[u8; 8]>::try_from(s).ok()).map(u64::from_be_bytes).unwrap_or(0);
            let q = out.entry(target).or_default();
            q.0 += 1;
            q.1 += v.value().len() as u64;
            q.2 = q.2.max(seq);
        }
        Ok(out)
    }

    /// The queue keys of all event notifications for `target` (to drop a removed target's).
    pub fn event_keys(&self, target: &str) -> S3Result<Vec<Vec<u8>>> {
        Ok(self.events(target, usize::MAX)?.into_iter().map(|(k, _)| k).collect())
    }

    /// Access keys created through the admin API: (access key, record).
    pub fn access_keys(&self) -> S3Result<Vec<(String, Vec<u8>)>> {
        let txn = self.db.get()?.begin_read()?;
        let mut out = Vec::new();
        for e in txn.open_table(KEYS)?.iter()? {
            let (k, v) = e?;
            out.push((k.value().to_string(), v.value().to_vec()));
        }
        Ok(out)
    }

    /// Number of keys waiting to be replicated (queued, or waiting to be retried).
    pub fn repl_pending(&self) -> S3Result<u64> {
        use redb::ReadableTableMetadata;
        let txn = self.db.get()?.begin_read()?;
        Ok(txn.open_table(REPL)?.len()? + txn.open_table(REPL_WAIT)?.len()?)
    }

    /// Whether a waiting key's retry time is before `now_ms`.
    pub fn repl_due(&self, now_ms: u64) -> S3Result<bool> {
        let txn = self.db.get()?.begin_read()?;
        let end = now_ms.to_be_bytes();
        Ok(txn.open_table(REPL_WAIT)?.range::<&[u8]>(..end.as_slice())?.next().is_some())
    }

    /// The time of the oldest change waiting to be retried (0: none).
    pub fn repl_wait_oldest(&self) -> S3Result<u64> {
        let txn = self.db.get()?.begin_read()?;
        let mut oldest = u64::MAX;
        for e in txn.open_table(REPL_WAIT)?.iter()? {
            oldest = oldest.min(e?.1.value().1);
        }
        Ok(if oldest == u64::MAX { 0 } else { oldest })
    }

    /// Buckets that have a configuration of the given kind.
    pub fn buckets_with_config(&self, kind: &str) -> S3Result<Vec<String>> {
        let txn = self.db.get()?.begin_read()?;
        let config = txn.open_table(CONFIG)?;
        let mut out = Vec::new();
        for e in txn.open_table(BUCKETS)?.iter()? {
            let (b, _) = e?;
            if config.get((b.value(), kind))?.is_some() {
                out.push(b.value().to_string());
            }
        }
        Ok(out)
    }

    /// Buckets whose replication backfill (queuing existing objects) has not finished.
    pub fn repl_backfills(&self) -> S3Result<Vec<String>> {
        let txn = self.db.get()?.begin_read()?;
        let config = txn.open_table(CONFIG)?;
        let mut out = Vec::new();
        for e in txn.open_table(BUCKETS)?.iter()? {
            let (b, _) = e?;
            if config.get((b.value(), "replication-backfill"))?.is_some() {
                out.push(b.value().to_string());
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------- reads

    pub fn bucket_exists(&self, bucket: &str) -> S3Result<bool> {
        let t = self.db.get()?.begin_read()?.open_table(BUCKETS)?;
        Ok(t.get(bucket)?.is_some())
    }

    pub fn require_bucket(&self, bucket: &str) -> S3Result<()> {
        if self.bucket_exists(bucket)? { Ok(()) } else { Err(err::NoSuchBucket()) }
    }

    pub fn list_buckets(&self) -> S3Result<Vec<(String, u64)>> {
        let t = self.db.get()?.begin_read()?.open_table(BUCKETS)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            let (k, v) = e?;
            out.push((k.value().to_string(), v.value()));
        }
        Ok(out)
    }

    /// Fetch object metadata (and inline bytes, from the same snapshot). Errors with
    /// NoSuchBucket / NoSuchKey as appropriate.
    pub fn get_object(&self, bucket: &str, key: &str) -> S3Result<(ObjectMeta, Option<Bytes>)> {
        let txn = self.db.get()?.begin_read()?;
        let objects = txn.open_table(OBJECTS)?;
        let Some(v) = objects.get(obj_key(bucket, key).as_slice())? else {
            let buckets = txn.open_table(BUCKETS)?;
            if buckets.get(bucket)?.is_none() {
                return Err(err::NoSuchBucket());
            }
            // If the latest version is a delete marker, say so (as S3 does).
            let versions = txn.open_table(VERSIONS)?;
            let p = ver_prefix(bucket, key);
            let end = prefix_successor(&p).expect("prefix ends with 0");
            if let Some(e) = versions.range::<&[u8]>(p.as_slice()..end.as_slice())?.next() {
                let m = ObjectMeta::decode(e?.1.value())?;
                if m.delete_marker {
                    return Err(err::NoSuchKey()
                        .with_header("x-amz-delete-marker", "true")
                        .with_header("x-amz-version-id", m.version.unwrap_or_else(|| "null".into())));
                }
            }
            return Err(err::NoSuchKey());
        };
        let meta = ObjectMeta::decode(v.value())?;
        let inline = match meta.storage {
            Storage::Inline(id) => {
                let t = txn.open_table(INLINE)?;
                let g = t.get(id)?.ok_or_else(|| S3Error::internal("missing inline data"))?;
                Some(Bytes::copy_from_slice(g.value()))
            }
            Storage::Segments(_) => None,
        };
        Ok((meta, inline))
    }

    pub fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: &str,
        marker: Option<&str>,
        max_keys: usize,
    ) -> S3Result<ListResult> {
        let txn = self.db.get()?.begin_read()?;
        if txn.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(err::NoSuchBucket());
        }
        let t = txn.open_table(OBJECTS)?;
        let base = obj_key(bucket, "");
        let full_prefix = obj_key(bucket, prefix);
        let end: Vec<u8> = prefix_successor(&full_prefix).unwrap_or_else(|| {
            let mut e = bucket.as_bytes().to_vec();
            e.push(1);
            e
        });

        let mut start: Bound<Vec<u8>> = Bound::Included(full_prefix.clone());
        if let Some(m) = marker.filter(|m| *m >= prefix) {
            start = Bound::Excluded(obj_key(bucket, m));
            // Resuming right after a common prefix: skip everything rolled up under it.
            if !delimiter.is_empty() && m.starts_with(prefix) && m.ends_with(delimiter) {
                let rest = &m[prefix.len()..];
                if rest.find(delimiter) == Some(rest.len() - delimiter.len()) {
                    match prefix_successor(&obj_key(bucket, m)) {
                        Some(s) => start = Bound::Included(s),
                        None => {
                            return Ok(ListResult { contents: vec![], prefixes: vec![], truncated: false, next_marker: None });
                        }
                    }
                }
            }
        }

        let mut res = ListResult { contents: Vec::new(), prefixes: Vec::new(), truncated: false, next_marker: None };
        let mut count = 0usize;
        'outer: loop {
            let lower = match &start {
                Bound::Included(v) => Bound::Included(v.as_slice()),
                Bound::Excluded(v) => Bound::Excluded(v.as_slice()),
                Bound::Unbounded => Bound::Unbounded,
            };
            if let Bound::Included(v) | Bound::Excluded(v) = &start
                && v.as_slice() >= end.as_slice()
            {
                break;
            }
            let range = t.range::<&[u8]>((lower, Bound::Excluded(end.as_slice())))?;
            for entry in range {
                let (k, v) = entry?;
                let kb = k.value();
                let key = std::str::from_utf8(&kb[base.len()..]).map_err(|_| S3Error::internal("bad key"))?;
                if !key.starts_with(prefix) {
                    break 'outer;
                }
                if !delimiter.is_empty()
                    && let Some(i) = key[prefix.len()..].find(delimiter)
                {
                    let cp = &key[..prefix.len() + i + delimiter.len()];
                    if count >= max_keys {
                        res.truncated = true;
                        break 'outer;
                    }
                    res.prefixes.push(cp.to_string());
                    res.next_marker = Some(cp.to_string());
                    count += 1;
                    match prefix_successor(&obj_key(bucket, cp)) {
                        Some(s) => {
                            start = Bound::Included(s);
                            continue 'outer;
                        }
                        None => break 'outer,
                    }
                }
                if count >= max_keys {
                    res.truncated = true;
                    break 'outer;
                }
                res.contents.push((key.to_string(), ObjectMeta::decode_summary(v.value())?));
                res.next_marker = Some(key.to_string());
                count += 1;
            }
            break;
        }
        if !res.truncated {
            res.next_marker = None;
        }
        Ok(res)
    }

    /// (object versions, bytes) stored in a bucket.
    pub fn bucket_usage(&self, bucket: &str) -> S3Result<(u64, u64)> {
        Ok(self.db.get()?.begin_read()?.open_table(USAGE)?.get(bucket)?.map(|v| v.value()).unwrap_or((0, 0)))
    }

    /// Early quota check before receiving `size` bytes for `target`. The writer checks again
    /// atomically when the data is committed.
    pub fn quota_allows(&self, bucket: &str, target: Incoming, size: u64) -> S3Result<()> {
        let txn = self.db.get()?.begin_read()?;
        let Some(q) = txn.open_table(CONFIG)?.get((bucket, "quota"))?.and_then(|v| Quota::decode(v.value())) else {
            return Ok(());
        };
        let usage = txn.open_table(USAGE)?.get(bucket)?.map(|v| v.value()).unwrap_or((0, 0));
        let parts = txn.open_table(PART_BYTES)?.get(bucket)?.map(|v| v.value()).unwrap_or(0);
        let delta = match target {
            Incoming::Part { upload, part } => {
                let old = txn.open_table(PARTS)?.get((upload, part))?.map(|v| PartMeta::decode(v.value())).transpose()?;
                QuotaDelta { add: size, freed_parts: old.map_or(0, |p| p.size), ..Default::default() }
            }
            Incoming::Object(key) => {
                let versioned =
                    Versioning::parse(txn.open_table(CONFIG)?.get((bucket, "versioning"))?.as_ref().map(|v| v.value()))
                        == Versioning::Enabled;
                // Approximate (the writer's check is exact): assume an overwrite frees the
                // current object unless the bucket keeps every version.
                let replaced = if versioned {
                    None
                } else {
                    txn.open_table(OBJECTS)?
                        .get(obj_key(bucket, key).as_slice())?
                        .map(|v| ObjectMeta::decode_summary(v.value()))
                        .transpose()?
                        .map(|m| m.size)
                };
                QuotaDelta::object(size, replaced)
            }
        };
        if !delta.allowed(&q, usage, parts) {
            return Err(quota_exceeded());
        }
        Ok(())
    }

    /// Bytes held by unfinished multipart uploads in a bucket.
    pub fn bucket_part_bytes(&self, bucket: &str) -> S3Result<u64> {
        Ok(self.db.get()?.begin_read()?.open_table(PART_BYTES)?.get(bucket)?.map(|v| v.value()).unwrap_or(0))
    }

    /// Usage of every bucket (for metrics).
    pub fn all_usage(&self) -> S3Result<Vec<(String, u64, u64)>> {
        let t = self.db.get()?.begin_read()?.open_table(USAGE)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            let (k, v) = e?;
            let (n, b) = v.value();
            out.push((k.value().to_string(), n, b));
        }
        Ok(out)
    }

    /// A bucket configuration document, if set. Errors with NoSuchBucket.
    pub fn bucket_config(&self, bucket: &str, kind: &str) -> S3Result<Option<Vec<u8>>> {
        let txn = self.db.get()?.begin_read()?;
        if txn.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(err::NoSuchBucket());
        }
        Ok(txn.open_table(CONFIG)?.get((bucket, kind))?.map(|v| v.value().to_vec()))
    }

    pub fn get_upload(&self, id: u128) -> S3Result<Option<UploadMeta>> {
        let t = self.db.get()?.begin_read()?.open_table(UPLOADS)?;
        match t.get(id)? {
            Some(v) => Ok(Some(UploadMeta::decode(v.value())?)),
            None => Ok(None),
        }
    }

    /// Parts of an upload with part number > `marker`, at most `max` (+ whether truncated).
    pub fn list_parts(&self, id: u128, marker: u32, max: usize) -> S3Result<(Vec<(u32, PartMeta)>, bool)> {
        let t = self.db.get()?.begin_read()?.open_table(PARTS)?;
        let mut out = Vec::new();
        let mut truncated = false;
        for e in t.range((id, marker.saturating_add(1))..=(id, u32::MAX))? {
            let (k, v) = e?;
            if out.len() >= max {
                truncated = true;
                break;
            }
            out.push((k.value().1, PartMeta::decode(v.value())?));
        }
        Ok((out, truncated))
    }

    /// A specific version of an object (and its inline bytes). Delete markers produce
    /// `MethodNotAllowed` with `x-amz-delete-marker`, like S3.
    pub fn get_object_version(&self, bucket: &str, key: &str, vid: &str) -> S3Result<(ObjectMeta, Option<Bytes>)> {
        if !valid_version_id(vid) {
            return Err(err::InvalidArgument().with_message("Invalid version id specified"));
        }
        let txn = self.db.get()?.begin_read()?;
        if txn.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(err::NoSuchBucket());
        }
        let want = (vid != "null").then_some(vid);
        let mut found = None;
        if let Some(v) = txn.open_table(OBJECTS)?.get(obj_key(bucket, key).as_slice())? {
            let m = ObjectMeta::decode(v.value())?;
            if m.version.as_deref() == want {
                found = Some(m);
            }
        }
        if found.is_none() {
            let versions = txn.open_table(VERSIONS)?;
            match want.and_then(version_seq) {
                Some(seq) => {
                    if let Some(v) = versions.get(ver_key(bucket, key, seq).as_slice())? {
                        let m = ObjectMeta::decode(v.value())?;
                        if m.version.as_deref() == want {
                            found = Some(m);
                        }
                    }
                }
                None => {
                    let p = ver_prefix(bucket, key);
                    let end = prefix_successor(&p).expect("prefix ends with 0");
                    for e in versions.range::<&[u8]>(p.as_slice()..end.as_slice())? {
                        let m = ObjectMeta::decode(e?.1.value())?;
                        if m.version.is_none() {
                            found = Some(m);
                            break;
                        }
                    }
                }
            }
        }
        let Some(meta) = found else {
            return Err(err::NoSuchVersion());
        };
        if meta.delete_marker {
            return Err(err::MethodNotAllowed()
                .with_header("x-amz-delete-marker", "true")
                .with_header("x-amz-version-id", vid.to_string()));
        }
        let inline = match meta.storage {
            Storage::Inline(id) => {
                let t = txn.open_table(INLINE)?;
                let g = t.get(id)?.ok_or_else(|| S3Error::internal("missing inline data"))?;
                Some(Bytes::copy_from_slice(g.value()))
            }
            Storage::Segments(_) => None,
        };
        Ok((meta, inline))
    }

    pub fn versioning(&self, bucket: &str) -> S3Result<Versioning> {
        Ok(Versioning::parse(self.bucket_config(bucket, "versioning")?.as_deref()))
    }

    /// ListObjectVersions: every version and delete marker, keys ascending, newest first per key.
    pub fn list_object_versions(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: &str,
        key_marker: Option<&str>,
        version_marker: Option<&str>,
        max: usize,
    ) -> S3Result<VersionList> {
        let txn = self.db.get()?.begin_read()?;
        if txn.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(err::NoSuchBucket());
        }
        let objects = txn.open_table(OBJECTS)?;
        let versions = txn.open_table(VERSIONS)?;
        let base = obj_key(bucket, "");
        let full_prefix = obj_key(bucket, prefix);
        let end: Vec<u8> = prefix_successor(&full_prefix).unwrap_or_else(|| {
            let mut e = bucket.as_bytes().to_vec();
            e.push(1);
            e
        });
        let mut out = VersionList::default();
        let mut count = 0usize;

        // Cursor over key bytes (relative to `base`): (bytes, inclusive).
        let mut cursor: (Vec<u8>, bool) = (prefix.as_bytes().to_vec(), true);
        let mut resume: Option<(String, String)> = None;
        if let Some(km) = key_marker.filter(|k| *k >= prefix) {
            match version_marker.filter(|v| !v.is_empty()) {
                Some(vm) => {
                    cursor = (km.as_bytes().to_vec(), true);
                    resume = Some((km.to_string(), vm.to_string()));
                }
                None => {
                    cursor = (km.as_bytes().to_vec(), false);
                    // Resuming after a common prefix: skip everything rolled up under it.
                    if !delimiter.is_empty() && km.starts_with(prefix) && km.ends_with(delimiter) {
                        let rest = &km[prefix.len()..];
                        if rest.find(delimiter) == Some(rest.len() - delimiter.len()) {
                            match prefix_successor(km.as_bytes()) {
                                Some(s) => cursor = (s, true),
                                None => return Ok(VersionList::default()),
                            }
                        }
                    }
                }
            }
        }

        loop {
            // Next key present in either table.
            let (ob, vb) = {
                let mut o = base.clone();
                o.extend_from_slice(&cursor.0);
                let mut v = o.clone();
                if !cursor.1 {
                    v.push(1); // skip every version entry of the cursor key itself
                }
                (o, v)
            };
            if ob.as_slice() >= end.as_slice() {
                break;
            }
            let lower = if cursor.1 { Bound::Included(ob.as_slice()) } else { Bound::Excluded(ob.as_slice()) };
            let next_obj = match objects.range::<&[u8]>((lower, Bound::Excluded(end.as_slice())))?.next() {
                Some(e) => Some(e?.0.value()[base.len()..].to_vec()),
                None => None,
            };
            let next_ver = match versions.range::<&[u8]>(vb.as_slice()..end.as_slice())?.next() {
                Some(e) => {
                    let k = e?.0.value().to_vec();
                    Some(k[base.len()..k.len() - 9].to_vec())
                }
                None => None,
            };
            let kb = match (next_obj, next_ver) {
                (Some(a), Some(b)) => a.min(b),
                (Some(a), None) | (None, Some(a)) => a,
                (None, None) => break,
            };
            let key = String::from_utf8(kb.clone()).map_err(|_| S3Error::internal("bad key"))?;
            if !key.starts_with(prefix) {
                break;
            }
            if !delimiter.is_empty()
                && let Some(i) = key[prefix.len()..].find(delimiter)
            {
                let cp = key[..prefix.len() + i + delimiter.len()].to_string();
                if count >= max {
                    out.truncated = true;
                    break;
                }
                count += 1;
                out.next = Some((cp.clone(), None));
                out.prefixes.push(cp.clone());
                match prefix_successor(cp.as_bytes()) {
                    Some(s) => cursor = (s, true),
                    None => break,
                }
                continue;
            }

            // All entries of this key, newest first.
            let mut entries = Vec::new();
            if let Some(v) = objects.get(obj_key(bucket, &key).as_slice())? {
                entries.push(ObjectMeta::decode(v.value())?);
            }
            let p = ver_prefix(bucket, &key);
            let pend = prefix_successor(&p).expect("prefix ends with 0");
            for e in versions.range::<&[u8]>(p.as_slice()..pend.as_slice())? {
                entries.push(ObjectMeta::decode(e?.1.value())?);
            }
            let mut skipping = resume.as_ref().is_some_and(|(k, _)| *k == key);
            for (i, m) in entries.into_iter().enumerate() {
                let vid = m.version.clone().unwrap_or_else(|| "null".into());
                if skipping {
                    if resume.as_ref().is_some_and(|(_, v)| *v == vid) {
                        skipping = false;
                    }
                    continue;
                }
                if count >= max {
                    out.truncated = true;
                    return Ok(out);
                }
                count += 1;
                out.next = Some((key.clone(), Some(vid)));
                out.entries.push(VersionEntry { key: key.clone(), is_latest: i == 0, meta: m });
            }
            resume = None;
            cursor = (kb, false);
        }
        if !out.truncated {
            out.next = None;
        }
        Ok(out)
    }

    /// Noncurrent entries for lifecycle: (key, meta, became-noncurrent time in ms or None if the
    /// entry is itself the latest version, whether it is the only version of its key).
    pub fn scan_noncurrent(&self, bucket: &str, prefix: &str, after: Option<&[u8]>, limit: usize) -> S3Result<NoncurrentPage> {
        let txn = self.db.get()?.begin_read()?;
        let objects = txn.open_table(OBJECTS)?;
        let versions = txn.open_table(VERSIONS)?;
        let base_len = bucket.len() + 1;
        let start = match after {
            Some(a) => Bound::Excluded(a.to_vec()),
            None => Bound::Included(obj_key(bucket, prefix)),
        };
        let full_prefix = obj_key(bucket, prefix);
        let end = prefix_successor(&full_prefix).unwrap_or_else(|| {
            let mut e = bucket.as_bytes().to_vec();
            e.push(1);
            e
        });
        let lower = match &start {
            Bound::Included(v) => Bound::Included(v.as_slice()),
            Bound::Excluded(v) => Bound::Excluded(v.as_slice()),
            Bound::Unbounded => Bound::Unbounded,
        };
        let mut page = NoncurrentPage::default();
        // Previous (newer) entry of the same key: (key, mtime). When resuming, seed it with the
        // entry we stopped at, so a key whose versions span two pages keeps the right times.
        let mut newer: Option<(String, u64)> = None;
        if let Some(a) = after
            && a.len() > base_len + 9
            && let Some(g) = versions.get(a)?
        {
            let key = String::from_utf8(a[base_len..a.len() - 9].to_vec()).map_err(|_| S3Error::internal("bad key"))?;
            newer = Some((key, ObjectMeta::decode(g.value())?.mtime_ms));
        }
        let mut items: Vec<(String, ObjectMeta, Option<u64>)> = Vec::new();
        for e in versions.range::<&[u8]>((lower, Bound::Excluded(end.as_slice())))? {
            let (k, v) = e?;
            let kb = k.value();
            let key = String::from_utf8(kb[base_len..kb.len() - 9].to_vec()).map_err(|_| S3Error::internal("bad key"))?;
            let m = ObjectMeta::decode(v.value())?;
            let since = match &newer {
                Some((nk, mt)) if *nk == key => Some(*mt),
                _ => objects
                    .get(obj_key(bucket, &key).as_slice())?
                    .map(|c| ObjectMeta::decode(c.value()))
                    .transpose()?
                    .map(|c| c.mtime_ms),
            };
            newer = Some((key.clone(), m.mtime_ms));
            page.last = Some(kb.to_vec());
            items.push((key, m, since));
            if items.len() >= limit {
                break;
            }
        }
        // A latest delete marker is the only version when nothing else exists for its key.
        for (key, m, since) in items {
            let only = since.is_none() && {
                let p = ver_prefix(bucket, &key);
                let pend = prefix_successor(&p).expect("prefix ends with 0");
                versions.range::<&[u8]>(p.as_slice()..pend.as_slice())?.take(2).count() == 1
            };
            page.items.push(NoncurrentItem { key, meta: m, noncurrent_since_ms: since, only_version: only });
        }
        Ok(page)
    }

    /// Objects with full metadata, in key order: keys starting with `prefix` and greater than
    /// `after`, at most `limit`. Used by background jobs that need tags.
    pub fn scan_objects(
        &self,
        bucket: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> S3Result<Vec<(String, ObjectMeta)>> {
        let txn = self.db.get()?.begin_read()?;
        let t = txn.open_table(OBJECTS)?;
        let base_len = bucket.len() + 1;
        let full_prefix = obj_key(bucket, prefix);
        let end = prefix_successor(&full_prefix).unwrap_or_else(|| {
            let mut e = bucket.as_bytes().to_vec();
            e.push(1);
            e
        });
        let start = match after {
            Some(a) if a >= prefix => Bound::Excluded(obj_key(bucket, a)),
            _ => Bound::Included(full_prefix),
        };
        let lower = match &start {
            Bound::Included(v) => Bound::Included(v.as_slice()),
            Bound::Excluded(v) => Bound::Excluded(v.as_slice()),
            Bound::Unbounded => Bound::Unbounded,
        };
        let mut out = Vec::new();
        for e in t.range::<&[u8]>((lower, Bound::Excluded(end.as_slice())))? {
            if out.len() >= limit {
                break;
            }
            let (k, v) = e?;
            let key = String::from_utf8(k.value()[base_len..].to_vec()).map_err(|_| S3Error::internal("bad key"))?;
            out.push((key, ObjectMeta::decode(v.value())?));
        }
        Ok(out)
    }

    pub fn list_uploads(&self, bucket: &str, prefix: &str) -> S3Result<Vec<UploadEntry>> {
        let t = self.db.get()?.begin_read()?.open_table(UPLOADS)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            let (k, v) = e?;
            let meta = UploadMeta::decode(v.value())?;
            if meta.bucket == bucket && meta.key.starts_with(prefix) {
                out.push(UploadEntry { id: k.value(), meta });
            }
        }
        out.sort_by(|a, b| (&a.meta.key, a.meta.initiated_ms, a.id).cmp(&(&b.meta.key, b.meta.initiated_ms, b.id)));
        Ok(out)
    }
}

const CLEAN_MARKER: &str = "clean-shutdown";

/// Delete data files that no object or part references. Only safe while nothing else is
/// writing, i.e. before the server starts serving.
fn collect_orphans(db: &Database, root: &Path) -> S3Result<(usize, u64)> {
    let txn = db.begin_read()?;
    let mut live = std::collections::HashSet::new();
    for e in txn.open_table(OBJECTS)?.iter()? {
        let (_, v) = e?;
        if let Storage::Segments(segs) = ObjectMeta::decode(v.value())?.storage {
            live.extend(segs.into_iter().map(|(id, _)| id));
        }
    }
    for e in txn.open_table(VERSIONS)?.iter()? {
        let (_, v) = e?;
        if let Storage::Segments(segs) = ObjectMeta::decode(v.value())?.storage {
            live.extend(segs.into_iter().map(|(id, _)| id));
        }
    }
    for e in txn.open_table(PARTS)?.iter()? {
        let (_, v) = e?;
        live.insert(PartMeta::decode(v.value())?.file);
    }
    let (mut n, mut bytes) = (0usize, 0u64);
    for dir in std::fs::read_dir(root.join("data"))? {
        let dir = dir?;
        if !dir.file_type()?.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(dir.path())? {
            let f = f?;
            let Some(id) = f.file_name().to_str().and_then(util::parse_id_hex) else { continue };
            if !live.contains(&id) {
                bytes += f.metadata().map(|m| m.len()).unwrap_or(0);
                std::fs::remove_file(f.path())?;
                n += 1;
            }
        }
    }
    Ok((n, bytes))
}

pub fn data_path(root: &Path, id: u128) -> PathBuf {
    root.join("data").join(format!("{:02x}", id as u8)).join(util::id_hex(id))
}

// -------------------------------------------------------------------- writer

fn writer_loop(
    cell: Arc<DbCell>,
    rx: mpsc::Receiver<Job>,
    deleter: mpsc::Sender<Gc>,
    durable: bool,
    space: Arc<space::Space>,
    repl_wake: Arc<tokio::sync::Notify>,
    events_committed: tokio::sync::watch::Sender<u64>,
) {
    let ballast = &space.ballast;
    // In non-durable mode redb can only recycle pages freed by earlier commits once a durable
    // commit happens, so make one at least this often even under constant load.
    const DURABLE_EVERY: Duration = Duration::from_secs(1);
    let mut dirty = false;
    let mut last_durable = Instant::now();
    let mut last_seq = 0u64;
    // Data files made obsolete by commits that are not durable yet (--no-fsync). They are
    // deleted only once a durable commit covers those commits: if the database had to be
    // reopened (or the process died) before that, the metadata still refers to them.
    let mut held: Vec<u128> = Vec::new();
    loop {
        let first = if durable || !dirty {
            match rx.recv() {
                Ok(j) => j,
                Err(_) => break,
            }
        } else {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(j) => j,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Periodically make non-durable commits durable so redb can reclaim pages.
                    match cell.get().and_then(|db| flush(&db)) {
                        Ok(()) => {
                            dirty = false;
                            last_durable = Instant::now();
                            if !held.is_empty() {
                                let _ = deleter.send(Gc::Remove(std::mem::take(&mut held)));
                            }
                        }
                        Err(e) => {
                            elog!("metadata flush failed: {e}");
                            if recover(&cell) {
                                held.clear();
                                dirty = false;
                            }
                        }
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        };
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(j) => batch.push(j),
                Err(_) => break,
            }
        }
        // Health probes only need the writer to be responsive: answer them without a commit
        // (which could fail on a full disk while reads and deletes still work).
        let (pings, rest): (Vec<Job>, Vec<Job>) = batch.into_iter().partition(|j| matches!(j.op, Op::Ping));
        for j in pings {
            let _ = j.reply.send(Ok(OpOut::Done));
        }
        let mut batch = rest;
        if batch.is_empty() {
            continue;
        }
        let force_durable = batch.iter().any(|j| matches!(j.op, Op::Flush));
        let events = batch.iter().any(|j| matches!(j.op, Op::WithEvents(..)));
        let immediate = durable || force_durable || last_durable.elapsed() >= DURABLE_EVERY;

        // While the ballast can still be given up, keep the batch so a commit that fails on a
        // full disk can be retried.
        let backup: Option<Vec<Op>> = ballast.present().then(|| batch.iter().map(|j| j.op.clone()).collect());
        let mut results: Vec<S3Result<OpOut>> = Vec::with_capacity(batch.len());
        let mut obsolete: Vec<u128> = Vec::new();
        let mut queued = false;
        let mut outcome = run_batch(&cell, &mut batch, immediate, &mut last_seq, &mut results, &mut obsolete, &mut queued);
        if let Err(e) = &outcome {
            elog!("metadata commit failed: {e}");
            // On a full disk, give up the ballast first: reopening the database may need space.
            let retry = e.code == "StorageFull" && backup.is_some() && ballast.release();
            if recover(&cell) {
                // Non-durable commits were rolled back with the reopen.
                held.clear();
                dirty = false;
            }
            if retry && let Some(ops) = backup {
                elog!("disk full: released the {} MiB ballast file and retrying", ballast.size >> 20);
                for (job, op) in batch.iter_mut().zip(ops) {
                    job.op = op;
                }
                results.clear();
                obsolete.clear();
                queued = false;
                outcome = run_batch(&cell, &mut batch, immediate, &mut last_seq, &mut results, &mut obsolete, &mut queued);
                if let Err(e) = &outcome {
                    elog!("metadata commit failed again: {e}");
                    if recover(&cell) {
                        held.clear();
                        dirty = false;
                    }
                }
            }
        }

        match outcome {
            Ok(()) => {
                if queued {
                    repl_wake.notify_one();
                }
                if events {
                    events_committed.send_modify(|n| *n += 1);
                }
                if immediate {
                    // Durable: everything held back so far is now safe to delete.
                    dirty = false;
                    last_durable = Instant::now();
                    obsolete.append(&mut held);
                    if !obsolete.is_empty() {
                        let _ = deleter.send(Gc::Remove(obsolete));
                    }
                } else {
                    dirty = true;
                    held.append(&mut obsolete);
                }
                for (job, r) in batch.into_iter().zip(results) {
                    let _ = job.reply.send(r);
                }
            }
            Err(e) => {
                for job in batch {
                    let _ = job.reply.send(Err(e.clone()));
                }
            }
        }
    }
    if dirty && cell.get().and_then(|db| flush(&db)).is_ok() && !held.is_empty() {
        let _ = deleter.send(Gc::Remove(held));
    }
}

/// Apply a batch of operations in one transaction. On error nothing is committed.
fn run_batch(
    cell: &DbCell,
    batch: &mut [Job],
    immediate: bool,
    last_seq: &mut u64,
    results: &mut Vec<S3Result<OpOut>>,
    obsolete: &mut Vec<u128>,
    queued: &mut bool,
) -> S3Result<()> {
    let db = cell.get()?;
    let mut txn = db.begin_write()?;
    if !immediate {
        txn.set_durability(Durability::None).map_err(S3Error::internal)?;
    }
    {
        let mut tx = Tables {
            buckets: txn.open_table(BUCKETS)?,
            objects: txn.open_table(OBJECTS)?,
            inline: txn.open_table(INLINE)?,
            uploads: txn.open_table(UPLOADS)?,
            parts: txn.open_table(PARTS)?,
            config: txn.open_table(CONFIG)?,
            versions: txn.open_table(VERSIONS)?,
            usage: txn.open_table(USAGE)?,
            part_bytes: txn.open_table(PART_BYTES)?,
            repl: txn.open_table(REPL)?,
            repl_wait: txn.open_table(REPL_WAIT)?,
            events: txn.open_table(EVENTS)?,
            keys: txn.open_table(KEYS)?,
        };
        // Replication rule prefixes per bucket, looked up once per batch.
        let mut repl_rules: HashMap<String, Vec<String>> = HashMap::new();
        for job in batch.iter_mut() {
            let mut garbage = Vec::new();
            let op = std::mem::replace(&mut job.op, Op::Flush);
            let (op, event_rows) = match op {
                Op::WithEvents(inner, rows) => (*inner, Some(rows)),
                op => (op, None),
            };
            let touched = repl_touched(&mut tx, &mut repl_rules, &op)?;
            let backfill = matches!(op, Op::ReplBackfill { .. });
            let r = apply(&mut tx, op, &mut garbage, last_seq);
            if let (Ok(out), Some(rows)) = (&r, &event_rows) {
                for (k, v) in rows(out) {
                    tx.events.insert(k.as_slice(), v.as_slice())?;
                }
            }
            if r.is_ok()
                && let Some((bucket, keys)) = touched
                && !matches!(&r, Ok(OpOut::Object(m)) if is_replica(&m.headers))
            {
                *queued |= repl_enqueue(&mut tx, &bucket, &keys)?;
            }
            *queued |= backfill && r.is_ok();
            // Storage failures abort the whole transaction; S3-level errors only fail their op.
            if let Err(e) = &r
                && matches!(e.code, "InternalError" | "StorageFull")
            {
                return Err(e.clone());
            }
            if r.is_ok() {
                obsolete.extend(garbage);
            }
            results.push(r);
        }
    }
    txn.commit()?;
    Ok(())
}

/// After a failed write: an I/O error (typically a full disk) poisons redb; reopen it so later
/// writes, including the deletes that free space, can work again.
/// Returns whether the database was closed (and reopened if possible), which rolls back
/// commits that were not durable yet.
fn recover(cell: &DbCell) -> bool {
    let broken = match cell.get() {
        Ok(db) => poisoned(&db),
        Err(_) => true,
    };
    if broken {
        match cell.reopen() {
            Ok(()) => elog!("reopened the metadata database after an I/O error"),
            Err(e) => elog!("could not reopen the metadata database yet: {e}"),
        }
    }
    broken
}

fn flush(db: &Database) -> S3Result<()> {
    let txn = db.begin_write()?;
    txn.commit()?;
    Ok(())
}

struct Tables<'t> {
    buckets: redb::Table<'t, &'static str, u64>,
    objects: redb::Table<'t, &'static [u8], &'static [u8]>,
    inline: redb::Table<'t, u128, &'static [u8]>,
    uploads: redb::Table<'t, u128, &'static [u8]>,
    parts: redb::Table<'t, (u128, u32), &'static [u8]>,
    config: redb::Table<'t, (&'static str, &'static str), &'static [u8]>,
    versions: redb::Table<'t, &'static [u8], &'static [u8]>,
    usage: redb::Table<'t, &'static str, (u64, u64)>,
    part_bytes: redb::Table<'t, &'static str, u64>,
    repl: redb::Table<'t, &'static [u8], (u64, u64)>,
    repl_wait: redb::Table<'t, &'static [u8], (u64, u64)>,
    events: redb::Table<'t, &'static [u8], &'static [u8]>,
    keys: redb::Table<'t, &'static str, &'static [u8]>,
}

fn usage_add(tx: &mut Tables, bucket: &str, objects: i64, bytes: i64) -> S3Result<()> {
    let (n, b) = tx.usage.get(bucket)?.map(|v| v.value()).unwrap_or((0, 0));
    let n = n.saturating_add_signed(objects);
    let b = b.saturating_add_signed(bytes);
    tx.usage.insert(bucket, (n, b))?;
    Ok(())
}

fn part_bytes_add(tx: &mut Tables, bucket: &str, bytes: i64) -> S3Result<()> {
    let b = tx.part_bytes.get(bucket)?.map(|v| v.value()).unwrap_or(0).saturating_add_signed(bytes);
    if b == 0 {
        tx.part_bytes.remove(bucket)?;
    } else {
        tx.part_bytes.insert(bucket, b)?;
    }
    Ok(())
}

/// What a write changes, for the quota check.
#[derive(Default)]
struct QuotaDelta {
    /// Bytes added.
    add: u64,
    /// Adds an object version (false for parts and for overwrites that replace one).
    new_object: bool,
    /// Bytes of objects the write discards.
    freed: u64,
    /// Bytes of multipart parts the write releases.
    freed_parts: u64,
}

impl QuotaDelta {
    /// An upload of `size` bytes replacing `replaced` (see `replaced_size`).
    fn object(size: u64, replaced: Option<u64>) -> Self {
        QuotaDelta { add: size, new_object: replaced.is_none(), freed: replaced.unwrap_or(0), freed_parts: 0 }
    }

    /// Whether `q` allows the write, given the bucket's `usage` and bytes in pending `parts`.
    fn allowed(&self, q: &Quota, (n, b): (u64, u64), parts: u64) -> bool {
        let n_after = n + self.new_object as u64;
        let b_after = (b + parts).saturating_sub(self.freed + self.freed_parts).saturating_add(self.add);
        !((q.max_objects > 0 && self.new_object && n_after > q.max_objects) || (q.max_bytes > 0 && b_after > q.max_bytes))
    }
}

/// Refuse a write that would take the bucket over its quota. Bytes in multipart parts count
/// towards the byte quota until the upload is completed or aborted.
fn check_quota(tx: &Tables, bucket: &str, d: QuotaDelta) -> S3Result<()> {
    let Some(q) = tx.config.get((bucket, "quota"))?.and_then(|v| Quota::decode(v.value())) else { return Ok(()) };
    let usage = tx.usage.get(bucket)?.map(|v| v.value()).unwrap_or((0, 0));
    let parts = tx.part_bytes.get(bucket)?.map(|v| v.value()).unwrap_or(0);
    if !d.allowed(&q, usage, parts) {
        return Err(quota_exceeded());
    }
    Ok(())
}

/// Bytes an upload of `key` would free by replacing a stored object version: the current
/// object if the bucket keeps no history of it, or (versioning suspended) the "null" version.
fn replaced_size(tx: &Tables, bucket: &str, key: &str) -> S3Result<Option<u64>> {
    let state = versioning_state(tx, bucket)?;
    let cur = get_meta(tx, &obj_key(bucket, key))?;
    Ok(match (state, cur) {
        (Versioning::Unversioned, Some(cur)) => Some(cur.size),
        (Versioning::Suspended, Some(cur)) if cur.version.is_none() => (!cur.delete_marker).then_some(cur.size),
        (Versioning::Suspended, _) => {
            // The new null version replaces a noncurrent null version (a delete marker frees nothing).
            let p = ver_prefix(bucket, key);
            let end = prefix_successor(&p).expect("prefix ends with 0");
            let mut found = None;
            for e in tx.versions.range::<&[u8]>(p.as_slice()..end.as_slice())? {
                let m = ObjectMeta::decode(e?.1.value())?;
                if m.version.is_none() && !m.delete_marker {
                    found = Some(m.size);
                }
            }
            found
        }
        _ => None,
    })
}

/// Compute per-bucket usage from scratch (first start with usage tracking, or `force`).
fn rebuild_usage_if_needed(db: &Database, force: bool) -> S3Result<()> {
    let txn = db.begin_write()?;
    if !force && txn.open_table(STATE)?.get("usage_version")?.map(|v| v.value()) == Some(USAGE_VERSION) {
        return Ok(());
    }
    let started = Instant::now();
    let mut usage: std::collections::HashMap<String, (u64, u64)> = std::collections::HashMap::new();
    let bucket_of = |k: &[u8]| String::from_utf8_lossy(&k[..k.iter().position(|b| *b == 0).unwrap_or(k.len())]).into_owned();
    // Unreadable records are skipped (s3rs fsck reports them) rather than failing the start.
    let mut skipped = 0u64;
    for e in txn.open_table(OBJECTS)?.iter()? {
        let (k, v) = e?;
        let Ok(m) = ObjectMeta::decode_summary(v.value()) else {
            skipped += 1;
            continue;
        };
        let u = usage.entry(bucket_of(k.value())).or_default();
        *u = (u.0 + 1, u.1 + m.size);
    }
    for e in txn.open_table(VERSIONS)?.iter()? {
        let (k, v) = e?;
        let Ok(m) = ObjectMeta::decode(v.value()) else {
            skipped += 1;
            continue;
        };
        if !m.delete_marker {
            let u = usage.entry(bucket_of(k.value())).or_default();
            *u = (u.0 + 1, u.1 + m.size);
        }
    }
    let parts = pending_part_bytes(&txn)?;
    {
        let mut t = txn.open_table(USAGE)?;
        t.retain(|_, _| false)?;
        for (b, u) in &usage {
            t.insert(b.as_str(), *u)?;
        }
        let mut t = txn.open_table(PART_BYTES)?;
        t.retain(|_, _| false)?;
        for (b, n) in &parts {
            t.insert(b.as_str(), *n)?;
        }
        txn.open_table(STATE)?.insert("usage_version", USAGE_VERSION)?;
    }
    txn.commit()?;
    if !usage.is_empty() {
        elog!("usage: computed for {} bucket(s) in {:.1}s", usage.len(), started.elapsed().as_secs_f64());
    }
    if skipped > 0 {
        elog!("usage: skipped {skipped} unreadable object record(s); run s3rs fsck");
    }
    Ok(())
}

/// Bytes in multipart upload parts per bucket.
fn pending_part_bytes(txn: &redb::WriteTransaction) -> S3Result<std::collections::HashMap<String, u64>> {
    let uploads = txn.open_table(UPLOADS)?;
    let mut out: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut bucket_of: std::collections::HashMap<u128, Option<String>> = std::collections::HashMap::new();
    for e in txn.open_table(PARTS)?.iter()? {
        let (k, v) = e?;
        let upload = k.value().0;
        if let std::collections::hash_map::Entry::Vacant(slot) = bucket_of.entry(upload) {
            slot.insert(uploads.get(upload)?.and_then(|u| UploadMeta::decode(u.value()).ok()).map(|u| u.bucket));
        }
        if let Some(Some(b)) = bucket_of.get(&upload) {
            *out.entry(b.clone()).or_default() += PartMeta::decode(v.value()).map_or(0, |p| p.size);
        }
    }
    out.retain(|_, n| *n > 0);
    Ok(out)
}

fn check_cond(existing: Option<&ObjectMeta>, cond: &Option<WriteCond>) -> S3Result<()> {
    // A delete marker is no object.
    let existing = existing.filter(|m| !m.delete_marker);
    match (cond, existing) {
        (None, _) => Ok(()),
        (Some(WriteCond::All(conds)), _) => conds.iter().try_for_each(|c| check_cond(existing, &Some(c.clone()))),
        (Some(WriteCond::NotMatches(list)), Some(m)) if list.split(',').any(|e| norm_etag(e) == norm_etag(&m.etag)) => {
            Err(err::PreconditionFailed())
        }
        (Some(WriteCond::NotMatches(_)), _) => Ok(()),
        (Some(WriteCond::NotExists), None) => Ok(()),
        (Some(WriteCond::NotExists), Some(_)) => Err(err::PreconditionFailed()),
        (Some(WriteCond::Matches(_)), None) => Err(err::NoSuchKey()),
        (Some(WriteCond::Matches(e)), Some(m)) => {
            if e.split(',').any(|e| e.trim() == "*" || norm_etag(e) == norm_etag(&m.etag)) {
                Ok(())
            } else {
                Err(err::PreconditionFailed())
            }
        }
    }
}

fn get_meta(tx: &Tables, k: &[u8]) -> S3Result<Option<ObjectMeta>> {
    match tx.objects.get(k)? {
        Some(v) => Ok(Some(ObjectMeta::decode(v.value())?)),
        None => Ok(None),
    }
}

fn drop_upload(tx: &mut Tables, upload: u128, garbage: &mut Vec<u128>) -> S3Result<()> {
    let bucket = tx.uploads.remove(upload)?.map(|u| UploadMeta::decode(u.value())).transpose()?.map(|u| u.bucket);
    let mut keys = Vec::new();
    let mut bytes = 0u64;
    for e in tx.parts.range((upload, 0)..=(upload, u32::MAX))? {
        let (k, v) = e?;
        keys.push(k.value().1);
        let p = PartMeta::decode(v.value())?;
        bytes += p.size;
        garbage.push(p.file);
    }
    for p in keys {
        tx.parts.remove((upload, p))?;
    }
    if let Some(b) = bucket {
        part_bytes_add(tx, &b, -(bytes as i64))?;
    }
    Ok(())
}

/// Bytes held by the parts of one upload.
fn upload_part_bytes(tx: &Tables, upload: u128) -> S3Result<u64> {
    let mut bytes = 0;
    for e in tx.parts.range((upload, 0)..=(upload, u32::MAX))? {
        bytes += PartMeta::decode(e?.1.value())?.size;
    }
    Ok(bytes)
}

// -------------------------------------------------------------------- versioning (writer side)

fn versioning_state(tx: &Tables, bucket: &str) -> S3Result<Versioning> {
    Ok(Versioning::parse(tx.config.get((bucket, "versioning"))?.as_ref().map(|v| v.value())))
}

/// Release the storage behind a version (no-op for delete markers).
fn release(tx: &mut Tables, bucket: &str, meta: &ObjectMeta, garbage: &mut Vec<u128>) -> S3Result<()> {
    if meta.delete_marker {
        return Ok(());
    }
    usage_add(tx, bucket, -1, -(meta.size as i64))?;
    match &meta.storage {
        Storage::Inline(id) => {
            tx.inline.remove(*id)?;
        }
        Storage::Segments(s) => garbage.extend(s.iter().map(|(id, _)| *id)),
    }
    Ok(())
}

/// Newest noncurrent entry of a key.
fn newest_noncurrent(tx: &Tables, bucket: &str, key: &str) -> S3Result<Option<(Vec<u8>, ObjectMeta)>> {
    let p = ver_prefix(bucket, key);
    let end = prefix_successor(&p).expect("prefix ends with 0");
    match tx.versions.range::<&[u8]>(p.as_slice()..end.as_slice())?.next() {
        Some(e) => {
            let (k, v) = e?;
            Ok(Some((k.value().to_vec(), ObjectMeta::decode(v.value())?)))
        }
        None => Ok(None),
    }
}

/// A sequence number newer than anything this key has (robust against clock steps).
fn alloc_seq(tx: &Tables, last: &mut u64, bucket: &str, key: &str, current: Option<&ObjectMeta>) -> S3Result<u64> {
    let mut seq = (*last + 1).max(now_ms() << 20);
    if let Some(c) = current {
        seq = seq.max(c.seq + 1);
    }
    if let Some((_, n)) = newest_noncurrent(tx, bucket, key)? {
        seq = seq.max(n.seq + 1);
    }
    *last = seq;
    Ok(seq)
}

/// Remove every noncurrent "null" version (or null delete marker) of a key.
fn remove_null_versions(tx: &mut Tables, bucket: &str, key: &str, garbage: &mut Vec<u128>) -> S3Result<()> {
    let p = ver_prefix(bucket, key);
    let end = prefix_successor(&p).expect("prefix ends with 0");
    let mut doomed = Vec::new();
    for e in tx.versions.range::<&[u8]>(p.as_slice()..end.as_slice())? {
        let (k, v) = e?;
        let m = ObjectMeta::decode(v.value())?;
        if m.version.is_none() {
            doomed.push((k.value().to_vec(), m));
        }
    }
    for (k, m) in doomed {
        tx.versions.remove(k.as_slice())?;
        release(tx, bucket, &m, garbage)?;
    }
    Ok(())
}

/// Move the current version (if any) out of OBJECTS according to the bucket's versioning.
fn retire_current(tx: &mut Tables, state: Versioning, bucket: &str, key: &str, garbage: &mut Vec<u128>) -> S3Result<()> {
    let k = obj_key(bucket, key);
    let Some(old) = tx.objects.remove(k.as_slice())?.map(|g| ObjectMeta::decode(g.value())).transpose()? else {
        return Ok(());
    };
    // Unversioned buckets keep no history; a suspended bucket's new "null" version replaces
    // the old null one; with versioning enabled every previous version is kept.
    let discard = match state {
        Versioning::Unversioned => true,
        Versioning::Suspended => old.version.is_none(),
        Versioning::Enabled => false,
    };
    if discard {
        release(tx, bucket, &old, garbage)
    } else {
        tx.versions.insert(ver_key(bucket, key, old.seq).as_slice(), old.encode().as_slice())?;
        Ok(())
    }
}

/// Install `meta` as the new current version of a key.
fn put_version(
    tx: &mut Tables,
    last_seq: &mut u64,
    bucket: &str,
    key: &str,
    mut meta: ObjectMeta,
    garbage: &mut Vec<u128>,
) -> S3Result<ObjectMeta> {
    let state = versioning_state(tx, bucket)?;
    let k = obj_key(bucket, key);
    let current = get_meta(tx, &k)?;
    meta.seq = alloc_seq(tx, last_seq, bucket, key, current.as_ref())?;
    meta.delete_marker = false;
    meta.version = (state == Versioning::Enabled).then(|| new_version_id(meta.seq));
    retire_current(tx, state, bucket, key, garbage)?;
    if state == Versioning::Suspended {
        remove_null_versions(tx, bucket, key, garbage)?;
    }
    tx.objects.insert(k.as_slice(), meta.encode().as_slice())?;
    usage_add(tx, bucket, 1, meta.size as i64)?;
    Ok(meta)
}

/// DELETE without a version id.
fn delete_current(
    tx: &mut Tables,
    last_seq: &mut u64,
    bucket: &str,
    key: &str,
    garbage: &mut Vec<u128>,
) -> S3Result<DeleteOutcome> {
    let state = versioning_state(tx, bucket)?;
    if state == Versioning::Unversioned {
        let existed = get_meta(tx, &obj_key(bucket, key))?.is_some();
        retire_current(tx, state, bucket, key, garbage)?;
        let seq = if existed { next_seq(last_seq) } else { 0 };
        return Ok(DeleteOutcome { removed: existed, seq, ..Default::default() });
    }
    let current = get_meta(tx, &obj_key(bucket, key))?;
    let seq = alloc_seq(tx, last_seq, bucket, key, current.as_ref())?;
    retire_current(tx, state, bucket, key, garbage)?;
    if state == Versioning::Suspended {
        remove_null_versions(tx, bucket, key, garbage)?;
    }
    let version = (state == Versioning::Enabled).then(|| new_version_id(seq));
    let marker = ObjectMeta {
        size: 0,
        mtime_ms: now_ms(),
        etag: String::new(),
        headers: Vec::new(),
        checksum: None,
        storage: Storage::Segments(Vec::new()),
        tags: Vec::new(),
        version: version.clone(),
        seq,
        delete_marker: true,
    };
    tx.versions.insert(ver_key(bucket, key, seq).as_slice(), marker.encode().as_slice())?;
    Ok(DeleteOutcome { version_id: Some(version.unwrap_or_else(|| "null".into())), delete_marker: true, removed: true, seq })
}

/// If a key has no current version, make its newest noncurrent entry current, unless that
/// entry is a delete marker (which then simply remains the latest version).
fn promote(tx: &mut Tables, bucket: &str, key: &str) -> S3Result<()> {
    let k = obj_key(bucket, key);
    if tx.objects.get(k.as_slice())?.is_some() {
        return Ok(());
    }
    if let Some((vk, m)) = newest_noncurrent(tx, bucket, key)?
        && !m.delete_marker
    {
        tx.versions.remove(vk.as_slice())?;
        tx.objects.insert(k.as_slice(), m.encode().as_slice())?;
    }
    Ok(())
}

/// Locate a specific version: Some((in_objects, versions_key, meta)).
fn find_version(tx: &Tables, bucket: &str, key: &str, vid: &str) -> S3Result<Option<(bool, Vec<u8>, ObjectMeta)>> {
    let want = (vid != "null").then_some(vid);
    let k = obj_key(bucket, key);
    if let Some(cur) = get_meta(tx, &k)?
        && cur.version.as_deref() == want
    {
        return Ok(Some((true, k, cur)));
    }
    match want {
        Some(v) => {
            let Some(seq) = version_seq(v) else { return Ok(None) };
            let vk = ver_key(bucket, key, seq);
            match tx.versions.get(vk.as_slice())? {
                Some(g) => {
                    let m = ObjectMeta::decode(g.value())?;
                    Ok((m.version.as_deref() == Some(v)).then_some((false, vk, m)))
                }
                None => Ok(None),
            }
        }
        None => {
            let p = ver_prefix(bucket, key);
            let end = prefix_successor(&p).expect("prefix ends with 0");
            for e in tx.versions.range::<&[u8]>(p.as_slice()..end.as_slice())? {
                let (vk, v) = e?;
                let m = ObjectMeta::decode(v.value())?;
                if m.version.is_none() {
                    return Ok(Some((false, vk.value().to_vec(), m)));
                }
            }
            Ok(None)
        }
    }
}

/// DELETE with a version id: permanently remove that version (unless Object Lock protects it).
fn delete_version(
    tx: &mut Tables,
    bucket: &str,
    key: &str,
    vid: &str,
    bypass: bool,
    garbage: &mut Vec<u128>,
) -> S3Result<DeleteOutcome> {
    if !valid_version_id(vid) {
        return Err(err::InvalidArgument().with_message("Invalid version id specified"));
    }
    let mut out = DeleteOutcome { version_id: Some(vid.to_string()), ..Default::default() };
    if let Some((in_objects, k, m)) = find_version(tx, bucket, key, vid)? {
        lock::State::of(&m.headers).check_delete(now_ms() / 1000, bypass)?;
        if in_objects {
            tx.objects.remove(k.as_slice())?;
        } else {
            tx.versions.remove(k.as_slice())?;
        }
        out.delete_marker = m.delete_marker;
        out.removed = true;
        release(tx, bucket, &m, garbage)?;
        promote(tx, bucket, key)?;
    }
    Ok(out)
}

/// Modify one version's metadata in place (the current version when `version` is None).
fn update_version(
    tx: &mut Tables,
    bucket: &str,
    key: &str,
    version: Option<&str>,
    change: impl FnOnce(&mut ObjectMeta) -> S3Result<()>,
) -> S3Result<ObjectMeta> {
    if tx.buckets.get(bucket)?.is_none() {
        return Err(err::NoSuchBucket());
    }
    let found = match version {
        Some(v) => find_version(tx, bucket, key, v)?,
        None => get_meta(tx, &obj_key(bucket, key))?.map(|m| (true, obj_key(bucket, key), m)),
    };
    let Some((in_objects, k, mut meta)) = found else {
        return Err(if version.is_some() { err::NoSuchVersion() } else { err::NoSuchKey() });
    };
    if meta.delete_marker {
        return Err(err::MethodNotAllowed());
    }
    change(&mut meta)?;
    if in_objects {
        tx.objects.insert(k.as_slice(), meta.encode().as_slice())?;
    } else {
        tx.versions.insert(k.as_slice(), meta.encode().as_slice())?;
    }
    Ok(meta)
}

fn bucket_has_versions(tx: &Tables, bucket: &str) -> S3Result<bool> {
    let lo = obj_key(bucket, "");
    let mut hi = bucket.as_bytes().to_vec();
    hi.push(1);
    Ok(tx.versions.range::<&[u8]>(lo.as_slice()..hi.as_slice())?.next().is_some())
}

/// Stored headers with this prefix are internal: never sent to clients or copied.
pub const INTERNAL_PREFIX: &str = "x-s3rs-";
/// An upload's checksum algorithm and type (CreateMultipartUpload).
pub const UPLOAD_CHECKSUM_ALGO: &str = "x-s3rs-checksum-algorithm";
pub const UPLOAD_CHECKSUM_TYPE: &str = "x-s3rs-checksum-type";
/// A multipart object's part checksums, comma-separated in part order.
pub const PART_CHECKSUMS: &str = "x-s3rs-part-checksums";

/// The stored header that marks an object written by replication from another server.
pub const REPLICA_HEADER: &str = "x-amz-replication-status";

pub fn is_replica(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| k == REPLICA_HEADER && v == "REPLICA")
}

/// Sequence numbers for replication queue entries: increasing, also across restarts.
fn next_repl_seq() -> u64 {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    SEQ.fetch_max(now_ms() << 16, std::sync::atomic::Ordering::SeqCst);
    SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
}

/// Queue `key` for replication, keeping the time of the oldest change not yet replicated.
fn repl_insert(tx: &mut Tables, bucket: &str, key: &str, now: u64) -> S3Result<()> {
    let k = obj_key(bucket, key);
    let since = tx.repl.get(k.as_slice())?.map_or(now, |v| v.value().1);
    tx.repl.insert(k.as_slice(), (next_repl_seq(), since))?;
    Ok(())
}

/// The bucket and keys an operation may change, if the bucket replicates any of them. Ops that
/// change a bucket's configuration drop its cached rules.
fn repl_touched(tx: &mut Tables, rules: &mut HashMap<String, Vec<String>>, op: &Op) -> S3Result<Option<(String, Vec<String>)>> {
    // Changes made by replication from another server are not replicated again, deletes of
    // specific versions are not replicated (as in S3), and neither are lifecycle expirations
    // (each side applies its own lifecycle rules).
    let (bucket, keys): (&str, Vec<&str>) = match op {
        Op::PutObject { meta, .. } if is_replica(&meta.headers) => return Ok(None),
        Op::SetObjectTags { replica: true, .. } | Op::DeleteObjects { replica: true, .. } => return Ok(None),
        Op::PutObject { bucket, key, .. } | Op::Complete { bucket, key, .. } | Op::SetObjectTags { bucket, key, .. } => {
            (bucket, vec![key.as_str()])
        }
        Op::DeleteObjects { bucket, items, .. } => {
            (bucket, items.iter().filter(|(_, v)| v.is_none()).map(|(k, _)| k.as_str()).collect())
        }
        Op::SetBucketConfig { bucket, .. } | Op::DeleteBucket(bucket) => {
            rules.remove(bucket.as_str());
            return Ok(None);
        }
        _ => return Ok(None),
    };
    if !rules.contains_key(bucket) {
        let prefixes = match tx.config.get((bucket, "replication"))? {
            Some(raw) => crate::replication::load(raw.value()).into_iter().filter(|r| r.enabled).map(|r| r.prefix).collect(),
            None => Vec::new(),
        };
        rules.insert(bucket.to_string(), prefixes);
    }
    let prefixes = &rules[bucket];
    let keys: Vec<String> =
        keys.into_iter().filter(|k| prefixes.iter().any(|p| k.starts_with(p.as_str()))).map(String::from).collect();
    Ok((!keys.is_empty()).then(|| (bucket.to_string(), keys)))
}

/// Queue the keys `repl_touched` found. Returns whether anything was queued.
fn repl_enqueue(tx: &mut Tables, bucket: &str, keys: &[String]) -> S3Result<bool> {
    let now = now_ms();
    for key in keys {
        repl_insert(tx, bucket, key, now)?;
    }
    Ok(!keys.is_empty())
}

fn apply(tx: &mut Tables, op: Op, garbage: &mut Vec<u128>, last_seq: &mut u64) -> S3Result<OpOut> {
    match op {
        Op::WithEvents(op, _) => apply(tx, *op, garbage, last_seq),
        Op::Flush | Op::Ping => Ok(OpOut::Done),
        Op::DeleteEvents(keys) => {
            for k in keys {
                tx.events.remove(k.as_slice())?;
            }
            Ok(OpOut::Done)
        }
        Op::CreateKey { access_key, record } => {
            if tx.keys.get(access_key.as_str())?.is_some() {
                return Err(S3Error::new("KeyAlreadyExists", hyper::StatusCode::CONFLICT, "The access key already exists."));
            }
            tx.keys.insert(access_key.as_str(), record.as_slice())?;
            Ok(OpOut::Done)
        }
        Op::DeleteKeyIf { access_key, record } => {
            let same = tx.keys.get(access_key.as_str())?.is_some_and(|v| v.value() == record.as_slice());
            if same {
                tx.keys.remove(access_key.as_str())?;
            }
            Ok(OpOut::More(same))
        }
        Op::DeleteKey(access_key) => match tx.keys.remove(access_key.as_str())? {
            Some(_) => Ok(OpOut::Done),
            None => Err(S3Error::new("NoSuchAccessKey", hyper::StatusCode::NOT_FOUND, "The access key does not exist.")),
        },
        Op::ReplDone { bucket, key, seq } => {
            let k = obj_key(&bucket, &key);
            if tx.repl.get(k.as_slice())?.map(|v| v.value().0) == Some(seq) {
                tx.repl.remove(k.as_slice())?;
            }
            Ok(OpOut::Done)
        }
        Op::ReplFailed { bucket, key, seq, retry_ms } => {
            let k = obj_key(&bucket, &key);
            let current = tx.repl.get(k.as_slice())?.map(|v| v.value());
            if let Some((cur, since)) = current
                && cur == seq
            {
                tx.repl.remove(k.as_slice())?;
                let mut w = retry_ms.to_be_bytes().to_vec();
                w.extend_from_slice(&k);
                tx.repl_wait.insert(w.as_slice(), (seq, since))?;
            }
            Ok(OpOut::Done)
        }
        Op::ReplRequeue { before_ms, limit } => {
            let end = before_ms.to_be_bytes();
            let mut due = Vec::new();
            for e in tx.repl_wait.range::<&[u8]>(..end.as_slice())?.take(limit + 1) {
                let (k, v) = e?;
                due.push((k.value().to_vec(), v.value()));
            }
            let more = due.len() > limit;
            due.truncate(limit);
            for (w, (seq, since)) in due {
                tx.repl_wait.remove(w.as_slice())?;
                let k = &w[8..];
                // A newer change re-queued the key already; keep the older start time.
                let merged = match tx.repl.get(k)?.map(|v| v.value()) {
                    Some((cur, s)) => (cur, s.min(since)),
                    None => (seq, since),
                };
                tx.repl.insert(k, merged)?;
            }
            Ok(OpOut::More(more))
        }
        Op::ReplBackfill { bucket, limit } => {
            let Some(cursor) = tx.config.get((bucket.as_str(), "replication-backfill"))?.map(|v| v.value().to_vec()) else {
                return Ok(OpOut::More(false));
            };
            let prefixes: Vec<String> = match tx.config.get((bucket.as_str(), "replication"))? {
                Some(raw) => crate::replication::load(raw.value())
                    .into_iter()
                    .filter(|r| r.enabled && r.existing)
                    .map(|r| r.prefix)
                    .collect(),
                None => Vec::new(),
            };
            let start = obj_key(&bucket, std::str::from_utf8(&cursor).unwrap_or(""));
            let end = prefix_successor(&obj_key(&bucket, "")).expect("bucket prefix ends with 0");
            let lo = if cursor.is_empty() { Bound::Included(start.as_slice()) } else { Bound::Excluded(start.as_slice()) };
            let mut keys = Vec::new();
            if !prefixes.is_empty() {
                for e in tx.objects.range::<&[u8]>((lo, Bound::Excluded(end.as_slice())))?.take(limit) {
                    let (k, _) = e?;
                    keys.push(String::from_utf8_lossy(&k.value()[bucket.len() + 1..]).into_owned());
                }
            }
            let now = now_ms();
            for key in &keys {
                if prefixes.iter().any(|p| key.starts_with(p.as_str())) {
                    repl_insert(tx, &bucket, key, now)?;
                }
            }
            match keys.last() {
                Some(last) if keys.len() == limit => {
                    tx.config.insert((bucket.as_str(), "replication-backfill"), last.as_bytes())?;
                    Ok(OpOut::More(true))
                }
                _ => {
                    tx.config.remove((bucket.as_str(), "replication-backfill"))?;
                    Ok(OpOut::More(false))
                }
            }
        }
        Op::CreateBucket(name) => {
            if tx.buckets.get(name.as_str())?.is_some() {
                return Err(err::BucketAlreadyOwnedByYou());
            }
            tx.buckets.insert(name.as_str(), now_ms())?;
            Ok(OpOut::Done)
        }
        Op::DeleteBucket(name) => {
            if tx.buckets.get(name.as_str())?.is_none() {
                return Err(err::NoSuchBucket());
            }
            let lo = obj_key(&name, "");
            let mut hi = name.as_bytes().to_vec();
            hi.push(1);
            if tx.objects.range::<&[u8]>(lo.as_slice()..hi.as_slice())?.next().is_some() || bucket_has_versions(tx, &name)? {
                return Err(err::BucketNotEmpty());
            }
            let mut stale = Vec::new();
            for e in tx.uploads.iter()? {
                let (k, v) = e?;
                if UploadMeta::decode(v.value())?.bucket == name {
                    stale.push(k.value());
                }
            }
            for id in stale {
                drop_upload(tx, id, garbage)?;
            }
            for kind in CONFIG_KINDS {
                tx.config.remove((name.as_str(), *kind))?;
            }
            tx.usage.remove(name.as_str())?;
            tx.part_bytes.remove(name.as_str())?;
            tx.buckets.remove(name.as_str())?;
            let prefix = obj_key(&name, "");
            let end = prefix_successor(&prefix).expect("bucket prefix ends with 0");
            tx.repl.retain_in::<&[u8], _>(prefix.as_slice()..end.as_slice(), |_, _| false)?;
            Ok(OpOut::Done)
        }
        Op::PutObject { bucket, key, meta, inline, cond } => {
            check_key_chars(&key)?;
            if tx.buckets.get(bucket.as_str())?.is_none() {
                return Err(err::NoSuchBucket());
            }
            let k = obj_key(&bucket, &key);
            if cond.is_some() {
                check_cond(get_meta(tx, &k)?.as_ref(), &cond)?;
            }
            check_quota(tx, &bucket, QuotaDelta::object(meta.size, replaced_size(tx, &bucket, &key)?))?;
            if let (Storage::Inline(id), Some(data)) = (&meta.storage, &inline) {
                tx.inline.insert(*id, data.as_ref())?;
            }
            Ok(OpOut::Object(put_version(tx, last_seq, &bucket, &key, meta, garbage)?))
        }
        Op::Expire { bucket, items } => {
            let mut out = Vec::new();
            for (key, mtime) in items {
                let k = obj_key(&bucket, &key);
                if let Some(m) = get_meta(tx, &k)?.filter(|m| m.mtime_ms == mtime) {
                    let o = delete_current(tx, last_seq, &bucket, &key, garbage)?;
                    let marker = o.delete_marker;
                    let version = if marker { o.version_id.filter(|v| v != "null") } else { m.version.clone() };
                    let (size, etag) = if marker { (0, String::new()) } else { (m.size, m.etag) };
                    out.push(Removed { key, version, marker_created: marker, size, etag, seq: o.seq });
                }
            }
            Ok(OpOut::Removed(out))
        }
        Op::DeleteObjects { bucket, items, conds, bypass, .. } => {
            if tx.buckets.get(bucket.as_str())?.is_none() {
                return Err(err::NoSuchBucket());
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, (key, version)) in items.into_iter().enumerate() {
                let cond = conds.get(i).cloned().flatten();
                let r = check_key_chars(&key).and_then(|_| {
                    if let Some(c) = &cond {
                        let target = match &version {
                            Some(v) if valid_version_id(v) => find_version(tx, &bucket, &key, v)?.map(|(_, _, m)| m),
                            Some(_) => None,
                            None => get_meta(tx, &obj_key(&bucket, &key))?.filter(|m| !m.delete_marker),
                        };
                        if let Some(m) = target {
                            c.check(&m)?;
                        }
                    }
                    Ok(())
                });
                let r = r.and_then(|_| match version {
                    Some(v) => delete_version(tx, &bucket, &key, &v, bypass, garbage).map(|mut o| {
                        if o.removed {
                            o.seq = next_seq(last_seq);
                        }
                        o
                    }),
                    None => delete_current(tx, last_seq, &bucket, &key, garbage),
                });
                if let Err(e) = &r
                    && e.code == "InternalError"
                {
                    return Err(e.clone());
                }
                out.push(r);
            }
            Ok(OpOut::Deleted(out))
        }
        Op::CreateUpload { id, meta } => {
            check_key_chars(&meta.key)?;
            if tx.buckets.get(meta.bucket.as_str())?.is_none() {
                return Err(err::NoSuchBucket());
            }
            tx.uploads.insert(id, meta.encode().as_slice())?;
            Ok(OpOut::Done)
        }
        Op::PutPart { upload, bucket, key, part, meta } => {
            let Some(u) = tx.uploads.get(upload)?.map(|v| UploadMeta::decode(v.value())).transpose()? else {
                return Err(err::NoSuchUpload());
            };
            if u.bucket != bucket || u.key != key {
                return Err(err::NoSuchUpload());
            }
            let old = tx.parts.get((upload, part))?.map(|v| PartMeta::decode(v.value())).transpose()?;
            let old_size = old.as_ref().map_or(0, |o| o.size);
            check_quota(tx, &bucket, QuotaDelta { add: meta.size, freed_parts: old_size, ..Default::default() })?;
            tx.parts.insert((upload, part), meta.encode().as_slice())?;
            if let Some(old) = old {
                garbage.push(old.file);
            }
            part_bytes_add(tx, &bucket, meta.size as i64 - old_size as i64)?;
            Ok(OpOut::Done)
        }
        Op::Abort { bucket, key, upload } => {
            let Some(u) = tx.uploads.get(upload)?.map(|v| UploadMeta::decode(v.value())).transpose()? else {
                return Err(err::NoSuchUpload());
            };
            if u.bucket != bucket || u.key != key {
                return Err(err::NoSuchUpload());
            }
            drop_upload(tx, upload, garbage)?;
            Ok(OpOut::Done)
        }
        Op::SetBucketConfig { bucket, kind, value } => {
            if tx.buckets.get(bucket.as_str())?.is_none() {
                return Err(err::NoSuchBucket());
            }
            // Object Lock relies on every version being kept: it needs versioning enabled, and
            // versioning cannot be suspended once it is on.
            let has_lock = tx.config.get((bucket.as_str(), "object-lock"))?.is_some();
            if kind == "versioning" && has_lock && value.as_deref() != Some(b"Enabled".as_slice()) {
                return Err(lock::invalid_bucket_state(
                    "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.",
                ));
            }
            if kind == "object-lock" {
                if value.is_none() {
                    return Err(lock::invalid_bucket_state("Object Lock cannot be disabled once enabled"));
                }
                if versioning_state(tx, &bucket)? != Versioning::Enabled {
                    return Err(lock::invalid_bucket_state(
                        "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration",
                    ));
                }
            }
            match value {
                Some(v) => tx.config.insert((bucket.as_str(), kind), v.as_slice())?,
                None => tx.config.remove((bucket.as_str(), kind))?,
            };
            Ok(OpOut::Done)
        }
        Op::SetObjectTags { bucket, key, version, tags, .. } => {
            update_version(tx, &bucket, &key, version.as_deref(), |meta| {
                meta.tags = tags;
                Ok(())
            })?;
            Ok(OpOut::Done)
        }
        Op::SetObjectLock { bucket, key, version, retention, legal_hold, bypass } => {
            if tx.config.get((bucket.as_str(), "object-lock"))?.is_none() && tx.buckets.get(bucket.as_str())?.is_some() {
                return Err(lock::missing_config());
            }
            let meta = update_version(tx, &bucket, &key, version.as_deref(), |meta| {
                let mut state = lock::State::of(&meta.headers);
                if let Some(new) = retention {
                    state.check_retention_change(new, now_ms() / 1000, bypass)?;
                    state.retention = new;
                }
                if let Some(on) = legal_hold {
                    state.legal_hold = Some(on);
                }
                state.store(&mut meta.headers);
                Ok(())
            })?;
            Ok(OpOut::Object(meta))
        }
        Op::PurgeVersions { bucket, items } => {
            let mut out = Vec::new();
            for (key, seq, rule) in items {
                let vk = ver_key(&bucket, &key, seq);
                let Some(m) = tx.versions.get(vk.as_slice())?.map(|g| ObjectMeta::decode(g.value())).transpose()? else {
                    continue;
                };
                let p = ver_prefix(&bucket, &key);
                let still_due = match rule {
                    // Noncurrent since the next-newer version was written.
                    PurgeRule::NoncurrentBefore(cutoff_secs) => {
                        let newer = match tx.versions.range::<&[u8]>(p.as_slice()..vk.as_slice())?.next_back() {
                            Some(e) => Some(ObjectMeta::decode(e?.1.value())?.mtime_ms),
                            None => get_meta(tx, &obj_key(&bucket, &key))?.map(|c| c.mtime_ms),
                        };
                        newer.is_some_and(|since| since / 1000 <= cutoff_secs)
                    }
                    // A delete marker that is the only thing left of its key.
                    PurgeRule::LoneDeleteMarker => {
                        let end = prefix_successor(&p).expect("prefix ends with 0");
                        m.delete_marker
                            && get_meta(tx, &obj_key(&bucket, &key))?.is_none()
                            && tx.versions.range::<&[u8]>(p.as_slice()..end.as_slice())?.take(2).count() == 1
                    }
                };
                // Lifecycle never removes a version that Object Lock protects.
                if still_due && lock::State::of(&m.headers).check_delete(now_ms() / 1000, false).is_ok() {
                    tx.versions.remove(vk.as_slice())?;
                    release(tx, &bucket, &m, garbage)?;
                    promote(tx, &bucket, &key)?;
                    let seq = next_seq(last_seq);
                    out.push(Removed {
                        key,
                        version: m.version.clone(),
                        marker_created: false,
                        size: m.size,
                        etag: m.etag.clone(),
                        seq,
                    });
                }
            }
            Ok(OpOut::Removed(out))
        }
        Op::Complete { bucket, key, upload, parts, checksum, cond } => {
            let Some(u) = tx.uploads.get(upload)?.map(|v| UploadMeta::decode(v.value())).transpose()? else {
                return Err(err::NoSuchUpload());
            };
            if u.bucket != bucket || u.key != key {
                return Err(err::NoSuchUpload());
            }
            if parts.is_empty() {
                return Err(err::MalformedXML().with_message("You must specify at least one part"));
            }
            let mut segs = Vec::with_capacity(parts.len());
            let mut md5s = Vec::with_capacity(parts.len() * 16);
            let mut part_sums: Vec<(Option<(ChecksumAlgo, String)>, u64)> = Vec::with_capacity(parts.len());
            let mut size = 0u64;
            let mut prev = 0u32;
            for (i, (num, etag, listed)) in parts.iter().enumerate() {
                if *num <= prev && i > 0 {
                    return Err(err::InvalidPartOrder());
                }
                prev = *num;
                let p = match tx.parts.get((upload, *num))? {
                    Some(v) => PartMeta::decode(v.value())?,
                    None => return Err(err::InvalidPart()),
                };
                if norm_etag(etag) != util::hex(&p.md5) {
                    return Err(err::InvalidPart());
                }
                if let Some(listed) = listed
                    && p.checksum.as_ref().is_none_or(|(_, v)| v != listed.trim())
                {
                    return Err(err::BadDigest().with_message(format!("The checksum of part {num} does not match")));
                }
                part_sums.push((p.checksum.clone(), p.size));
                if i + 1 < parts.len() && p.size < MIN_PART_SIZE {
                    return Err(err::EntityTooSmall());
                }
                size += p.size;
                md5s.extend_from_slice(&p.md5);
                segs.push((p.file, p.size));
            }
            let k = obj_key(&bucket, &key);
            check_cond(get_meta(tx, &k)?.as_ref(), &cond)?;
            let mut delta = QuotaDelta::object(size, replaced_size(tx, &bucket, &key)?);
            delta.freed_parts = upload_part_bytes(tx, upload)?;
            check_quota(tx, &bucket, delta)?;

            use md5::Digest;
            let etag = format!("\"{}-{}\"", util::hex(&md5::Md5::digest(&md5s)), parts.len());
            // The object's checksum: as declared at CreateMultipartUpload (verified against the
            // client's value if it sent one), or composite when all parts happen to have one.
            let header = |name: &str| u.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
            let declared = header(UPLOAD_CHECKSUM_ALGO).and_then(|a| ChecksumAlgo::from_name(&a));
            let algo = declared.or_else(|| {
                let first = part_sums.first()?.0.as_ref()?.0;
                part_sums.iter().all(|(c, _)| c.as_ref().is_some_and(|(a, _)| *a == first)).then_some(first)
            });
            let mut object_checksum = None;
            let mut part_list = None;
            // The client's checksum of the whole object, if it sent one, must match.
            let claimed = checksum.as_ref().map(|(a, v)| (*a, v.trim().to_string()));
            let unverifiable = || {
                err::InvalidRequest()
                    .with_message("The object checksum can't be verified: the parts have no checksums of that algorithm")
            };
            let mismatch = || err::BadDigest().with_message("The checksum you specified did not match the calculated checksum.");
            if let Some(algo) = algo {
                let kind = header(UPLOAD_CHECKSUM_TYPE)
                    .and_then(|t| crate::checksum::Kind::parse(&t))
                    .or_else(|| crate::checksum::Kind::for_algo(algo, None))
                    .unwrap_or(crate::checksum::Kind::Composite);
                let sums: Option<Vec<(&str, u64)>> = part_sums
                    .iter()
                    .map(|(c, n)| c.as_ref().filter(|(a, _)| *a == algo).map(|(_, v)| (v.as_str(), *n)))
                    .collect();
                match sums.and_then(|s: Vec<(&str, u64)>| crate::checksum::combine(algo, kind, &s).map(|total| (s, total))) {
                    Some((s, mut total)) => {
                        if let Some((a, c)) = &claimed {
                            if *a != algo {
                                return Err(unverifiable());
                            }
                            if *c != total {
                                // Without a declared type, a CRC of the whole object (instead of
                                // the composite default) is fine too, and is then what is stored.
                                let full = (declared.is_none() && !c.contains('-'))
                                    .then(|| crate::checksum::combine(algo, crate::checksum::Kind::FullObject, &s))
                                    .flatten();
                                if full.as_ref() != Some(c) {
                                    return Err(mismatch());
                                }
                                total = c.clone();
                            }
                        }
                        part_list = Some(s.iter().map(|(v, _)| *v).collect::<Vec<_>>().join(","));
                        object_checksum = Some((algo, total));
                    }
                    None if declared.is_some() => {
                        return Err(err::InvalidPart().with_message("A part has no checksum of the upload's algorithm"));
                    }
                    None if claimed.is_some() => return Err(unverifiable()),
                    None => {}
                }
            } else if claimed.is_some() {
                return Err(unverifiable());
            }
            let mut headers: Vec<(String, String)> =
                u.headers.into_iter().filter(|(k, _)| !k.starts_with(INTERNAL_PREFIX)).collect();
            if let Some(list) = part_list {
                headers.push((PART_CHECKSUMS.to_string(), list));
            }
            let meta = ObjectMeta {
                size,
                mtime_ms: now_ms(),
                etag,
                headers,
                checksum: object_checksum,
                storage: Storage::Segments(segs.clone()),
                tags: u.tags,
                version: None,
                seq: 0,
                delete_marker: false,
            };
            let meta = put_version(tx, last_seq, &bucket, &key, meta, garbage)?;
            // Release all parts except those now owned by the object.
            let mut released = Vec::new();
            drop_upload(tx, upload, &mut released)?;
            let used: std::collections::HashSet<u128> = segs.iter().map(|(id, _)| *id).collect();
            garbage.extend(released.into_iter().filter(|id| !used.contains(id)));
            Ok(OpOut::Object(meta))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (Arc<Store>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("s3rs-test-{}", util::id_hex(util::new_id())));
        let store = Store::open(StoreConfig {
            root: dir.clone(),
            fsync: false,
            inline_threshold: 1024,
            cache_bytes: 1 << 20,
            min_free: Some(0),
        })
        .unwrap();
        (store, dir)
    }

    #[test]
    fn newer_data_formats_are_refused() {
        let dir = std::env::temp_dir().join(format!("s3rs-test-{}", util::id_hex(util::new_id())));
        std::fs::create_dir_all(&dir).unwrap();
        {
            let db = Database::create(dir.join("meta.redb")).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(STATE).unwrap().insert("format", FORMAT + 1).unwrap();
            txn.commit().unwrap();
        }
        let open = || {
            Store::open(StoreConfig {
                root: dir.clone(),
                fsync: false,
                inline_threshold: 1024,
                cache_bytes: 1 << 20,
                min_free: Some(0),
            })
        };
        let e = open().err().expect("a newer format is refused");
        assert!(e.message.contains("newer release"), "{}", e.message);
        assert!(fsck::run(&dir, false, None, true).err().unwrap().contains("newer release"));
        assert!(backup::offline(&dir, &mut std::io::sink()).err().unwrap().contains("newer release"));
        // The refusal changed nothing: the stored format is still the newer one.
        {
            let db = Database::create(dir.join("meta.redb")).unwrap();
            let txn = db.begin_read().unwrap();
            assert_eq!(txn.open_table(STATE).unwrap().get("format").unwrap().unwrap().value(), FORMAT + 1);
            assert!(txn.open_table(BUCKETS).is_err(), "no tables were created");
        }
        // A data directory from before the format was recorded is upgraded to the current one.
        std::fs::remove_dir_all(&dir).unwrap();
        let store = open().unwrap();
        drop(store);
        // The writer thread lets go of the database shortly after the store is dropped.
        let mut tries = 0;
        let db = loop {
            match Database::create(dir.join("meta.redb")) {
                Ok(db) => break db,
                Err(_) if tries < 100 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("database still in use: {e}"),
            }
        };
        let txn = db.begin_read().unwrap();
        assert_eq!(txn.open_table(STATE).unwrap().get("format").unwrap().unwrap().value(), FORMAT);
        drop(txn);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn small(data: &str) -> (ObjectMeta, Option<Bytes>) {
        let meta = ObjectMeta {
            size: data.len() as u64,
            mtime_ms: now_ms(),
            etag: format!("\"{}\"", data),
            headers: vec![],
            checksum: None,
            storage: Storage::Inline(util::new_id()),
            tags: vec![],
            version: None,
            seq: 0,
            delete_marker: false,
        };
        (meta, Some(Bytes::copy_from_slice(data.as_bytes())))
    }

    async fn put(store: &Store, key: &str, data: &str) -> ObjectMeta {
        let (meta, inline) = small(data);
        match store.submit(Op::PutObject { bucket: "b".into(), key: key.into(), meta, inline, cond: None }).await.unwrap() {
            OpOut::Object(m) => m,
            _ => unreachable!(),
        }
    }

    async fn delete_version(store: &Store, vid: &str, bypass: bool) -> S3Result<DeleteOutcome> {
        match store
            .submit(Op::DeleteObjects {
                bucket: "b".into(),
                items: vec![("k".into(), Some(vid.into()))],
                conds: vec![],
                bypass,
                replica: false,
            })
            .await
        {
            Ok(OpOut::Deleted(mut r)) => r.pop().unwrap(),
            Ok(_) => unreachable!(),
            Err(e) => Err(e),
        }
    }

    #[tokio::test]
    async fn object_lock_blocks_deletes_and_purges() {
        let (store, dir) = temp_store();
        store.submit(Op::CreateBucket("b".into())).await.unwrap();
        let cfg = |kind, v: &[u8]| Op::SetBucketConfig { bucket: "b".into(), kind, value: Some(v.to_vec()) };
        // Object Lock needs versioning enabled first, and then keeps it enabled.
        assert!(store.submit(cfg("object-lock", b"x")).await.is_err());
        store.submit(cfg("versioning", b"Enabled")).await.unwrap();
        store.submit(cfg("object-lock", lock::BucketLock::default().to_xml().as_bytes())).await.unwrap();
        assert_eq!(store.submit(cfg("versioning", b"Suspended")).await.err().unwrap().code, "InvalidBucketState");

        let set_lock = |version: &str, retention, legal_hold, bypass| Op::SetObjectLock {
            bucket: "b".into(),
            key: "k".into(),
            version: Some(version.to_string()),
            retention,
            legal_hold,
            bypass,
        };
        let far = now_ms() / 1000 + 3600;
        let gov = Some(lock::Retention { mode: lock::Mode::Governance, until: far });
        let comp = Some(lock::Retention { mode: lock::Mode::Compliance, until: far });

        let v1 = put(&store, "k", "one").await.version.unwrap();
        store.submit(set_lock(&v1, Some(gov), None, false)).await.unwrap();
        assert_eq!(delete_version(&store, &v1, false).await.unwrap_err().code, "AccessDenied");
        // GOVERNANCE -> COMPLIANCE needs the bypass; COMPLIANCE can then never be shortened.
        assert_eq!(store.submit(set_lock(&v1, Some(comp), None, false)).await.err().unwrap().code, "AccessDenied");
        store.submit(set_lock(&v1, Some(comp), None, true)).await.unwrap();
        assert!(store.submit(set_lock(&v1, Some(None), None, true)).await.is_err());
        assert_eq!(delete_version(&store, &v1, true).await.unwrap_err().code, "AccessDenied");

        // A newer version makes v1 noncurrent; lifecycle must not purge it while locked.
        let v2 = put(&store, "k", "two").await.version.unwrap();
        let seq = version_seq(&v1).unwrap();
        let purge =
            Op::PurgeVersions { bucket: "b".into(), items: vec![("k".into(), seq, PurgeRule::NoncurrentBefore(u64::MAX))] };
        assert!(matches!(store.submit(purge).await.unwrap(), OpOut::Removed(r) if r.is_empty()));
        assert_eq!(store.get_object_version("b", "k", &v1).unwrap().1.unwrap(), "one");

        // Legal hold blocks even with bypass; GOVERNANCE yields to bypass.
        store.submit(set_lock(&v2, Some(gov), Some(true), false)).await.unwrap();
        assert!(delete_version(&store, &v2, true).await.is_err());
        store.submit(set_lock(&v2, None, Some(false), false)).await.unwrap();
        assert!(delete_version(&store, &v2, false).await.is_err());
        assert!(delete_version(&store, &v2, true).await.is_ok());
        // Deleting without a version id only adds a delete marker.
        let OpOut::Deleted(r) = store
            .submit(Op::DeleteObjects {
                bucket: "b".into(),
                items: vec![("k".into(), None)],
                conds: vec![],
                bypass: false,
                replica: false,
            })
            .await
            .unwrap()
        else {
            unreachable!()
        };
        assert!(r[0].as_ref().unwrap().delete_marker);
        assert_eq!(store.get_object_version("b", "k", &v1).unwrap().1.unwrap(), "one");
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn usage_tracking_and_quotas() {
        let (store, dir) = temp_store();
        store.submit(Op::CreateBucket("b".into())).await.unwrap();
        let usage = |s: &Store| s.bucket_usage("b").unwrap();
        put(&store, "a", "12345").await;
        put(&store, "b", "123").await;
        assert_eq!(usage(&store), (2, 8));
        put(&store, "a", "1").await; // unversioned overwrite replaces
        assert_eq!(usage(&store), (2, 4));
        let del = |key: &str, version: Option<String>| Op::DeleteObjects {
            bucket: "b".into(),
            items: vec![(key.into(), version)],
            conds: vec![],
            bypass: false,
            replica: false,
        };
        store.submit(del("b", None)).await.unwrap();
        assert_eq!(usage(&store), (1, 1));
        // Versioned: every version counts, delete markers don't, permanent deletes subtract.
        store
            .submit(Op::SetBucketConfig { bucket: "b".into(), kind: "versioning", value: Some(b"Enabled".to_vec()) })
            .await
            .unwrap();
        let v1 = put(&store, "a", "22").await.version.unwrap();
        assert_eq!(usage(&store), (2, 3));
        store.submit(del("a", None)).await.unwrap(); // marker
        assert_eq!(usage(&store), (2, 3));
        store.submit(del("a", Some(v1))).await.unwrap();
        store.submit(del("a", Some("null".into()))).await.unwrap();
        assert_eq!(usage(&store), (0, 0));
        // Quotas are enforced by the writer.
        let quota = Quota { max_objects: 2, max_bytes: 10 };
        store.submit(Op::SetBucketConfig { bucket: "b".into(), kind: "quota", value: Some(quota.encode()) }).await.unwrap();
        put(&store, "x", "123456").await;
        let (meta, inline) = small("123456");
        let err =
            store.submit(Op::PutObject { bucket: "b".into(), key: "y".into(), meta, inline, cond: None }).await.err().unwrap();
        assert_eq!(err.code, "QuotaExceeded");
        put(&store, "y", "1234").await;
        let (meta, inline) = small("z");
        assert!(store.submit(Op::PutObject { bucket: "b".into(), key: "z".into(), meta, inline, cond: None }).await.is_err());
        assert_eq!(usage(&store), (2, 10));
        // Usage survives a restart, and is rebuilt if its bookkeeping is missing.
        drop(store);
        {
            // The writer thread releases the database shortly after the store is dropped.
            let db = (0..100)
                .find_map(|_| {
                    Database::create(dir.join("meta.redb")).ok().or_else(|| {
                        std::thread::sleep(Duration::from_millis(20));
                        None
                    })
                })
                .expect("database reopens");
            let txn = db.begin_write().unwrap();
            txn.open_table(STATE).unwrap().remove("usage_version").unwrap();
            txn.open_table(USAGE).unwrap().retain(|_, _| false).unwrap();
            txn.commit().unwrap();
        }
        let store = (0..100)
            .find_map(|_| {
                Store::open(StoreConfig {
                    root: dir.clone(),
                    fsync: false,
                    inline_threshold: 1024,
                    cache_bytes: 1 << 20,
                    min_free: Some(0),
                })
                .ok()
                .or_else(|| {
                    std::thread::sleep(Duration::from_millis(20));
                    None
                })
            })
            .expect("store reopens");
        assert_eq!(store.bucket_usage("b").unwrap(), (2, 10));
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn multipart_parts_count_towards_quotas() {
        let (store, dir) = temp_store();
        store.submit(Op::CreateBucket("b".into())).await.unwrap();
        let quota = Quota { max_objects: 0, max_bytes: 100 };
        store.submit(Op::SetBucketConfig { bucket: "b".into(), kind: "quota", value: Some(quota.encode()) }).await.unwrap();
        let upload = util::new_id();
        let u = UploadMeta { bucket: "b".into(), key: "k".into(), initiated_ms: 0, headers: vec![], tags: vec![] };
        store.submit(Op::CreateUpload { id: upload, meta: u }).await.unwrap();
        let part = |n: u32, size: u64| Op::PutPart {
            upload,
            bucket: "b".into(),
            key: "k".into(),
            part: n,
            meta: PartMeta { size, md5: [n as u8; 16], mtime_ms: 0, file: util::new_id(), checksum: None },
        };
        store.submit(part(1, 60)).await.unwrap();
        assert_eq!(store.bucket_part_bytes("b").unwrap(), 60);
        // Parts count towards the byte quota, and a re-uploaded part replaces the old one.
        assert_eq!(store.submit(part(2, 50)).await.err().unwrap().code, "QuotaExceeded");
        assert!(store.quota_allows("b", Incoming::Part { upload, part: 2 }, 50).is_err());
        assert!(store.quota_allows("b", Incoming::Part { upload, part: 1 }, 90).is_ok());
        store.submit(part(1, 90)).await.unwrap();
        assert_eq!(store.bucket_part_bytes("b").unwrap(), 90);
        // Completing moves the bytes from parts to the object (no double counting).
        let etag = util::hex(&[1u8; 16]);
        store
            .submit(Op::Complete {
                bucket: "b".into(),
                key: "k".into(),
                upload,
                parts: vec![(1, etag, None)],
                checksum: None,
                cond: None,
            })
            .await
            .unwrap();
        assert_eq!((store.bucket_usage("b").unwrap(), store.bucket_part_bytes("b").unwrap()), ((1, 90), 0));
        // Aborting releases them.
        let upload2 = util::new_id();
        let u = UploadMeta { bucket: "b".into(), key: "k2".into(), initiated_ms: 0, headers: vec![], tags: vec![] };
        store.submit(Op::CreateUpload { id: upload2, meta: u }).await.unwrap();
        store
            .submit(Op::PutPart {
                upload: upload2,
                bucket: "b".into(),
                key: "k2".into(),
                part: 1,
                meta: PartMeta { size: 10, md5: [0; 16], mtime_ms: 0, file: util::new_id(), checksum: None },
            })
            .await
            .unwrap();
        assert_eq!(store.bucket_part_bytes("b").unwrap(), 10);
        store.submit(Op::Abort { bucket: "b".into(), key: "k2".into(), upload: upload2 }).await.unwrap();
        assert_eq!(store.bucket_part_bytes("b").unwrap(), 0);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn suspended_overwrite_frees_the_null_version() {
        let (store, dir) = temp_store();
        store.submit(Op::CreateBucket("b".into())).await.unwrap();
        put(&store, "k", "12345").await; // null version
        let versioning =
            |v: &'static [u8]| Op::SetBucketConfig { bucket: "b".into(), kind: "versioning", value: Some(v.to_vec()) };
        store.submit(versioning(b"Enabled")).await.unwrap();
        put(&store, "k", "1234").await; // versioned current, null version is noncurrent
        store.submit(versioning(b"Suspended")).await.unwrap();
        assert_eq!(store.bucket_usage("b").unwrap(), (2, 9));
        // At the limit, a new null version that replaces the old one still fits.
        let quota = Quota { max_objects: 2, max_bytes: 9 };
        store.submit(Op::SetBucketConfig { bucket: "b".into(), kind: "quota", value: Some(quota.encode()) }).await.unwrap();
        put(&store, "k", "12345").await;
        assert_eq!(store.bucket_usage("b").unwrap(), (2, 9));
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn versioning_invariants_and_noncurrent_paging() {
        let (store, dir) = temp_store();
        store.submit(Op::CreateBucket("b".into())).await.unwrap();
        store
            .submit(Op::SetBucketConfig { bucket: "b".into(), kind: "versioning", value: Some(b"Enabled".to_vec()) })
            .await
            .unwrap();
        let mut ids = Vec::new();
        for i in 0..5 {
            ids.push(put(&store, "k", &format!("v{i}")).await.version.unwrap());
            put(&store, "k-other", &format!("o{i}")).await;
        }
        // Latest is current; older versions readable by id.
        assert_eq!(store.get_object("b", "k").unwrap().1.unwrap(), "v4");
        assert_eq!(store.get_object_version("b", "k", &ids[1]).unwrap().1.unwrap(), "v1");

        // Noncurrent scan: paging with limit 1 must give the same "noncurrent since" times.
        let full = store.scan_noncurrent("b", "", None, 1000).unwrap();
        let mut paged = Vec::new();
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page = store.scan_noncurrent("b", "", after.as_deref(), 1).unwrap();
            if page.items.is_empty() {
                break;
            }
            after = page.last.clone();
            paged.extend(page.items);
        }
        let sig = |v: &[NoncurrentItem]| v.iter().map(|i| (i.key.clone(), i.meta.seq, i.noncurrent_since_ms)).collect::<Vec<_>>();
        assert_eq!(full.items.len(), 8);
        assert_eq!(sig(&full.items), sig(&paged));
        // Each noncurrent version became noncurrent when the next-newer one was written.
        let k: Vec<_> = full.items.iter().filter(|i| i.key == "k").collect();
        for w in k.windows(2) {
            assert_eq!(w[1].noncurrent_since_ms, Some(w[0].meta.mtime_ms));
        }

        // Delete marker, then removing it restores the object.
        let OpOut::Deleted(r) = store
            .submit(Op::DeleteObjects {
                bucket: "b".into(),
                items: vec![("k".into(), None)],
                conds: vec![],
                bypass: false,
                replica: false,
            })
            .await
            .unwrap()
        else {
            unreachable!()
        };
        let marker = r[0].as_ref().unwrap().version_id.clone().unwrap();
        let e = store.get_object("b", "k").unwrap_err();
        assert_eq!(e.code, "NoSuchKey");
        assert!(e.headers.iter().any(|(h, v)| *h == "x-amz-delete-marker" && v == "true"));
        store
            .submit(Op::DeleteObjects {
                bucket: "b".into(),
                items: vec![("k".into(), Some(marker))],
                conds: vec![],
                bypass: false,
                replica: false,
            })
            .await
            .unwrap();
        assert_eq!(store.get_object("b", "k").unwrap().1.unwrap(), "v4");

        // Deleting the current version by id promotes the previous one.
        store
            .submit(Op::DeleteObjects {
                bucket: "b".into(),
                items: vec![("k".into(), Some(ids[4].clone()))],
                conds: vec![],
                bypass: false,
                replica: false,
            })
            .await
            .unwrap();
        let (m, d) = store.get_object("b", "k").unwrap();
        assert_eq!((m.version.as_deref(), d.unwrap().as_ref()), (Some(ids[3].as_str()), &b"v3"[..]));

        // Keys with NUL are refused.
        let (meta, inline) = small("x");
        assert!(store.submit(Op::PutObject { bucket: "b".into(), key: "a\0b".into(), meta, inline, cond: None }).await.is_err());

        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn successor() {
        assert_eq!(prefix_successor(b"ab"), Some(b"ac".to_vec()));
        assert_eq!(prefix_successor(b"a\xff"), Some(b"b".to_vec()));
        assert_eq!(prefix_successor(b"\xff"), None);
    }
}
