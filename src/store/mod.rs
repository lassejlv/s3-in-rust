//! Storage engine.
//!
//! * Object bytes live in immutable data files (`data/<xx>/<id>`) or, for small objects, inline
//!   in the metadata database. Files are never modified after they are written, so overwrites,
//!   copies (hard links) and multipart completion never rewrite data.
//! * All metadata lives in a single redb database. Reads run concurrently on any thread; all
//!   mutations go through one writer thread that group-commits batches of operations so a burst
//!   of small PUTs costs one fsync instead of one each.

pub mod meta;

use crate::error::{S3Error, S3Result, err};
use crate::lock;
use crate::util::{self, now_ms};
use bytes::Bytes;
use meta::{ObjectMeta, ObjectSummary, PartMeta, Storage, UploadMeta};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
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
pub const CONFIG_KINDS: &[&str] =
    &["acl", "policy", "cors", "tagging", "lifecycle", "versioning", "encryption", "object-lock", "website"];
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

macro_rules! internal_from {
    ($($t:ty),*) => {$(
        impl From<$t> for S3Error {
            fn from(e: $t) -> Self { S3Error::internal(e) }
        }
    )*};
}
internal_from!(redb::Error, redb::DatabaseError, redb::TransactionError, redb::TableError, redb::StorageError, redb::CommitError);

pub struct StoreConfig {
    pub root: PathBuf,
    pub fsync: bool,
    pub inline_threshold: usize,
    pub cache_bytes: usize,
}

pub struct Store {
    root: PathBuf,
    pub fsync: bool,
    pub inline_threshold: usize,
    db: Arc<Database>,
    writer: mpsc::Sender<Job>,
    deleter: mpsc::Sender<Vec<u128>>,
}

#[derive(Debug, Clone)]
pub enum WriteCond {
    /// `If-None-Match: *` — only create.
    NotExists,
    /// `If-Match: "etag"` — only overwrite this version.
    Matches(String),
}

pub enum Op {
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
        bypass: bool,
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
        parts: Vec<(u32, String)>,
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
    Flush,
}

pub enum OpOut {
    Done,
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
        let unclean = root.join("meta.redb").exists() && !marker.exists();
        let _ = std::fs::remove_file(&marker);

        let db = Database::builder().set_cache_size(cfg.cache_bytes).create(root.join("meta.redb"))?;
        {
            let txn = db.begin_write()?;
            txn.open_table(BUCKETS)?;
            txn.open_table(OBJECTS)?;
            txn.open_table(INLINE)?;
            txn.open_table(UPLOADS)?;
            txn.open_table(PARTS)?;
            txn.open_table(CONFIG)?;
            txn.open_table(VERSIONS)?;
            txn.commit()?;
        }
        if unclean {
            let started = std::time::Instant::now();
            match collect_orphans(&db, &root) {
                Ok((n, bytes)) => eprintln!(
                    "recovery: removed {n} orphaned data file(s), {bytes} bytes, in {:.1}s",
                    started.elapsed().as_secs_f64()
                ),
                Err(e) => eprintln!("recovery: orphan scan failed: {e}"),
            }
        }
        let db = Arc::new(db);

        let (del_tx, del_rx) = mpsc::channel::<Vec<u128>>();
        let del_root = root.clone();
        std::thread::Builder::new().name("s3rs-gc".into()).spawn(move || {
            for ids in del_rx {
                for id in ids {
                    if let Err(e) = std::fs::remove_file(data_path(&del_root, id))
                        && e.kind() != std::io::ErrorKind::NotFound
                    {
                        eprintln!("gc: failed to remove {}: {e}", util::id_hex(id));
                    }
                }
            }
        })?;

        let (tx, rx) = mpsc::channel::<Job>();
        let wdb = db.clone();
        let wdel = del_tx.clone();
        let durable = cfg.fsync;
        std::thread::Builder::new().name("s3rs-writer".into()).spawn(move || writer_loop(wdb, rx, wdel, durable))?;

        Ok(Arc::new(Store { root, fsync: cfg.fsync, inline_threshold: cfg.inline_threshold, db, writer: tx, deleter: del_tx }))
    }

    /// Record that the store shut down cleanly (all metadata flushed, nothing in flight).
    pub fn mark_clean_shutdown(&self) {
        let _ = std::fs::write(self.root.join(CLEAN_MARKER), b"");
    }

    pub fn data_path(&self, id: u128) -> PathBuf {
        data_path(&self.root, id)
    }

    pub fn tmp_path(&self, id: u128) -> PathBuf {
        self.root.join("tmp").join(util::id_hex(id))
    }

    /// Schedule data files for deletion (used to clean up after failed writes).
    pub fn discard(&self, ids: Vec<u128>) {
        if !ids.is_empty() {
            let _ = self.deleter.send(ids);
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

    // ---------------------------------------------------------------- reads

    pub fn bucket_exists(&self, bucket: &str) -> S3Result<bool> {
        let t = self.db.begin_read()?.open_table(BUCKETS)?;
        Ok(t.get(bucket)?.is_some())
    }

    pub fn require_bucket(&self, bucket: &str) -> S3Result<()> {
        if self.bucket_exists(bucket)? { Ok(()) } else { Err(err::NoSuchBucket()) }
    }

    pub fn list_buckets(&self) -> S3Result<Vec<(String, u64)>> {
        let t = self.db.begin_read()?.open_table(BUCKETS)?;
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
        let txn = self.db.begin_read()?;
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
        let txn = self.db.begin_read()?;
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

    /// A bucket configuration document, if set. Errors with NoSuchBucket.
    pub fn bucket_config(&self, bucket: &str, kind: &str) -> S3Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read()?;
        if txn.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(err::NoSuchBucket());
        }
        Ok(txn.open_table(CONFIG)?.get((bucket, kind))?.map(|v| v.value().to_vec()))
    }

    pub fn get_upload(&self, id: u128) -> S3Result<Option<UploadMeta>> {
        let t = self.db.begin_read()?.open_table(UPLOADS)?;
        match t.get(id)? {
            Some(v) => Ok(Some(UploadMeta::decode(v.value())?)),
            None => Ok(None),
        }
    }

    /// Parts of an upload with part number > `marker`, at most `max` (+ whether truncated).
    pub fn list_parts(&self, id: u128, marker: u32, max: usize) -> S3Result<(Vec<(u32, PartMeta)>, bool)> {
        let t = self.db.begin_read()?.open_table(PARTS)?;
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
        let txn = self.db.begin_read()?;
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
        let txn = self.db.begin_read()?;
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
        let txn = self.db.begin_read()?;
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
        let txn = self.db.begin_read()?;
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
        let t = self.db.begin_read()?.open_table(UPLOADS)?;
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

fn writer_loop(db: Arc<Database>, rx: mpsc::Receiver<Job>, deleter: mpsc::Sender<Vec<u128>>, durable: bool) {
    // In non-durable mode redb can only recycle pages freed by earlier commits once a durable
    // commit happens, so make one at least this often even under constant load.
    const DURABLE_EVERY: Duration = Duration::from_secs(1);
    let mut dirty = false;
    let mut last_durable = Instant::now();
    let mut last_seq = 0u64;
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
                    if flush(&db).is_ok() {
                        dirty = false;
                        last_durable = Instant::now();
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
        let force_durable = batch.iter().any(|j| matches!(j.op, Op::Flush));
        let immediate = durable || force_durable || last_durable.elapsed() >= DURABLE_EVERY;

        let mut results: Vec<S3Result<OpOut>> = Vec::with_capacity(batch.len());
        let mut obsolete: Vec<u128> = Vec::new();
        let outcome: S3Result<()> = (|| {
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
                };
                for job in batch.iter_mut() {
                    let mut garbage = Vec::new();
                    let op = std::mem::replace(&mut job.op, Op::Flush);
                    let r = apply(&mut tx, op, &mut garbage, &mut last_seq);
                    if let Err(e) = &r
                        && e.code == "InternalError"
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
        })();

        match outcome {
            Ok(()) => {
                dirty = !immediate;
                if immediate {
                    last_durable = Instant::now();
                }
                if !obsolete.is_empty() {
                    let _ = deleter.send(obsolete);
                }
                for (job, r) in batch.into_iter().zip(results) {
                    let _ = job.reply.send(r);
                }
            }
            Err(e) => {
                eprintln!("metadata commit failed: {e}");
                for job in batch {
                    let _ = job.reply.send(Err(e.clone()));
                }
            }
        }
    }
    if dirty {
        let _ = flush(&db);
    }
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
}

fn check_cond(existing: Option<&ObjectMeta>, cond: &Option<WriteCond>) -> S3Result<()> {
    match (cond, existing) {
        (None, _) => Ok(()),
        (Some(WriteCond::NotExists), None) => Ok(()),
        (Some(WriteCond::NotExists), Some(_)) => Err(err::PreconditionFailed()),
        (Some(WriteCond::Matches(_)), None) => Err(err::NoSuchKey()),
        (Some(WriteCond::Matches(e)), Some(m)) => {
            if e.trim() == "*" || norm_etag(e) == norm_etag(&m.etag) {
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
    tx.uploads.remove(upload)?;
    let mut keys = Vec::new();
    for e in tx.parts.range((upload, 0)..=(upload, u32::MAX))? {
        let (k, v) = e?;
        keys.push(k.value().1);
        garbage.push(PartMeta::decode(v.value())?.file);
    }
    for p in keys {
        tx.parts.remove((upload, p))?;
    }
    Ok(())
}

// -------------------------------------------------------------------- versioning (writer side)

fn versioning_state(tx: &Tables, bucket: &str) -> S3Result<Versioning> {
    Ok(Versioning::parse(tx.config.get((bucket, "versioning"))?.as_ref().map(|v| v.value())))
}

/// Release the storage behind a version (no-op for delete markers).
fn release(tx: &mut Tables, meta: &ObjectMeta, garbage: &mut Vec<u128>) -> S3Result<()> {
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
        release(tx, &m, garbage)?;
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
        release(tx, &old, garbage)
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
        release(tx, &m, garbage)?;
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

fn apply(tx: &mut Tables, op: Op, garbage: &mut Vec<u128>, last_seq: &mut u64) -> S3Result<OpOut> {
    match op {
        Op::Flush => Ok(OpOut::Done),
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
            tx.buckets.remove(name.as_str())?;
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
        Op::DeleteObjects { bucket, items, bypass } => {
            if tx.buckets.get(bucket.as_str())?.is_none() {
                return Err(err::NoSuchBucket());
            }
            let mut out = Vec::with_capacity(items.len());
            for (key, version) in items {
                let r = check_key_chars(&key).and_then(|_| match version {
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
            if let Some(old) = tx.parts.insert((upload, part), meta.encode().as_slice())? {
                garbage.push(PartMeta::decode(old.value())?.file);
            }
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
        Op::SetObjectTags { bucket, key, version, tags } => {
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
                    release(tx, &m, garbage)?;
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
        Op::Complete { bucket, key, upload, parts, cond } => {
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
            let mut size = 0u64;
            let mut prev = 0u32;
            for (i, (num, etag)) in parts.iter().enumerate() {
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
                if i + 1 < parts.len() && p.size < MIN_PART_SIZE {
                    return Err(err::EntityTooSmall());
                }
                size += p.size;
                md5s.extend_from_slice(&p.md5);
                segs.push((p.file, p.size));
            }
            let k = obj_key(&bucket, &key);
            check_cond(get_meta(tx, &k)?.as_ref(), &cond)?;

            use md5::Digest;
            let etag = format!("\"{}-{}\"", util::hex(&md5::Md5::digest(&md5s)), parts.len());
            let meta = ObjectMeta {
                size,
                mtime_ms: now_ms(),
                etag,
                headers: u.headers,
                checksum: None,
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
        let store =
            Store::open(StoreConfig { root: dir.clone(), fsync: false, inline_threshold: 1024, cache_bytes: 1 << 20 }).unwrap();
        (store, dir)
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
        match store.submit(Op::DeleteObjects { bucket: "b".into(), items: vec![("k".into(), Some(vid.into()))], bypass }).await {
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
        // GOVERNANCE -> COMPLIANCE is an extension; COMPLIANCE can then never be shortened.
        store.submit(set_lock(&v1, Some(comp), None, false)).await.unwrap();
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
        let OpOut::Deleted(r) =
            store.submit(Op::DeleteObjects { bucket: "b".into(), items: vec![("k".into(), None)], bypass: false }).await.unwrap()
        else {
            unreachable!()
        };
        assert!(r[0].as_ref().unwrap().delete_marker);
        assert_eq!(store.get_object_version("b", "k", &v1).unwrap().1.unwrap(), "one");
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
        let OpOut::Deleted(r) =
            store.submit(Op::DeleteObjects { bucket: "b".into(), items: vec![("k".into(), None)], bypass: false }).await.unwrap()
        else {
            unreachable!()
        };
        let marker = r[0].as_ref().unwrap().version_id.clone().unwrap();
        let e = store.get_object("b", "k").unwrap_err();
        assert_eq!(e.code, "NoSuchKey");
        assert!(e.headers.iter().any(|(h, v)| *h == "x-amz-delete-marker" && v == "true"));
        store
            .submit(Op::DeleteObjects { bucket: "b".into(), items: vec![("k".into(), Some(marker))], bypass: false })
            .await
            .unwrap();
        assert_eq!(store.get_object("b", "k").unwrap().1.unwrap(), "v4");

        // Deleting the current version by id promotes the previous one.
        store
            .submit(Op::DeleteObjects { bucket: "b".into(), items: vec![("k".into(), Some(ids[4].clone()))], bypass: false })
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
