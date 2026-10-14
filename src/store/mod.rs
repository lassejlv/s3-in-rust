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
pub const CONFIG_KINDS: &[&str] = &["acl", "policy", "cors", "tagging", "lifecycle"];

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
    DeleteObjects {
        bucket: String,
        keys: Vec<String>,
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
        tags: Vec<(String, String)>,
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
    Deleted(Vec<S3Result<()>>),
    Count(usize),
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
            return Err(if buckets.get(bucket)?.is_some() { err::NoSuchKey() } else { err::NoSuchBucket() });
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
                };
                for job in batch.iter_mut() {
                    let mut garbage = Vec::new();
                    let op = std::mem::replace(&mut job.op, Op::Flush);
                    let r = apply(&mut tx, op, &mut garbage);
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

/// Replace (or remove) the object at `k`, releasing whatever backed the previous version.
fn replace_object(tx: &mut Tables, k: &[u8], new: Option<&ObjectMeta>, garbage: &mut Vec<u128>) -> S3Result<()> {
    let old = match new {
        Some(m) => tx.objects.insert(k, m.encode().as_slice())?.map(|g| ObjectMeta::decode(g.value())),
        None => tx.objects.remove(k)?.map(|g| ObjectMeta::decode(g.value())),
    };
    if let Some(old) = old {
        let old = old?;
        match old.storage {
            Storage::Inline(id) => {
                tx.inline.remove(id)?;
            }
            Storage::Segments(s) => garbage.extend(s.into_iter().map(|(id, _)| id)),
        }
    }
    Ok(())
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

fn apply(tx: &mut Tables, op: Op, garbage: &mut Vec<u128>) -> S3Result<OpOut> {
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
            if tx.objects.range::<&[u8]>(lo.as_slice()..hi.as_slice())?.next().is_some() {
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
            replace_object(tx, &k, Some(&meta), garbage)?;
            Ok(OpOut::Object(meta))
        }
        Op::Expire { bucket, items } => {
            let mut n = 0;
            for (key, mtime) in items {
                let k = obj_key(&bucket, &key);
                if get_meta(tx, &k)?.is_some_and(|m| m.mtime_ms == mtime) {
                    replace_object(tx, &k, None, garbage)?;
                    n += 1;
                }
            }
            Ok(OpOut::Count(n))
        }
        Op::DeleteObjects { bucket, keys } => {
            if tx.buckets.get(bucket.as_str())?.is_none() {
                return Err(err::NoSuchBucket());
            }
            let mut out = Vec::with_capacity(keys.len());
            for key in keys {
                replace_object(tx, &obj_key(&bucket, &key), None, garbage)?;
                out.push(Ok(()));
            }
            Ok(OpOut::Deleted(out))
        }
        Op::CreateUpload { id, meta } => {
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
            match value {
                Some(v) => tx.config.insert((bucket.as_str(), kind), v.as_slice())?,
                None => tx.config.remove((bucket.as_str(), kind))?,
            };
            Ok(OpOut::Done)
        }
        Op::SetObjectTags { bucket, key, tags } => {
            let k = obj_key(&bucket, &key);
            let Some(mut meta) = get_meta(tx, &k)? else {
                return Err(if tx.buckets.get(bucket.as_str())?.is_some() { err::NoSuchKey() } else { err::NoSuchBucket() });
            };
            meta.tags = tags;
            tx.objects.insert(k.as_slice(), meta.encode().as_slice())?;
            Ok(OpOut::Done)
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
            };
            replace_object(tx, &k, Some(&meta), garbage)?;
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

    #[test]
    fn successor() {
        assert_eq!(prefix_successor(b"ab"), Some(b"ac".to_vec()));
        assert_eq!(prefix_successor(b"a\xff"), Some(b"b".to_vec()));
        assert_eq!(prefix_successor(b"\xff"), None);
    }
}
