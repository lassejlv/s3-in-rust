//! `s3rs fsck`: offline consistency check of a data directory.
//!
//! Checks that every object version's data exists with the expected size, reports orphaned
//! data files and usage counters that disagree with the stored objects, and with `--deep`
//! re-reads every object and verifies its ETag (MD5, or the multipart composite ETag), which
//! also authenticates encrypted data. `--repair` removes orphaned files and rebuilds the usage
//! counters; it never touches object data. Data directories written by releases before usage
//! tracking can be checked too (their counters are reported as missing).

use super::meta::{ObjectMeta, PartMeta, Storage, UploadMeta};
use super::{INLINE, OBJECTS, PART_BYTES, PARTS, UPLOADS, USAGE, VERSIONS, data_path};
use crate::crypt::{self, KeyKind, WrapKey};
use crate::util;
use redb::{Database, Key, ReadOnlyTable, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Default)]
pub struct Report {
    pub versions: u64,
    pub bytes: u64,
    pub deep_verified: u64,
    /// Encrypted objects that could not be verified deeply (SSE-C, or no master key given).
    pub deep_skipped: u64,
    pub problems: Vec<String>,
    pub orphans: u64,
    pub orphan_bytes: u64,
    /// Inline data rows no object refers to.
    pub orphan_inline: u64,
    /// Orphans were found but kept, because unreadable metadata may still refer to them.
    pub orphans_kept: bool,
    pub usage_mismatches: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.problems.is_empty() && self.orphans == 0 && self.orphan_inline == 0 && self.usage_mismatches.is_empty()
    }
}

/// A table, or None if this database predates it.
fn table<K: Key + 'static, V: Value + 'static>(
    txn: &ReadTransaction,
    def: TableDefinition<K, V>,
) -> Result<Option<ReadOnlyTable<K, V>>, String> {
    match txn.open_table(def) {
        Ok(t) => Ok(Some(t)),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn is_encrypted(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, _)| k == "x-amz-server-side-encryption" || k == "x-amz-server-side-encryption-customer-algorithm")
}

enum Enc {
    Plain,
    Master,
    Customer,
}

fn encryption(meta: &ObjectMeta) -> Enc {
    let has = |n: &str| meta.headers.iter().any(|(k, _)| k == n);
    if has("x-amz-server-side-encryption-customer-algorithm") {
        Enc::Customer
    } else if has("x-amz-server-side-encryption") {
        Enc::Master
    } else {
        Enc::Plain
    }
}

/// Check the data directory at `root`. The server must not be running (the database is locked).
pub fn run(root: &Path, deep: bool, master: Option<[u8; 32]>, repair: bool) -> Result<Report, String> {
    let db_path = root.join("meta.redb");
    if !db_path.exists() {
        return Err(format!("{} does not exist", db_path.display()));
    }
    let db = Database::open(&db_path).map_err(|e| match e {
        redb::DatabaseError::DatabaseAlreadyOpen => "the data directory is in use; stop the server first".to_string(),
        e => format!("cannot open {}: {e}", db_path.display()),
    })?;
    let master = master.map(|k| WrapKey::new(KeyKind::Master, k));
    let mut report = Report::default();
    let mut live: HashSet<u128> = HashSet::new();
    let mut live_inline: HashSet<u128> = HashSet::new();
    let mut orphan_inline: Vec<u128> = Vec::new();
    // Set when a record cannot be decoded: the files it refers to are unknown, so nothing may
    // be removed as an orphan.
    let mut unreadable = false;
    let mut usage: HashMap<String, (u64, u64)> = HashMap::new();
    {
        let txn = db.begin_read().map_err(|e| e.to_string())?;
        super::check_format_read(&txn)?;
        let inline = table(&txn, INLINE)?;
        for def in [OBJECTS, VERSIONS] {
            let Some(t) = table(&txn, def)? else { continue };
            for e in t.iter().map_err(|e| e.to_string())? {
                let (k, v) = e.map_err(|e| e.to_string())?;
                let raw = k.value();
                let sep = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
                let bucket = String::from_utf8_lossy(&raw[..sep]).into_owned();
                let key = String::from_utf8_lossy(raw.get(sep + 1..).unwrap_or_default());
                // VERSIONS keys end in \0 + 8-byte sequence; show only the object key.
                let key = key.split('\0').next().unwrap_or_default().to_string();
                let meta = match ObjectMeta::decode(v.value()) {
                    Ok(m) => m,
                    Err(_) => {
                        report.problems.push(format!("{bucket}/{key}: unreadable metadata record"));
                        unreadable = true;
                        continue;
                    }
                };
                if meta.delete_marker {
                    continue;
                }
                let label =
                    format!("{bucket}/{key}{}", meta.version.as_ref().map(|v| format!(" (version {v})")).unwrap_or_default());
                report.versions += 1;
                report.bytes += meta.size;
                let u = usage.entry(bucket).or_default();
                *u = (u.0 + 1, u.1 + meta.size);
                let enc = encryption(&meta);
                let stored_len = |plain: u64| if matches!(enc, Enc::Plain) { plain } else { crypt::encrypted_len(plain) };
                let key_for_deep = match enc {
                    Enc::Plain => Some(None),
                    Enc::Master => master.clone().map(Some),
                    Enc::Customer => None,
                };
                let mut intact = true;
                let mut digests: Vec<[u8; 16]> = Vec::new();
                if let Storage::Inline(id) = &meta.storage {
                    live_inline.insert(*id);
                }
                match &meta.storage {
                    Storage::Inline(id) => {
                        match inline.as_ref().map(|t| t.get(*id)).transpose().map_err(|e| e.to_string())?.flatten() {
                            None => {
                                report.problems.push(format!("{label}: inline data is missing"));
                                intact = false;
                            }
                            Some(data) => {
                                let data = data.value();
                                if data.len() as u64 != stored_len(meta.size) {
                                    report.problems.push(format!(
                                        "{label}: inline data has {} bytes, expected {}",
                                        data.len(),
                                        stored_len(meta.size)
                                    ));
                                    intact = false;
                                } else if deep && let Some(k) = &key_for_deep {
                                    let plain = match k {
                                        Some(k) => crypt::decrypt_range(k, data, 0, meta.size, meta.size).map_err(|e| e.message),
                                        None => Ok(data.to_vec()),
                                    };
                                    match plain {
                                        Ok(p) => {
                                            use md5::Digest;
                                            digests.push(md5::Md5::digest(&p).into());
                                        }
                                        Err(e) => {
                                            report.problems.push(format!("{label}: cannot decrypt: {e}"));
                                            intact = false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Storage::Segments(segs) => {
                        for (id, len) in segs {
                            live.insert(*id);
                            let path = data_path(root, *id);
                            match std::fs::metadata(&path) {
                                Err(_) => {
                                    report.problems.push(format!("{label}: data file {} is missing", path.display()));
                                    intact = false;
                                }
                                Ok(m) if m.len() != stored_len(*len) => {
                                    report.problems.push(format!(
                                        "{label}: data file {} has {} bytes, expected {}",
                                        path.display(),
                                        m.len(),
                                        stored_len(*len)
                                    ));
                                    intact = false;
                                }
                                Ok(_) if deep && intact => {
                                    if let Some(k) = &key_for_deep {
                                        match crate::io::segment_md5(&path, *len, k.as_ref()) {
                                            Ok(d) => digests.push(d),
                                            Err(e) => {
                                                report.problems.push(format!("{label}: cannot read {}: {e}", path.display()));
                                                intact = false;
                                            }
                                        }
                                    }
                                }
                                Ok(_) => {}
                            }
                        }
                    }
                }
                if !deep || !intact {
                    continue;
                }
                if key_for_deep.is_none() {
                    report.deep_skipped += 1;
                    continue;
                }
                // Multipart objects: ETag = MD5 of the parts' MD5s, "-N" (parts are the segments).
                let want = meta.etag.trim_matches('"').to_ascii_lowercase();
                let got = if want.contains('-') {
                    use md5::Digest;
                    let mut h = md5::Md5::new();
                    digests.iter().for_each(|d| h.update(d));
                    format!("{}-{}", util::hex(&h.finalize()), digests.len())
                } else if digests.len() == 1 {
                    util::hex(&digests[0])
                } else {
                    use md5::Digest;
                    // A single-part object stored in several files cannot happen; check the whole.
                    let mut h = md5::Md5::new();
                    digests.iter().for_each(|d| h.update(d));
                    util::hex(&h.finalize())
                };
                if got == want || (meta.size == 0 && digests.is_empty()) {
                    report.deep_verified += 1;
                } else {
                    report.problems.push(format!("{label}: content does not match its ETag ({got} != {want})"));
                }
            }
        }
        if let Some(t) = &inline {
            for e in t.iter().map_err(|e| e.to_string())? {
                let id = e.map_err(|e| e.to_string())?.0.value();
                if !live_inline.contains(&id) {
                    orphan_inline.push(id);
                }
            }
        }
        report.orphan_inline = orphan_inline.len() as u64;

        // Multipart upload parts: files exist with the right size; bytes per bucket.
        let uploads = table(&txn, UPLOADS)?;
        let mut upload_info: HashMap<u128, Option<(String, bool)>> = HashMap::new();
        let mut part_bytes: HashMap<String, u64> = HashMap::new();
        if let Some(parts) = table(&txn, PARTS)? {
            for e in parts.iter().map_err(|e| e.to_string())? {
                let (k, v) = e.map_err(|e| e.to_string())?;
                let (upload, num) = k.value();
                let p = match PartMeta::decode(v.value()) {
                    Ok(p) => p,
                    Err(_) => {
                        report.problems.push(format!("upload {}: part {num}: unreadable record", util::id_hex(upload)));
                        unreadable = true;
                        continue;
                    }
                };
                live.insert(p.file);
                if let std::collections::hash_map::Entry::Vacant(slot) = upload_info.entry(upload) {
                    let u = match &uploads {
                        Some(t) => t.get(upload).map_err(|e| e.to_string())?.map(|u| UploadMeta::decode(u.value())),
                        None => None,
                    };
                    let info = match u {
                        Some(Ok(u)) => Some((u.bucket, is_encrypted(&u.headers))),
                        Some(Err(_)) => {
                            report.problems.push(format!("upload {}: unreadable record", util::id_hex(upload)));
                            None
                        }
                        None => {
                            report.problems.push(format!("upload {}: parts without an upload record", util::id_hex(upload)));
                            None
                        }
                    };
                    slot.insert(info);
                }
                let path = data_path(root, p.file);
                match (std::fs::metadata(&path), upload_info.get(&upload).cloned().flatten()) {
                    (Err(_), _) => report.problems.push(format!("multipart upload part file {} is missing", path.display())),
                    (Ok(m), Some((bucket, encrypted))) => {
                        let want = if encrypted { crypt::encrypted_len(p.size) } else { p.size };
                        if m.len() != want {
                            report.problems.push(format!(
                                "multipart upload part file {} has {} bytes, expected {want}",
                                path.display(),
                                m.len()
                            ));
                        }
                        *part_bytes.entry(bucket).or_default() += p.size;
                    }
                    (Ok(_), None) => {}
                }
            }
        }
        part_bytes.retain(|_, n| *n > 0);
        let stored_parts: HashMap<String, u64> = match table(&txn, PART_BYTES)? {
            Some(t) => t
                .iter()
                .map_err(|e| e.to_string())?
                .filter_map(|e| e.ok().map(|(k, v)| (k.value().to_string(), v.value())))
                .filter(|(_, v)| *v != 0)
                .collect(),
            None => HashMap::new(),
        };
        for b in part_bytes.keys().chain(stored_parts.keys()).collect::<HashSet<_>>() {
            let (got, want) = (stored_parts.get(b).copied().unwrap_or(0), part_bytes.get(b).copied().unwrap_or(0));
            if got != want {
                report.usage_mismatches.push(format!("{b}: recorded {got} bytes in multipart parts, actual {want}"));
            }
        }

        let stored: HashMap<String, (u64, u64)> = match table(&txn, USAGE)? {
            Some(t) => t
                .iter()
                .map_err(|e| e.to_string())?
                .filter_map(|e| e.ok().map(|(k, v)| (k.value().to_string(), v.value())))
                .filter(|(_, v)| *v != (0, 0))
                .collect(),
            None => HashMap::new(),
        };
        let computed: HashMap<String, (u64, u64)> =
            usage.iter().filter(|(_, v)| **v != (0, 0)).map(|(k, v)| (k.clone(), *v)).collect();
        for (b, want) in &computed {
            let got = stored.get(b).copied().unwrap_or((0, 0));
            if got != *want {
                report
                    .usage_mismatches
                    .push(format!("{b}: recorded {} objects / {} bytes, actual {} / {}", got.0, got.1, want.0, want.1));
            }
        }
        for (b, got) in &stored {
            if !computed.contains_key(b) {
                report.usage_mismatches.push(format!("{b}: recorded {} objects / {} bytes, actual 0 / 0", got.0, got.1));
            }
        }
    }

    // Orphaned data files (and, with --repair, their removal).
    let mut orphan_paths = Vec::new();
    if let Ok(dirs) = std::fs::read_dir(root.join("data")) {
        for dir in dirs.flatten() {
            let Ok(files) = std::fs::read_dir(dir.path()) else { continue };
            for f in files.flatten() {
                let Some(id) = f.file_name().to_str().and_then(util::parse_id_hex) else { continue };
                if !live.contains(&id) {
                    report.orphans += 1;
                    report.orphan_bytes += f.metadata().map(|m| m.len()).unwrap_or(0);
                    orphan_paths.push(f.path());
                }
            }
        }
    }
    report.orphans_kept = unreadable && (report.orphans > 0 || report.orphan_inline > 0);
    if repair {
        if !unreadable {
            for p in &orphan_paths {
                let _ = std::fs::remove_file(p);
            }
            if !orphan_inline.is_empty() {
                let txn = db.begin_write().map_err(|e| e.to_string())?;
                {
                    let mut t = txn.open_table(INLINE).map_err(|e| e.to_string())?;
                    for id in &orphan_inline {
                        t.remove(*id).map_err(|e| e.to_string())?;
                    }
                }
                txn.commit().map_err(|e| e.to_string())?;
            }
        }
        if !report.usage_mismatches.is_empty() && !unreadable {
            super::rebuild_usage_if_needed(&db, true).map_err(|e| e.message)?;
        }
    }
    Ok(report)
}
