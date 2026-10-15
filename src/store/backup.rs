//! Consistent backups of a data directory, as a tar stream.
//!
//! A backup is a snapshot of the metadata database (every table copied from one read
//! transaction into a new database file) plus exactly the data files that snapshot refers to.
//! Data files are immutable, and while a backup runs the server postpones deleting any (see
//! `Store::begin_backup`), so the files stay as the snapshot saw them however long the stream
//! takes. Extracting the tar into an empty directory gives a data directory that `s3rs` can
//! serve and `s3rs fsck` accepts.

use super::meta::{ObjectMeta, PartMeta, Storage};
use super::{BUCKETS, CONFIG, INLINE, OBJECTS, PART_BYTES, PARTS, REPL, STATE, UPLOADS, USAGE, VERSIONS, data_path};
use crate::error::{S3Error, S3Result};
use crate::util;
use redb::{Database, ReadableDatabase, ReadableTable};
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// What a backup contains: (name in the archive, file on disk, size).
pub struct Plan {
    pub entries: Vec<(String, PathBuf, u64)>,
    /// Data files the snapshot refers to that are missing on disk (reported, not archived).
    pub missing: Vec<u128>,
}

impl Plan {
    /// Size of the tar archive in bytes.
    pub fn tar_size(&self) -> u64 {
        self.entries.iter().map(|(_, _, n)| 512 + n.div_ceil(512) * 512).sum::<u64>() + 1024
    }
}

/// Copy every table of `db` (as of one read transaction) into a new database at `dest`, and
/// list the data files that snapshot refers to.
pub fn snapshot(db: &Database, root: &Path, dest: &Path) -> S3Result<Plan> {
    let txn = db.begin_read()?;
    let out = Database::create(dest)?;
    let wtx = out.begin_write()?;
    macro_rules! copy {
        ($($def:expr),*) => {$({
            match txn.open_table($def) {
                Ok(src) => {
                    let mut dst = wtx.open_table($def)?;
                    for e in src.iter()? {
                        let (k, v) = e?;
                        dst.insert(k.value(), v.value())?;
                    }
                }
                Err(redb::TableError::TableDoesNotExist(_)) => {}
                Err(e) => return Err(e.into()),
            }
        })*};
    }
    copy!(BUCKETS, OBJECTS, INLINE, UPLOADS, PARTS, CONFIG, VERSIONS, USAGE, STATE, PART_BYTES, REPL);
    wtx.commit()?;
    drop(out);

    let mut files = BTreeSet::new();
    for def in [OBJECTS, VERSIONS] {
        if let Ok(t) = txn.open_table(def) {
            for e in t.iter()? {
                if let Storage::Segments(segs) = ObjectMeta::decode(e?.1.value())?.storage {
                    files.extend(segs.into_iter().map(|(id, _)| id));
                }
            }
        }
    }
    if let Ok(t) = txn.open_table(PARTS) {
        for e in t.iter()? {
            files.insert(PartMeta::decode(e?.1.value())?.file);
        }
    }
    let meta_len = std::fs::metadata(dest)?.len();
    let mut plan = Plan { entries: vec![("meta.redb".to_string(), dest.to_path_buf(), meta_len)], missing: Vec::new() };
    for id in files {
        let path = data_path(root, id);
        match std::fs::metadata(&path) {
            Ok(m) => {
                // Archive names mirror the data directory layout.
                let name = path.strip_prefix(root).map_err(S3Error::internal)?.to_string_lossy().replace('\\', "/");
                plan.entries.push((name, path, m.len()));
            }
            Err(_) => plan.missing.push(id),
        }
    }
    Ok(plan)
}

/// Write the archive. Fails if a file changed size since the plan was made.
pub fn write_tar(plan: &Plan, out: &mut impl Write) -> io::Result<()> {
    let mtime = util::now_ms() / 1000;
    let mut buf = vec![0u8; 256 * 1024];
    for (name, path, size) in &plan.entries {
        out.write_all(&header(name, *size, mtime))?;
        let mut f = std::fs::File::open(path)?;
        let mut left = *size;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            let n = f.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("{} shrank during the backup", path.display())));
            }
            out.write_all(&buf[..n])?;
            left -= n as u64;
        }
        let pad = (512 - (size % 512) as usize) % 512;
        out.write_all(&[0u8; 512][..pad])?;
    }
    out.write_all(&[0u8; 1024])?;
    out.flush()
}

/// A ustar header for a regular file. Sizes of 8 GiB and more use the GNU base-256 encoding.
fn header(name: &str, size: u64, mtime: u64) -> [u8; 512] {
    let mut h = [0u8; 512];
    debug_assert!(name.len() < 100);
    h[..name.len()].copy_from_slice(name.as_bytes());
    let octal = |field: &mut [u8], v: u64| {
        let s = format!("{:0w$o}\0", v, w = field.len() - 1);
        field.copy_from_slice(s.as_bytes());
    };
    octal(&mut h[100..108], 0o644);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    if size < 1 << 33 {
        octal(&mut h[124..136], size);
    } else {
        h[124] = 0x80;
        h[128..136].copy_from_slice(&size.to_be_bytes());
    }
    octal(&mut h[136..148], mtime);
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

/// Run a backup of a stopped server's data directory into `out` (`s3rs backup`).
pub fn offline(root: &Path, out: &mut impl Write) -> Result<Plan, String> {
    let db_path = root.join("meta.redb");
    if !db_path.exists() {
        return Err(format!("{} does not exist", db_path.display()));
    }
    let db = Database::open(&db_path).map_err(|e| match e {
        redb::DatabaseError::DatabaseAlreadyOpen => {
            "the data directory is in use; back up a running server with GET /_admin/backup".to_string()
        }
        e => format!("cannot open {}: {e}", db_path.display()),
    })?;
    super::check_format_read(&db.begin_read().map_err(|e| e.to_string())?)?;
    let snap = SnapshotFile(root.join("tmp").join(format!("backup-{}.redb", util::id_hex(util::new_id()))));
    std::fs::create_dir_all(root.join("tmp")).map_err(|e| e.to_string())?;
    let plan = snapshot(&db, root, &snap.0).map_err(|e: S3Error| e.message)?;
    write_tar(&plan, out).map_err(|e| e.to_string())?;
    Ok(plan)
}

/// An `io::Write` that sends the archive to a response body in chunks (from a blocking thread).
pub struct ChunkSender {
    tx: tokio::sync::mpsc::Sender<io::Result<bytes::Bytes>>,
    buf: Vec<u8>,
}

const CHUNK: usize = 256 * 1024;

impl ChunkSender {
    pub fn new(tx: tokio::sync::mpsc::Sender<io::Result<bytes::Bytes>>) -> Self {
        ChunkSender { tx, buf: Vec::with_capacity(CHUNK) }
    }

    fn send(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = bytes::Bytes::from(std::mem::replace(&mut self.buf, Vec::with_capacity(CHUNK)));
        self.tx.blocking_send(Ok(chunk)).map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the client went away"))
    }

    /// Abort the response (the client sees a truncated transfer, not a complete archive).
    pub fn fail(self, e: io::Error) {
        let _ = self.tx.blocking_send(Err(e));
    }
}

impl Write for ChunkSender {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= CHUNK {
            self.send()?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send()
    }
}

/// A temporary snapshot database, removed when dropped.
pub struct SnapshotFile(pub PathBuf);

impl Drop for SnapshotFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_headers_are_valid() {
        let h = header("data/ab/abcdef", 1234, 1_700_000_000);
        assert_eq!(&h[124..136], b"00000002322\0");
        assert_eq!(&h[257..263], b"ustar\0");
        // The checksum covers the header with the checksum field read as spaces.
        let mut copy = h;
        copy[148..156].copy_from_slice(b"        ");
        let sum: u32 = copy.iter().map(|b| u32::from(*b)).sum();
        assert_eq!(std::str::from_utf8(&h[148..154]).unwrap(), format!("{sum:06o}"));
        let big = header("meta.redb", 10 << 30, 0);
        assert_eq!(big[124], 0x80);
        assert_eq!(u64::from_be_bytes(big[128..136].try_into().unwrap()), 10 << 30);
    }
}
