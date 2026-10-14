//! Data paths: ingesting request bodies into storage and streaming object bytes back out.
//!
//! Hashing and disk I/O run on blocking threads, connected to the async side by small bounded
//! channels, so a single upload or download never stalls the runtime's worker threads.

use crate::auth::Payload;
use crate::body::Body;
use crate::chunked::ChunkDecoder;
use crate::error::{S3Error, S3Result, err};
use crate::store::Store;
use crate::store::meta::{ChecksumAlgo, ObjectMeta, Storage};
use crate::util::{self, base64};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use md5::Md5;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Write batches handed to the disk thread.
const WRITE_CHUNK: usize = 1024 * 1024;
/// Read size for streamed downloads.
const READ_CHUNK: usize = 512 * 1024;
/// Downloads up to this size are read in one go and sent as a single buffer.
const SMALL_READ: u64 = 1024 * 1024;

// ------------------------------------------------------------------ request bodies

/// A stream of upload bytes: a plain request body, or the file part of a form upload.
pub trait Source: Send {
    fn next(&mut self) -> impl std::future::Future<Output = S3Result<Option<Bytes>>> + Send;
    /// A trailing header (aws-chunked trailers carry checksums).
    fn trailer(&self, _name: &str) -> Option<&str> {
        None
    }
}

impl Source for BodyStream {
    async fn next(&mut self) -> S3Result<Option<Bytes>> {
        BodyStream::next(self).await
    }
    fn trailer(&self, name: &str) -> Option<&str> {
        BodyStream::trailer(self, name)
    }
}

/// Request body with aws-chunked framing removed.
pub struct BodyStream {
    body: Option<Incoming>,
    dec: Option<ChunkDecoder>,
    pending: VecDeque<Bytes>,
    eof: bool,
}

impl BodyStream {
    pub fn new(body: Incoming, payload: &mut Payload) -> Self {
        let dec = match payload {
            Payload::Chunked { signer, trailer } => Some(ChunkDecoder::new(signer.take(), *trailer)),
            _ => None,
        };
        BodyStream { body: Some(body), dec, pending: VecDeque::new(), eof: false }
    }

    /// A placeholder left behind after the real body has been taken.
    pub fn empty() -> Self {
        BodyStream { body: None, dec: None, pending: VecDeque::new(), eof: true }
    }

    pub async fn next(&mut self) -> S3Result<Option<Bytes>> {
        loop {
            if let Some(b) = self.pending.pop_front() {
                return Ok(Some(b));
            }
            if self.eof {
                return Ok(None);
            }
            let Some(body) = &mut self.body else { return Ok(None) };
            match body.frame().await {
                None => {
                    self.eof = true;
                    if let Some(d) = &mut self.dec {
                        d.finish()?;
                    }
                }
                Some(Err(_)) => return Err(err::IncompleteBody()),
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else { continue };
                    match &mut self.dec {
                        None if data.is_empty() => {}
                        None => return Ok(Some(data)),
                        Some(d) => {
                            let pending = &mut self.pending;
                            d.feed(data, &mut |b| pending.push_back(b))?;
                        }
                    }
                }
            }
        }
    }

    pub fn trailer(&self, name: &str) -> Option<&str> {
        self.dec.as_ref()?.trailers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Read a small body (XML documents) fully, enforcing `limit`.
    pub async fn read_all(&mut self, limit: usize) -> S3Result<Bytes> {
        let mut buf = BytesMut::new();
        while let Some(b) = self.next().await? {
            if buf.len() + b.len() > limit {
                return Err(err::EntityTooLarge());
            }
            buf.extend_from_slice(&b);
        }
        Ok(buf.freeze())
    }
}

pub enum ChecksumHasher {
    Crc32(crc32fast::Hasher),
    Crc32c(u32),
    Crc64(crc64fast_nvme::Digest),
    Sha1(sha1::Sha1),
    Sha256(Sha256),
}

impl ChecksumHasher {
    pub fn new(a: ChecksumAlgo) -> Self {
        match a {
            ChecksumAlgo::Crc32 => Self::Crc32(crc32fast::Hasher::new()),
            ChecksumAlgo::Crc32c => Self::Crc32c(0),
            ChecksumAlgo::Crc64Nvme => Self::Crc64(crc64fast_nvme::Digest::new()),
            ChecksumAlgo::Sha1 => Self::Sha1(sha1::Sha1::new()),
            ChecksumAlgo::Sha256 => Self::Sha256(Sha256::new()),
        }
    }

    fn update(&mut self, d: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(d),
            Self::Crc32c(c) => *c = crc32c::crc32c_append(*c, d),
            Self::Crc64(h) => h.write(d),
            Self::Sha1(h) => h.update(d),
            Self::Sha256(h) => h.update(d),
        }
    }

    fn finish(self) -> String {
        match self {
            Self::Crc32(h) => base64(&h.finalize().to_be_bytes()),
            Self::Crc32c(c) => base64(&c.to_be_bytes()),
            Self::Crc64(h) => base64(&h.sum64().to_be_bytes()),
            Self::Sha1(h) => base64(&h.finalize()),
            Self::Sha256(h) => base64(&h.finalize()),
        }
    }
}

/// What the client told us to expect about the body.
#[derive(Default)]
pub struct Expect {
    /// Decoded content length, if declared.
    pub len: Option<u64>,
    pub max_len: u64,
    pub sha256: Option<[u8; 32]>,
    pub md5: Option<[u8; 16]>,
    /// Checksum algorithm and value (None = value arrives in a trailer).
    pub checksum: Option<(ChecksumAlgo, Option<String>)>,
    /// Allow small bodies to be stored inline in the metadata database.
    pub allow_inline: bool,
}

struct Hashers {
    md5: Md5,
    sha256: Option<Sha256>,
    checksum: Option<ChecksumHasher>,
}

impl Hashers {
    fn new(e: &Expect) -> Self {
        Hashers {
            md5: Md5::new(),
            sha256: e.sha256.map(|_| Sha256::new()),
            checksum: e.checksum.as_ref().map(|(a, _)| ChecksumHasher::new(*a)),
        }
    }
    fn update(&mut self, d: &[u8]) {
        self.md5.update(d);
        if let Some(h) = &mut self.sha256 {
            h.update(d);
        }
        if let Some(h) = &mut self.checksum {
            h.update(d);
        }
    }
}

pub enum Data {
    Inline(Bytes),
    /// Data file id (already moved into place).
    File(u128),
}

pub struct Ingested {
    pub size: u64,
    pub md5: [u8; 16],
    pub checksum: Option<(ChecksumAlgo, String)>,
    pub data: Data,
}

impl Ingested {
    pub fn etag(&self) -> String {
        format!("\"{}\"", util::hex(&self.md5))
    }

    pub fn storage(&self) -> (Storage, Option<Bytes>, Vec<u128>) {
        match &self.data {
            Data::Inline(b) => (Storage::Inline(util::new_id()), Some(b.clone()), vec![]),
            Data::File(id) => (Storage::Segments(vec![(*id, self.size)]), None, vec![*id]),
        }
    }
}

type Checksum = Option<(ChecksumAlgo, String)>;

fn verify(h: Hashers, size: u64, e: &Expect, body: &impl Source) -> S3Result<([u8; 16], Checksum)> {
    if let Some(len) = e.len
        && len != size
    {
        return Err(err::IncompleteBody());
    }
    let md5: [u8; 16] = h.md5.finalize().into();
    if let Some(want) = e.md5
        && want != md5
    {
        return Err(err::BadDigest());
    }
    if let (Some(want), Some(got)) = (e.sha256, h.sha256) {
        let got: [u8; 32] = got.finalize().into();
        if want != got {
            return Err(err::XAmzContentSHA256Mismatch());
        }
    }
    let checksum = match (&e.checksum, h.checksum) {
        (Some((algo, value)), Some(hasher)) => {
            let got = hasher.finish();
            let want = match value {
                Some(v) => Some(v.as_str()),
                None => body.trailer(algo.header()),
            };
            match want {
                Some(w) if w.trim() != got => {
                    return Err(err::BadDigest().with_message(format!(
                        "The {} you specified did not match the calculated checksum.",
                        algo.header().trim_start_matches("x-amz-checksum-")
                    )));
                }
                _ => Some((*algo, got)),
            }
        }
        _ => None,
    };
    Ok((md5, checksum))
}

/// Stream a request body into storage, verifying lengths, digests and checksums.
pub async fn ingest(store: &Arc<Store>, mut body: impl Source, e: Expect) -> S3Result<Ingested> {
    if e.len.is_some_and(|l| l > e.max_len) {
        return Err(err::EntityTooLarge());
    }
    let threshold = if e.allow_inline { store.inline_threshold } else { 0 };
    let mut buf = BytesMut::new();
    if threshold > 0 && e.len.is_none_or(|l| l as usize <= threshold) {
        if let Some(l) = e.len {
            buf.reserve(l as usize);
        }
        loop {
            match body.next().await? {
                None => {
                    let mut h = Hashers::new(&e);
                    h.update(&buf);
                    let size = buf.len() as u64;
                    let (md5, checksum) = verify(h, size, &e, &body)?;
                    return Ok(Ingested { size, md5, checksum, data: Data::Inline(buf.freeze()) });
                }
                Some(b) => {
                    buf.extend_from_slice(&b);
                    if buf.len() > threshold {
                        break;
                    }
                }
            }
        }
    }

    // Spill to a data file written by a blocking thread.
    let id = util::new_id();
    let tmp = store.tmp_path(id);
    let fsync = store.fsync;
    let (tx, mut rx) = mpsc::channel::<Bytes>(4);
    let mut hashers = Hashers::new(&e);
    let tmp2 = tmp.clone();
    let writer = tokio::task::spawn_blocking(move || -> io::Result<(Hashers, u64)> {
        let mut f = File::create(&tmp2)?;
        let mut n = 0u64;
        while let Some(b) = rx.blocking_recv() {
            hashers.update(&b);
            f.write_all(&b)?;
            n += b.len() as u64;
        }
        if fsync {
            f.sync_data()?;
        }
        Ok((hashers, n))
    });

    let feed = async {
        let mut total = buf.len() as u64;
        loop {
            match body.next().await? {
                Some(b) => {
                    total += b.len() as u64;
                    if total > e.max_len {
                        return Err(err::EntityTooLarge());
                    }
                    buf.extend_from_slice(&b);
                    if buf.len() >= WRITE_CHUNK && tx.send(buf.split().freeze()).await.is_err() {
                        return Ok(false);
                    }
                }
                None => {
                    if !buf.is_empty() && tx.send(buf.split().freeze()).await.is_err() {
                        return Ok(false);
                    }
                    return Ok(true);
                }
            }
        }
    };
    let fed: S3Result<bool> = feed.await;
    drop(tx);
    let written = writer.await.map_err(S3Error::internal)?;

    let verified = (|| {
        let fed = fed?;
        let (h, n) = written?;
        if !fed {
            return Err(S3Error::internal("writer stopped early"));
        }
        let (md5, checksum) = verify(h, n, &e, &body)?;
        Ok(Ingested { size: n, md5, checksum, data: Data::File(id) })
    })();
    let result = match verified {
        Ok(ing) => {
            let st = store.clone();
            let tmp = tmp.clone();
            tokio::task::spawn_blocking(move || install(&st, &tmp, id))
                .await
                .map_err(S3Error::internal)?
                .map(|_| ing)
                .map_err(S3Error::from)
        }
        Err(e) => Err(e),
    };
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Move a finished temp file to its final data path. With fsync enabled the directory entry is
/// made durable too, so committed metadata never points at a file a crash could lose.
fn install(store: &Store, tmp: &std::path::Path, id: u128) -> io::Result<()> {
    let dst = store.data_path(id);
    std::fs::rename(tmp, &dst)?;
    if store.fsync
        && let Some(dir) = dst.parent()
    {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

// ------------------------------------------------------------------ object reads

/// (file id, offset within file, length) pieces covering `[start, start+len)`.
fn plan(segs: &[(u128, u64)], start: u64, len: u64) -> Vec<(u128, u64, u64)> {
    let mut out = Vec::new();
    let end = start + len;
    let mut pos = 0u64;
    for &(id, slen) in segs {
        let (s, e) = (pos, pos + slen);
        pos = e;
        if e <= start || slen == 0 {
            continue;
        }
        if s >= end {
            break;
        }
        let from = start.max(s);
        let to = end.min(e);
        out.push((id, from - s, to - from));
    }
    out
}

fn open_at(store: &Store, id: u128, off: u64) -> io::Result<File> {
    let mut f = File::open(store.data_path(id))?;
    if off > 0 {
        f.seek(SeekFrom::Start(off))?;
    }
    Ok(f)
}

fn read_exact_into(f: &mut File, n: u64, out: &mut Vec<u8>) -> io::Result<()> {
    let before = out.len();
    f.take(n).read_to_end(out)?;
    if (out.len() - before) as u64 != n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "data file shorter than recorded"));
    }
    Ok(())
}

/// Produce a response body for `[start, start+len)` of an object. Returns `NotFound` io errors
/// (as `Err(None)`) when a data file vanished because the object was concurrently replaced, so
/// the caller can re-read the metadata and retry.
pub async fn read_body(
    store: &Arc<Store>,
    meta: &ObjectMeta,
    inline: Option<Bytes>,
    start: u64,
    len: u64,
) -> Result<Body, Option<S3Error>> {
    if len == 0 {
        return Ok(Body::Empty);
    }
    let segs = match &meta.storage {
        Storage::Inline(_) => {
            let data = inline.ok_or_else(|| Some(S3Error::internal("inline data missing")))?;
            return Ok(Body::full(data.slice(start as usize..(start + len) as usize)));
        }
        Storage::Segments(s) => s,
    };
    let pieces = plan(segs, start, len);
    let st = store.clone();
    let not_found = |e: io::Error| if e.kind() == io::ErrorKind::NotFound { None } else { Some(S3Error::from(e)) };

    if len <= SMALL_READ {
        let data = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
            let mut out = Vec::with_capacity(len as usize);
            for (id, off, n) in pieces {
                read_exact_into(&mut open_at(&st, id, off)?, n, &mut out)?;
            }
            Ok(out)
        })
        .await
        .map_err(|e| Some(S3Error::internal(e)))?
        .map_err(not_found)?;
        return Ok(Body::full(data));
    }

    let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(4);
    let (ready_tx, ready_rx) = oneshot::channel::<io::Result<()>>();
    tokio::task::spawn_blocking(move || {
        let mut ready = Some(ready_tx);
        for (id, off, mut n) in pieces {
            let mut f = match open_at(&st, id, off) {
                Ok(f) => f,
                Err(e) => {
                    match ready.take() {
                        Some(r) => _ = r.send(Err(e)),
                        None => _ = tx.blocking_send(Err(e)),
                    }
                    return;
                }
            };
            if let Some(r) = ready.take() {
                let _ = r.send(Ok(()));
            }
            while n > 0 {
                let want = n.min(READ_CHUNK as u64);
                let mut buf = Vec::with_capacity(want as usize);
                if let Err(e) = read_exact_into(&mut f, want, &mut buf) {
                    let _ = tx.blocking_send(Err(e));
                    return;
                }
                n -= want;
                if tx.blocking_send(Ok(Bytes::from(buf))).is_err() {
                    return; // client went away
                }
            }
        }
    });
    match ready_rx.await {
        Ok(Ok(())) => Ok(Body::Stream { rx, remaining: len }),
        Ok(Err(e)) => Err(not_found(e)),
        Err(_) => Err(Some(S3Error::internal("reader failed"))),
    }
}

/// Copy `[start, start+len)` of an object into a new data file. Returns (file id, md5).
pub fn copy_range_blocking(
    store: &Store,
    meta: &ObjectMeta,
    inline: Option<&Bytes>,
    start: u64,
    len: u64,
) -> io::Result<(u128, [u8; 16])> {
    let id = util::new_id();
    let tmp = store.tmp_path(id);
    let res = (|| {
        let mut out = File::create(&tmp)?;
        let mut md5 = Md5::new();
        match &meta.storage {
            Storage::Inline(_) => {
                let data = inline.ok_or_else(|| io::Error::other("inline data missing"))?;
                let d = &data[start as usize..(start + len) as usize];
                md5.update(d);
                out.write_all(d)?;
            }
            Storage::Segments(segs) => {
                let mut buf = Vec::with_capacity(READ_CHUNK);
                for (fid, off, mut n) in plan(segs, start, len) {
                    let mut f = open_at(store, fid, off)?;
                    while n > 0 {
                        let want = n.min(READ_CHUNK as u64);
                        buf.clear();
                        read_exact_into(&mut f, want, &mut buf)?;
                        md5.update(&buf);
                        out.write_all(&buf)?;
                        n -= want;
                    }
                }
            }
        }
        if store.fsync {
            out.sync_data()?;
        }
        install(store, &tmp, id)?;
        Ok((id, md5.finalize().into()))
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Create new data files sharing the content of `segs` (hard links; falls back to copying).
pub fn link_segments_blocking(store: &Store, segs: &[(u128, u64)]) -> io::Result<Vec<(u128, u64)>> {
    let mut out: Vec<(u128, u64)> = Vec::with_capacity(segs.len());
    for &(id, len) in segs {
        let new = util::new_id();
        let (src, dst) = (store.data_path(id), store.data_path(new));
        let r = std::fs::hard_link(&src, &dst)
            .or_else(|e| if e.kind() == io::ErrorKind::NotFound { Err(e) } else { std::fs::copy(&src, &dst).map(|_| ()) });
        if let Err(e) = r {
            store.discard(out.iter().map(|(id, _)| *id).collect());
            return Err(e);
        }
        out.push((new, len));
    }
    if store.fsync {
        let mut dirs: Vec<u8> = out.iter().map(|(id, _)| *id as u8).collect();
        dirs.sort_unstable();
        dirs.dedup();
        for d in dirs {
            if let Some(dir) = store.data_path(d as u128).parent() {
                File::open(dir)?.sync_all()?;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_ranges() {
        let segs = [(1, 10), (2, 10), (3, 5)];
        assert_eq!(plan(&segs, 0, 25), vec![(1, 0, 10), (2, 0, 10), (3, 0, 5)]);
        assert_eq!(plan(&segs, 5, 10), vec![(1, 5, 5), (2, 0, 5)]);
        assert_eq!(plan(&segs, 20, 2), vec![(3, 0, 2)]);
        assert_eq!(plan(&segs, 10, 10), vec![(2, 0, 10)]);
    }
}
