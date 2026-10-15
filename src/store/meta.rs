//! Compact binary encodings for metadata stored in redb.
//!
//! The leading fields of `ObjectMeta` (size, mtime, etag) are fixed in position so listings can
//! decode just a summary without touching headers or the segment table.

use crate::error::{S3Error, S3Result};

/// Record format version. v2 appended tags; v3 appended version id, sequence number and the
/// delete-marker flag (objects only). Older records are still readable.
const VERSION: u8 = 3;

fn check_version(v: u8) -> S3Result<u8> {
    if (1..=VERSION).contains(&v) { Ok(v) } else { Err(corrupt()) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgo {
    Crc32 = 1,
    Crc32c = 2,
    Crc64Nvme = 3,
    Sha1 = 4,
    Sha256 = 5,
}

impl ChecksumAlgo {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Crc32,
            2 => Self::Crc32c,
            3 => Self::Crc64Nvme,
            4 => Self::Sha1,
            5 => Self::Sha256,
            _ => return None,
        })
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "crc32" => Self::Crc32,
            "crc32c" => Self::Crc32c,
            "crc64nvme" => Self::Crc64Nvme,
            "sha1" => Self::Sha1,
            "sha256" => Self::Sha256,
            _ => return None,
        })
    }

    pub fn header(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
        }
    }

    /// The algorithm's name in S3 APIs (`x-amz-checksum-algorithm`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32C",
            Self::Crc64Nvme => "CRC64NVME",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }

    /// The XML element of a checksum value, e.g. `ChecksumSHA256`.
    pub fn xml_name(self) -> &'static str {
        match self {
            Self::Crc32 => "ChecksumCRC32",
            Self::Crc32c => "ChecksumCRC32C",
            Self::Crc64Nvme => "ChecksumCRC64NVME",
            Self::Sha1 => "ChecksumSHA1",
            Self::Sha256 => "ChecksumSHA256",
        }
    }

    pub const ALL: [ChecksumAlgo; 5] = [Self::Crc32, Self::Crc32c, Self::Crc64Nvme, Self::Sha1, Self::Sha256];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Storage {
    /// Object bytes live in the `inline` table under this id.
    Inline(u128),
    /// Object bytes are the concatenation of these data files (id, length).
    Segments(Vec<(u128, u64)>),
}

#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub size: u64,
    pub mtime_ms: u64,
    pub etag: String,
    /// Response headers to replay: content-type, cache-control, x-amz-meta-*, ...
    pub headers: Vec<(String, String)>,
    pub checksum: Option<(ChecksumAlgo, String)>,
    pub storage: Storage,
    pub tags: Vec<(String, String)>,
    /// Version id; `None` is the "null" version (unversioned or versioning-suspended writes).
    pub version: Option<String>,
    /// Write sequence number; orders versions of a key (assigned by the writer).
    pub seq: u64,
    /// A delete marker (only ever stored among noncurrent versions).
    pub delete_marker: bool,
}

pub struct ObjectSummary {
    pub size: u64,
    pub mtime_ms: u64,
    pub etag: String,
}

#[derive(Debug, Clone)]
pub struct UploadMeta {
    pub bucket: String,
    pub key: String,
    pub initiated_ms: u64,
    pub headers: Vec<(String, String)>,
    pub tags: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct PartMeta {
    pub size: u64,
    pub md5: [u8; 16],
    pub mtime_ms: u64,
    pub file: u128,
    /// The part's checksum, when the upload has a checksum algorithm.
    pub checksum: Option<(ChecksumAlgo, String)>,
}

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u128(&mut self, v: u128) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }
    fn headers(&mut self, h: &[(String, String)]) {
        self.u32(h.len() as u32);
        for (k, v) in h {
            self.str(k);
            self.str(v);
        }
    }
}

struct R<'a>(&'a [u8]);

fn corrupt() -> S3Error {
    S3Error::internal("corrupt metadata record")
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> S3Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(corrupt());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> S3Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> S3Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> S3Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u128(&mut self) -> S3Result<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn str(&mut self) -> S3Result<String> {
        let n = self.u32()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| corrupt())
    }
    fn headers(&mut self) -> S3Result<Vec<(String, String)>> {
        let n = self.u32()? as usize;
        let mut h = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            h.push((self.str()?, self.str()?));
        }
        Ok(h)
    }
}

impl ObjectMeta {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::with_capacity(128));
        w.u8(VERSION);
        w.u64(self.size);
        w.u64(self.mtime_ms);
        w.str(&self.etag);
        w.headers(&self.headers);
        match &self.checksum {
            None => w.u8(0),
            Some((a, v)) => {
                w.u8(*a as u8);
                w.str(v);
            }
        }
        match &self.storage {
            Storage::Inline(id) => {
                w.u8(0);
                w.u128(*id);
            }
            Storage::Segments(segs) => {
                w.u8(1);
                w.u32(segs.len() as u32);
                for (id, len) in segs {
                    w.u128(*id);
                    w.u64(*len);
                }
            }
        }
        w.headers(&self.tags);
        match &self.version {
            Some(v) => {
                w.u8(1);
                w.str(v);
            }
            None => w.u8(0),
        }
        w.u64(self.seq);
        w.u8(self.delete_marker as u8);
        w.0
    }

    pub fn decode(b: &[u8]) -> S3Result<Self> {
        let mut r = R(b);
        let version = check_version(r.u8()?)?;
        let size = r.u64()?;
        let mtime_ms = r.u64()?;
        let etag = r.str()?;
        let headers = r.headers()?;
        let checksum = match r.u8()? {
            0 => None,
            a => Some((ChecksumAlgo::from_u8(a).ok_or_else(corrupt)?, r.str()?)),
        };
        let storage = match r.u8()? {
            0 => Storage::Inline(r.u128()?),
            1 => {
                let n = r.u32()? as usize;
                // A corrupt count must not turn into a huge allocation: each entry is 24 bytes.
                let mut segs = Vec::with_capacity(n.min(r.0.len() / 24));
                for _ in 0..n {
                    segs.push((r.u128()?, r.u64()?));
                }
                Storage::Segments(segs)
            }
            _ => return Err(corrupt()),
        };
        let tags = if version >= 2 { r.headers()? } else { Vec::new() };
        let (version_id, seq, delete_marker) = if version >= 3 {
            let v = if r.u8()? == 1 { Some(r.str()?) } else { None };
            (v, r.u64()?, r.u8()? == 1)
        } else {
            (None, mtime_ms << 20, false)
        };
        Ok(ObjectMeta { size, mtime_ms, etag, headers, checksum, storage, tags, version: version_id, seq, delete_marker })
    }

    pub fn decode_summary(b: &[u8]) -> S3Result<ObjectSummary> {
        let mut r = R(b);
        check_version(r.u8()?)?;
        Ok(ObjectSummary { size: r.u64()?, mtime_ms: r.u64()?, etag: r.str()? })
    }
}

impl UploadMeta {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::with_capacity(64));
        w.u8(VERSION);
        w.str(&self.bucket);
        w.str(&self.key);
        w.u64(self.initiated_ms);
        w.headers(&self.headers);
        w.headers(&self.tags);
        w.0
    }

    pub fn decode(b: &[u8]) -> S3Result<Self> {
        let mut r = R(b);
        let version = check_version(r.u8()?)?;
        let (bucket, key, initiated_ms, headers) = (r.str()?, r.str()?, r.u64()?, r.headers()?);
        let tags = if version >= 2 { r.headers()? } else { Vec::new() };
        Ok(UploadMeta { bucket, key, initiated_ms, headers, tags })
    }
}

impl PartMeta {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::with_capacity(48));
        w.u64(self.size);
        w.0.extend_from_slice(&self.md5);
        w.u64(self.mtime_ms);
        w.u128(self.file);
        if let Some((a, v)) = &self.checksum {
            w.u8(*a as u8);
            w.str(v);
        }
        w.0
    }

    pub fn decode(b: &[u8]) -> S3Result<Self> {
        let mut r = R(b);
        let (size, md5, mtime_ms, file) = (r.u64()?, r.take(16)?.try_into().unwrap(), r.u64()?, r.u128()?);
        // The checksum was added later, as optional trailing bytes (older releases ignore them).
        let checksum = if r.0.is_empty() {
            None
        } else {
            let a = ChecksumAlgo::from_u8(r.u8()?).ok_or_else(corrupt)?;
            Some((a, r.str()?))
        };
        Ok(PartMeta { size, md5, mtime_ms, file, checksum })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_roundtrip() {
        let m = ObjectMeta {
            size: 42,
            mtime_ms: 7,
            etag: "\"abc\"".into(),
            headers: vec![("content-type".into(), "text/plain".into())],
            checksum: Some((ChecksumAlgo::Crc32c, "AAAA".into())),
            storage: Storage::Segments(vec![(1, 2), (3, 4)]),
            tags: vec![("k".into(), "v".into())],
            version: Some("v1".into()),
            seq: 42,
            delete_marker: true,
        };
        let d = ObjectMeta::decode(&m.encode()).unwrap();
        assert_eq!(d.size, 42);
        assert_eq!(d.etag, "\"abc\"");
        assert_eq!(d.storage, m.storage);
        assert_eq!(d.checksum, m.checksum);
        assert_eq!(d.tags, m.tags);
        assert_eq!((d.version.as_deref(), d.seq, d.delete_marker), (Some("v1"), 42, true));
        let s = ObjectMeta::decode_summary(&m.encode()).unwrap();
        assert_eq!((s.size, s.mtime_ms), (42, 7));
    }
}

#[cfg(test)]
mod compat_tests {
    use super::*;

    /// Records written by v1 (no tags) must still decode.
    #[test]
    fn decodes_v1_records() {
        let m = ObjectMeta {
            size: 1,
            mtime_ms: 2,
            etag: "\"e\"".into(),
            headers: vec![],
            checksum: None,
            storage: Storage::Inline(9),
            tags: vec![],
            version: None,
            seq: 0,
            delete_marker: false,
        };
        let mut v1 = m.encode();
        v1[0] = 1;
        v1.truncate(v1.len() - 4 - 1 - 8 - 1); // drop the v2 (tags) and v3 (version) trailers
        let d = ObjectMeta::decode(&v1).unwrap();
        assert_eq!(d.storage, Storage::Inline(9));
        assert!(d.tags.is_empty());
        assert_eq!((d.version, d.seq, d.delete_marker), (None, 2 << 20, false));
    }
}
