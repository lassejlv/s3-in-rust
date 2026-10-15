//! Encryption at rest (SSE-S3, SSE-KMS and SSE-C).
//!
//! Encrypted object data (a data file or an inline blob) is self-describing:
//!
//! ```text
//! header: "S3E1" | kind u8 | key id [8] | wrap nonce [12] | wrapped data key [32 + 16 tag]
//! body:   chunk 0 | chunk 1 | ...   each = AES-256-GCM(data key, nonce = index, aad = is_last) of
//!                                   up to CHUNK plaintext bytes, followed by its 16-byte tag
//! ```
//!
//! Each file has its own random data key, wrapped either by the server master key (SSE-S3) or
//! by the customer's key (SSE-C). Because the key travels with the file, hard-linked copies,
//! multipart parts and old versions need no extra bookkeeping. Range reads decrypt only the
//! chunks they overlap. The final chunk is authenticated as final, so truncation is detected.

use crate::error::{S3Error, S3Result, err};
use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use sha2::{Digest, Sha256};

pub const CHUNK: usize = 64 * 1024;
pub const TAG: usize = 16;
const MAGIC: &[u8; 4] = b"S3E1";
pub const HEADER: usize = 4 + 1 + 8 + 12 + 32 + TAG;

/// Who wraps the data key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Master = 1,
    Customer = 2,
}

/// A 256-bit wrapping key plus a short id used to detect the wrong key early.
#[derive(Clone)]
pub struct WrapKey {
    pub kind: KeyKind,
    key: [u8; 32],
    id: [u8; 8],
}

impl WrapKey {
    /// Whether two keys are the same key (data wrapped by one can be read with the other).
    pub fn same(&self, other: &WrapKey) -> bool {
        self.kind == other.kind && self.id == other.id
    }

    pub fn new(kind: KeyKind, key: [u8; 32]) -> Self {
        let digest = Sha256::digest([b"s3rs-key-id:".as_slice(), &key].concat());
        WrapKey { kind, key, id: digest[..8].try_into().unwrap() }
    }
}

impl std::fmt::Debug for WrapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrapKey({:?}, id={})", self.kind, crate::util::hex(&self.id))
    }
}

pub const KMS_KEY_ID: &str = "x-amz-server-side-encryption-aws-kms-key-id";
/// The KMS key of SSE-KMS requests that name none (S3's AWS-managed key).
pub const DEFAULT_KMS_KEY: &str = "alias/aws/s3";

/// SSE-KMS without an external KMS: each KMS key id gets its own wrapping key, derived from
/// the master key. Objects under different key ids can't be read with each other's key.
pub fn kms_key(master: &WrapKey, key_id: &str) -> WrapKey {
    WrapKey::new(KeyKind::Master, crate::auth::hmac(&master.key, format!("s3rs-kms-key\0{key_id}").as_bytes()))
}

/// The server-side key that reads data stored with `headers`: the master key (SSE-S3) or the
/// key of its KMS key id (SSE-KMS). `None` if the data is not encrypted by the server.
pub fn server_key(headers: &[(String, String)], master: &WrapKey) -> Option<WrapKey> {
    let get = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    match get("x-amz-server-side-encryption")? {
        a if a.starts_with("aws:kms") => Some(kms_key(master, get(KMS_KEY_ID).unwrap_or(DEFAULT_KMS_KEY))),
        _ => Some(master.clone()),
    }
}

fn crypto_err(msg: &str) -> S3Error {
    S3Error::internal(format!("decryption failed: {msg}"))
}

fn chunk_nonce(index: u64) -> Nonce<aes_gcm::aead::consts::U12> {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&index.to_be_bytes());
    n.into()
}

fn seal(cipher: &Aes256Gcm, index: u64, last: bool, buf: &mut [u8]) -> [u8; TAG] {
    let tag = cipher.encrypt_inout_detached(&chunk_nonce(index), &[last as u8], buf.into()).expect("chunk within AES-GCM limits");
    tag.into()
}

fn open(cipher: &Aes256Gcm, index: u64, last: bool, buf: &mut [u8], tag: &[u8]) -> S3Result<()> {
    let tag: Tag = <[u8; TAG]>::try_from(tag).map_err(|_| crypto_err("short tag"))?.into();
    cipher
        .decrypt_inout_detached(&chunk_nonce(index), &[last as u8], buf.into(), &tag)
        .map_err(|_| crypto_err("authentication failed"))
}

/// Number of chunks used for `len` plaintext bytes (an empty object still has one empty chunk).
pub fn chunks(len: u64) -> u64 {
    len.div_ceil(CHUNK as u64).max(1)
}

/// Stored size of an encrypted object with `len` plaintext bytes.
pub fn encrypted_len(len: u64) -> u64 {
    HEADER as u64 + len + chunks(len) * TAG as u64
}

/// Build a header with a fresh data key wrapped by `wrap`; returns (header, data cipher).
pub fn new_header(wrap: &WrapKey) -> ([u8; HEADER], Aes256Gcm) {
    let mut dek = [0u8; 32];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut dek).expect("system randomness");
    getrandom::fill(&mut nonce).expect("system randomness");
    let mut h = [0u8; HEADER];
    h[..4].copy_from_slice(MAGIC);
    h[4] = wrap.kind as u8;
    h[5..13].copy_from_slice(&wrap.id);
    h[13..25].copy_from_slice(&nonce);
    let mut wrapped = dek;
    let kek = Aes256Gcm::new_from_slice(&wrap.key).expect("32-byte key");
    let tag = kek.encrypt_inout_detached(&nonce.into(), &h[..13], wrapped.as_mut_slice().into()).expect("wrap");
    h[25..57].copy_from_slice(&wrapped);
    h[57..].copy_from_slice(&tag);
    (h, Aes256Gcm::new_from_slice(&dek).expect("32-byte key"))
}

/// Unwrap the data key from a header.
pub fn open_header(h: &[u8], wrap: &WrapKey) -> S3Result<Aes256Gcm> {
    if h.len() < HEADER || &h[..4] != MAGIC {
        return Err(crypto_err("missing encryption header"));
    }
    if h[4] != wrap.kind as u8 || h[5..13] != wrap.id {
        return Err(match wrap.kind {
            KeyKind::Customer => err::AccessDenied().with_message("The provided customer key does not match the object's key."),
            KeyKind::Master => crypto_err("object was encrypted with a different master key"),
        });
    }
    let nonce: [u8; 12] = h[13..25].try_into().unwrap();
    let mut dek: [u8; 32] = h[25..57].try_into().unwrap();
    let tag: Tag = <[u8; TAG]>::try_from(&h[57..HEADER]).unwrap().into();
    let kek = Aes256Gcm::new_from_slice(&wrap.key).expect("32-byte key");
    kek.decrypt_inout_detached(&nonce.into(), &h[..13], dek.as_mut_slice().into(), &tag)
        .map_err(|_| crypto_err("cannot unwrap data key"))?;
    Ok(Aes256Gcm::new_from_slice(&dek).expect("32-byte key"))
}

/// Streaming encryptor: feed plaintext, get header + sealed chunks.
pub struct Encryptor {
    cipher: Aes256Gcm,
    index: u64,
    pending: Vec<u8>,
    header: Option<[u8; HEADER]>,
}

impl Encryptor {
    pub fn new(wrap: &WrapKey) -> Self {
        let (header, cipher) = new_header(wrap);
        Encryptor { cipher, index: 0, pending: Vec::with_capacity(CHUNK + TAG), header: Some(header) }
    }

    /// Append ciphertext for `data` to `out`. A full chunk is only sealed once more data
    /// arrives, because the last chunk is authenticated differently.
    pub fn update(&mut self, mut data: &[u8], out: &mut Vec<u8>) {
        if let Some(h) = self.header.take() {
            out.extend_from_slice(&h);
        }
        while !data.is_empty() {
            if self.pending.len() == CHUNK {
                self.flush_chunk(false, out);
            }
            let n = (CHUNK - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..n]);
            data = &data[n..];
        }
    }

    fn flush_chunk(&mut self, last: bool, out: &mut Vec<u8>) {
        let tag = seal(&self.cipher, self.index, last, &mut self.pending);
        out.extend_from_slice(&self.pending);
        out.extend_from_slice(&tag);
        self.pending.clear();
        self.index += 1;
    }

    pub fn finish(mut self, out: &mut Vec<u8>) {
        if let Some(h) = self.header.take() {
            out.extend_from_slice(&h);
        }
        self.flush_chunk(true, out);
    }
}

/// Encrypt a whole buffer.
pub fn encrypt_all(wrap: &WrapKey, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(encrypted_len(data.len() as u64) as usize);
    let mut e = Encryptor::new(wrap);
    e.update(data, &mut out);
    e.finish(&mut out);
    out
}

/// Byte range of ciphertext (relative to the start of the stored object, header included)
/// needed to decrypt plaintext `[start, start+len)` of an object of `total` plaintext bytes.
pub fn cipher_span(start: u64, len: u64, total: u64) -> (u64, u64, u64) {
    let first = start / CHUNK as u64;
    let last = if len == 0 { first } else { (start + len - 1) / CHUNK as u64 };
    let last = last.min(chunks(total) - 1);
    let off = HEADER as u64 + first * (CHUNK + TAG) as u64;
    let end_plain = ((last + 1) * CHUNK as u64).min(total);
    let span = end_plain - first * CHUNK as u64 + (last - first + 1) * TAG as u64;
    (first, off, span)
}

/// Decrypt chunks starting at chunk index `first` (whose ciphertext is in `buf`), appending
/// plaintext `[start, start+len)` to `out`.
pub fn decrypt_span(
    cipher: &Aes256Gcm,
    first: u64,
    buf: &mut [u8],
    start: u64,
    len: u64,
    total: u64,
    out: &mut Vec<u8>,
) -> S3Result<()> {
    let last_chunk = chunks(total) - 1;
    let mut idx = first;
    let mut rest = buf;
    while !rest.is_empty() {
        let plain_len = (total - idx * CHUNK as u64).min(CHUNK as u64) as usize;
        if rest.len() < plain_len + TAG {
            return Err(crypto_err("truncated ciphertext"));
        }
        let (chunk, tail) = rest.split_at_mut(plain_len + TAG);
        let (data, tag) = chunk.split_at_mut(plain_len);
        open(cipher, idx, idx == last_chunk, data, tag)?;
        let chunk_start = idx * CHUNK as u64;
        let lo = start.max(chunk_start);
        let hi = (start + len).min(chunk_start + plain_len as u64);
        if hi > lo {
            out.extend_from_slice(&data[(lo - chunk_start) as usize..(hi - chunk_start) as usize]);
        }
        idx += 1;
        rest = tail;
    }
    Ok(())
}

/// Decrypt `[start, start+len)` of a whole in-memory encrypted object.
pub fn decrypt_range(wrap: &WrapKey, blob: &[u8], start: u64, len: u64, total: u64) -> S3Result<Vec<u8>> {
    let cipher = open_header(blob, wrap)?;
    let (first, off, span) = cipher_span(start, len, total);
    let mut buf = blob.get(off as usize..(off + span) as usize).ok_or_else(|| crypto_err("truncated object"))?.to_vec();
    // `len` comes from metadata; never reserve more than the blob could hold.
    let mut out = Vec::with_capacity(len.min(blob.len() as u64) as usize);
    decrypt_span(&cipher, first, &mut buf, start, len, total, &mut out)?;
    Ok(out)
}

/// The digest used as an object's ETag. SSE-C objects must not expose the plaintext MD5 to
/// callers without the key (as on S3, their ETag is not the MD5), so it is keyed with the
/// customer key. Plain and SSE-S3 objects keep the MD5, matching S3.
pub fn etag_digest(key: Option<&WrapKey>, md5: [u8; 16]) -> [u8; 16] {
    match key {
        Some(k) if k.kind == KeyKind::Customer => {
            let mac = crate::auth::hmac(&k.key, &[b"s3rs-etag:".as_slice(), &md5].concat());
            mac[..16].try_into().unwrap()
        }
        _ => md5,
    }
}

/// Parse a base64 256-bit key (and optionally check its base64 MD5), as SSE-C headers carry.
pub fn parse_customer_key(key_b64: &str, md5_b64: Option<&str>) -> S3Result<[u8; 32]> {
    let key = crate::util::unbase64(key_b64)
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .ok_or_else(|| err::InvalidArgument().with_message("The secret key was invalid for the specified algorithm."))?;
    if let Some(m) = md5_b64 {
        use md5::Digest as _;
        if crate::util::unbase64(m).as_deref() != Some(&md5::Md5::digest(key)[..]) {
            return Err(err::InvalidArgument()
                .with_message("The calculated MD5 hash of the key did not match the hash that was provided."));
        }
    }
    Ok(key)
}

pub fn key_md5_b64(key: &[u8; 32]) -> String {
    use md5::Digest as _;
    crate::util::base64(&md5::Md5::digest(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kind: KeyKind, b: u8) -> WrapKey {
        WrapKey::new(kind, [b; 32])
    }

    #[test]
    fn roundtrip_all_sizes_and_ranges() {
        let k = key(KeyKind::Master, 7);
        for size in [0usize, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 17] {
            let data: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
            let blob = encrypt_all(&k, &data);
            assert_eq!(blob.len() as u64, encrypted_len(size as u64));
            assert_eq!(decrypt_range(&k, &blob, 0, size as u64, size as u64).unwrap(), data);
            for (s, l) in [(0, 1), (CHUNK - 1, 2), (CHUNK, CHUNK), (5, 3 * CHUNK)] {
                if s + l <= size {
                    let got = decrypt_range(&k, &blob, s as u64, l as u64, size as u64).unwrap();
                    assert_eq!(got, &data[s..s + l], "size {size} range {s}+{l}");
                }
            }
        }
    }

    #[test]
    fn streaming_matches_one_shot_framing() {
        let k = key(KeyKind::Master, 1);
        let data = vec![9u8; 2 * CHUNK + 5];
        let mut out = Vec::new();
        let mut e = Encryptor::new(&k);
        for piece in data.chunks(1000) {
            e.update(piece, &mut out);
        }
        e.finish(&mut out);
        assert_eq!(out.len() as u64, encrypted_len(data.len() as u64));
        assert_eq!(decrypt_range(&k, &out, 0, data.len() as u64, data.len() as u64).unwrap(), data);
    }

    #[test]
    fn detects_tampering_wrong_key_and_truncation() {
        let k = key(KeyKind::Master, 3);
        let data = vec![1u8; CHUNK * 2];
        let mut blob = encrypt_all(&k, &data);
        assert!(decrypt_range(&key(KeyKind::Master, 4), &blob, 0, 10, data.len() as u64).is_err());
        let c = key(KeyKind::Customer, 3);
        assert_eq!(decrypt_range(&c, &blob, 0, 10, data.len() as u64).unwrap_err().code, "AccessDenied");
        // Dropping the last chunk and claiming a shorter object fails: chunk 0 was not sealed as last.
        let short = &blob[..HEADER + CHUNK + TAG];
        assert!(decrypt_range(&k, short, 0, CHUNK as u64, CHUNK as u64).is_err());
        blob[HEADER + 5] ^= 1;
        assert!(decrypt_range(&k, &blob, 0, 10, data.len() as u64).is_err());
    }

    #[test]
    fn customer_key_parsing() {
        let raw = [5u8; 32];
        let b64 = crate::util::base64(&raw);
        assert_eq!(parse_customer_key(&b64, Some(&key_md5_b64(&raw))).unwrap(), raw);
        assert!(parse_customer_key(&b64, Some("AAAA")).is_err());
        assert!(parse_customer_key("c2hvcnQ=", None).is_err());
    }
}
