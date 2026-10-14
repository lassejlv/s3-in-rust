//! Incremental decoder for `aws-chunked` request bodies (signed or unsigned, with or without
//! trailing headers). Data is emitted as soon as it arrives; chunk signatures are checked when
//! each chunk completes.

use crate::auth::ChunkSigner;
use crate::error::{S3Result, err};
use bytes::{Buf, Bytes, BytesMut};
use sha2::{Digest, Sha256};

const MAX_LINE: usize = 8 * 1024;

enum State {
    Header,
    Data { remaining: u64 },
    DataEnd,
    Trailers,
    Done,
}

pub struct ChunkDecoder {
    buf: BytesMut,
    state: State,
    signer: Option<ChunkSigner>,
    trailer: bool,
    hasher: Sha256,
    chunk_sig: String,
    pub trailers: Vec<(String, String)>,
    trailer_sig: Option<String>,
    final_seen: bool,
}

fn bad(msg: &str) -> crate::error::S3Error {
    err::IncompleteBody().with_message(format!("Malformed aws-chunked body: {msg}"))
}

impl ChunkDecoder {
    pub fn new(signer: Option<ChunkSigner>, trailer: bool) -> Self {
        ChunkDecoder {
            buf: BytesMut::new(),
            state: State::Header,
            signer,
            trailer,
            hasher: Sha256::new(),
            chunk_sig: String::new(),
            trailers: Vec::new(),
            trailer_sig: None,
            final_seen: false,
        }
    }

    fn take_line(&mut self) -> S3Result<Option<String>> {
        match self.buf.windows(2).position(|w| w == b"\r\n") {
            Some(i) => {
                let line = self.buf.split_to(i);
                self.buf.advance(2);
                String::from_utf8(line.to_vec()).map(Some).map_err(|_| bad("invalid header line"))
            }
            None if self.buf.len() > MAX_LINE => Err(bad("header line too long")),
            None => Ok(None),
        }
    }

    /// Feed raw body bytes; decoded payload bytes are pushed to `out`.
    pub fn feed(&mut self, input: Bytes, out: &mut impl FnMut(Bytes)) -> S3Result<()> {
        self.buf.extend_from_slice(&input);
        loop {
            match self.state {
                State::Header => {
                    let Some(line) = self.take_line()? else { return Ok(()) };
                    let mut it = line.split(';');
                    let size = u64::from_str_radix(it.next().unwrap_or("").trim(), 16).map_err(|_| bad("invalid chunk size"))?;
                    self.chunk_sig.clear();
                    for ext in it {
                        if let Some(s) = ext.trim().strip_prefix("chunk-signature=") {
                            self.chunk_sig = s.to_string();
                        }
                    }
                    if self.signer.is_some() && self.chunk_sig.is_empty() {
                        return Err(err::SignatureDoesNotMatch().with_message("Missing chunk signature"));
                    }
                    if size == 0 {
                        self.verify_chunk()?;
                        self.state = if self.trailer { State::Trailers } else { State::DataEnd };
                    } else {
                        self.state = State::Data { remaining: size };
                    }
                }
                State::Data { remaining } => {
                    if self.buf.is_empty() {
                        return Ok(());
                    }
                    let n = (self.buf.len() as u64).min(remaining) as usize;
                    let data = self.buf.split_to(n).freeze();
                    if self.signer.is_some() {
                        self.hasher.update(&data);
                    }
                    out(data);
                    let remaining = remaining - n as u64;
                    if remaining == 0 {
                        self.verify_chunk()?;
                        self.state = State::DataEnd;
                    } else {
                        self.state = State::Data { remaining };
                    }
                }
                State::DataEnd => {
                    if self.buf.len() < 2 {
                        return Ok(());
                    }
                    if &self.buf[..2] != b"\r\n" {
                        return Err(bad("missing CRLF after chunk"));
                    }
                    self.buf.advance(2);
                    self.state = if self.is_final() { State::Done } else { State::Header };
                }
                State::Trailers => {
                    let Some(line) = self.take_line()? else { return Ok(()) };
                    if line.is_empty() {
                        self.finish_trailers()?;
                        self.state = State::Done;
                        continue;
                    }
                    let (k, v) = line.split_once(':').ok_or_else(|| bad("invalid trailer"))?;
                    let k = k.trim().to_ascii_lowercase();
                    if k == "x-amz-trailer-signature" {
                        self.trailer_sig = Some(v.trim().to_string());
                    } else {
                        self.trailers.push((k, v.trim().to_string()));
                    }
                }
                State::Done => {
                    // Ignore any trailing CRLFs some clients add.
                    self.buf.clear();
                    return Ok(());
                }
            }
        }
    }

    /// The zero-length chunk was seen and its CRLF is all that remains.
    fn is_final(&self) -> bool {
        self.final_seen
    }

    fn verify_chunk(&mut self) -> S3Result<()> {
        if let State::Header = self.state {
            // Zero-size chunk: marks the end of the data.
            self.final_seen = true;
        }
        if let Some(s) = &mut self.signer {
            let digest = std::mem::take(&mut self.hasher).finalize();
            s.verify_chunk(&digest, &self.chunk_sig)?;
        }
        Ok(())
    }

    fn finish_trailers(&mut self) -> S3Result<()> {
        if let Some(s) = &mut self.signer {
            let sig =
                self.trailer_sig.take().ok_or_else(|| err::SignatureDoesNotMatch().with_message("Missing trailer signature"))?;
            let mut canonical = String::new();
            for (k, v) in &self.trailers {
                canonical.push_str(k);
                canonical.push(':');
                canonical.push_str(v);
                canonical.push('\n');
            }
            s.verify_trailer(&canonical, &sig)?;
        }
        Ok(())
    }

    /// Called at end of input.
    pub fn finish(&mut self) -> S3Result<()> {
        match self.state {
            State::Done => Ok(()),
            // Tolerate a missing final blank line (or CRLF) after the trailers.
            State::Trailers => {
                if !self.buf.is_empty() {
                    self.feed(Bytes::from_static(b"\r\n"), &mut |_| {})?;
                }
                if matches!(self.state, State::Trailers) && self.buf.is_empty() {
                    self.finish_trailers()?;
                    self.state = State::Done;
                }
                if matches!(self.state, State::Done) { Ok(()) } else { Err(err::IncompleteBody()) }
            }
            _ => Err(err::IncompleteBody()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(input: &[u8], split: usize, trailer: bool) -> (Vec<u8>, Vec<(String, String)>) {
        let mut d = ChunkDecoder::new(None, trailer);
        let mut out = Vec::new();
        for piece in input.chunks(split) {
            d.feed(Bytes::copy_from_slice(piece), &mut |b| out.extend_from_slice(&b)).unwrap();
        }
        d.finish().unwrap();
        (out, d.trailers)
    }

    #[test]
    fn unsigned_trailer() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n";
        for split in [1, 2, 3, 7, 100] {
            let (data, tr) = decode(body, split, true);
            assert_eq!(data, b"hello world");
            assert_eq!(tr, vec![("x-amz-checksum-crc32".to_string(), "AAAAAA==".to_string())]);
        }
    }

    #[test]
    fn plain_signed_shape() {
        let body = b"5;chunk-signature=abc\r\nhello\r\n0;chunk-signature=def\r\n\r\n";
        let (data, _) = decode(body, 4, false);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn missing_final_crlf_after_trailers() {
        let body = b"3\r\nabc\r\n0\r\nx-amz-checksum-crc32c:xyz\r\n";
        let (data, tr) = decode(body, 5, true);
        assert_eq!(data, b"abc");
        assert_eq!(tr.len(), 1);
    }
}
