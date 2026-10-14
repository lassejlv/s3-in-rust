//! Small, dependency-free helpers: hex/base64, time formatting, URI encoding, XML escaping, ids.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.as_chunks::<2>().0 {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            3 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32,
            2 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8,
            _ => (chunk[0] as u32) << 16,
        };
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn unbase64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2009-10-12T17:50:30.000Z`
pub fn iso8601(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, (rem / 60) % 60, rem % 60, ms % 1000)
}

/// RFC 7231 date, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn http_date(ms: u64) -> String {
    httpdate::fmt_http_date(UNIX_EPOCH + std::time::Duration::from_millis(ms))
}

pub fn parse_http_date(s: &str) -> Option<u64> {
    let t = httpdate::parse_http_date(s.trim()).ok()?;
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_secs())
}

/// Parse `20130524T000000Z` into unix seconds.
pub fn parse_amz_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> { s.get(r)?.parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (h, mi, se) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let days = days_from_civil(y as i64, mo, d);
    Some((days * 86_400 + (h * 3600 + mi * 60 + se) as i64) as u64)
}

/// Parse `2026-01-01T00:00:00Z` or `2026-01-01T00:00:00.000Z` into unix seconds.
pub fn parse_iso8601(s: &str) -> Option<u64> {
    if !s.is_ascii() {
        return None;
    }
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || !s.ends_with('Z') {
        return None;
    }
    let frac = &s[19..s.len() - 1];
    if !(frac.is_empty() || (frac.starts_with('.') && frac.len() > 1 && frac[1..].bytes().all(|c| c.is_ascii_digit()))) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> { s.get(r)?.parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let days = days_from_civil(y as i64, mo, d);
    Some((days * 86_400 + (h * 3600 + mi * 60 + se) as i64) as u64)
}

/// Format unix seconds as `20130524T000000Z`.
pub fn amz_date(secs: u64) -> String {
    let (y, mo, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!("{y:04}{mo:02}{d:02}T{:02}{:02}{:02}Z", rem / 3600, (rem / 60) % 60, rem % 60)
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// AWS-style URI encoding (RFC 3986 unreserved set kept). `keep_slash` for paths.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for &b in s.as_bytes() {
        if is_unreserved(b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize].to_ascii_uppercase() as char);
            out.push(HEX[(b & 15) as usize].to_ascii_uppercase() as char);
        }
    }
    out
}

/// Percent-decode. When `plus_as_space` is set, `+` decodes to a space (query strings).
pub fn uri_decode(s: &str, plus_as_space: bool) -> Option<String> {
    if !s.contains(['%', '+']) {
        return Some(s.to_owned());
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                out.push((hex_val(b[i + 1])? << 4) | hex_val(b[i + 2])?);
                i += 3;
            }
            b'%' => return None,
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Escape text for inclusion in XML element content.
pub fn xml_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\r' => out.push_str("&#13;"),
            // NUL cannot appear in XML 1.0 at all, not even as a character reference.
            '\0' => out.push('\u{FFFD}'),
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' => {
                out.push_str(&format!("&#{};", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// Process-unique, restart-unique 128-bit identifiers (data files, upload ids).
pub fn new_id() -> u128 {
    static SEEDS: OnceLock<(u64, u64)> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let (s1, s2) = *SEEDS.get_or_init(|| {
        let mut b = [0u8; 16];
        if getrandom::fill(&mut b).is_err() {
            let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
            b = (t ^ (std::process::id() as u128) << 64).to_le_bytes();
        }
        (u64::from_le_bytes(b[..8].try_into().unwrap()), u64::from_le_bytes(b[8..].try_into().unwrap()))
    });
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    // splitmix64 is a bijection, so `lo` is unique within this process; `hi` mixes in a
    // second random seed so ids from different runs do not collide.
    let lo = splitmix64(c ^ s1);
    let hi = splitmix64(c.wrapping_add(s2) ^ s1.rotate_left(17));
    ((hi as u128) << 64) | lo as u128
}

/// A unique id that increases over time: milliseconds since the epoch, then a counter that
/// starts at a random value each run. Used as the key of inline object data, so new entries
/// are appended at the end of the table instead of scattered across it (far fewer pages to
/// write per commit). The random counter start keeps ids unique even if the clock steps back.
pub fn new_seq_id() -> u128 {
    static START: OnceLock<u64> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let start = *START.get_or_init(|| (new_id() >> 64) as u64);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    ((now_ms() as u128) << 64) | start.wrapping_add(c) as u128
}

fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

pub fn id_hex(id: u128) -> String {
    format!("{id:032x}")
}

pub fn parse_id_hex(s: &str) -> Option<u128> {
    if s.len() != 32 {
        return None;
    }
    u128::from_str_radix(s, 16).ok()
}

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(unbase64(&base64(s.as_bytes())).unwrap(), s.as_bytes());
        }
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"fo"), "Zm8=");
    }

    #[test]
    fn dates() {
        assert_eq!(iso8601(1_255_369_830_000), "2009-10-12T17:50:30.000Z");
        assert_eq!(parse_amz_date("20091012T175030Z"), Some(1_255_369_830));
        assert_eq!(amz_date(1_255_369_830), "20091012T175030Z");
        assert_eq!(parse_iso8601("2009-10-12T17:50:30.000Z"), Some(1_255_369_830));
        assert_eq!(parse_iso8601("2009-10-12T17:50:30Z"), Some(1_255_369_830));
        assert_eq!(parse_iso8601("2009-10-12 17:50:30Z"), None);
        // Multi-byte characters must not panic (byte slicing).
        assert_eq!(parse_iso8601("2030-01-01T00:00:0éZ"), None);
        assert_eq!(parse_iso8601("2030-01-01T00:00:00.é"), None);
        assert_eq!(parse_iso8601(&iso8601(1_700_000_000_123)), Some(1_700_000_000));
    }

    #[test]
    fn uri() {
        assert_eq!(uri_encode("a b/c~d+é", true), "a%20b/c~d%2B%C3%A9");
        assert_eq!(uri_decode("a%20b+c", true).unwrap(), "a b c");
        assert_eq!(uri_decode("a%2", false), None);
        assert_eq!(uri_decode("%41", false).unwrap(), "A");
    }

    #[test]
    fn ids_unique() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert_eq!(parse_id_hex(&id_hex(a)), Some(a));
    }
}
