//! Browser-based uploads (`POST /bucket` with `multipart/form-data`): a streaming multipart
//! parser and POST policy evaluation.
//!
//! Form fields before the `file` part are buffered (they are small); the file part itself is
//! streamed straight into storage. Fields after the file are ignored, as S3 does.

use crate::access::{Json, parse_json};
use crate::error::{S3Error, S3Result, err};
use crate::io::{BodyStream, Source};
use crate::util;
use bytes::{Bytes, BytesMut};
use memchr::memmem;
use std::collections::HashMap;

const MAX_HEADER: usize = 16 * 1024;
const MAX_FIELDS: usize = 1024 * 1024;

pub struct Form {
    /// Lowercased field name -> value.
    pub fields: HashMap<String, String>,
    pub file_name: Option<String>,
    pub file_content_type: Option<String>,
}

/// The file part's content, ending at the next boundary.
pub struct FilePart {
    body: BodyStream,
    buf: BytesMut,
    delim: Vec<u8>,
    done: bool,
}

fn malformed(msg: &str) -> S3Error {
    err::MalformedXML().with_message(msg).with_code("MalformedPOSTRequest")
}

/// Extract the boundary from a `multipart/form-data; boundary=...` content type.
pub fn boundary(content_type: &str) -> Option<String> {
    let (mime, params) = content_type.split_once(';')?;
    if !mime.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    params.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        k.trim().eq_ignore_ascii_case("boundary").then(|| v.trim().trim_matches('"').to_string())
    })
}

/// Parameters of a `Content-Disposition: form-data; name="x"; filename="y"` header.
fn disposition_param(value: &str, param: &str) -> Option<String> {
    let mut rest = value;
    while let Some(i) = rest.find(';') {
        rest = rest[i + 1..].trim_start();
        let (k, after) = rest.split_once('=')?;
        let (v, next) = if let Some(q) = after.strip_prefix('"') {
            let mut out = String::new();
            let mut chars = q.char_indices();
            let mut end = q.len();
            while let Some((i, c)) = chars.next() {
                match c {
                    '\\' => {
                        if let Some((_, n)) = chars.next() {
                            out.push(n);
                        }
                    }
                    '"' => {
                        end = i + 1;
                        break;
                    }
                    c => out.push(c),
                }
            }
            (out, &q[end..])
        } else {
            let end = after.find(';').unwrap_or(after.len());
            (after[..end].trim().to_string(), &after[end..])
        };
        if k.trim().eq_ignore_ascii_case(param) {
            return Some(v);
        }
        rest = next;
    }
    None
}

async fn fill(body: &mut BodyStream, buf: &mut BytesMut) -> S3Result<()> {
    match body.next().await? {
        Some(b) => {
            buf.extend_from_slice(&b);
            Ok(())
        }
        None => Err(malformed("The body of your POST request is not well-formed multipart/form-data.")),
    }
}

/// Read form fields up to (and including the headers of) the `file` part.
pub async fn parse_form(mut body: BodyStream, boundary: &str) -> S3Result<(Form, FilePart)> {
    let first = format!("--{boundary}");
    let delim = format!("\r\n--{boundary}").into_bytes();
    let mut buf = BytesMut::new();
    // Skip any preamble up to the first boundary line.
    loop {
        if let Some(i) = memmem::find(&buf, first.as_bytes()) {
            let after = i + first.len();
            if buf.len() >= after + 2 {
                if &buf[after..after + 2] != b"\r\n" {
                    return Err(malformed("Malformed multipart boundary"));
                }
                let _ = buf.split_to(after + 2);
                break;
            }
        } else if buf.len() > MAX_HEADER {
            return Err(malformed("Missing multipart boundary"));
        }
        fill(&mut body, &mut buf).await?;
    }

    let mut fields = HashMap::new();
    let mut total = 0usize;
    loop {
        // Part headers.
        let headers_end = loop {
            if let Some(i) = memmem::find(&buf, b"\r\n\r\n") {
                break i;
            }
            if buf.len() > MAX_HEADER {
                return Err(malformed("Multipart part headers too large"));
            }
            fill(&mut body, &mut buf).await?;
        };
        let head = String::from_utf8_lossy(&buf[..headers_end]).into_owned();
        let _ = buf.split_to(headers_end + 4);
        let (mut name, mut filename, mut ctype) = (None, None, None);
        for line in head.split("\r\n") {
            let Some((k, v)) = line.split_once(':') else { continue };
            if k.trim().eq_ignore_ascii_case("content-disposition") {
                name = disposition_param(v, "name");
                filename = disposition_param(v, "filename");
            } else if k.trim().eq_ignore_ascii_case("content-type") {
                ctype = Some(v.trim().to_string());
            }
        }
        let name = name.ok_or_else(|| malformed("Multipart part without a name"))?.to_ascii_lowercase();
        if name == "file" {
            let form = Form { fields, file_name: filename, file_content_type: ctype };
            return Ok((form, FilePart { body, buf, delim, done: false }));
        }
        // A regular field: buffer until the next boundary.
        let end = loop {
            if let Some(i) = memmem::find(&buf, &delim) {
                break i;
            }
            if total + buf.len() > MAX_FIELDS {
                return Err(malformed("Form fields too large"));
            }
            fill(&mut body, &mut buf).await?;
        };
        let value = String::from_utf8(buf[..end].to_vec()).map_err(|_| malformed("Form field is not valid UTF-8"))?;
        total += value.len();
        let _ = buf.split_to(end + delim.len());
        while buf.len() < 2 {
            fill(&mut body, &mut buf).await?;
        }
        if &buf[..2] == b"--" {
            return Err(err::InvalidArgument().with_message("POST requires exactly one file upload per request."));
        }
        let _ = buf.split_to(2); // CRLF
        fields.insert(name, value);
    }
}

impl Source for FilePart {
    async fn next(&mut self) -> S3Result<Option<Bytes>> {
        loop {
            if self.done {
                return Ok(None);
            }
            if let Some(i) = memmem::find(&self.buf, &self.delim) {
                self.done = true;
                let out = self.buf.split_to(i).freeze();
                return Ok((!out.is_empty()).then_some(out));
            }
            // Everything except a possible partial delimiter at the end can be emitted.
            let keep = self.delim.len() - 1;
            if self.buf.len() > keep {
                let n = self.buf.len() - keep;
                return Ok(Some(self.buf.split_to(n).freeze()));
            }
            fill(&mut self.body, &mut self.buf).await.map_err(|_| err::IncompleteBody())?;
        }
    }
}

// ------------------------------------------------------------------ POST policy

enum Cond {
    Eq(String, String),
    StartsWith(String, String),
    LengthRange(u64, u64),
}

pub struct PostPolicy {
    conds: Vec<Cond>,
}

fn policy_err(msg: impl Into<String>) -> S3Error {
    err::AccessDenied().with_message(format!("Invalid according to Policy: {}", msg.into()))
}

/// Fields that never need a policy condition.
fn exempt(field: &str) -> bool {
    // Checksums only protect the upload's integrity, so they need no condition (as on S3).
    matches!(field, "policy" | "x-amz-signature" | "signature" | "awsaccesskeyid" | "file")
        || field.starts_with("x-ignore-")
        || field.starts_with("x-amz-checksum-")
}

impl PostPolicy {
    pub fn parse(policy_b64: &str) -> S3Result<PostPolicy> {
        let raw = util::unbase64(policy_b64).ok_or_else(|| malformed("Invalid Policy: Invalid Base64 encoding"))?;
        let json = parse_json(std::str::from_utf8(&raw).map_err(|_| malformed("Invalid Policy"))?)
            .ok_or_else(|| malformed("Invalid Policy: Invalid JSON."))?;
        let Some(Json::Str(exp)) = json.get("expiration") else {
            return Err(malformed("Invalid Policy: Policy missing expiration."));
        };
        let exp = util::parse_iso8601(exp).ok_or_else(|| malformed("Invalid Policy: Invalid 'expiration' value"))?;
        if util::now_ms() / 1000 > exp {
            return Err(policy_err("Policy expired."));
        }
        let Some(Json::Arr(list)) = json.get("conditions") else {
            return Err(malformed("Invalid Policy: Policy missing conditions."));
        };
        let field = |s: &str| s.trim_start_matches('$').to_ascii_lowercase();
        let num = |j: &Json| match j {
            Json::Num(n) if *n >= 0.0 => Some(*n as u64),
            Json::Str(s) => s.parse().ok(),
            _ => None,
        };
        let mut conds = Vec::new();
        for c in list {
            match c {
                Json::Obj(m) if m.is_empty() => return Err(malformed("Invalid Policy: Invalid condition")),
                Json::Obj(m) => {
                    for (k, v) in m {
                        let Json::Str(v) = v else { return Err(malformed("Invalid Policy: Invalid condition")) };
                        conds.push(Cond::Eq(field(k), v.clone()));
                    }
                }
                Json::Arr(a) => match a.as_slice() {
                    [Json::Str(op), Json::Str(f), Json::Str(v)] if op.eq_ignore_ascii_case("eq") => {
                        conds.push(Cond::Eq(field(f), v.clone()))
                    }
                    [Json::Str(op), Json::Str(f), Json::Str(v)] if op.eq_ignore_ascii_case("starts-with") => {
                        conds.push(Cond::StartsWith(field(f), v.clone()))
                    }
                    [Json::Str(op), lo, hi] if op.eq_ignore_ascii_case("content-length-range") => {
                        let (Some(lo), Some(hi)) = (num(lo), num(hi)) else {
                            return Err(malformed("Invalid Policy: Invalid content-length-range"));
                        };
                        conds.push(Cond::LengthRange(lo, hi));
                    }
                    _ => return Err(malformed("Invalid Policy: Invalid condition")),
                },
                _ => return Err(malformed("Invalid Policy: Invalid condition")),
            }
        }
        Ok(PostPolicy { conds })
    }

    /// Check every condition against the form; returns the allowed content-length range.
    pub fn check(&self, fields: &HashMap<String, String>, bucket: &str) -> S3Result<Option<(u64, u64)>> {
        let value = |f: &str| if f == "bucket" { Some(bucket) } else { fields.get(f).map(String::as_str) };
        let mut range = None;
        for c in &self.conds {
            match c {
                Cond::Eq(f, v) => {
                    if value(f) != Some(v.as_str()) {
                        return Err(policy_err(format!("Policy Condition failed: [\"eq\", \"${f}\", \"{v}\"]")));
                    }
                }
                // An empty prefix allows any value, including none.
                Cond::StartsWith(_, p) if p.is_empty() => {}
                Cond::StartsWith(f, p) => {
                    let ok = value(f).is_some_and(|actual| {
                        if f == "content-type" {
                            actual.split(',').all(|part| part.trim().starts_with(p.as_str()))
                        } else {
                            actual.starts_with(p.as_str())
                        }
                    });
                    if !ok {
                        return Err(policy_err(format!("Policy Condition failed: [\"starts-with\", \"${f}\", \"{p}\"]")));
                    }
                }
                Cond::LengthRange(lo, hi) => range = Some((*lo, *hi)),
            }
        }
        let covered = |f: &str| self.conds.iter().any(|c| matches!(c, Cond::Eq(n, _) | Cond::StartsWith(n, _) if n == f));
        let mut extra: Vec<&str> = fields.keys().map(String::as_str).filter(|f| !exempt(f) && !covered(f)).collect();
        if !extra.is_empty() {
            extra.sort_unstable();
            return Err(policy_err(format!("Extra input fields: {}", extra.join(", "))));
        }
        Ok(range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_and_disposition() {
        assert_eq!(boundary("multipart/form-data; boundary=----abc").as_deref(), Some("----abc"));
        assert_eq!(boundary("multipart/form-data; charset=x; boundary=\"q b\"").as_deref(), Some("q b"));
        assert_eq!(boundary("application/json"), None);
        let v = " form-data; name=\"file\"; filename=\"a \\\"b\\\".png\"";
        assert_eq!(disposition_param(v, "name").as_deref(), Some("file"));
        assert_eq!(disposition_param(v, "filename").as_deref(), Some("a \"b\".png"));
        assert_eq!(disposition_param(" form-data; name=key", "name").as_deref(), Some("key"));
    }

    #[test]
    fn policy_conditions() {
        let doc = r#"{"expiration": "2099-01-01T00:00:00Z", "conditions": [
            {"bucket": "b"}, ["starts-with", "$key", "uploads/"], ["content-length-range", 1, 100],
            {"x-amz-algorithm": "AWS4-HMAC-SHA256"}, ["starts-with", "$Content-Type", "image/"]]}"#;
        let p = PostPolicy::parse(&util::base64(doc.as_bytes())).unwrap();
        let mut f: HashMap<String, String> = [
            ("key", "uploads/x.png"),
            ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
            ("content-type", "image/png"),
            ("policy", "..."),
            ("x-amz-signature", "..."),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(p.check(&f, "b").unwrap(), Some((1, 100)));
        assert!(p.check(&f, "other").is_err());
        f.insert("x-amz-meta-extra".into(), "1".into());
        assert!(p.check(&f, "b").unwrap_err().message.contains("Extra input fields"));
        f.remove("x-amz-meta-extra");
        f.insert("key".into(), "elsewhere/x".into());
        assert!(p.check(&f, "b").is_err());
        let expired = r#"{"expiration": "2001-01-01T00:00:00Z", "conditions": []}"#;
        assert!(PostPolicy::parse(&util::base64(expired.as_bytes())).is_err());
    }
}
