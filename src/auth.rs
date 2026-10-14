//! AWS Signature Version 4: header auth, presigned URLs and streaming (aws-chunked) payloads.

use crate::error::{S3Result, err};
use crate::util::{self, ct_eq, hex, uri_decode, uri_encode};
use hmac::{KeyInit, Mac};
use hyper::http::request::Parts;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type HmacSha256 = hmac::Hmac<Sha256>;

const ALGO: &str = "AWS4-HMAC-SHA256";
const MAX_SKEW_SECS: u64 = 15 * 60;
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// How the request payload is protected, as declared by `x-amz-content-sha256`.
pub enum Payload {
    Unsigned,
    Sha256([u8; 32]),
    /// `Content-Encoding: aws-chunked` framing; `signer` is set for signed chunk streams.
    Chunked {
        signer: Option<ChunkSigner>,
        trailer: bool,
    },
}

/// State for verifying a chain of chunk signatures.
pub struct ChunkSigner {
    key: [u8; 32],
    date: String,
    scope: String,
    prev: String,
}

impl ChunkSigner {
    /// Verify the signature of one chunk whose data hashes to `data_sha256`.
    pub fn verify_chunk(&mut self, data_sha256: &[u8], signature: &str) -> S3Result<()> {
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            self.date,
            self.scope,
            self.prev,
            EMPTY_SHA256,
            hex(data_sha256)
        );
        self.check(&sts, signature)
    }

    /// Verify the signature over the trailing headers (`name:value\n` each).
    pub fn verify_trailer(&mut self, canonical: &str, signature: &str) -> S3Result<()> {
        let sts = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            self.date,
            self.scope,
            self.prev,
            sha256_hex(canonical.as_bytes())
        );
        self.check(&sts, signature)
    }

    fn check(&mut self, sts: &str, signature: &str) -> S3Result<()> {
        let expected = hex(&hmac(&self.key, sts.as_bytes()));
        if !ct_eq(expected.as_bytes(), signature.trim().as_bytes()) {
            return Err(err::SignatureDoesNotMatch());
        }
        self.prev = expected;
        Ok(())
    }
}

/// One access key: its secret, whether it may only read, and which buckets it may use.
#[derive(Debug, PartialEq, Eq)]
pub struct Credential {
    pub access_key: String,
    pub secret: String,
    pub read_only: bool,
    /// Bucket name patterns (`*` wildcards) this key is limited to; `None` = all buckets.
    pub buckets: Option<Vec<String>>,
}

impl Credential {
    pub fn can_access(&self, bucket: &str) -> bool {
        self.buckets.as_ref().is_none_or(|pats| pats.iter().any(|p| crate::access::glob(p, bucket, false)))
    }
}

/// Who made a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    Anonymous,
    User(Arc<Credential>),
    /// Authentication is disabled server-wide (`--anonymous`).
    Everyone,
}

impl Principal {
    /// Whether this caller may use `bucket` at all (anonymous access is decided separately).
    pub fn can_access(&self, bucket: &str) -> bool {
        match self {
            Principal::User(c) => c.can_access(bucket),
            _ => true,
        }
    }

    pub fn read_only(&self) -> bool {
        matches!(self, Principal::User(c) if c.read_only)
    }
}

pub struct Auth {
    creds: HashMap<String, Arc<Credential>>,
    key_cache: Mutex<HashMap<String, [u8; 32]>>,
}

/// Whether a request carries any authentication (header or presigned query).
pub fn has_credentials(parts: &Parts, raw_query: &str) -> bool {
    parts.headers.contains_key(hyper::header::AUTHORIZATION)
        || raw_query.contains("X-Amz-Signature=")
        || (raw_query.contains("Signature=") && raw_query.contains("AWSAccessKeyId="))
}

struct SigParams<'a> {
    access_key: &'a str,
    date: &'a str,
    region: &'a str,
    service: &'a str,
    signed_headers: &'a str,
    signature: &'a str,
}

fn parse_credential(cred: &str) -> S3Result<(&str, &str, &str, &str)> {
    let mut it = cred.rsplitn(5, '/');
    let (Some(term), Some(service), Some(region), Some(date), Some(ak)) = (it.next(), it.next(), it.next(), it.next(), it.next())
    else {
        return Err(err::InvalidArgument().with_message("Invalid credential scope"));
    };
    if term != "aws4_request" {
        return Err(err::InvalidArgument().with_message("Invalid credential scope terminator"));
    }
    Ok((ak, date, region, service))
}

/// Decide the payload mode from `x-amz-content-sha256` without verifying anything (anonymous mode).
pub fn payload_mode(parts: &Parts) -> S3Result<Payload> {
    let v = parts.headers.get("x-amz-content-sha256").and_then(|v| v.to_str().ok());
    Ok(match v {
        None | Some("UNSIGNED-PAYLOAD") => Payload::Unsigned,
        Some("STREAMING-UNSIGNED-PAYLOAD-TRAILER") => Payload::Chunked { signer: None, trailer: true },
        Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD") => Payload::Chunked { signer: None, trailer: false },
        Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER") => Payload::Chunked { signer: None, trailer: true },
        Some(h) => match util::unhex(h) {
            Some(b) if b.len() == 32 => Payload::Sha256(b.try_into().unwrap()),
            _ if h.starts_with("STREAMING-") => return Err(err::NotImplemented().with_message(format!("{h} is not supported"))),
            _ => {
                return Err(err::InvalidArgument()
                    .with_message("x-amz-content-sha256 must be UNSIGNED-PAYLOAD, a streaming mode, or a valid sha256 value."));
            }
        },
    })
}

impl Auth {
    pub fn new(creds: Vec<Credential>) -> Self {
        let creds = creds.into_iter().map(|c| (c.access_key.clone(), Arc::new(c))).collect();
        Auth { creds, key_cache: Mutex::new(HashMap::new()) }
    }

    fn credential(&self, access_key: &str) -> S3Result<&Credential> {
        self.creds.get(access_key).map(|c| c.as_ref()).ok_or_else(err::InvalidAccessKeyId)
    }

    fn principal(&self, access_key: &str) -> Principal {
        match self.creds.get(access_key) {
            Some(c) => Principal::User(c.clone()),
            None => Principal::Anonymous,
        }
    }

    fn signing_key(&self, access_key: &str, date: &str, region: &str, service: &str) -> S3Result<[u8; 32]> {
        let secret = &self.credential(access_key)?.secret;
        let cache_key = format!("{access_key}/{date}/{region}/{service}");
        if let Some(k) = self.key_cache.lock().unwrap().get(&cache_key) {
            return Ok(*k);
        }
        let k_date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
        let k_region = hmac(&k_date, region.as_bytes());
        let k_service = hmac(&k_region, service.as_bytes());
        let key = hmac(&k_service, b"aws4_request");
        let mut cache = self.key_cache.lock().unwrap();
        if cache.len() > 1024 {
            cache.clear();
        }
        cache.insert(cache_key, key);
        Ok(key)
    }

    /// Authenticate a request. `vhost_bucket` is the bucket taken from the Host header for
    /// virtual-hosted-style requests (needed for SigV2's canonical resource).
    pub fn verify(&self, parts: &Parts, raw_query: &str, vhost_bucket: Option<&str>) -> S3Result<(Payload, Principal)> {
        if let Some(h) = parts.headers.get(hyper::header::AUTHORIZATION) {
            let h = h.to_str().map_err(|_| err::AccessDenied())?;
            if let Some(v2) = h.strip_prefix("AWS ") {
                let (ak, sig) =
                    v2.split_once(':').ok_or_else(|| err::InvalidArgument().with_message("Malformed Authorization header"))?;
                self.verify_v2(parts, raw_query, vhost_bucket, ak, sig, None)?;
                return Ok((payload_mode(parts)?, self.principal(ak)));
            }
            return self.verify_header(parts, raw_query, h);
        }
        if raw_query.contains("X-Amz-Signature=") {
            return self.verify_presigned(parts, raw_query);
        }
        if raw_query.contains("Signature=") && raw_query.contains("AWSAccessKeyId=") {
            let q: HashMap<String, String> = raw_query
                .split('&')
                .filter_map(|p| p.split_once('='))
                .map(|(k, v)| (k.to_string(), uri_decode(v, false).unwrap_or_default()))
                .collect();
            let get = |k: &str| q.get(k).map(String::as_str).ok_or_else(err::AccessDenied);
            let expires: u64 = get("Expires")?.parse().map_err(|_| err::AccessDenied())?;
            if util::now_ms() / 1000 > expires {
                return Err(err::AccessDenied().with_message("Request has expired"));
            }
            let ak = get("AWSAccessKeyId")?;
            self.verify_v2(parts, raw_query, vhost_bucket, ak, get("Signature")?, Some(expires))?;
            return Ok((payload_mode(parts)?, self.principal(ak)));
        }
        Err(err::AccessDenied())
    }

    /// Verify the signature of a browser-form upload (POST policy). `fields` maps lowercase
    /// form-field names to values; the signature covers the base64 policy document.
    pub fn verify_post_policy(&self, fields: &HashMap<String, String>, policy_b64: &str) -> S3Result<Principal> {
        if let Some(sig) = fields.get("x-amz-signature") {
            if fields.get("x-amz-algorithm").map(String::as_str) != Some(ALGO) {
                return Err(err::InvalidArgument().with_message("x-amz-algorithm must be AWS4-HMAC-SHA256"));
            }
            let cred =
                fields.get("x-amz-credential").ok_or_else(|| err::AccessDenied().with_message("Missing x-amz-credential"))?;
            let (ak, date, region, service) = parse_credential(cred)?;
            let key = self.signing_key(ak, date, region, service)?;
            let expected = hex(&hmac(&key, policy_b64.as_bytes()));
            if !ct_eq(expected.as_bytes(), sig.trim().as_bytes()) {
                return Err(err::SignatureDoesNotMatch());
            }
            return Ok(self.principal(ak));
        }
        if let (Some(ak), Some(sig)) = (fields.get("awsaccesskeyid"), fields.get("signature")) {
            let secret = self.credential(ak)?.secret.as_bytes();
            let mut m = <hmac::Hmac<sha1::Sha1> as KeyInit>::new_from_slice(secret).expect("hmac key");
            m.update(policy_b64.as_bytes());
            if !ct_eq(util::base64(&m.finalize().into_bytes()).as_bytes(), sig.trim().as_bytes()) {
                return Err(err::SignatureDoesNotMatch());
            }
            return Ok(self.principal(ak));
        }
        Err(err::AccessDenied().with_message("POST policy requires a signature"))
    }

    /// AWS Signature Version 2 (legacy; still used by some clients for presigned URLs).
    fn verify_v2(
        &self,
        parts: &Parts,
        raw_query: &str,
        vhost_bucket: Option<&str>,
        access_key: &str,
        signature: &str,
        expires: Option<u64>,
    ) -> S3Result<()> {
        let secret = self.credential(access_key)?.secret.as_bytes();
        let h = |n: &str| parts.headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").trim();
        let date = match expires {
            Some(e) => e.to_string(),
            None => {
                let d = if h("x-amz-date").is_empty() { h("date") } else { h("x-amz-date") };
                let t = util::parse_http_date(d).ok_or_else(|| err::AccessDenied().with_message("Missing or invalid Date"))?;
                if t.abs_diff(util::now_ms() / 1000) > MAX_SKEW_SECS {
                    return Err(err::RequestTimeTooSkewed());
                }
                if h("x-amz-date").is_empty() { h("date").to_string() } else { String::new() }
            }
        };
        let mut amz: Vec<(String, String)> = Vec::new();
        for (name, value) in &parts.headers {
            let n = name.as_str();
            if n.starts_with("x-amz-") {
                let v = String::from_utf8_lossy(value.as_bytes()).trim().to_string();
                match amz.iter_mut().find(|(k, _)| k == n) {
                    Some((_, existing)) => {
                        existing.push(',');
                        existing.push_str(&v);
                    }
                    None => amz.push((n.to_string(), v)),
                }
            }
        }
        amz.sort();
        let mut sts = format!("{}\n{}\n{}\n{}\n", parts.method.as_str(), h("content-md5"), h("content-type"), date);
        for (k, v) in &amz {
            sts.push_str(k);
            sts.push(':');
            sts.push_str(v);
            sts.push('\n');
        }
        if let Some(b) = vhost_bucket {
            sts.push('/');
            sts.push_str(b);
        }
        sts.push_str(parts.uri.path());
        // The canonical resource for a bucket is "/bucket/".
        if vhost_bucket.is_none() && parts.uri.path().len() > 1 && !parts.uri.path()[1..].contains('/') {
            sts.push('/');
        }
        const SUBRESOURCES: &[&str] = &[
            "acl",
            "cors",
            "delete",
            "lifecycle",
            "location",
            "logging",
            "notification",
            "partNumber",
            "policy",
            "requestPayment",
            "response-cache-control",
            "response-content-disposition",
            "response-content-encoding",
            "response-content-language",
            "response-content-type",
            "response-expires",
            "restore",
            "tagging",
            "torrent",
            "uploadId",
            "uploads",
            "versionId",
            "versioning",
            "versions",
            "website",
        ];
        let mut subs: Vec<(String, Option<String>)> = raw_query
            .split('&')
            .filter_map(|p| {
                let (k, v) = match p.split_once('=') {
                    Some((k, v)) => (k, Some(uri_decode(v, false).unwrap_or_else(|| v.to_string()))),
                    None => (p, None),
                };
                SUBRESOURCES.contains(&k).then(|| (k.to_string(), v))
            })
            .collect();
        subs.sort();
        for (i, (k, v)) in subs.iter().enumerate() {
            sts.push(if i == 0 { '?' } else { '&' });
            sts.push_str(k);
            if let Some(v) = v {
                sts.push('=');
                sts.push_str(v);
            }
        }
        let mut m = <hmac::Hmac<sha1::Sha1> as KeyInit>::new_from_slice(secret).expect("hmac key");
        m.update(sts.as_bytes());
        let expected = util::base64(&m.finalize().into_bytes());
        if !ct_eq(expected.as_bytes(), signature.as_bytes()) {
            return Err(err::SignatureDoesNotMatch());
        }
        Ok(())
    }

    fn verify_header(&self, parts: &Parts, raw_query: &str, h: &str) -> S3Result<(Payload, Principal)> {
        let Some(rest) = h.strip_prefix(ALGO) else {
            return Err(
                err::InvalidArgument().with_message("Unsupported authorization type (only AWS4-HMAC-SHA256 is supported)")
            );
        };
        let (mut cred, mut signed, mut sig) = (None, None, None);
        for kv in rest.split(',') {
            let kv = kv.trim();
            if let Some(v) = kv.strip_prefix("Credential=") {
                cred = Some(v);
            } else if let Some(v) = kv.strip_prefix("SignedHeaders=") {
                signed = Some(v);
            } else if let Some(v) = kv.strip_prefix("Signature=") {
                sig = Some(v);
            }
        }
        let (Some(cred), Some(signed_headers), Some(signature)) = (cred, signed, sig) else {
            return Err(err::InvalidArgument().with_message("Malformed Authorization header"));
        };
        let (access_key, date, region, service) = parse_credential(cred)?;

        let amz_date = match parts.headers.get("x-amz-date").and_then(|v| v.to_str().ok()) {
            Some(d) => d.to_string(),
            None => {
                let d = parts.headers.get(hyper::header::DATE).and_then(|v| v.to_str().ok()).and_then(util::parse_http_date);
                util::amz_date(d.ok_or_else(|| err::AccessDenied().with_message("Missing x-amz-date"))?)
            }
        };
        let t = util::parse_amz_date(&amz_date).ok_or_else(|| err::AccessDenied().with_message("Invalid x-amz-date"))?;
        let now = util::now_ms() / 1000;
        if t.abs_diff(now) > MAX_SKEW_SECS {
            return Err(err::RequestTimeTooSkewed());
        }

        let content_sha = parts
            .headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| err::InvalidRequest().with_message("Missing required header for this request: x-amz-content-sha256"))?
            .to_string();

        let p = SigParams { access_key, date, region, service, signed_headers, signature };
        let key = self.check_signature(parts, raw_query, &p, &amz_date, &content_sha, false)?;

        let mut mode = payload_mode(parts)?;
        if let Payload::Chunked { signer, .. } = &mut mode
            && content_sha.starts_with("STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
        {
            *signer = Some(ChunkSigner {
                key,
                date: amz_date,
                scope: format!("{date}/{region}/{service}/aws4_request"),
                prev: signature.to_string(),
            });
        }
        Ok((mode, self.principal(access_key)))
    }

    fn verify_presigned(&self, parts: &Parts, raw_query: &str) -> S3Result<(Payload, Principal)> {
        let mut get = HashMap::new();
        for pair in raw_query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if k.starts_with("X-Amz-") {
                get.insert(k, uri_decode(v, false).unwrap_or_default());
            }
        }
        let field =
            |k: &str| get.get(k).map(String::as_str).ok_or_else(|| err::AccessDenied().with_message(format!("Missing {k}")));
        if field("X-Amz-Algorithm")? != ALGO {
            return Err(err::InvalidArgument().with_message("Unsupported X-Amz-Algorithm"));
        }
        let (access_key, date, region, service) = parse_credential(field("X-Amz-Credential")?)?;
        let amz_date = field("X-Amz-Date")?;
        let t = util::parse_amz_date(amz_date).ok_or_else(|| err::AccessDenied().with_message("Invalid X-Amz-Date"))?;
        let expires: u64 = field("X-Amz-Expires")?.parse().map_err(|_| err::AccessDenied())?;
        if expires > 604_800 {
            return Err(err::AccessDenied().with_message("X-Amz-Expires must be less than a week (in seconds)"));
        }
        let now = util::now_ms() / 1000;
        if now > t + expires {
            return Err(err::AccessDenied().with_message("Request has expired"));
        }
        if t > now + MAX_SKEW_SECS {
            return Err(err::AccessDenied().with_message("Request is not valid yet"));
        }
        let content_sha =
            parts.headers.get("x-amz-content-sha256").and_then(|v| v.to_str().ok()).unwrap_or("UNSIGNED-PAYLOAD").to_string();
        let p = SigParams {
            access_key,
            date,
            region,
            service,
            signed_headers: field("X-Amz-SignedHeaders")?,
            signature: field("X-Amz-Signature")?,
        };
        self.check_signature(parts, raw_query, &p, amz_date, &content_sha, true)?;
        match payload_mode(parts)? {
            Payload::Chunked { .. } => {
                Err(err::NotImplemented().with_message("Streaming payloads are not supported with presigned URLs"))
            }
            m => Ok((m, self.principal(access_key))),
        }
    }

    fn check_signature(
        &self,
        parts: &Parts,
        raw_query: &str,
        p: &SigParams,
        amz_date: &str,
        content_sha: &str,
        presigned: bool,
    ) -> S3Result<[u8; 32]> {
        if !amz_date.starts_with(p.date) {
            return Err(err::SignatureDoesNotMatch().with_message("Credential date does not match request date"));
        }
        let signed: Vec<&str> = p.signed_headers.split(';').collect();
        if !signed.contains(&"host") {
            return Err(err::AccessDenied().with_message("Host header must be signed"));
        }
        let canonical_headers = canonical_headers(parts, &signed);
        let canonical_query = canonical_query(raw_query, presigned);
        let scope = format!("{}/{}/{}/aws4_request", p.date, p.region, p.service);
        let key = self.signing_key(p.access_key, p.date, p.region, p.service)?;

        let raw_path = parts.uri.path();
        let normalized = uri_decode(raw_path, false).map(|d| uri_encode(&d, true));
        let mut candidates = Vec::with_capacity(2);
        if let Some(n) = &normalized {
            candidates.push(n.as_str());
        }
        if normalized.as_deref() != Some(raw_path) {
            candidates.push(raw_path);
        }
        for path in candidates {
            let creq = format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                parts.method.as_str(),
                path,
                canonical_query,
                canonical_headers,
                p.signed_headers,
                content_sha
            );
            let sts = format!("{ALGO}\n{amz_date}\n{scope}\n{}", sha256_hex(creq.as_bytes()));
            let sig = hex(&hmac(&key, sts.as_bytes()));
            if ct_eq(sig.as_bytes(), p.signature.as_bytes()) {
                return Ok(key);
            }
        }
        Err(err::SignatureDoesNotMatch())
    }
}

fn canonical_query(raw: &str, presigned: bool) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = uri_decode(k, false).unwrap_or_else(|| k.to_string());
            if presigned && k == "X-Amz-Signature" {
                return None;
            }
            let v = uri_decode(v, false).unwrap_or_else(|| v.to_string());
            Some((uri_encode(&k, false), uri_encode(&v, false)))
        })
        .collect();
    pairs.sort();
    let mut out = String::with_capacity(raw.len() + 16);
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

fn canonical_headers(parts: &Parts, signed: &[&str]) -> String {
    let mut out = String::with_capacity(256);
    for name in signed {
        out.push_str(name);
        out.push(':');
        let mut first = true;
        for v in parts.headers.get_all(*name) {
            if !first {
                out.push(',');
            }
            first = false;
            push_trimmed(&mut out, &String::from_utf8_lossy(v.as_bytes()));
        }
        if first && *name == "host" {
            // HTTP/2 carries the host in the :authority pseudo-header.
            if let Some(a) = parts.uri.authority() {
                out.push_str(a.as_str());
            }
        }
        out.push('\n');
    }
    out
}

fn push_trimmed(out: &mut String, v: &str) {
    let mut space = false;
    for c in v.trim().chars() {
        if c == ' ' || c == '\t' {
            space = true;
        } else {
            if space {
                out.push(' ');
                space = false;
            }
            out.push(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_auth() -> Auth {
        Auth::new(vec![Credential {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            read_only: false,
            buckets: None,
        }])
    }

    #[test]
    fn bucket_scoping() {
        let c = Credential {
            access_key: "k".into(),
            secret: "s".into(),
            read_only: false,
            buckets: Some(vec!["team-a-*".into(), "shared".into()]),
        };
        assert!(c.can_access("team-a-logs") && c.can_access("shared"));
        assert!(!c.can_access("team-b") && !c.can_access("shared2"));
    }

    /// Example from the AWS SigV4 documentation ("GET Object" with a Range header).
    #[test]
    fn aws_doc_get_object() {
        let auth = doc_auth();
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/test.txt")
            .header("host", "examplebucket.s3.amazonaws.com")
            .header("range", "bytes=0-9")
            .header("x-amz-content-sha256", EMPTY_SHA256)
            .header("x-amz-date", "20130524T000000Z")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let signed = ["host", "range", "x-amz-content-sha256", "x-amz-date"];
        let p = SigParams {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            date: "20130524",
            region: "us-east-1",
            service: "s3",
            signed_headers: "host;range;x-amz-content-sha256;x-amz-date",
            signature: "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        };
        let _ = signed;
        auth.check_signature(&parts, "", &p, "20130524T000000Z", EMPTY_SHA256, false).unwrap();
    }

    /// Example from the AWS documentation for presigned URLs.
    #[test]
    fn aws_doc_presigned() {
        let auth = doc_auth();
        let q = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";
        let req = hyper::Request::builder()
            .method("GET")
            .uri(format!("/test.txt?{q}"))
            .header("host", "examplebucket.s3.amazonaws.com")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let p = SigParams {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            date: "20130524",
            region: "us-east-1",
            service: "s3",
            signed_headers: "host",
            signature: "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
        };
        auth.check_signature(&parts, q, &p, "20130524T000000Z", "UNSIGNED-PAYLOAD", true).unwrap();
    }

    /// Chunk signature example from the AWS streaming SigV4 documentation.
    #[test]
    fn aws_doc_chunk_signature() {
        let auth = doc_auth();
        let mut s = ChunkSigner {
            key: auth.signing_key("AKIAIOSFODNN7EXAMPLE", "20130524", "us-east-1", "s3").unwrap(),
            date: "20130524T000000Z".into(),
            scope: "20130524/us-east-1/s3/aws4_request".into(),
            prev: "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9".into(),
        };
        let chunk = vec![b'a'; 65536];
        s.verify_chunk(&Sha256::digest(&chunk), "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648").unwrap();
        s.verify_chunk(&Sha256::digest(vec![b'a'; 1024]), "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497")
            .unwrap();
        s.verify_chunk(&Sha256::digest(b""), "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9").unwrap();
    }
}
