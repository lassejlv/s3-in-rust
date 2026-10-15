//! Per-bucket access settings (canned ACLs, bucket policies), CORS rules, a small JSON parser
//! and tag parsing. Policy evaluation itself lives in `iam`.

use crate::error::{S3Error, S3Result, err};
use crate::util::uri_decode;
#[cfg(test)]
use crate::util::uri_encode;
use crate::xml::{self, Xml};
use hyper::StatusCode;

// ------------------------------------------------------------------ JSON (just enough for policies)

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Serialize (compactly).
    pub fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) if n.fract() == 0.0 && n.abs() < 1e15 => out.push_str(&(*n as i64).to_string()),
            Json::Num(n) => out.push_str(&n.to_string()),
            Json::Str(s) => crate::accesslog::json_str(out, s),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Obj(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    crate::accesslog::json_str(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    pub fn to_text(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }
}

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

pub fn parse_json(s: &str) -> Option<Json> {
    let mut p = JsonParser { b: s.as_bytes(), i: 0, depth: 0 };
    let v = p.value()?;
    p.ws();
    (p.i == p.b.len()).then_some(v)
}

impl JsonParser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> Option<()> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Some(())
        } else {
            None
        }
    }

    fn value(&mut self) -> Option<Json> {
        self.ws();
        self.depth += 1;
        if self.depth > 64 {
            return None;
        }
        let v = match *self.b.get(self.i)? {
            b'{' => {
                self.i += 1;
                let mut m = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        let k = self.string()?;
                        self.ws();
                        self.eat(":")?;
                        m.push((k, self.value()?));
                        self.ws();
                        match *self.b.get(self.i)? {
                            b',' => self.i += 1,
                            b'}' => {
                                self.i += 1;
                                break;
                            }
                            _ => return None,
                        }
                    }
                }
                Json::Obj(m)
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                } else {
                    loop {
                        a.push(self.value()?);
                        self.ws();
                        match *self.b.get(self.i)? {
                            b',' => self.i += 1,
                            b']' => {
                                self.i += 1;
                                break;
                            }
                            _ => return None,
                        }
                    }
                }
                Json::Arr(a)
            }
            b'"' => Json::Str(self.string()?),
            b't' => self.eat("true").map(|_| Json::Bool(true))?,
            b'f' => self.eat("false").map(|_| Json::Bool(false))?,
            b'n' => self.eat("null").map(|_| Json::Null)?,
            _ => {
                let start = self.i;
                while self.i < self.b.len() && matches!(self.b[self.i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    self.i += 1;
                }
                Json::Num(std::str::from_utf8(&self.b[start..self.i]).ok()?.parse().ok()?)
            }
        };
        self.depth -= 1;
        Some(v)
    }

    fn string(&mut self) -> Option<String> {
        self.eat("\"")?;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.i < self.b.len() && self.b[self.i] != b'"' && self.b[self.i] != b'\\' {
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.b[start..self.i]).ok()?);
            match *self.b.get(self.i)? {
                b'"' => {
                    self.i += 1;
                    return Some(out);
                }
                _ => {
                    self.i += 1;
                    let c = *self.b.get(self.i)?;
                    self.i += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
                            self.i += 4;
                            let mut cp = u32::from_str_radix(hex, 16).ok()?;
                            if (0xD800..0xDC00).contains(&cp) {
                                self.eat("\\u")?;
                                let lo =
                                    u32::from_str_radix(std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?, 16).ok()?;
                                self.i += 4;
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo.checked_sub(0xDC00)?);
                            }
                            out.push(char::from_u32(cp)?);
                        }
                        _ => return None,
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ wildcard matching

/// A compiled wildcard pattern: `*` matches any run of characters, `?` exactly one.
///
/// Matching splits the pattern at `*` and finds each literal segment with a substring search,
/// so even hostile patterns (from bucket policies) cost roughly linear time. Text added as a
/// literal piece (e.g. a policy variable's value) never acts as a wildcard.
#[derive(Debug, Clone)]
pub struct Pattern {
    segs: Vec<Seg>,
    lead: bool,
    trail: bool,
    /// The pattern consists of `*`s only (matches everything).
    any: bool,
}

#[derive(Debug, Clone)]
struct Seg {
    /// `None` is `?`.
    chars: Vec<Option<char>>,
    /// The segment as a string when it has no `?` (searched with `str::find`).
    plain: Option<String>,
}

impl Pattern {
    pub fn new(p: &str) -> Pattern {
        Pattern::from_pieces(&[(p, false)])
    }

    /// Build from pieces of (text, literal): literal pieces match only themselves.
    pub fn from_pieces(pieces: &[(&str, bool)]) -> Pattern {
        let (mut segs, mut cur, mut lead, mut trail, mut stars, mut empty) = (Vec::new(), Vec::new(), false, false, 0usize, true);
        let flush = |cur: &mut Vec<Option<char>>, segs: &mut Vec<Seg>| {
            if !cur.is_empty() {
                let plain = cur.iter().copied().collect::<Option<String>>();
                segs.push(Seg { chars: std::mem::take(cur), plain });
            }
        };
        for (text, literal) in pieces {
            for c in text.chars() {
                if !*literal && c == '*' {
                    if empty {
                        lead = true;
                    }
                    flush(&mut cur, &mut segs);
                    trail = true;
                    stars += 1;
                } else {
                    cur.push(if !*literal && c == '?' { None } else { Some(c) });
                    trail = false;
                }
                empty = false;
            }
        }
        flush(&mut cur, &mut segs);
        Pattern { any: stars > 0 && segs.is_empty(), segs, lead, trail }
    }

    pub fn matches(&self, s: &str) -> bool {
        if self.any {
            return true;
        }
        if self.segs.is_empty() {
            return s.is_empty();
        }
        let n = self.segs.len();
        let mut pos = 0;
        for (i, seg) in self.segs.iter().enumerate() {
            let (first, last) = (i == 0, i == n - 1);
            if first && !self.lead {
                let Some(end) = seg.match_at(s, 0) else { return false };
                if last && !self.trail {
                    return end == s.len();
                }
                pos = end;
                continue;
            }
            if last && !self.trail {
                // Must end exactly at the end of the input.
                let Some(start) = nth_char_from_end(s, seg.chars.len()) else { return false };
                return start >= pos && seg.match_at(s, start) == Some(s.len());
            }
            let Some(end) = seg.find(s, pos) else { return false };
            pos = end;
        }
        true
    }
}

impl Seg {
    /// End of a match starting at byte `pos`.
    fn match_at(&self, s: &str, pos: usize) -> Option<usize> {
        let mut it = s[pos..].char_indices();
        let mut end = pos;
        for want in &self.chars {
            let (i, c) = it.next()?;
            if want.is_some_and(|w| w != c) {
                return None;
            }
            end = pos + i + c.len_utf8();
        }
        Some(end)
    }

    /// End of the leftmost match at or after byte `from`.
    fn find(&self, s: &str, from: usize) -> Option<usize> {
        if let Some(p) = &self.plain {
            return s[from..].find(p.as_str()).map(|i| from + i + p.len());
        }
        s[from..].char_indices().find_map(|(i, _)| self.match_at(s, from + i))
    }
}

/// Byte index where the last `n` characters of `s` start.
fn nth_char_from_end(s: &str, n: usize) -> Option<usize> {
    if n == 0 {
        return Some(s.len());
    }
    s.char_indices().rev().nth(n - 1).map(|(i, _)| i)
}

/// Glob match supporting `*` (any run) and `?` (any single char).
pub fn glob(pattern: &str, s: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        Pattern::new(&pattern.to_lowercase()).matches(&s.to_lowercase())
    } else {
        Pattern::new(pattern).matches(s)
    }
}

// ------------------------------------------------------------------ CORS

#[derive(Debug, Clone)]
pub struct CorsRule {
    pub origins: Vec<String>,
    pub methods: Vec<String>,
    pub headers: Vec<String>,
    pub expose: Vec<String>,
    pub max_age: Option<u64>,
}

pub fn parse_cors(doc: &xml::Node) -> S3Result<Vec<CorsRule>> {
    if doc.name != "CORSConfiguration" {
        return Err(err::MalformedXML());
    }
    let mut rules = Vec::new();
    for r in doc.children_named("CORSRule") {
        let texts = |name: &str| r.children_named(name).map(|n| n.text.trim().to_string()).collect::<Vec<_>>();
        let rule = CorsRule {
            origins: texts("AllowedOrigin"),
            methods: texts("AllowedMethod"),
            headers: texts("AllowedHeader"),
            expose: texts("ExposeHeader"),
            max_age: r.child_text("MaxAgeSeconds").and_then(|v| v.trim().parse().ok()),
        };
        if rule.origins.is_empty() || rule.methods.is_empty() {
            return Err(err::MalformedXML().with_message("Each CORSRule needs AllowedOrigin and AllowedMethod"));
        }
        if let Some(m) = rule.methods.iter().find(|m| !matches!(m.as_str(), "GET" | "PUT" | "POST" | "DELETE" | "HEAD")) {
            return Err(err::InvalidRequest()
                .with_message(format!("Found unsupported HTTP method in CORS config. Unsupported method is {m}")));
        }
        rules.push(rule);
    }
    if rules.is_empty() || rules.len() > 100 {
        return Err(err::MalformedXML().with_message("CORS configuration must have between 1 and 100 rules"));
    }
    Ok(rules)
}

/// First rule matching origin, method and (for preflight) every requested header.
pub fn find_cors_rule<'a>(rules: &'a [CorsRule], origin: &str, method: &str, req_headers: &[&str]) -> Option<&'a CorsRule> {
    rules.iter().find(|r| {
        r.origins.iter().any(|o| glob(o, origin, false))
            && r.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
            && req_headers.iter().all(|h| r.headers.iter().any(|a| glob(a, h, true)))
    })
}

// ------------------------------------------------------------------ tags

fn invalid_tag(msg: &str) -> S3Error {
    S3Error::new("InvalidTag", StatusCode::BAD_REQUEST, msg)
}

pub fn validate_tags(tags: &[(String, String)], max: usize) -> S3Result<()> {
    if tags.len() > max {
        return Err(invalid_tag(&format!("Object tags cannot be greater than {max}")));
    }
    for (i, (k, v)) in tags.iter().enumerate() {
        if k.is_empty() || k.chars().count() > 128 {
            return Err(invalid_tag("The TagKey you have provided is invalid"));
        }
        if v.chars().count() > 256 {
            return Err(invalid_tag("The TagValue you have provided is invalid"));
        }
        if tags[..i].iter().any(|(k2, _)| k2 == k) {
            return Err(invalid_tag("Cannot provide multiple Tags with the same key"));
        }
    }
    Ok(())
}

/// `x-amz-tagging: k1=v1&k2=v2` (URL-encoded).
pub fn parse_tagging_header(s: &str) -> S3Result<Vec<(String, String)>> {
    let mut tags = Vec::new();
    for pair in s.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = uri_decode(k, true).ok_or_else(|| invalid_tag("Invalid tag encoding"))?;
        let v = uri_decode(v, true).ok_or_else(|| invalid_tag("Invalid tag encoding"))?;
        tags.push((k, v));
    }
    validate_tags(&tags, 10)?;
    Ok(tags)
}

#[cfg(test)]
pub fn tagging_to_header(tags: &[(String, String)]) -> String {
    tags.iter().map(|(k, v)| format!("{}={}", uri_encode(k, false), uri_encode(v, false))).collect::<Vec<_>>().join("&")
}

pub fn parse_tagging_xml(doc: &xml::Node, max: usize) -> S3Result<Vec<(String, String)>> {
    if doc.name != "Tagging" {
        return Err(err::MalformedXML());
    }
    let set = doc.child("TagSet").ok_or_else(err::MalformedXML)?;
    let mut tags = Vec::new();
    for t in set.children_named("Tag") {
        let k = t.child_text("Key").ok_or_else(err::MalformedXML)?;
        let v = t.child_text("Value").unwrap_or("");
        tags.push((k.to_string(), v.to_string()));
    }
    validate_tags(&tags, max)?;
    Ok(tags)
}

/// A TagSet document, sorted by key (as S3-compatible servers return them).
pub fn tagging_xml(tags: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = tags.iter().collect();
    sorted.sort();
    let mut x = Xml::new("Tagging");
    x.open("TagSet");
    for (k, v) in sorted {
        x.open("Tag").elem("Key", k).elem("Value", v).close("Tag");
    }
    x.close("TagSet");
    x.finish("Tagging")
}

// ------------------------------------------------------------------ per-bucket access summary

/// Canned ACL values we act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CannedAcl {
    #[default]
    Private,
    PublicRead,
    PublicReadWrite,
}

impl CannedAcl {
    pub fn parse(s: &str) -> S3Result<Self> {
        Ok(match s.trim() {
            "private" | "bucket-owner-full-control" | "bucket-owner-read" | "authenticated-read" => Self::Private,
            "public-read" => Self::PublicRead,
            "public-read-write" => Self::PublicReadWrite,
            other => return Err(err::InvalidArgument().with_message(format!("Invalid canned ACL: {other}"))),
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::PublicRead => "public-read",
            Self::PublicReadWrite => "public-read-write",
        }
    }
}

/// Everything needed to authorize anonymous requests and answer CORS for one bucket.
#[derive(Debug, Default)]
pub struct BucketAccess {
    pub acl: CannedAcl,
    pub versioning: crate::store::Versioning,
    /// Bucket default encryption (PutBucketEncryption).
    pub default_sse: bool,
    /// The KMS key id when the bucket default is SSE-KMS.
    pub default_kms: Option<String>,
    pub policy: Option<crate::iam::Policy>,
    pub cors: Option<Vec<CorsRule>>,
    /// Object Lock configuration (present = Object Lock enabled).
    pub lock: Option<crate::lock::BucketLock>,
    pub website: Option<std::sync::Arc<crate::website::Config>>,
    pub lifecycle: Option<std::sync::Arc<Vec<crate::lifecycle::Rule>>>,
    pub public_block: PublicAccessBlock,
    pub ownership: Option<Ownership>,
}

/// PutPublicAccessBlock settings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PublicAccessBlock {
    /// Refuse public ACLs on buckets and objects.
    pub block_acls: bool,
    /// Treat public ACLs as private.
    pub ignore_acls: bool,
    /// Refuse bucket policies that grant public access.
    pub block_policy: bool,
    /// Don't let a public bucket policy give anonymous callers access.
    pub restrict: bool,
}

impl PublicAccessBlock {
    pub const ALL: PublicAccessBlock =
        PublicAccessBlock { block_acls: true, ignore_acls: true, block_policy: true, restrict: true };

    /// Both blocks combined (each setting on if it is on in either).
    pub fn or(self, other: Option<PublicAccessBlock>) -> PublicAccessBlock {
        let o = other.unwrap_or_default();
        PublicAccessBlock {
            block_acls: self.block_acls || o.block_acls,
            ignore_acls: self.ignore_acls || o.ignore_acls,
            block_policy: self.block_policy || o.block_policy,
            restrict: self.restrict || o.restrict,
        }
    }
}

const PAB_FIELDS: [&str; 4] = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"];

impl PublicAccessBlock {
    pub fn parse(doc: &xml::Node) -> S3Result<Self> {
        if doc.name != "PublicAccessBlockConfiguration" {
            return Err(err::MalformedXML());
        }
        let mut v = [false; 4];
        for (i, name) in PAB_FIELDS.iter().enumerate() {
            v[i] = match doc.child_text(name).map(str::trim) {
                None => false,
                Some(t) if t.eq_ignore_ascii_case("true") => true,
                Some(t) if t.eq_ignore_ascii_case("false") => false,
                Some(_) => return Err(err::MalformedXML().with_message(format!("{name} must be true or false"))),
            };
        }
        Ok(PublicAccessBlock { block_acls: v[0], ignore_acls: v[1], block_policy: v[2], restrict: v[3] })
    }

    pub fn to_xml(self) -> String {
        let mut x = xml::Xml::new("PublicAccessBlockConfiguration");
        for (name, on) in PAB_FIELDS.iter().zip([self.block_acls, self.ignore_acls, self.block_policy, self.restrict]) {
            x.elem(name, on.to_string());
        }
        x.finish("PublicAccessBlockConfiguration")
    }
}

/// PutBucketOwnershipControls settings. Every object belongs to the bucket owner here, so the
/// difference is whether ACLs may be set (`BucketOwnerEnforced` disables them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    BucketOwnerEnforced,
    BucketOwnerPreferred,
    ObjectWriter,
}

impl Ownership {
    pub fn parse(s: &str) -> S3Result<Self> {
        match s.trim() {
            "BucketOwnerEnforced" => Ok(Ownership::BucketOwnerEnforced),
            "BucketOwnerPreferred" => Ok(Ownership::BucketOwnerPreferred),
            "ObjectWriter" => Ok(Ownership::ObjectWriter),
            _ => Err(err::InvalidArgument()
                .with_message("ObjectOwnership must be BucketOwnerEnforced, BucketOwnerPreferred or ObjectWriter")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Ownership::BucketOwnerEnforced => "BucketOwnerEnforced",
            Ownership::BucketOwnerPreferred => "BucketOwnerPreferred",
            Ownership::ObjectWriter => "ObjectWriter",
        }
    }

    pub fn parse_xml(doc: &xml::Node) -> S3Result<Self> {
        let v = (doc.name == "OwnershipControls")
            .then(|| doc.child("Rule")?.child_text("ObjectOwnership"))
            .flatten()
            .ok_or_else(err::MalformedXML)?;
        Ownership::parse(v).map_err(|e| err::MalformedXML().with_message(e.message))
    }

    pub fn to_xml(self) -> String {
        let mut x = xml::Xml::new("OwnershipControls");
        x.open("Rule").elem("ObjectOwnership", self.as_str()).close("Rule");
        x.finish("OwnershipControls")
    }
}

impl BucketAccess {
    /// What the canned ACL grants to anonymous callers.
    fn acl_grants(&self, action: &str) -> bool {
        if self.public_block.ignore_acls {
            return false;
        }
        match self.acl {
            CannedAcl::Private => false,
            CannedAcl::PublicRead => matches!(action, "s3:GetObject" | "s3:ListBucket" | "s3:GetBucketLocation"),
            CannedAcl::PublicReadWrite => matches!(
                action,
                "s3:GetObject"
                    | "s3:ListBucket"
                    | "s3:GetBucketLocation"
                    | "s3:PutObject"
                    | "s3:DeleteObject"
                    | "s3:AbortMultipartUpload"
                    | "s3:ListMultipartUploadParts"
                    | "s3:ListBucketMultipartUploads"
            ),
        }
    }

    /// The bucket policy's verdict on a request (`NotApplicable` without a policy).
    pub fn policy_decision(&self, action: &str, resource: &str, ctx: &crate::iam::Ctx) -> crate::iam::Decision {
        self.policy.as_ref().map_or(crate::iam::Decision::NotApplicable, |p| p.evaluate(action, resource, ctx))
    }

    /// May an anonymous caller do this? The policy decides first (an explicit Deny overrides the
    /// ACL), then the ACL.
    pub fn allows_anonymous(&self, action: &str, resource: &str, ctx: &crate::iam::Ctx) -> bool {
        match self.policy_decision(action, resource, ctx) {
            crate::iam::Decision::Deny => false,
            // RestrictPublicBuckets: a public policy gives anonymous callers nothing.
            crate::iam::Decision::Allow if self.public_block.restrict => self.acl_grants(action),
            crate::iam::Decision::Allow => true,
            crate::iam::Decision::NotApplicable => self.acl_grants(action),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_parses() {
        let j = parse_json(r#"{"a": [1, "xé\"", true, null, {"b": -2.5e1}], "c": {}}"#).unwrap();
        assert_eq!(
            j.get("a"),
            Some(&Json::Arr(vec![
                Json::Num(1.0),
                Json::Str("xé\"".into()),
                Json::Bool(true),
                Json::Null,
                Json::Obj(vec![("b".into(), Json::Num(-25.0))])
            ]))
        );
        assert!(parse_json("{\"a\":}").is_none());
        assert!(parse_json("[1,2").is_none());
        assert!(parse_json("{} x").is_none());
    }

    #[test]
    fn globbing() {
        assert!(glob("s3:Get*", "s3:GetObject", true));
        assert!(glob("arn:aws:s3:::b/public/*", "arn:aws:s3:::b/public/a/b.txt", false));
        assert!(!glob("arn:aws:s3:::b/public/*", "arn:aws:s3:::b/private/x", false));
        assert!(glob("https://*.example.com", "https://app.example.com", false));
        assert!(glob("a?c", "abc", false));
        assert!(!glob("a?c", "abbc", false));
        assert!(glob("*", "", false));
        assert!(glob("", "", false) && !glob("", "a", false));
        assert!(glob("a*b*c", "aXbYbZc", false) && !glob("a*b*c", "aXbYbZ", false));
        assert!(glob("*ab", "aab", false) && glob("ab*ab", "abab", false) && !glob("ab*ab", "aba", false));
        assert!(glob("*?", "x", false) && !glob("*?", "", false) && glob("?*?", "ü✓", false));
        assert!(glob("**a**", "xxaxx", false) && glob("é*", "éclair", false));
        // Literal pieces never act as wildcards.
        let p = Pattern::from_pieces(&[("files/", false), ("*", true), ("/*", false)]);
        assert!(p.matches("files/*/x") && !p.matches("files/any/x"));
        // Pathological patterns stay fast.
        let evil = format!("*{}b", "a".repeat(500));
        let input = "a".repeat(5000);
        let t = std::time::Instant::now();
        for _ in 0..1000 {
            assert!(!glob(&evil, &input, false));
        }
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
    }

    #[test]
    fn cors_matching() {
        let doc = xml::parse(
            "<CORSConfiguration><CORSRule><AllowedOrigin>https://*.example.com</AllowedOrigin>\
             <AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedHeader>*</AllowedHeader>\
             <ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>300</MaxAgeSeconds></CORSRule></CORSConfiguration>",
        )
        .unwrap();
        let rules = parse_cors(&doc).unwrap();
        assert!(find_cors_rule(&rules, "https://app.example.com", "PUT", &["content-type"]).is_some());
        assert!(find_cors_rule(&rules, "https://evil.com", "GET", &[]).is_none());
        assert!(find_cors_rule(&rules, "https://app.example.com", "DELETE", &[]).is_none());
        assert_eq!(rules[0].max_age, Some(300));
    }

    #[test]
    fn tags() {
        let t = parse_tagging_header("a=1&b%20c=x%2By").unwrap();
        assert_eq!(t, vec![("a".into(), "1".into()), ("b c".into(), "x+y".into())]);
        assert!(parse_tagging_header("a=1&a=2").is_err());
        let back = tagging_to_header(&t);
        assert_eq!(parse_tagging_header(&back).unwrap(), t);
        let doc = xml::parse(&tagging_xml(&t)).unwrap();
        assert_eq!(parse_tagging_xml(&doc, 10).unwrap(), t);
    }

    #[test]
    fn acl_and_policy_combine() {
        use crate::iam::{Ctx, Kind, Policy};
        let h = hyper::HeaderMap::new();
        let ctx = Ctx {
            username: None,
            source_ip: "1.2.3.4".parse().unwrap(),
            secure: false,
            headers: &h,
            query: &[],
            auth_type: "REST-HEADER",
            now: 0,
            object_tags: None,
        };
        let mut a = BucketAccess { acl: CannedAcl::PublicRead, ..Default::default() };
        assert!(a.allows_anonymous("s3:GetObject", "arn:aws:s3:::b/x", &ctx));
        assert!(!a.allows_anonymous("s3:PutObject", "arn:aws:s3:::b/x", &ctx));
        let deny = r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/x"}}"#;
        a.policy = Some(Policy::parse(deny, Kind::Bucket, Some("b")).unwrap());
        assert!(!a.allows_anonymous("s3:GetObject", "arn:aws:s3:::b/x", &ctx));
        assert!(a.allows_anonymous("s3:GetObject", "arn:aws:s3:::b/y", &ctx));
    }
}
