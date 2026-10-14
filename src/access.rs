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

/// Glob match supporting `*` (any run) and `?` (any single char).
pub fn glob(pattern: &str, s: &str, case_insensitive: bool) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = if case_insensitive {
        (pattern.to_lowercase().chars().collect(), s.to_lowercase().chars().collect())
    } else {
        (pattern.chars().collect(), s.chars().collect())
    };
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
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

pub fn tagging_xml(tags: &[(String, String)]) -> String {
    let mut x = Xml::new("Tagging");
    x.open("TagSet");
    for (k, v) in tags {
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
    /// Bucket default encryption (PutBucketEncryption with AES256).
    pub default_sse: bool,
    pub policy: Option<crate::iam::Policy>,
    pub cors: Option<Vec<CorsRule>>,
    /// Object Lock configuration (present = Object Lock enabled).
    pub lock: Option<crate::lock::BucketLock>,
    pub website: Option<std::sync::Arc<crate::website::Config>>,
}

impl BucketAccess {
    /// What the canned ACL grants to anonymous callers.
    fn acl_grants(&self, action: &str) -> bool {
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
