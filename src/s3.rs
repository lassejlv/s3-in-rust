//! Request routing and S3 operation handlers.

use crate::access::{self, BucketAccess, CannedAcl, CorsRule, Policy};
use crate::auth::{self, Auth, Payload, Principal};
use crate::body::Body;
use crate::error::{S3Error, S3Result, err};
use crate::io::{self, BodyStream, Data, Expect};
use crate::store::meta::{ChecksumAlgo, ObjectMeta, PartMeta, Storage, UploadMeta};
use crate::store::{self, Op, OpOut, Store, WriteCond, norm_etag};
use crate::util::{self, base64, http_date, iso8601, now_ms, unbase64, uri_decode, uri_encode};
use crate::xml::{self, Xml};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method, Request, Response, StatusCode};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

const MAX_OBJECT_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const MAX_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const MAX_PARTS: u32 = 10_000;
const MAX_KEY_LEN: usize = 1024;
const MAX_XML_BODY: usize = 4 * 1024 * 1024;

pub struct Options {
    pub region: String,
    pub domain: Option<String>,
    pub verbose: bool,
    /// Origins allowed by default for buckets without their own CORS configuration.
    pub cors_origins: Vec<String>,
}

pub struct Server {
    pub store: Arc<Store>,
    pub auth: Option<Auth>,
    pub region: String,
    pub domain: Option<String>,
    pub verbose: bool,
    pub metrics: crate::metrics::Metrics,
    default_cors: Option<Vec<CorsRule>>,
    /// Parsed ACL / policy / CORS per bucket; invalidated whenever they change.
    access_cache: RwLock<HashMap<String, Arc<BucketAccess>>>,
    req_counter: AtomicU64,
    rid_base: u64,
}

struct Req {
    parts: Parts,
    query: Vec<(String, String)>,
    payload: Payload,
    body: BodyStream,
}

impl Req {
    fn q(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    fn has(&self, name: &str) -> bool {
        self.query.iter().any(|(k, _)| k == name)
    }
    fn header(&self, name: &str) -> Option<&str> {
        header(&self.parts.headers, name)
    }
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn parse_query(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (uri_decode(k, true).unwrap_or_else(|| k.to_string()), uri_decode(v, true).unwrap_or_else(|| v.to_string()))
        })
        .collect()
}

// ------------------------------------------------------------------ response helpers

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Body,
}

impl Resp {
    fn new(status: StatusCode) -> Self {
        Resp { status, headers: HeaderMap::new(), body: Body::Empty }
    }
    fn ok() -> Self {
        Self::new(StatusCode::OK)
    }
    fn xml(doc: String) -> Self {
        let mut r = Self::ok();
        r.set("content-type", "application/xml");
        r.body = Body::full(doc);
        r
    }
    fn set(&mut self, name: &str, value: &str) -> &mut Self {
        if let (Ok(n), Ok(v)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            self.headers.insert(n, v);
        }
        self
    }
}

fn error_body(e: &S3Error, resource: &str, rid: &str) -> String {
    let mut s = String::with_capacity(256);
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>");
    s.push_str(e.code);
    s.push_str("</Code><Message>");
    util::xml_escape(&e.message, &mut s);
    s.push_str("</Message><Resource>");
    util::xml_escape(resource, &mut s);
    s.push_str("</Resource><RequestId>");
    s.push_str(rid);
    s.push_str("</RequestId></Error>");
    s
}

// ------------------------------------------------------------------ conditionals & ranges

fn etag_matches(list: &str, etag: &str) -> bool {
    let e = norm_etag(etag);
    list.split(',').any(|t| t.trim() == "*" || norm_etag(t) == e)
}

/// Returns Ok(true) when a 304 Not Modified should be sent.
fn check_read_conditions(h: &HeaderMap, meta: &ObjectMeta) -> S3Result<bool> {
    let mtime = meta.mtime_ms / 1000;
    let if_match = header(h, "if-match");
    if let Some(im) = if_match {
        if !etag_matches(im, &meta.etag) {
            return Err(err::PreconditionFailed());
        }
    } else if let Some(t) = header(h, "if-unmodified-since").and_then(util::parse_http_date)
        && mtime > t
    {
        return Err(err::PreconditionFailed());
    }
    if let Some(inm) = header(h, "if-none-match") {
        if etag_matches(inm, &meta.etag) {
            return Ok(true);
        }
    } else if let Some(t) = header(h, "if-modified-since").and_then(util::parse_http_date)
        && mtime <= t
    {
        return Ok(true);
    }
    Ok(false)
}

fn check_copy_conditions(h: &HeaderMap, meta: &ObjectMeta) -> S3Result<()> {
    let mtime = meta.mtime_ms / 1000;
    let im = header(h, "x-amz-copy-source-if-match");
    if let Some(v) = im
        && !etag_matches(v, &meta.etag)
    {
        return Err(err::PreconditionFailed());
    }
    if im.is_none()
        && let Some(t) = header(h, "x-amz-copy-source-if-unmodified-since").and_then(util::parse_http_date)
        && mtime > t
    {
        return Err(err::PreconditionFailed());
    }
    let inm = header(h, "x-amz-copy-source-if-none-match");
    if let Some(v) = inm
        && etag_matches(v, &meta.etag)
    {
        return Err(err::PreconditionFailed());
    }
    if inm.is_none()
        && let Some(t) = header(h, "x-amz-copy-source-if-modified-since").and_then(util::parse_http_date)
        && mtime <= t
    {
        return Err(err::PreconditionFailed());
    }
    Ok(())
}

/// Parse a single `bytes=` range. `None` means "ignore and serve everything".
fn parse_range(spec: &str, size: u64) -> Option<S3Result<(u64, u64)>> {
    let spec = spec.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    let r = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 || size == 0 {
            return Some(Err(err::InvalidRange()));
        }
        (size.saturating_sub(n), size - 1)
    } else {
        let start: u64 = a.parse().ok()?;
        let end: u64 = if b.is_empty() { u64::MAX } else { b.parse().ok()? };
        if end < start {
            return None;
        }
        if start >= size {
            return Some(Err(err::InvalidRange()));
        }
        (start, end.min(size - 1))
    };
    Some(Ok(r))
}

fn write_cond(h: &HeaderMap) -> Option<WriteCond> {
    if header(h, "if-none-match").is_some_and(|v| v.trim() == "*") {
        return Some(WriteCond::NotExists);
    }
    header(h, "if-match").map(|v| WriteCond::Matches(v.to_string()))
}

/// Headers persisted with an object and replayed on GET/HEAD.
fn stored_headers(h: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in h {
        let n = name.as_str();
        let keep = matches!(
            n,
            "content-type"
                | "content-disposition"
                | "content-language"
                | "cache-control"
                | "expires"
                | "x-amz-website-redirect-location"
        ) || n.starts_with("x-amz-meta-");
        let v = String::from_utf8_lossy(value.as_bytes()).into_owned();
        if keep {
            out.push((n.to_string(), v));
        } else if n == "content-encoding" {
            let enc: Vec<&str> = v.split(',').map(str::trim).filter(|e| !e.is_empty() && *e != "aws-chunked").collect();
            if !enc.is_empty() {
                out.push((n.to_string(), enc.join(",")));
            }
        }
    }
    out
}

fn valid_bucket_name(b: &str) -> bool {
    let bytes = b.as_bytes();
    (3..=63).contains(&b.len())
        && bytes.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-')
        && bytes[0].is_ascii_alphanumeric()
        && bytes[b.len() - 1].is_ascii_alphanumeric()
        && !b.contains("..")
        && !b.split('.').all(|p| p.parse::<u8>().is_ok())
}

fn check_key(key: &str) -> S3Result<()> {
    if key.len() > MAX_KEY_LEN {
        return Err(err::KeyTooLongError());
    }
    Ok(())
}

/// `?encoding-type=url` support for list responses.
struct Enc(bool);

impl Enc {
    fn e<'a>(&self, s: &'a str) -> std::borrow::Cow<'a, str> {
        if self.0 { uri_encode(s, true).into() } else { s.into() }
    }
}

fn parse_max(v: Option<&str>, default: usize) -> S3Result<usize> {
    match v {
        None => Ok(default),
        Some(s) => s
            .parse::<i64>()
            .map_err(|_| err::InvalidArgument().with_message("Provided max-keys not an integer or within integer range"))
            .map(|n| n.clamp(0, default as i64) as usize),
    }
}

// ------------------------------------------------------------------ server

impl Server {
    pub fn new(store: Arc<Store>, auth: Option<Auth>, opts: Options) -> Self {
        let default_cors = (!opts.cors_origins.is_empty()).then(|| {
            vec![CorsRule {
                origins: opts.cors_origins.clone(),
                methods: ["GET", "PUT", "POST", "DELETE", "HEAD"].map(String::from).to_vec(),
                headers: vec!["*".into()],
                expose: ["ETag", "Content-Length", "Content-Range", "Last-Modified", "x-amz-request-id", "x-amz-version-id"]
                    .map(String::from)
                    .to_vec(),
                max_age: Some(3600),
            }]
        });
        Server {
            store,
            auth,
            region: opts.region,
            domain: opts.domain,
            verbose: opts.verbose,
            metrics: Default::default(),
            default_cors,
            access_cache: RwLock::new(HashMap::new()),
            req_counter: AtomicU64::new(1),
            rid_base: util::new_id() as u64,
        }
    }

    /// Access settings for a bucket (cached). Errors with NoSuchBucket.
    fn bucket_access(&self, bucket: &str) -> S3Result<Arc<BucketAccess>> {
        if let Some(a) = self.access_cache.read().unwrap().get(bucket) {
            return Ok(a.clone());
        }
        let acl = match self.store.bucket_config(bucket, "acl")? {
            Some(v) => CannedAcl::parse(&String::from_utf8_lossy(&v)).unwrap_or_default(),
            None => CannedAcl::Private,
        };
        let policy =
            self.store.bucket_config(bucket, "policy")?.and_then(|v| Policy::parse(&String::from_utf8_lossy(&v), bucket).ok());
        let cors = self
            .store
            .bucket_config(bucket, "cors")?
            .and_then(|v| xml::parse(&String::from_utf8_lossy(&v)))
            .and_then(|d| access::parse_cors(&d).ok());
        let a = Arc::new(BucketAccess { acl, policy, cors });
        let mut cache = self.access_cache.write().unwrap();
        if cache.len() > 10_000 {
            cache.clear();
        }
        cache.insert(bucket.to_string(), a.clone());
        Ok(a)
    }

    fn invalidate_access(&self, bucket: &str) {
        self.access_cache.write().unwrap().remove(bucket);
    }

    async fn set_bucket_config(&self, bucket: &str, kind: &'static str, value: Option<Vec<u8>>) -> S3Result<()> {
        let r = self.store.submit(Op::SetBucketConfig { bucket: bucket.into(), kind, value }).await;
        self.invalidate_access(bucket);
        r.map(|_| ())
    }

    /// CORS rules that apply to a bucket: its own configuration, else the server default.
    fn cors_rules(&self, bucket: Option<&str>) -> Option<Vec<CorsRule>> {
        if let Some(b) = bucket
            && let Ok(a) = self.bucket_access(b)
            && let Some(rules) = &a.cors
        {
            return Some(rules.clone());
        }
        self.default_cors.clone()
    }

    /// Add CORS response headers for an actual (non-preflight) cross-origin request.
    fn apply_cors(&self, parts_method: &Method, origin: &str, bucket: Option<&str>, resp: &mut Resp) {
        let Some(rules) = self.cors_rules(bucket) else { return };
        let method = parts_method.as_str();
        if let Some(rule) = access::find_cors_rule(&rules, origin, method, &[]) {
            let wildcard = rule.origins.iter().any(|o| o == "*");
            resp.set("access-control-allow-origin", if wildcard { "*" } else { origin });
            if !wildcard {
                resp.set("access-control-allow-credentials", "true");
            }
            resp.set("access-control-allow-methods", &rule.methods.join(", "));
            if !rule.expose.is_empty() {
                resp.set("access-control-expose-headers", &rule.expose.join(", "));
            }
            resp.set("vary", "Origin, Access-Control-Request-Headers, Access-Control-Request-Method");
        }
    }

    /// Answer a CORS preflight (`OPTIONS`). Never requires authentication.
    fn preflight(&self, parts: &Parts, bucket: Option<&str>) -> S3Result<Resp> {
        let origin = header(&parts.headers, "origin");
        let method = header(&parts.headers, "access-control-request-method");
        let (Some(origin), Some(method)) = (origin, method) else {
            return Err(err::InvalidRequest().with_message("Insufficient information. Origin request header needed."));
        };
        if let Some(b) = bucket {
            self.store.require_bucket(b)?;
        }
        let req_headers: Vec<String> = header(&parts.headers, "access-control-request-headers")
            .map(|h| h.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        let hdr_refs: Vec<&str> = req_headers.iter().map(String::as_str).collect();
        let forbidden =
            || S3Error::new("AccessForbidden", StatusCode::FORBIDDEN, "CORSResponse: This CORS request is not allowed.");
        let rules = self.cors_rules(bucket).ok_or_else(forbidden)?;
        let rule = access::find_cors_rule(&rules, origin, method, &hdr_refs).ok_or_else(forbidden)?;
        let wildcard = rule.origins.iter().any(|o| o == "*");
        let mut resp = Resp::ok();
        resp.set("access-control-allow-origin", if wildcard { "*" } else { origin });
        if !wildcard {
            resp.set("access-control-allow-credentials", "true");
        }
        resp.set("access-control-allow-methods", &rule.methods.join(", "));
        if !req_headers.is_empty() {
            resp.set("access-control-allow-headers", &req_headers.join(", "));
        }
        if !rule.expose.is_empty() {
            resp.set("access-control-expose-headers", &rule.expose.join(", "));
        }
        if let Some(age) = rule.max_age {
            resp.set("access-control-max-age", &age.to_string());
        }
        resp.set("vary", "Origin, Access-Control-Request-Headers, Access-Control-Request-Method");
        Ok(resp)
    }

    /// Decide whether an anonymous request is allowed by the bucket's ACL / policy.
    fn authorize_anonymous(&self, r: &Req, bucket: Option<&str>, key: Option<&str>) -> S3Result<()> {
        let Some(bucket) = bucket else { return Err(err::AccessDenied()) };
        let m = &r.parts.method;
        let action = match (key, m) {
            (Some(_), &Method::GET) if r.has("uploadId") => "s3:ListMultipartUploadParts",
            (Some(_), &Method::GET | &Method::HEAD) if !r.has("acl") && !r.has("tagging") => "s3:GetObject",
            (Some(_), &Method::PUT) if r.header("x-amz-copy-source").is_none() && !r.has("acl") && !r.has("tagging") => {
                "s3:PutObject"
            }
            (Some(_), &Method::POST) if r.has("uploads") || r.has("uploadId") => "s3:PutObject",
            (Some(_), &Method::DELETE) if r.has("uploadId") => "s3:AbortMultipartUpload",
            (Some(_), &Method::DELETE) if !r.has("tagging") => "s3:DeleteObject",
            (None, &Method::GET) if r.has("location") => "s3:GetBucketLocation",
            (None, &Method::GET) if r.has("uploads") => "s3:ListBucketMultipartUploads",
            (None, &Method::GET | &Method::HEAD)
                if !r.query.iter().any(|(k, _)| {
                    !matches!(
                        k.as_str(),
                        "list-type"
                            | "prefix"
                            | "delimiter"
                            | "max-keys"
                            | "marker"
                            | "continuation-token"
                            | "start-after"
                            | "encoding-type"
                            | "fetch-owner"
                    )
                }) =>
            {
                "s3:ListBucket"
            }
            _ => return Err(err::AccessDenied()),
        };
        let resource = match key {
            Some(k) => format!("arn:aws:s3:::{bucket}/{k}"),
            None => format!("arn:aws:s3:::{bucket}"),
        };
        // Unknown buckets look the same as forbidden ones to anonymous callers.
        let access = self.bucket_access(bucket).map_err(|_| err::AccessDenied())?;
        if access.allows_anonymous(action, &resource) { Ok(()) } else { Err(err::AccessDenied()) }
    }

    pub async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        let started = Instant::now();
        let rid = format!("{:016X}", self.rid_base.wrapping_add(self.req_counter.fetch_add(1, Ordering::Relaxed)));
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
        let origin = header(req.headers(), "origin").map(str::to_string);
        let cors_bucket = origin.as_ref().and_then(|_| self.resolve(req.uri(), req.headers()).ok()).and_then(|(b, _, _)| b);
        self.metrics.start();
        let mut resp = match self.route(req).await {
            Ok(r) => r,
            Err(e) => {
                if e.status.is_server_error() {
                    eprintln!("error: {method} {path}: {e}");
                }
                let mut r = Resp::new(e.status);
                if method != Method::HEAD {
                    r.set("content-type", "application/xml");
                    r.body = Body::full(error_body(&e, &path, &rid));
                }
                r
            }
        };
        if let Some(o) = &origin
            && method != Method::OPTIONS
        {
            self.apply_cors(&method, o, cors_bucket.as_deref(), &mut resp);
        }
        let elapsed = started.elapsed();
        self.metrics.finish(&method, resp.status.as_u16(), elapsed);
        if self.verbose {
            eprintln!("{method} {path}{query} -> {} ({:.2}ms)", resp.status.as_u16(), elapsed.as_secs_f64() * 1000.0);
        }
        let mut out = Response::new(resp.body);
        *out.status_mut() = resp.status;
        *out.headers_mut() = resp.headers;
        let h = out.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&rid) {
            h.insert("x-amz-request-id", v);
        }
        h.insert("server", HeaderValue::from_static("s3rs"));
        out
    }

    /// Split the request into (bucket, key) for path-style and virtual-hosted-style addressing.
    fn resolve(&self, uri: &hyper::Uri, headers: &HeaderMap) -> S3Result<(Option<String>, Option<String>, bool)> {
        let path = uri_decode(uri.path(), false).ok_or_else(|| err::InvalidArgument().with_message("Invalid URI encoding"))?;
        let path = path.strip_prefix('/').unwrap_or(&path);
        if let Some(domain) = &self.domain {
            let host = header(headers, "host").or_else(|| uri.authority().map(|a| a.as_str())).unwrap_or("");
            let host = host.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(host, |(h, _)| h);
            if let Some(b) = host.strip_suffix(domain.as_str()).and_then(|h| h.strip_suffix('.'))
                && !b.is_empty()
            {
                let key = (!path.is_empty()).then(|| path.to_string());
                return Ok((Some(b.to_string()), key, true));
            }
        }
        if path.is_empty() {
            return Ok((None, None, false));
        }
        Ok(match path.split_once('/') {
            None => (Some(path.to_string()), None, false),
            Some((b, "")) => (Some(b.to_string()), None, false),
            Some((b, k)) => (Some(b.to_string()), Some(k.to_string()), false),
        })
    }

    async fn route(&self, req: Request<Incoming>) -> S3Result<Resp> {
        let (parts, body) = req.into_parts();
        if parts.uri.path() == "/_health" {
            let mut r = Resp::ok();
            r.body = Body::full(Bytes::from_static(b"ok\n"));
            return Ok(r);
        }
        if parts.uri.path() == "/_metrics" {
            let mut r = Resp::ok();
            r.set("content-type", "text/plain; version=0.0.4");
            r.body = Body::full(self.metrics.render(&self.store));
            return Ok(r);
        }
        let raw_query = parts.uri.query().unwrap_or("");
        let (bucket, key, vhost) = self.resolve(&parts.uri, &parts.headers)?;
        if parts.method == Method::OPTIONS {
            return self.preflight(&parts, bucket.as_deref());
        }
        let (mut payload, principal) = match &self.auth {
            None => (auth::payload_mode(&parts)?, Principal::Everyone),
            Some(a) if auth::has_credentials(&parts, raw_query) => {
                a.verify(&parts, raw_query, if vhost { bucket.as_deref() } else { None })?
            }
            Some(_) => (auth::payload_mode(&parts)?, Principal::Anonymous),
        };
        let query = parse_query(raw_query);
        let body = BodyStream::new(body, &mut payload);
        let mut r = Req { parts, query, payload, body };
        let m = r.parts.method.clone();
        match principal {
            Principal::Everyone | Principal::User { read_only: false } => {}
            Principal::User { read_only: true } => {
                if !matches!(m, Method::GET | Method::HEAD) {
                    return Err(err::AccessDenied().with_message("This access key is read-only"));
                }
            }
            Principal::Anonymous => self.authorize_anonymous(&r, bucket.as_deref(), key.as_deref())?,
        }

        let Some(bucket) = bucket else {
            return match m {
                Method::GET => self.list_buckets(),
                _ => Err(err::MethodNotAllowed()),
            };
        };
        match key {
            None => self.bucket_op(&mut r, m, &bucket).await,
            Some(key) => {
                check_key(&key)?;
                self.object_op(&mut r, m, &bucket, &key).await
            }
        }
    }

    async fn bucket_op(&self, r: &mut Req, m: Method, bucket: &str) -> S3Result<Resp> {
        const CONFIG_SUBRESOURCES: &[&str] = &[
            "acl",
            "policy",
            "cors",
            "lifecycle",
            "encryption",
            "tagging",
            "website",
            "logging",
            "notification",
            "replication",
            "object-lock",
            "accelerate",
            "requestPayment",
            "ownershipControls",
            "policyStatus",
            "publicAccessBlock",
            "analytics",
            "metrics",
            "inventory",
            "intelligent-tiering",
        ];
        let sub = CONFIG_SUBRESOURCES.iter().find(|s| r.has(s)).copied();
        match m {
            Method::GET if r.has("location") => {
                self.store.require_bucket(bucket)?;
                let mut x = Xml(String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
                x.0.push_str(&format!("<LocationConstraint xmlns=\"{}\">", xml::NS));
                if self.region != "us-east-1" {
                    util::xml_escape(&self.region, &mut x.0);
                }
                x.0.push_str("</LocationConstraint>");
                Ok(Resp::xml(x.0))
            }
            Method::GET if r.has("versioning") => {
                self.store.require_bucket(bucket)?;
                Ok(Resp::xml(Xml::new("VersioningConfiguration").finish("VersioningConfiguration")))
            }
            Method::GET if r.has("uploads") => self.list_uploads(r, bucket),
            Method::GET if r.has("versions") => self.list_versions(r, bucket),
            Method::GET if sub.is_some() => {
                self.store.require_bucket(bucket)?;
                match sub.unwrap() {
                    "acl" => Ok(Resp::xml(acl_doc(self.bucket_access(bucket)?.acl))),
                    "policy" => {
                        let doc = self.store.bucket_config(bucket, "policy")?.ok_or_else(err::NoSuchBucketPolicy)?;
                        let mut resp = Resp::ok();
                        resp.set("content-type", "application/json");
                        resp.body = Body::full(doc);
                        Ok(resp)
                    }
                    "policyStatus" => {
                        let public = self.bucket_access(bucket)?.policy.as_ref().is_some_and(Policy::is_public);
                        let mut x = Xml::new("PolicyStatus");
                        x.elem("IsPublic", public.to_string());
                        Ok(Resp::xml(x.finish("PolicyStatus")))
                    }
                    "cors" => {
                        let doc = self.store.bucket_config(bucket, "cors")?.ok_or_else(err::NoSuchCORSConfiguration)?;
                        Ok(Resp::xml(String::from_utf8_lossy(&doc).into_owned()))
                    }
                    "tagging" => {
                        let doc = self.store.bucket_config(bucket, "tagging")?.ok_or_else(err::NoSuchTagSet)?;
                        Ok(Resp::xml(String::from_utf8_lossy(&doc).into_owned()))
                    }
                    "lifecycle" => Err(err::NoSuchLifecycleConfiguration()),
                    "encryption" => Err(err::ServerSideEncryptionConfigurationNotFoundError()),
                    "logging" => Ok(Resp::xml(Xml::new("BucketLoggingStatus").finish("BucketLoggingStatus"))),
                    "notification" => Ok(Resp::xml(Xml::new("NotificationConfiguration").finish("NotificationConfiguration"))),
                    "accelerate" => Ok(Resp::xml(Xml::new("AccelerateConfiguration").finish("AccelerateConfiguration"))),
                    "requestPayment" => {
                        let mut x = Xml::new("RequestPaymentConfiguration");
                        x.elem("Payer", "BucketOwner");
                        Ok(Resp::xml(x.finish("RequestPaymentConfiguration")))
                    }
                    _ => Err(err::NotImplemented()),
                }
            }
            Method::GET => self.list_objects(r, bucket),
            Method::HEAD => {
                self.store.require_bucket(bucket)?;
                let mut resp = Resp::ok();
                resp.set("x-amz-bucket-region", &self.region);
                Ok(resp)
            }
            Method::PUT if sub == Some("acl") => {
                self.store.require_bucket(bucket)?;
                let acl = match r.header("x-amz-acl") {
                    Some(a) => CannedAcl::parse(a)?,
                    None => acl_from_xml(&self.read_xml(r).await?)?,
                };
                let value = (acl != CannedAcl::Private).then(|| acl.as_str().as_bytes().to_vec());
                self.set_bucket_config(bucket, "acl", value).await?;
                Ok(Resp::ok())
            }
            Method::PUT if sub == Some("policy") => {
                let body = self.read_body(r, 20 * 1024).await?;
                Policy::parse(&String::from_utf8_lossy(&body), bucket)?;
                self.set_bucket_config(bucket, "policy", Some(body.to_vec())).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            Method::PUT if sub == Some("cors") => {
                let body = self.read_body(r, MAX_XML_BODY).await?;
                let doc = xml::parse(&String::from_utf8_lossy(&body)).ok_or_else(err::MalformedXML)?;
                access::parse_cors(&doc)?;
                self.set_bucket_config(bucket, "cors", Some(body.to_vec())).await?;
                Ok(Resp::ok())
            }
            Method::PUT if sub == Some("tagging") => {
                let doc = self.read_xml(r).await?;
                let tags = access::parse_tagging_xml(&doc, 50)?;
                self.set_bucket_config(bucket, "tagging", Some(access::tagging_xml(&tags).into_bytes())).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            Method::PUT if sub.is_some() || r.has("versioning") => Err(err::NotImplemented()),
            Method::PUT => {
                if !valid_bucket_name(bucket) {
                    return Err(err::InvalidBucketName());
                }
                // Body is an optional CreateBucketConfiguration; we only have one region.
                let acl = r.header("x-amz-acl").map(CannedAcl::parse).transpose()?;
                let _ = r.body.read_all(MAX_XML_BODY).await?;
                self.store.submit(Op::CreateBucket(bucket.to_string())).await?;
                self.invalidate_access(bucket);
                if let Some(acl) = acl.filter(|a| *a != CannedAcl::Private) {
                    self.set_bucket_config(bucket, "acl", Some(acl.as_str().as_bytes().to_vec())).await?;
                }
                let mut resp = Resp::ok();
                resp.set("location", &format!("/{bucket}"));
                Ok(resp)
            }
            Method::DELETE if matches!(sub, Some("policy" | "cors" | "tagging")) => {
                let kind = sub.unwrap();
                let kind: &'static str = store::CONFIG_KINDS.iter().find(|k| **k == kind).unwrap();
                self.set_bucket_config(bucket, kind, None).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            Method::DELETE if sub.is_some() => {
                self.store.require_bucket(bucket)?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            Method::DELETE => {
                let r = self.store.submit(Op::DeleteBucket(bucket.to_string())).await;
                self.invalidate_access(bucket);
                r?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            Method::POST if r.has("delete") => self.delete_objects(r, bucket).await,
            _ => Err(err::MethodNotAllowed()),
        }
    }

    async fn object_op(&self, r: &mut Req, m: Method, bucket: &str, key: &str) -> S3Result<Resp> {
        const UNSUPPORTED: &[&str] = &["retention", "legal-hold", "torrent", "restore", "select", "attributes", "renameObject"];
        if UNSUPPORTED.iter().any(|s| r.has(s)) {
            return Err(err::NotImplemented());
        }
        if let Some(v) = r.q("versionId")
            && v != "null"
        {
            return Err(S3Error::new("NoSuchVersion", StatusCode::NOT_FOUND, "The specified version does not exist."));
        }
        match m {
            Method::GET if r.has("uploadId") => self.list_parts(r, bucket, key),
            Method::GET if r.has("acl") => {
                self.store.get_object(bucket, key)?;
                Ok(Resp::xml(acl_doc(CannedAcl::Private)))
            }
            Method::GET if r.has("tagging") => {
                let (meta, _) = self.store.get_object(bucket, key)?;
                Ok(Resp::xml(access::tagging_xml(&meta.tags)))
            }
            Method::GET | Method::HEAD => self.get_object(r, bucket, key, m == Method::HEAD).await,
            Method::PUT if r.has("partNumber") && r.has("uploadId") => self.upload_part(r, bucket, key).await,
            Method::PUT if r.has("acl") => {
                self.store.get_object(bucket, key)?;
                Ok(Resp::ok())
            }
            Method::PUT if r.has("tagging") => {
                let doc = self.read_xml(r).await?;
                let tags = access::parse_tagging_xml(&doc, 10)?;
                self.store.submit(Op::SetObjectTags { bucket: bucket.into(), key: key.into(), tags }).await?;
                Ok(Resp::ok())
            }
            Method::PUT if r.header("x-amz-copy-source").is_some() => self.copy_object(r, bucket, key).await,
            Method::PUT => self.put_object(r, bucket, key).await,
            Method::POST if r.has("uploads") => self.create_upload(r, bucket, key).await,
            Method::POST if r.has("uploadId") => self.complete_upload(r, bucket, key).await,
            Method::DELETE if r.has("uploadId") => {
                let upload = parse_upload_id(r)?;
                self.store.submit(Op::Abort { bucket: bucket.into(), key: key.into(), upload }).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            Method::DELETE if r.has("tagging") => {
                self.store.submit(Op::SetObjectTags { bucket: bucket.into(), key: key.into(), tags: vec![] }).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            Method::DELETE => {
                self.store.submit(Op::DeleteObjects { bucket: bucket.into(), keys: vec![key.into()] }).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            _ => Err(err::MethodNotAllowed()),
        }
    }

    // -------------------------------------------------------------- listing

    fn list_buckets(&self) -> S3Result<Resp> {
        let mut x = Xml::new("ListAllMyBucketsResult");
        x.owner("Owner").open("Buckets");
        for (name, created) in self.store.list_buckets()? {
            x.open("Bucket")
                .elem("Name", &name)
                .elem("CreationDate", iso8601(created))
                .elem("BucketRegion", &self.region)
                .close("Bucket");
        }
        x.close("Buckets");
        Ok(Resp::xml(x.finish("ListAllMyBucketsResult")))
    }

    fn list_objects(&self, r: &Req, bucket: &str) -> S3Result<Resp> {
        let v2 = r.q("list-type") == Some("2");
        let prefix = r.q("prefix").unwrap_or("");
        let delimiter = r.q("delimiter").unwrap_or("");
        let max = parse_max(r.q("max-keys"), 1000)?;
        let enc = Enc(match r.q("encoding-type") {
            None => false,
            Some(e) if e.eq_ignore_ascii_case("url") => true,
            Some(_) => return Err(err::InvalidArgument().with_message("Invalid Encoding Method specified in Request")),
        });
        let token = match r.q("continuation-token").filter(|_| v2) {
            Some(t) => Some(
                unbase64(t)
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or_else(|| err::InvalidArgument().with_message("The continuation token provided is incorrect"))?,
            ),
            None => None,
        };
        let marker: Option<&str> = if v2 { token.as_deref().or(r.q("start-after")) } else { r.q("marker") };
        let res = self.store.list_objects(bucket, prefix, delimiter, marker.filter(|m| !m.is_empty()), max)?;
        let fetch_owner = !v2 || r.q("fetch-owner") == Some("true");

        let mut x = Xml::new("ListBucketResult");
        x.elem("Name", bucket).elem("Prefix", enc.e(prefix));
        if v2 {
            x.elem("KeyCount", (res.contents.len() + res.prefixes.len()).to_string());
            x.opt("ContinuationToken", r.q("continuation-token"));
            x.opt("StartAfter", r.q("start-after").map(|s| enc.e(s)));
        } else {
            x.elem("Marker", enc.e(r.q("marker").unwrap_or("")));
        }
        x.elem("MaxKeys", max.to_string());
        if !delimiter.is_empty() {
            x.elem("Delimiter", enc.e(delimiter));
        }
        if enc.0 {
            x.elem("EncodingType", "url");
        }
        x.elem("IsTruncated", res.truncated.to_string());
        if let Some(n) = &res.next_marker {
            if v2 {
                x.elem("NextContinuationToken", base64(n.as_bytes()));
            } else {
                x.elem("NextMarker", enc.e(n));
            }
        }
        for (key, s) in &res.contents {
            x.open("Contents")
                .elem("Key", enc.e(key))
                .elem("LastModified", iso8601(s.mtime_ms))
                .elem("ETag", &s.etag)
                .elem("Size", s.size.to_string())
                .elem("StorageClass", "STANDARD");
            if fetch_owner {
                x.owner("Owner");
            }
            x.close("Contents");
        }
        for p in &res.prefixes {
            x.open("CommonPrefixes").elem("Prefix", enc.e(p)).close("CommonPrefixes");
        }
        Ok(Resp::xml(x.finish("ListBucketResult")))
    }

    fn list_versions(&self, r: &Req, bucket: &str) -> S3Result<Resp> {
        let prefix = r.q("prefix").unwrap_or("");
        let delimiter = r.q("delimiter").unwrap_or("");
        let max = parse_max(r.q("max-keys"), 1000)?;
        let enc = Enc(r.q("encoding-type").is_some_and(|e| e.eq_ignore_ascii_case("url")));
        let marker = r.q("key-marker").filter(|m| !m.is_empty());
        let res = self.store.list_objects(bucket, prefix, delimiter, marker, max)?;
        let mut x = Xml::new("ListVersionsResult");
        x.elem("Name", bucket)
            .elem("Prefix", enc.e(prefix))
            .elem("KeyMarker", enc.e(marker.unwrap_or("")))
            .elem("VersionIdMarker", r.q("version-id-marker").unwrap_or(""))
            .elem("MaxKeys", max.to_string());
        if !delimiter.is_empty() {
            x.elem("Delimiter", enc.e(delimiter));
        }
        if enc.0 {
            x.elem("EncodingType", "url");
        }
        x.elem("IsTruncated", res.truncated.to_string());
        if let Some(n) = &res.next_marker {
            x.elem("NextKeyMarker", enc.e(n)).elem("NextVersionIdMarker", "null");
        }
        for (key, s) in &res.contents {
            x.open("Version")
                .elem("Key", enc.e(key))
                .elem("VersionId", "null")
                .elem("IsLatest", "true")
                .elem("LastModified", iso8601(s.mtime_ms))
                .elem("ETag", &s.etag)
                .elem("Size", s.size.to_string())
                .elem("StorageClass", "STANDARD")
                .owner("Owner")
                .close("Version");
        }
        for p in &res.prefixes {
            x.open("CommonPrefixes").elem("Prefix", enc.e(p)).close("CommonPrefixes");
        }
        Ok(Resp::xml(x.finish("ListVersionsResult")))
    }

    fn list_uploads(&self, r: &Req, bucket: &str) -> S3Result<Resp> {
        self.store.require_bucket(bucket)?;
        let prefix = r.q("prefix").unwrap_or("");
        let delimiter = r.q("delimiter").unwrap_or("");
        let max = parse_max(r.q("max-uploads"), 1000)?;
        let enc = Enc(r.q("encoding-type").is_some_and(|e| e.eq_ignore_ascii_case("url")));
        let key_marker = r.q("key-marker").unwrap_or("");
        let id_marker = r.q("upload-id-marker").and_then(util::parse_id_hex);
        let all = self.store.list_uploads(bucket, prefix)?;

        let mut started = key_marker.is_empty();
        let mut uploads = Vec::new();
        let mut prefixes: Vec<String> = Vec::new();
        let mut truncated = false;
        let mut next: Option<(String, u128)> = None;
        for u in all {
            if !started {
                let after = match id_marker {
                    Some(id) => u.meta.key.as_str() > key_marker || (u.meta.key == key_marker && u.id == id),
                    None => u.meta.key.as_str() > key_marker,
                };
                if !after {
                    continue;
                }
                started = true;
                if id_marker.is_some() && u.meta.key == key_marker {
                    continue; // this is the marker entry itself
                }
            }
            if !delimiter.is_empty()
                && let Some(i) = u.meta.key[prefix.len()..].find(delimiter)
            {
                let cp = u.meta.key[..prefix.len() + i + delimiter.len()].to_string();
                if prefixes.last() != Some(&cp) {
                    if uploads.len() + prefixes.len() >= max {
                        truncated = true;
                        break;
                    }
                    prefixes.push(cp);
                }
                continue;
            }
            if uploads.len() + prefixes.len() >= max {
                truncated = true;
                break;
            }
            next = Some((u.meta.key.clone(), u.id));
            uploads.push(u);
        }

        let mut x = Xml::new("ListMultipartUploadsResult");
        x.elem("Bucket", bucket)
            .elem("KeyMarker", enc.e(key_marker))
            .elem("UploadIdMarker", r.q("upload-id-marker").unwrap_or(""))
            .elem("Prefix", enc.e(prefix));
        if truncated && let Some((k, id)) = &next {
            x.elem("NextKeyMarker", enc.e(k)).elem("NextUploadIdMarker", util::id_hex(*id));
        }
        if !delimiter.is_empty() {
            x.elem("Delimiter", enc.e(delimiter));
        }
        if enc.0 {
            x.elem("EncodingType", "url");
        }
        x.elem("MaxUploads", max.to_string()).elem("IsTruncated", truncated.to_string());
        for u in &uploads {
            x.open("Upload")
                .elem("Key", enc.e(&u.meta.key))
                .elem("UploadId", util::id_hex(u.id))
                .owner("Initiator")
                .owner("Owner")
                .elem("StorageClass", "STANDARD")
                .elem("Initiated", iso8601(u.meta.initiated_ms))
                .close("Upload");
        }
        for p in &prefixes {
            x.open("CommonPrefixes").elem("Prefix", enc.e(p)).close("CommonPrefixes");
        }
        Ok(Resp::xml(x.finish("ListMultipartUploadsResult")))
    }

    fn list_parts(&self, r: &Req, bucket: &str, key: &str) -> S3Result<Resp> {
        let upload = parse_upload_id(r)?;
        let u = self.store.get_upload(upload)?.filter(|u| u.bucket == bucket && u.key == key).ok_or_else(err::NoSuchUpload)?;
        let max = parse_max(r.q("max-parts"), 1000)?;
        let marker: u32 = r.q("part-number-marker").and_then(|m| m.parse().ok()).unwrap_or(0);
        let (parts, truncated) = self.store.list_parts(upload, marker, max)?;
        let mut x = Xml::new("ListPartsResult");
        x.elem("Bucket", bucket)
            .elem("Key", &u.key)
            .elem("UploadId", util::id_hex(upload))
            .owner("Initiator")
            .owner("Owner")
            .elem("StorageClass", "STANDARD")
            .elem("PartNumberMarker", marker.to_string());
        if let Some((n, _)) = parts.last() {
            x.elem("NextPartNumberMarker", n.to_string());
        }
        x.elem("MaxParts", max.to_string()).elem("IsTruncated", truncated.to_string());
        for (n, p) in &parts {
            x.open("Part")
                .elem("PartNumber", n.to_string())
                .elem("LastModified", iso8601(p.mtime_ms))
                .elem("ETag", format!("\"{}\"", util::hex(&p.md5)))
                .elem("Size", p.size.to_string())
                .close("Part");
        }
        Ok(Resp::xml(x.finish("ListPartsResult")))
    }

    // -------------------------------------------------------------- objects

    fn expect(&self, r: &Req, max_len: u64, allow_inline: bool) -> S3Result<Expect> {
        let chunked = matches!(r.payload, Payload::Chunked { .. });
        let len_header = if chunked { "x-amz-decoded-content-length" } else { "content-length" };
        let len = match r.header(len_header) {
            Some(v) => {
                Some(v.trim().parse::<u64>().map_err(|_| err::InvalidArgument().with_message(format!("Invalid {len_header}")))?)
            }
            None => None,
        };
        let md5 = match r.header("content-md5") {
            Some(v) => Some(unbase64(v).and_then(|b| <[u8; 16]>::try_from(b).ok()).ok_or_else(err::InvalidDigest)?),
            None => None,
        };
        let sha256 = match r.payload {
            Payload::Sha256(h) => Some(h),
            _ => None,
        };
        let mut checksum = ChecksumAlgo::ALL.iter().find_map(|a| r.header(a.header()).map(|v| (*a, Some(v.to_string()))));
        if checksum.is_none() {
            checksum = r
                .header("x-amz-trailer")
                .and_then(|t| ChecksumAlgo::ALL.iter().find(|a| a.header().eq_ignore_ascii_case(t.trim())))
                .or_else(|| {
                    r.header("x-amz-sdk-checksum-algorithm")
                        .and_then(ChecksumAlgo::from_name)
                        .as_ref()
                        .and_then(|a| ChecksumAlgo::ALL.iter().find(|x| *x == a))
                })
                .map(|a| (*a, None));
        }
        Ok(Expect { len, max_len, sha256, md5, checksum, allow_inline })
    }

    async fn put_object(&self, r: &mut Req, bucket: &str, key: &str) -> S3Result<Resp> {
        self.store.require_bucket(bucket)?;
        let tags = request_tags(r)?;
        let expect = self.expect(r, MAX_OBJECT_SIZE, true)?;
        let body = std::mem::replace(&mut r.body, BodyStream::empty());
        let ing = io::ingest(&self.store, body, expect).await?;
        self.metrics.add_bytes_in(ing.size);
        let (storage, inline, files) = ing.storage();
        let meta = ObjectMeta {
            size: ing.size,
            mtime_ms: now_ms(),
            etag: ing.etag(),
            headers: stored_headers(&r.parts.headers),
            checksum: ing.checksum.clone(),
            storage,
            tags,
        };
        let cond = write_cond(&r.parts.headers);
        self.store.submit_owning(Op::PutObject { bucket: bucket.into(), key: key.into(), meta, inline, cond }, files).await?;
        let mut resp = Resp::ok();
        resp.set("etag", &ing.etag());
        if let Some((a, v)) = &ing.checksum {
            resp.set(a.header(), v);
        }
        Ok(resp)
    }

    async fn get_object(&self, r: &Req, bucket: &str, key: &str, head: bool) -> S3Result<Resp> {
        let h = &r.parts.headers;
        for attempt in 0..3 {
            let (meta, inline) = self.store.get_object(bucket, key)?;
            let mut resp = Resp::ok();
            resp.set("etag", &meta.etag).set("last-modified", &http_date(meta.mtime_ms)).set("accept-ranges", "bytes");
            if check_read_conditions(h, &meta)? {
                resp.status = StatusCode::NOT_MODIFIED;
                return Ok(resp);
            }
            let mut ctype = false;
            for (k, v) in &meta.headers {
                ctype |= k == "content-type";
                resp.set(k, v);
            }
            if !ctype {
                resp.set("content-type", "binary/octet-stream");
            }
            if !meta.tags.is_empty() {
                resp.set("x-amz-tagging-count", &meta.tags.len().to_string());
            }
            for (q, hname) in [
                ("response-content-type", "content-type"),
                ("response-content-language", "content-language"),
                ("response-expires", "expires"),
                ("response-cache-control", "cache-control"),
                ("response-content-disposition", "content-disposition"),
                ("response-content-encoding", "content-encoding"),
            ] {
                if let Some(v) = r.q(q) {
                    resp.set(hname, v);
                }
            }

            // Byte range: explicit Range header, or a part of a multipart object.
            let mut range: Option<(u64, u64)> = None;
            if let Some(pn) = r.q("partNumber") {
                let pn: usize =
                    pn.parse().ok().filter(|n| (1..=MAX_PARTS as usize).contains(n)).ok_or_else(err::InvalidArgument)?;
                let segs: Vec<u64> = match &meta.storage {
                    Storage::Segments(s) if meta.etag.contains('-') => s.iter().map(|(_, l)| *l).collect(),
                    _ => vec![meta.size],
                };
                if pn > segs.len() {
                    return Err(err::InvalidRange().with_message("The requested partnumber is not satisfiable"));
                }
                let start: u64 = segs[..pn - 1].iter().sum();
                if segs[pn - 1] > 0 {
                    range = Some((start, start + segs[pn - 1] - 1));
                }
                resp.set("x-amz-mp-parts-count", &segs.len().to_string());
            } else if let Some(spec) = header(h, "range")
                && let Some(rr) = parse_range(spec, meta.size)
            {
                range = Some(rr?);
            }
            let (start, len) = match range {
                Some((s, e)) => {
                    resp.status = StatusCode::PARTIAL_CONTENT;
                    resp.set("content-range", &format!("bytes {s}-{e}/{}", meta.size));
                    (s, e - s + 1)
                }
                None => {
                    if header(h, "x-amz-checksum-mode").is_some_and(|m| m.eq_ignore_ascii_case("enabled"))
                        && let Some((a, v)) = &meta.checksum
                    {
                        resp.set(a.header(), v);
                    }
                    (0, meta.size)
                }
            };
            resp.set("content-length", &len.to_string());
            if head {
                return Ok(resp);
            }
            match io::read_body(&self.store, &meta, inline, start, len).await {
                Ok(body) => {
                    self.metrics.add_bytes_out(len);
                    resp.body = body;
                    return Ok(resp);
                }
                Err(None) if attempt < 2 => continue,
                Err(None) => return Err(err::NoSuchKey()),
                Err(Some(e)) => return Err(e),
            }
        }
        Err(err::NoSuchKey())
    }

    fn copy_source(&self, r: &Req) -> S3Result<(String, String)> {
        let raw = r.header("x-amz-copy-source").ok_or_else(err::InvalidArgument)?;
        let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
        if let Some(v) = parse_query(query).iter().find(|(k, _)| k == "versionId").map(|(_, v)| v.as_str())
            && v != "null"
        {
            return Err(S3Error::new("NoSuchVersion", StatusCode::NOT_FOUND, "The specified version does not exist."));
        }
        let path = uri_decode(path, false).ok_or_else(|| err::InvalidArgument().with_message("Invalid copy source encoding"))?;
        let path = path.strip_prefix('/').unwrap_or(&path);
        match path.split_once('/') {
            Some((b, k)) if !b.is_empty() && !k.is_empty() => Ok((b.to_string(), k.to_string())),
            _ => {
                Err(err::InvalidArgument()
                    .with_message("Copy Source must mention the source bucket and key: sourcebucket/sourcekey"))
            }
        }
    }

    async fn copy_object(&self, r: &mut Req, bucket: &str, key: &str) -> S3Result<Resp> {
        let (sb, sk) = self.copy_source(r)?;
        self.store.require_bucket(bucket)?;
        let replace = r.header("x-amz-metadata-directive").is_some_and(|d| d.eq_ignore_ascii_case("REPLACE"));
        let replace_tags = r.header("x-amz-tagging-directive").is_some_and(|d| d.eq_ignore_ascii_case("REPLACE"));
        let _ = r.body.read_all(MAX_XML_BODY).await?;
        for attempt in 0..3 {
            let (src, inline) = self.store.get_object(&sb, &sk)?;
            check_copy_conditions(&r.parts.headers, &src)?;
            if sb == bucket && sk == key && !replace {
                return Err(err::InvalidRequest().with_message(
                    "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
                ));
            }
            let (storage, files) = match &src.storage {
                Storage::Inline(_) => (Storage::Inline(util::new_id()), vec![]),
                Storage::Segments(segs) => {
                    let (st, segs) = (self.store.clone(), segs.clone());
                    match tokio::task::spawn_blocking(move || io::link_segments_blocking(&st, &segs))
                        .await
                        .map_err(S3Error::internal)?
                    {
                        Ok(new) => {
                            let files = new.iter().map(|(id, _)| *id).collect();
                            (Storage::Segments(new), files)
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound && attempt < 2 => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
            };
            let headers = if replace { stored_headers(&r.parts.headers) } else { src.headers.clone() };
            let tags = if replace_tags { request_tags(r)? } else { src.tags.clone() };
            let meta = ObjectMeta {
                size: src.size,
                mtime_ms: now_ms(),
                etag: src.etag.clone(),
                headers,
                checksum: src.checksum.clone(),
                storage,
                tags,
            };
            let mtime = meta.mtime_ms;
            let cond = write_cond(&r.parts.headers);
            self.store.submit_owning(Op::PutObject { bucket: bucket.into(), key: key.into(), meta, inline, cond }, files).await?;
            let mut x = Xml::new("CopyObjectResult");
            x.elem("LastModified", iso8601(mtime)).elem("ETag", &src.etag);
            if let Some((a, v)) = &src.checksum {
                let tag = match a {
                    ChecksumAlgo::Crc32 => "ChecksumCRC32",
                    ChecksumAlgo::Crc32c => "ChecksumCRC32C",
                    ChecksumAlgo::Crc64Nvme => "ChecksumCRC64NVME",
                    ChecksumAlgo::Sha1 => "ChecksumSHA1",
                    ChecksumAlgo::Sha256 => "ChecksumSHA256",
                };
                x.elem(tag, v);
            }
            return Ok(Resp::xml(x.finish("CopyObjectResult")));
        }
        Err(err::NoSuchKey())
    }

    async fn create_upload(&self, r: &mut Req, bucket: &str, key: &str) -> S3Result<Resp> {
        let _ = r.body.read_all(MAX_XML_BODY).await?;
        let id = util::new_id();
        let tags = request_tags(r)?;
        let meta = UploadMeta {
            bucket: bucket.into(),
            key: key.into(),
            initiated_ms: now_ms(),
            headers: stored_headers(&r.parts.headers),
            tags,
        };
        self.store.submit(Op::CreateUpload { id, meta }).await?;
        let mut x = Xml::new("InitiateMultipartUploadResult");
        x.elem("Bucket", bucket).elem("Key", key).elem("UploadId", util::id_hex(id));
        Ok(Resp::xml(x.finish("InitiateMultipartUploadResult")))
    }

    async fn upload_part(&self, r: &mut Req, bucket: &str, key: &str) -> S3Result<Resp> {
        let upload = parse_upload_id(r)?;
        let part: u32 =
            r.q("partNumber").and_then(|p| p.parse().ok()).filter(|p| (1..=MAX_PARTS).contains(p)).ok_or_else(|| {
                err::InvalidArgument().with_message("Part number must be an integer between 1 and 10000, inclusive")
            })?;
        self.store.get_upload(upload)?.filter(|u| u.bucket == bucket && u.key == key).ok_or_else(err::NoSuchUpload)?;

        if r.header("x-amz-copy-source").is_some() {
            return self.upload_part_copy(r, bucket, key, upload, part).await;
        }
        let expect = self.expect(r, MAX_PART_SIZE, false)?;
        let body = std::mem::replace(&mut r.body, BodyStream::empty());
        let ing = io::ingest(&self.store, body, expect).await?;
        self.metrics.add_bytes_in(ing.size);
        let Data::File(file) = ing.data else { return Err(S3Error::internal("part stored inline")) };
        let meta = PartMeta { size: ing.size, md5: ing.md5, mtime_ms: now_ms(), file };
        self.store.submit_owning(Op::PutPart { upload, bucket: bucket.into(), key: key.into(), part, meta }, vec![file]).await?;
        let mut resp = Resp::ok();
        resp.set("etag", &format!("\"{}\"", util::hex(&ing.md5)));
        if let Some((a, v)) = &ing.checksum {
            resp.set(a.header(), v);
        }
        Ok(resp)
    }

    async fn upload_part_copy(&self, r: &mut Req, bucket: &str, key: &str, upload: u128, part: u32) -> S3Result<Resp> {
        let (sb, sk) = self.copy_source(r)?;
        let _ = r.body.read_all(MAX_XML_BODY).await?;
        for attempt in 0..3 {
            let (src, inline) = self.store.get_object(&sb, &sk)?;
            check_copy_conditions(&r.parts.headers, &src)?;
            let (start, len) = match r.header("x-amz-copy-source-range") {
                None => (0, src.size),
                Some(spec) => {
                    let bad = || {
                        err::InvalidArgument().with_message("The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy")
                    };
                    let (a, b) = spec.trim().strip_prefix("bytes=").and_then(|s| s.split_once('-')).ok_or_else(bad)?;
                    let (a, b): (u64, u64) = (a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?);
                    if a > b || b >= src.size {
                        return Err(err::InvalidRange());
                    }
                    (a, b - a + 1)
                }
            };
            if len > MAX_PART_SIZE {
                return Err(err::EntityTooLarge());
            }
            let st = self.store.clone();
            let src2 = src.clone();
            let res = tokio::task::spawn_blocking(move || io::copy_range_blocking(&st, &src2, inline.as_ref(), start, len))
                .await
                .map_err(S3Error::internal)?;
            let (file, md5) = match res {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && attempt < 2 => continue,
                Err(e) => return Err(e.into()),
            };
            let meta = PartMeta { size: len, md5, mtime_ms: now_ms(), file };
            let mtime = meta.mtime_ms;
            self.store
                .submit_owning(Op::PutPart { upload, bucket: bucket.into(), key: key.into(), part, meta }, vec![file])
                .await?;
            let mut x = Xml::new("CopyPartResult");
            x.elem("LastModified", iso8601(mtime)).elem("ETag", format!("\"{}\"", util::hex(&md5)));
            return Ok(Resp::xml(x.finish("CopyPartResult")));
        }
        Err(err::NoSuchKey())
    }

    async fn read_xml(&self, r: &mut Req) -> S3Result<xml::Node> {
        let body = self.read_body(r, MAX_XML_BODY).await?;
        let text = std::str::from_utf8(&body).map_err(|_| err::MalformedXML())?;
        xml::parse(text).ok_or_else(err::MalformedXML)
    }

    /// Read a small request body, verifying `x-amz-content-sha256` and `Content-MD5`.
    async fn read_body(&self, r: &mut Req, limit: usize) -> S3Result<Bytes> {
        let body = r.body.read_all(limit).await?;
        if let Payload::Sha256(want) = r.payload {
            use sha2::Digest;
            if sha2::Sha256::digest(&body)[..] != want[..] {
                return Err(err::XAmzContentSHA256Mismatch());
            }
        }
        if let Some(v) = r.header("content-md5") {
            use md5::Digest;
            let want = unbase64(v).ok_or_else(err::InvalidDigest)?;
            if md5::Md5::digest(&body)[..] != want[..] {
                return Err(err::BadDigest());
            }
        }
        Ok(body)
    }

    async fn complete_upload(&self, r: &mut Req, bucket: &str, key: &str) -> S3Result<Resp> {
        let upload = parse_upload_id(r)?;
        let doc = self.read_xml(r).await?;
        if doc.name != "CompleteMultipartUpload" {
            return Err(err::MalformedXML());
        }
        let mut parts = Vec::new();
        for p in doc.children_named("Part") {
            let n: u32 = p.child_text("PartNumber").and_then(|n| n.trim().parse().ok()).ok_or_else(err::MalformedXML)?;
            let etag = p.child_text("ETag").ok_or_else(err::MalformedXML)?.to_string();
            parts.push((n, etag));
        }
        let cond = write_cond(&r.parts.headers);
        let out = self.store.submit(Op::Complete { bucket: bucket.into(), key: key.into(), upload, parts, cond }).await?;
        let OpOut::Object(meta) = out else { return Err(S3Error::internal("unexpected writer reply")) };
        let host = r.header("host").unwrap_or("localhost");
        let mut x = Xml::new("CompleteMultipartUploadResult");
        x.elem("Location", format!("http://{host}/{bucket}/{}", uri_encode(key, true)))
            .elem("Bucket", bucket)
            .elem("Key", key)
            .elem("ETag", &meta.etag);
        Ok(Resp::xml(x.finish("CompleteMultipartUploadResult")))
    }

    async fn delete_objects(&self, r: &mut Req, bucket: &str) -> S3Result<Resp> {
        let doc = self.read_xml(r).await?;
        if doc.name != "Delete" {
            return Err(err::MalformedXML());
        }
        let quiet = doc.child_text("Quiet").is_some_and(|q| q.trim().eq_ignore_ascii_case("true"));
        let keys: Vec<String> = doc.children_named("Object").filter_map(|o| o.child_text("Key").map(str::to_string)).collect();
        if keys.len() > 1000 {
            return Err(err::MalformedXML().with_message("The request must contain no more than 1000 keys"));
        }
        let (valid, invalid): (Vec<String>, Vec<String>) =
            keys.into_iter().partition(|k| !k.is_empty() && k.len() <= MAX_KEY_LEN);
        let OpOut::Deleted(results) = self.store.submit(Op::DeleteObjects { bucket: bucket.into(), keys: valid.clone() }).await?
        else {
            return Err(S3Error::internal("unexpected writer reply"));
        };
        let mut x = Xml::new("DeleteResult");
        for (k, res) in valid.iter().zip(results) {
            match res {
                Ok(()) if !quiet => {
                    x.open("Deleted").elem("Key", k).close("Deleted");
                }
                Ok(()) => {}
                Err(e) => {
                    x.open("Error").elem("Key", k).elem("Code", e.code).elem("Message", &e.message).close("Error");
                }
            }
        }
        for k in invalid {
            x.open("Error").elem("Key", &k).elem("Code", "InvalidArgument").elem("Message", "Invalid key").close("Error");
        }
        Ok(Resp::xml(x.finish("DeleteResult")))
    }
}

/// Tags from the `x-amz-tagging` request header.
fn request_tags(r: &Req) -> S3Result<Vec<(String, String)>> {
    r.header("x-amz-tagging").map(access::parse_tagging_header).transpose().map(Option::unwrap_or_default)
}

fn parse_upload_id(r: &Req) -> S3Result<u128> {
    r.q("uploadId").and_then(util::parse_id_hex).ok_or_else(err::NoSuchUpload)
}

const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";

fn acl_doc(acl: CannedAcl) -> String {
    let mut x = Xml::new("AccessControlPolicy");
    x.owner("Owner").open("AccessControlList");
    x.0.push_str("<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">");
    x.elem("ID", crate::OWNER_ID).elem("DisplayName", crate::OWNER_ID);
    x.0.push_str("</Grantee>");
    x.elem("Permission", "FULL_CONTROL").close("Grant");
    let public: &[&str] = match acl {
        CannedAcl::Private => &[],
        CannedAcl::PublicRead => &["READ"],
        CannedAcl::PublicReadWrite => &["READ", "WRITE"],
    };
    for perm in public {
        x.0.push_str("<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">");
        x.elem("URI", ALL_USERS);
        x.0.push_str("</Grantee>");
        x.elem("Permission", perm).close("Grant");
    }
    x.close("AccessControlList");
    x.finish("AccessControlPolicy")
}

/// Map an AccessControlPolicy document onto the canned ACLs we support.
fn acl_from_xml(doc: &xml::Node) -> S3Result<CannedAcl> {
    if doc.name != "AccessControlPolicy" {
        return Err(err::MalformedXML());
    }
    let mut read = false;
    let mut write = false;
    if let Some(list) = doc.child("AccessControlList") {
        for g in list.children_named("Grant") {
            let everyone = g.child("Grantee").and_then(|gr| gr.child_text("URI")).is_some_and(|u| u.trim() == ALL_USERS);
            if everyone {
                match g.child_text("Permission").map(str::trim) {
                    Some("READ") => read = true,
                    Some("WRITE") => write = true,
                    Some("FULL_CONTROL") => (read, write) = (true, true),
                    _ => {}
                }
            }
        }
    }
    Ok(match (read, write) {
        (true, true) => CannedAcl::PublicReadWrite,
        (true, false) => CannedAcl::PublicRead,
        (false, true) => return Err(err::NotImplemented().with_message("Write-only public access is not supported")),
        (false, false) => CannedAcl::Private,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100).unwrap().unwrap(), (0, 9));
        assert_eq!(parse_range("bytes=90-", 100).unwrap().unwrap(), (90, 99));
        assert_eq!(parse_range("bytes=-10", 100).unwrap().unwrap(), (90, 99));
        assert_eq!(parse_range("bytes=-1000", 100).unwrap().unwrap(), (0, 99));
        assert_eq!(parse_range("bytes=50-1000", 100).unwrap().unwrap(), (50, 99));
        assert!(parse_range("bytes=100-", 100).unwrap().is_err());
        assert!(parse_range("bytes=0-1,5-6", 100).is_none());
        assert!(parse_range("items=0-1", 100).is_none());
        assert!(parse_range("bytes=5-1", 100).is_none());
    }

    #[test]
    fn bucket_names() {
        assert!(valid_bucket_name("my-bucket.data"));
        assert!(!valid_bucket_name("ab"));
        assert!(!valid_bucket_name("Upper"));
        assert!(!valid_bucket_name("-dash"));
        assert!(!valid_bucket_name("192.168.1.1"));
        assert!(!valid_bucket_name("a..b"));
    }

    #[test]
    fn etags() {
        assert!(etag_matches("\"abc\"", "\"ABC\""));
        assert!(etag_matches("x, \"abc\"", "\"abc\""));
        assert!(etag_matches("*", "\"abc\""));
        assert!(!etag_matches("\"abd\"", "\"abc\""));
    }
}
