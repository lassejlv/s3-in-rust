//! Request routing and S3 operation handlers.

use crate::access::{self, BucketAccess, CannedAcl, CorsRule};
use crate::auth::{self, Auth, Payload, Principal};
use crate::body::Body;
use crate::crypt::{self, KeyKind, WrapKey};
use crate::error::{S3Error, S3Result, err};
use crate::events;
use crate::iam;
use crate::io::{self, BodyStream, Data, Expect};
use crate::lock;
use crate::ops::{self, BucketOp, ObjectOp};
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
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

const MAX_OBJECT_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const MAX_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const MAX_PARTS: u32 = 10_000;
const MAX_KEY_LEN: usize = 1024;
const MAX_XML_BODY: usize = 4 * 1024 * 1024;

pub struct Options {
    pub region: String,
    pub domain: Option<String>,
    /// Log every request (to stdout) in this format.
    pub access_log: Option<crate::accesslog::Format>,
    /// Origins allowed by default for buckets without their own CORS configuration.
    pub cors_origins: Vec<String>,
    /// Enables the admin API (`/_admin/...`) for `Authorization: Bearer <token>`.
    pub admin_token: Option<String>,
    /// If set, `/_metrics` requires `Authorization: Bearer <token>`.
    pub metrics_token: Option<String>,
    /// Master key for SSE-S3 (server-side encryption with server-managed keys).
    pub master_key: Option<[u8; 32]>,
    /// Encrypt every new object with the master key unless the request says otherwise.
    pub encrypt_by_default: bool,
    /// Website endpoint requests for `<bucket>.<website_domain>` serve that bucket's website.
    pub website_domain: Option<String>,
    /// Serve the web console at `/_console/`.
    pub console: bool,
    /// Trust X-Forwarded-For / X-Forwarded-Proto (client IP and HTTPS for policies).
    pub behind_proxy: bool,
    /// The listeners serve HTTPS.
    pub tls: bool,
    /// Event notifications (webhooks and live listeners).
    pub events: Arc<events::Bus>,
    /// Bucket replication to remote servers.
    pub replication: Arc<crate::replication::Replicator>,
    /// Requests per second allowed per access key, and per client address for unsigned
    /// requests (`None`: unlimited).
    pub rate_limit: Option<u32>,
    pub rate_limit_anonymous: Option<u32>,
}

pub struct Server {
    pub store: Arc<Store>,
    pub auth: Option<Auth>,
    pub region: String,
    pub domain: Option<String>,
    access_log: Option<Arc<crate::accesslog::AccessLog>>,
    admin_token: Option<String>,
    /// Set while a backup streams (one at a time).
    backup_running: Arc<std::sync::atomic::AtomicBool>,
    pub metrics: crate::metrics::Metrics,
    default_cors: Option<Vec<CorsRule>>,
    /// Parsed ACL / policy / CORS per bucket; invalidated whenever they change.
    access_cache: RwLock<HashMap<String, Arc<BucketAccess>>>,
    /// Bumped on every invalidation; a load only populates the cache if no invalidation
    /// happened while it was reading, so a stale (e.g. revoked public) entry is never cached.
    access_gen: AtomicU64,
    metrics_token: Option<String>,
    master_key: Option<WrapKey>,
    encrypt_by_default: bool,
    website_domain: Option<String>,
    console: bool,
    behind_proxy: bool,
    tls: bool,
    pub events: Arc<events::Bus>,
    pub replication: Arc<crate::replication::Replicator>,
    /// Per-bucket server access logs (PutBucketLogging).
    pub bucket_log: Arc<crate::bucketlog::Logger>,
    key_limit: Option<crate::ratelimit::Limiter>,
    /// Failed admin API logins per client address (against guessing the token).
    admin_failures: crate::ratelimit::Limiter,
    /// Keys from the command line and credentials file; merged with the stored ones.
    file_creds: RwLock<Vec<auth::Credential>>,
    keys_reload: Mutex<()>,
    /// When the next temporary key expires (unix ms; u64::MAX: none).
    next_key_expiry: AtomicU64,
    completed: std::sync::Mutex<Completed>,
    anon_limit: Option<crate::ratelimit::Limiter>,
    /// Weak self-reference, for background tasks that must re-check permissions.
    me: std::sync::OnceLock<std::sync::Weak<Server>>,
    req_counter: AtomicU64,
    rid_base: u64,
}

struct Req {
    parts: Parts,
    query: Vec<(String, String)>,
    payload: Payload,
    body: BodyStream,
    principal: Principal,
    client: Client,
    /// `REST-HEADER` or `REST-QUERY-STRING` (the `s3:authType` policy key).
    auth_type: &'static str,
    /// Request id (also sent as `x-amz-request-id`).
    rid: String,
    /// A write made by replication from another server (`x-amz-replication-status: REPLICA`,
    /// authorized with the s3:Replicate* actions): not replicated again.
    replica: bool,
}

/// Where a request came from.
#[derive(Clone, Copy)]
struct Client {
    ip: IpAddr,
    secure: bool,
}

impl Req {
    fn q(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    fn header(&self, name: &str) -> Option<&str> {
        header(&self.parts.headers, name)
    }
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

pub(crate) fn parse_query(raw: &str) -> Vec<(String, String)> {
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
pub(crate) fn parse_range(spec: &str, size: u64) -> Option<S3Result<(u64, u64)>> {
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
    let none_match = header(h, "if-none-match")
        .map(str::trim)
        .map(|v| if v.split(',').any(|e| e.trim() == "*") { WriteCond::NotExists } else { WriteCond::NotMatches(v.to_string()) });
    let matches = header(h, "if-match").map(|v| WriteCond::Matches(v.to_string()));
    match (matches, none_match) {
        (Some(a), Some(b)) => Some(WriteCond::All(vec![a, b])),
        (a, b) => a.or(b),
    }
}

const WEBSITE_REDIRECT: &str = "x-amz-website-redirect-location";

/// Website redirect targets must be a path on the same site or an absolute http(s) URL.
fn valid_redirect_location(v: &str) -> bool {
    (v.starts_with('/') && !v.starts_with("//")) || v.starts_with("http://") || v.starts_with("https://")
}

/// Headers persisted with an object and replayed on GET/HEAD.
fn stored_headers(h: &HeaderMap) -> S3Result<Vec<(String, String)>> {
    if let Some(loc) = header(h, WEBSITE_REDIRECT)
        && !valid_redirect_location(loc)
    {
        return Err(S3Error::new(
            "InvalidRedirectLocation",
            StatusCode::BAD_REQUEST,
            "The website redirect location must have a prefix of 'http://' or 'https://' or '/'.",
        ));
    }
    let mut out = Vec::new();
    for (name, value) in h {
        let n = name.as_str();
        let keep = matches!(
            n,
            "content-type" | "content-disposition" | "content-language" | "cache-control" | "expires" | WEBSITE_REDIRECT
        ) || n.starts_with("x-amz-meta-");
        let v = String::from_utf8_lossy(value.as_bytes()).into_owned();
        if n == store::REPLICA_HEADER {
            // Only accepted from replication (the router checks the permission).
            if v.eq_ignore_ascii_case("REPLICA") {
                out.push((n.to_string(), "REPLICA".to_string()));
            }
        } else if keep {
            out.push((n.to_string(), v));
        } else if n == "content-encoding" {
            let enc: Vec<&str> = v.split(',').map(str::trim).filter(|e| !e.is_empty() && *e != "aws-chunked").collect();
            if !enc.is_empty() {
                out.push((n.to_string(), enc.join(", ")));
            }
        }
    }
    Ok(out)
}

pub(crate) fn valid_bucket_name(b: &str) -> bool {
    let bytes = b.as_bytes();
    (3..=63).contains(&b.len())
        && bytes.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-')
        && bytes[0].is_ascii_alphanumeric()
        && bytes[b.len() - 1].is_ascii_alphanumeric()
        && !b.contains("..")
        // Each dot-separated label starts and ends with a letter or digit.
        && !b.contains(".-")
        && !b.contains("-.")
        && !b.split('.').all(|p| p.parse::<u8>().is_ok())
}

fn check_key(key: &str) -> S3Result<()> {
    if key.len() > MAX_KEY_LEN {
        return Err(err::KeyTooLongError());
    }
    store::check_key_chars(key)
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
        let bucket_log = crate::bucketlog::Logger::new(store.clone());
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
            access_log: opts.access_log.map(|f| Arc::new(crate::accesslog::AccessLog::new(f))),
            admin_token: opts.admin_token,
            backup_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            metrics: crate::metrics::Metrics::new(
                opts.events.stats.clone(),
                opts.replication.stats.clone(),
                bucket_log.stats.clone(),
            ),
            default_cors,
            access_cache: RwLock::new(HashMap::new()),
            access_gen: AtomicU64::new(0),
            metrics_token: opts.metrics_token,
            master_key: opts.master_key.map(|k| WrapKey::new(KeyKind::Master, k)),
            encrypt_by_default: opts.encrypt_by_default,
            website_domain: opts.website_domain,
            console: opts.console,
            behind_proxy: opts.behind_proxy,
            tls: opts.tls,
            events: opts.events,
            replication: opts.replication,
            bucket_log,
            key_limit: opts.rate_limit.map(crate::ratelimit::Limiter::new),
            admin_failures: crate::ratelimit::Limiter::new(1),
            file_creds: RwLock::new(Vec::new()),
            keys_reload: Mutex::new(()),
            next_key_expiry: AtomicU64::new(u64::MAX),
            completed: std::sync::Mutex::new(Completed::default()),
            anon_limit: opts.rate_limit_anonymous.map(crate::ratelimit::Limiter::new),
            me: std::sync::OnceLock::new(),
            req_counter: AtomicU64::new(1),
            rid_base: util::new_id() as u64,
        }
    }

    /// Must be called once after the server is wrapped in an `Arc`.
    pub fn set_self(self: &Arc<Self>) {
        let _ = self.me.set(Arc::downgrade(self));
    }

    /// Access settings for a bucket (cached). Errors with NoSuchBucket.
    fn bucket_access(&self, bucket: &str) -> S3Result<Arc<BucketAccess>> {
        if let Some(a) = self.access_cache.read().unwrap().get(bucket) {
            return Ok(a.clone());
        }
        let generation = self.access_gen.load(Ordering::SeqCst);
        let acl = match self.store.bucket_config(bucket, "acl")? {
            Some(v) => CannedAcl::parse(&String::from_utf8_lossy(&v)).unwrap_or_default(),
            None => CannedAcl::Private,
        };
        let policy = self
            .store
            .bucket_config(bucket, "policy")?
            .map(|v| {
                iam::Policy::parse(&String::from_utf8_lossy(&v), iam::Kind::Bucket, Some(bucket)).unwrap_or_else(|e| {
                    // Fail closed: a policy we can no longer read may have contained Denies.
                    elog!(
                        "warning: bucket {bucket}: stored policy is invalid ({}); denying all access except policy management until it is replaced",
                        e.message
                    );
                    iam::Policy::lockdown(bucket)
                })
            });
        let cors = self
            .store
            .bucket_config(bucket, "cors")?
            .and_then(|v| xml::parse(&String::from_utf8_lossy(&v)))
            .and_then(|d| access::parse_cors(&d).ok());
        let versioning = store::Versioning::parse(self.store.bucket_config(bucket, "versioning")?.as_deref());
        let default_sse = self.store.bucket_config(bucket, "encryption")?.is_some();
        let lock = self.store.bucket_config(bucket, "object-lock")?.and_then(|v| lock::BucketLock::from_stored(&v));
        let website = self
            .store
            .bucket_config(bucket, "website")?
            .and_then(|v| xml::parse(&String::from_utf8_lossy(&v)))
            .and_then(|d| crate::website::Config::parse(&d).ok())
            .map(Arc::new);
        let lifecycle = self
            .store
            .bucket_config(bucket, "lifecycle")?
            .and_then(|v| xml::parse(&String::from_utf8_lossy(&v)))
            .and_then(|d| crate::lifecycle::parse(&d).ok())
            .filter(|r| r.iter().any(|r| r.enabled && (r.expire_days.is_some() || r.expire_date.is_some())))
            .map(Arc::new);
        let public_block = self
            .store
            .bucket_config(bucket, "public-access-block")?
            .and_then(|v| xml::parse(&String::from_utf8_lossy(&v)))
            .and_then(|d| access::PublicAccessBlock::parse(&d).ok())
            .unwrap_or_default();
        let ownership = self
            .store
            .bucket_config(bucket, "ownership")?
            .and_then(|v| access::Ownership::parse(&String::from_utf8_lossy(&v)).ok());
        let a = Arc::new(BucketAccess {
            acl,
            policy,
            cors,
            versioning,
            default_sse,
            lock,
            website,
            lifecycle,
            public_block,
            ownership,
        });
        let mut cache = self.access_cache.write().unwrap();
        if self.access_gen.load(Ordering::SeqCst) == generation {
            if cache.len() > 10_000 {
                cache.clear();
            }
            cache.insert(bucket.to_string(), a.clone());
        }
        Ok(a)
    }

    fn invalidate_access(&self, bucket: &str) {
        let mut cache = self.access_cache.write().unwrap();
        self.access_gen.fetch_add(1, Ordering::SeqCst);
        cache.remove(bucket);
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
        let forbidden =
            || S3Error::new("AccessForbidden", StatusCode::FORBIDDEN, "CORSResponse: This CORS request is not allowed.");
        // Same answer for missing and existing buckets, so preflights don't reveal which exist.
        if let Some(b) = bucket
            && !self.store.bucket_exists(b)?
        {
            return Err(forbidden());
        }
        let req_headers: Vec<String> = header(&parts.headers, "access-control-request-headers")
            .map(|h| h.split(',').map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        let hdr_refs: Vec<&str> = req_headers.iter().map(String::as_str).collect();
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

    /// The client's address and whether it connected over HTTPS (as reported by a trusted
    /// reverse proxy with `--behind-proxy`, or because s3rs serves TLS itself).
    fn client(&self, headers: &HeaderMap, peer: SocketAddr) -> Client {
        if !self.behind_proxy {
            return Client { ip: peer.ip(), secure: self.tls };
        }
        // The proxy appends what it saw, so the last entry (across all header lines) is the one
        // it vouches for; anything before it came from the client.
        let last = |name: &str| {
            headers
                .get_all(name)
                .iter()
                .next_back()
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .map(str::trim)
        };
        let ip = last("x-forwarded-for").and_then(|v| v.parse::<IpAddr>().ok()).unwrap_or(peer.ip());
        let secure = last("x-forwarded-proto").map_or(self.tls, |p| p.eq_ignore_ascii_case("https"));
        Client { ip, secure }
    }

    /// `scheme://host` of a request, for URLs that point back at this server. HTTP/2 requests
    /// carry the host in the URI instead of a Host header.
    fn base_url(&self, parts: &Parts, client: Client) -> String {
        let host = header(&parts.headers, "host").or_else(|| parts.uri.authority().map(|a| a.as_str())).unwrap_or("localhost");
        format!("{}://{host}", if client.secure { "https" } else { "http" })
    }

    /// Policy context for a request.
    fn ctx<'a>(
        &self,
        principal: &'a Principal,
        headers: &'a HeaderMap,
        query: &'a [(String, String)],
        client: Client,
        auth_type: &'static str,
    ) -> iam::Ctx<'a> {
        iam::Ctx {
            username: match principal {
                Principal::User(c) => Some(c.access_key.as_str()),
                _ => None,
            },
            source_ip: client.ip,
            secure: client.secure,
            headers,
            query,
            auth_type,
            now: now_ms() / 1000,
        }
    }

    fn req_ctx<'a>(&self, r: &'a Req) -> iam::Ctx<'a> {
        self.ctx(&r.principal, &r.parts.headers, &r.query, r.client, r.auth_type)
    }

    /// May `who` perform `action` on the bucket / object? Combines, like AWS: the key's own
    /// limits (read-only, bucket patterns), explicit Denies in the bucket policy, and Allows
    /// from the key's policy or the bucket policy. Keys without a policy may do anything their
    /// limits allow; anonymous callers need an ACL grant or a bucket-policy Allow.
    fn authorize(&self, who: &Principal, action: &str, bucket: Option<&str>, key: Option<&str>, ctx: &iam::Ctx) -> S3Result<()> {
        // Built only when a policy has to look at it (the common no-policy path stays cheap).
        let resource = || match (bucket, key) {
            (Some(b), Some(k)) => format!("arn:aws:s3:::{b}/{k}"),
            (Some(b), None) => format!("arn:aws:s3:::{b}"),
            _ => "arn:aws:s3:::*".to_string(),
        };
        match who {
            Principal::Everyone => Ok(()),
            Principal::Anonymous => {
                let Some(b) = bucket else { return Err(err::AccessDenied()) };
                if !ops::anonymous_may(action) {
                    return Err(err::AccessDenied());
                }
                // Unknown buckets look the same as forbidden ones to anonymous callers.
                let access = self.bucket_access(b).map_err(|_| err::AccessDenied())?;
                if access.allows_anonymous(action, &resource(), ctx) { Ok(()) } else { Err(err::AccessDenied()) }
            }
            Principal::User(c) => {
                if c.read_only && !(action.starts_with("s3:Get") || action.starts_with("s3:List")) {
                    return Err(err::AccessDenied().with_message("This access key is read-only"));
                }
                if let Some(b) = bucket
                    && !c.can_access(b)
                {
                    return Err(err::AccessDenied().with_message("This access key may not use this bucket"));
                }
                let access = bucket.and_then(|b| self.bucket_access(b).ok());
                let bucket_policy = access.as_ref().is_some_and(|a| a.policy.is_some());
                if !bucket_policy && c.policy.is_none() {
                    return Ok(());
                }
                let resource = resource();
                let by_bucket = match &access {
                    Some(a) => a.policy_decision(action, &resource, ctx),
                    None => iam::Decision::NotApplicable,
                };
                if by_bucket == iam::Decision::Deny {
                    return Err(err::AccessDenied());
                }
                match c.policy.as_ref().map(|p| p.evaluate(action, &resource, ctx)) {
                    None | Some(iam::Decision::Allow) => Ok(()),
                    Some(iam::Decision::Deny) => Err(err::AccessDenied()),
                    Some(iam::Decision::NotApplicable) if by_bucket == iam::Decision::Allow => Ok(()),
                    Some(iam::Decision::NotApplicable) => Err(err::AccessDenied()),
                }
            }
        }
    }

    pub async fn handle(self: Arc<Self>, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
        let started = Instant::now();
        let rid = format!("{:016X}", self.rid_base.wrapping_add(self.req_counter.fetch_add(1, Ordering::Relaxed)));
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
        let origin = header(req.headers(), "origin").map(str::to_string);
        let cors_bucket = origin.as_ref().and_then(|_| self.resolve(req.uri(), req.headers()).ok()).and_then(|(b, _, _)| b);
        // Written when the response has been sent, or with 499 if this future is dropped first.
        let logging = self.access_log.is_some() || self.bucket_log.enabled();
        let mut pending = logging.then(|| {
            let h = req.headers();
            let n = |name| header(h, name).and_then(|v| v.parse::<u64>().ok());
            crate::accesslog::PendingLog::new(
                self.access_log.clone(),
                Some(self.bucket_log.clone()),
                "api",
                &rid,
                peer.ip(),
                method.as_str(),
                &path,
                query.strip_prefix('?').unwrap_or(&query),
                header(h, "user-agent"),
                n("x-amz-decoded-content-length").or_else(|| n("content-length")),
            )
        });
        let mut scratch = crate::accesslog::Record::default();
        let rec = pending.as_mut().map_or(&mut scratch, |p| &mut p.record);
        // An HTTP/1 request with a body that fails may leave part of that body unread; hyper
        // then closes the connection, so say so instead of letting the client reuse it.
        let h1_with_body = req.version() <= hyper::Version::HTTP_11
            && (req.headers().contains_key("transfer-encoding")
                || header(req.headers(), "content-length").is_some_and(|v| v.trim() != "0"));
        let mut error_code = None;
        let _inflight = self.metrics.start();
        let mut resp = match self.route(req, peer, &rid, rec).await {
            Ok(r) => r,
            Err(e) => {
                error_code = Some(e.code);
                if e.status == StatusCode::INTERNAL_SERVER_ERROR {
                    elog!("error: {method} {path}: {e}");
                }
                let mut r = Resp::new(e.status);
                for (k, v) in &e.headers {
                    r.set(k, v);
                }
                if h1_with_body {
                    r.set("connection", "close");
                }
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
        if let Some(mut p) = pending {
            p.respond(resp.status.as_u16(), error_code);
            resp.body = Body::Logged(Box::new(std::mem::replace(&mut resp.body, Body::Empty)), Box::new(p));
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

    fn console_asset(&self, parts: &Parts) -> S3Result<Resp> {
        if !matches!(parts.method, Method::GET | Method::HEAD) {
            return Err(err::MethodNotAllowed());
        }
        let (ctype, body) = crate::console::asset(parts.uri.path(), &self.region).ok_or_else(err::NoSuchKey)?;
        let mut r = Resp::ok();
        r.set("content-type", ctype)
            .set("cache-control", "no-cache")
            .set("content-security-policy", crate::console::CSP)
            .set("x-frame-options", "DENY")
            .set("x-content-type-options", "nosniff")
            // Share links carry signatures; never leak them (or page URLs) in Referer headers.
            .set("referrer-policy", "no-referrer");
        r.set("content-length", &body.len().to_string());
        if parts.method == Method::GET {
            r.body = Body::full(body);
        }
        Ok(r)
    }

    /// Entry point for the static website endpoint (`--website-listen`).
    pub async fn handle_website(self: Arc<Self>, req: Request<Incoming>, peer: SocketAddr) -> Response<Body> {
        let started = Instant::now();
        let rid = format!("{:016X}", self.rid_base.wrapping_add(self.req_counter.fetch_add(1, Ordering::Relaxed)));
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let _inflight = self.metrics.start();
        let (parts, _body) = req.into_parts();
        let resp = self.website(&parts, &rid, peer).await;
        let elapsed = started.elapsed();
        self.metrics.finish(&method, resp.status.as_u16(), elapsed);
        let mut resp = resp;
        if let Some(log) = &self.access_log {
            let mut p = crate::accesslog::PendingLog::new(
                Some(log.clone()),
                None,
                "website",
                &rid,
                peer.ip(),
                method.as_str(),
                &path,
                parts.uri.query().unwrap_or(""),
                header(&parts.headers, "user-agent"),
                None,
            );
            p.record.client_ip = Some(self.client(&parts.headers, peer).ip);
            p.respond(resp.status.as_u16(), None);
            resp.body = Body::Logged(Box::new(std::mem::replace(&mut resp.body, Body::Empty)), Box::new(p));
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

    async fn website(&self, parts: &Parts, rid: &str, peer: SocketAddr) -> Resp {
        let head = parts.method == Method::HEAD;
        let anon = Principal::Anonymous;
        let client = self.client(&parts.headers, peer);
        let ctx = self.ctx(&anon, &parts.headers, &[], client, "REST-HEADER");
        let page = |e: S3Error| website_error(&e, head, rid);
        if let Err(e) = self.throttle(&anon, client.ip) {
            return page(e);
        }
        if !matches!(parts.method, Method::GET | Method::HEAD) {
            return page(err::MethodNotAllowed());
        }
        let host_full = header(&parts.headers, "host").or_else(|| parts.uri.authority().map(|a| a.as_str())).unwrap_or("");
        let host =
            host_full.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(host_full, |(h, _)| h);
        let host = host.to_ascii_lowercase();
        let bucket = match &self.website_domain {
            Some(d) => host.strip_suffix(d.as_str()).and_then(|b| b.strip_suffix('.')).filter(|b| !b.is_empty()).unwrap_or(&host),
            None => &host,
        };
        let Some(key) = uri_decode(parts.uri.path(), false) else {
            return page(err::InvalidArgument().with_message("Invalid URI encoding"));
        };
        let key = key.strip_prefix('/').unwrap_or(&key).to_string();
        let access = match self.bucket_access(bucket) {
            Ok(a) => a,
            Err(e) => return page(e),
        };
        let Some(cfg) = access.website.clone() else { return page(err::NoSuchWebsiteConfiguration()) };
        // HTTPS when s3rs serves TLS, or (with --behind-proxy) when the proxy says so.
        let proto = if ctx.secure { "https" } else { "http" };
        let redirect = |code: u16, location: &str| {
            let mut r = Resp::new(StatusCode::from_u16(code).unwrap_or(StatusCode::MOVED_PERMANENTLY));
            r.set("location", location);
            r
        };
        if let Some(all) = &cfg.redirect_all {
            let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            return redirect(301, &format!("{}://{}{pq}", all.protocol.as_deref().unwrap_or(proto), all.host));
        }
        if let Some(rule) = cfg.rule_for(&key, None) {
            return redirect(rule.redirect.code, &rule.location(&key, proto, host_full));
        }
        let index = cfg.index.as_deref().unwrap_or("index.html");
        let target = if key.is_empty() || key.ends_with('/') { format!("{key}{index}") } else { key.clone() };
        let e = match self.website_object(parts, bucket, &target, head, &access, &ctx).await {
            Ok(r) => return r,
            Err(e) => e,
        };
        // `/dir` where `dir/<index>` exists: redirect to the "directory".
        if e.status == StatusCode::NOT_FOUND
            && !key.is_empty()
            && !key.ends_with('/')
            && access.allows_anonymous("s3:GetObject", &format!("arn:aws:s3:::{bucket}/{key}/{index}"), &ctx)
            && self.store.get_object(bucket, &format!("{key}/{index}")).is_ok()
        {
            // Absolute, so a key starting with "/" cannot become a protocol-relative URL.
            return redirect(302, &format!("{proto}://{host_full}/{}/", uri_encode(&key, true)));
        }
        if let Some(rule) = cfg.rule_for(&key, Some(e.status.as_u16())) {
            return redirect(rule.redirect.code, &rule.location(&key, proto, host_full));
        }
        if let Some(doc) = &cfg.error_document
            && matches!(e.status, StatusCode::NOT_FOUND | StatusCode::FORBIDDEN)
        {
            // Served without the request's conditional / range headers, with the original status.
            let mut plain = Request::new(()).into_parts().0;
            plain.method = parts.method.clone();
            if let Ok(mut r) = self.website_object(&plain, bucket, doc, head, &access, &ctx).await
                && r.status == StatusCode::OK
            {
                r.status = e.status;
                return r;
            }
        }
        page(e)
    }

    /// Serve one object to an anonymous website visitor (it must be publicly readable).
    async fn website_object(
        &self,
        parts: &Parts,
        bucket: &str,
        key: &str,
        head: bool,
        access: &BucketAccess,
        ctx: &iam::Ctx<'_>,
    ) -> S3Result<Resp> {
        if check_key(key).is_err() || !access.allows_anonymous("s3:GetObject", &format!("arn:aws:s3:::{bucket}/{key}"), ctx) {
            return Err(err::AccessDenied());
        }
        let (meta, _) = self.store.get_object(bucket, key)?;
        if let Some((_, loc)) = meta.headers.iter().find(|(k, v)| k == WEBSITE_REDIRECT && valid_redirect_location(v)) {
            let mut r = Resp::new(StatusCode::MOVED_PERMANENTLY);
            r.set("location", loc);
            return Ok(r);
        }
        let mut p = Request::new(()).into_parts().0;
        p.method = parts.method.clone();
        p.headers = parts.headers.clone();
        let req = Req {
            parts: p,
            query: Vec::new(),
            payload: Payload::Unsigned,
            body: BodyStream::empty(),
            principal: Principal::Anonymous,
            client: Client { ip: ctx.source_ip, secure: ctx.secure },
            auth_type: "REST-HEADER",
            rid: String::new(),
            replica: false,
        };
        let mut r = self.get_object(&req, bucket, key, head).await?;
        // Objects that need a customer key cannot be served to anonymous visitors anyway; and
        // version ids are an API detail.
        r.headers.remove("x-amz-version-id");
        Ok(r)
    }

    /// Split the request into (bucket, key) for path-style and virtual-hosted-style addressing.
    fn resolve(&self, uri: &hyper::Uri, headers: &HeaderMap) -> S3Result<(Option<String>, Option<String>, bool)> {
        let path = uri_decode(uri.path(), false).ok_or_else(|| err::InvalidArgument().with_message("Invalid URI encoding"))?;
        let path = path.strip_prefix('/').unwrap_or(&path);
        if let Some(domain) = &self.domain {
            let host = header(headers, "host").or_else(|| uri.authority().map(|a| a.as_str())).unwrap_or("");
            let host = host.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(host, |(h, _)| h);
            let host = host.to_ascii_lowercase();
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

    /// `GET /_admin/backup`: a tar of a consistent snapshot of the data directory.
    /// The admin API requires `Authorization: Bearer <--admin-token>`.
    fn check_admin(&self, parts: &Parts, peer: SocketAddr) -> S3Result<()> {
        let Some(token) = &self.admin_token else {
            return Err(err::AccessDenied().with_message("The admin API is disabled; start the server with --admin-token"));
        };
        // About one wrong token per second per client address: an address that used up its
        // allowance is refused before its token is even looked at.
        let ip = self.client(&parts.headers, peer).ip.to_string();
        let slow_down = |wait: std::time::Duration| {
            self.metrics.throttled.fetch_add(1, Ordering::Relaxed);
            Err(S3Error::new("SlowDown", StatusCode::SERVICE_UNAVAILABLE, "Please reduce your request rate.")
                .with_header("retry-after", wait.as_secs().max(1).to_string()))
        };
        if let Some(wait) = self.admin_failures.wait(&ip) {
            return slow_down(wait);
        }
        let given = header(&parts.headers, "authorization").and_then(|h| h.strip_prefix("Bearer ")).map(str::trim);
        if !given.is_some_and(|g| !token.is_empty() && util::ct_eq(g.as_bytes(), token.as_bytes())) {
            if let Err(wait) = self.admin_failures.check(&ip) {
                return slow_down(wait);
            }
            return Err(err::AccessDenied());
        }
        Ok(())
    }

    /// Set the keys from the command line and credentials file (at startup and on SIGHUP), and
    /// put them in effect together with the stored keys. Returns how many keys are in effect.
    pub fn set_file_credentials(&self, creds: Vec<auth::Credential>) -> S3Result<usize> {
        *self.file_creds.write().unwrap() = creds;
        self.reload_keys()
    }

    fn reload_keys(&self) -> S3Result<usize> {
        let Some(a) = &self.auth else { return Ok(0) };
        // One reload at a time, so one that read the keys earlier can't overwrite a later one.
        let _one = self.keys_reload.lock().unwrap();
        let stored = self.store.access_keys()?;
        let next = stored.iter().filter_map(|(_, raw)| crate::keys::Record::decode(raw)?.expires_ms).min().unwrap_or(u64::MAX);
        self.next_key_expiry.store(next, Ordering::SeqCst);
        let all = crate::keys::merge(&self.file_creds.read().unwrap(), &stored);
        let n = all.len();
        a.replace(all);
        Ok(n)
    }

    /// Remove temporary keys that have expired (they already stopped working).
    pub async fn purge_expired_keys(&self) {
        let now = now_ms();
        if self.auth.is_none() || now < self.next_key_expiry.load(Ordering::SeqCst) {
            return;
        }
        let expired: Vec<(String, Vec<u8>)> = match self.store.access_keys() {
            Ok(keys) => {
                keys.into_iter().filter(|(_, raw)| crate::keys::Record::decode(raw).is_some_and(|r| r.expired(now))).collect()
            }
            Err(_) => return,
        };
        for (k, record) in expired {
            if let Ok(OpOut::More(true)) = self.store.submit(Op::DeleteKeyIf { access_key: k.clone(), record }).await {
                elog!("admin: temporary access key {k} expired and was removed");
            }
        }
        if let Err(e) = self.reload_keys() {
            elog!("warning: reloading access keys failed: {}", e.message);
        }
    }

    /// `GET /_admin/keys` lists keys; `POST /_admin/keys` creates one (JSON body, see
    /// crate::keys::parse_request) and returns its secret, once; `DELETE /_admin/keys/<key>`
    /// revokes one created this way.
    async fn admin_keys(&self, parts: &Parts, body: Incoming, peer: SocketAddr) -> S3Result<Resp> {
        self.check_admin(parts, peer)?;
        if self.auth.is_none() {
            return Err(err::InvalidRequest().with_message("Authentication is disabled (--anonymous)"));
        }
        let json = |j: crate::access::Json| {
            let mut r = Resp::ok();
            r.set("content-type", "application/json");
            r.body = Body::full(j.to_text());
            r
        };
        let target = parts.uri.path().strip_prefix("/_admin/keys").unwrap_or("");
        match (&parts.method, target) {
            (&Method::GET, "" | "/") => {
                let file = self.file_creds.read().unwrap().clone();
                let mut list: Vec<crate::access::Json> =
                    file.iter().map(|c| crate::keys::describe(&c.access_key, "file", None, Some(c))).collect();
                for (ak, raw) in self.store.access_keys()? {
                    if let Some(r) = crate::keys::Record::decode(&raw) {
                        list.push(crate::keys::describe(&ak, "api", Some(&r), None));
                    }
                }
                Ok(json(crate::access::Json::Obj(vec![("keys".into(), crate::access::Json::Arr(list))])))
            }
            (&Method::POST, "" | "/") => {
                let body = http_body_util::BodyExt::collect(http_body_util::Limited::new(body, 64 * 1024))
                    .await
                    .map_err(|_| err::InvalidArgument().with_message("The request body is too large"))?
                    .to_bytes();
                let text = std::str::from_utf8(&body).map_err(|_| err::InvalidArgument())?;
                let (access_key, record) = crate::keys::parse_request(text, util::now_ms())?;
                if self.file_creds.read().unwrap().iter().any(|c| c.access_key == access_key) {
                    return Err(S3Error::new("KeyAlreadyExists", StatusCode::CONFLICT, "The access key already exists."));
                }
                let secret = record.secret.clone();
                let info = crate::keys::describe(&access_key, "api", Some(&record), None);
                self.store.submit(Op::CreateKey { access_key: access_key.clone(), record: record.encode() }).await?;
                // Key changes are durable even with --no-fsync.
                self.store.submit(Op::Flush).await?;
                self.reload_keys()?;
                elog!("admin: created access key {access_key}");
                let crate::access::Json::Obj(mut fields) = info else { unreachable!() };
                fields.insert(1, ("secret_key".into(), crate::access::Json::Str(secret)));
                let mut r = json(crate::access::Json::Obj(fields));
                r.status = StatusCode::CREATED;
                Ok(r)
            }
            (&Method::DELETE, t) if t.len() > 1 => {
                let access_key = uri_decode(&t[1..], false).ok_or_else(err::InvalidArgument)?;
                // A stored key hidden by a file key can still be deleted (else it would come back
                // when the file key is removed).
                let stored = self.store.access_keys()?.iter().any(|(k, _)| *k == access_key);
                if !stored && self.file_creds.read().unwrap().iter().any(|c| c.access_key == access_key) {
                    return Err(S3Error::new(
                        "KeyInCredentialsFile",
                        StatusCode::CONFLICT,
                        "This key comes from the command line or the credentials file; remove it there.",
                    ));
                }
                self.store.submit(Op::DeleteKey(access_key.clone())).await?;
                self.store.submit(Op::Flush).await?;
                self.reload_keys()?;
                elog!("admin: revoked access key {access_key}");
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            _ => Err(err::MethodNotAllowed()),
        }
    }

    async fn admin_backup(&self, parts: &Parts, peer: SocketAddr) -> S3Result<Resp> {
        self.check_admin(parts, peer)?;
        if parts.method != Method::GET {
            return Err(err::MethodNotAllowed());
        }
        if self.backup_running.swap(true, Ordering::SeqCst) {
            return Err(S3Error::new("BackupInProgress", StatusCode::CONFLICT, "Another backup is already running."));
        }
        // Cleared when dropped, whichever way the backup ends (including a panic).
        struct Running(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Running {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let running = Running(self.backup_running.clone());
        let store = self.store.clone();
        let backup = tokio::task::spawn_blocking(move || store.begin_backup()).await.map_err(S3Error::internal)??;
        let size = backup.plan.tar_size();
        if !backup.plan.missing.is_empty() {
            elog!(
                "backup: {} data file(s) referenced by the metadata are missing and not included; run s3rs fsck",
                backup.plan.missing.len()
            );
        }
        elog!("backup: streaming {} file(s), {size} bytes", backup.plan.entries.len());
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::task::spawn_blocking(move || {
            let mut out = crate::store::backup::ChunkSender::new(tx);
            match crate::store::backup::write_tar(&backup.plan, &mut out) {
                Ok(()) => elog!("backup: done"),
                Err(e) => {
                    elog!("backup: aborted: {e}");
                    out.fail(e);
                }
            }
            // Releases the hold on data file deletion and removes the snapshot.
            drop(backup);
            drop(running);
        });
        let mut r = Resp::ok();
        r.set("content-type", "application/x-tar")
            .set("content-length", &size.to_string())
            .set("content-disposition", &format!("attachment; filename=\"s3rs-backup-{}.tar\"", now_ms() / 1000))
            .set("cache-control", "no-store");
        r.body = Body::Stream { rx, remaining: size };
        Ok(r)
    }

    /// Write out buffered access log lines (at shutdown).
    pub fn flush_logs(&self) {
        if let Some(log) = &self.access_log {
            log.flush();
        }
    }

    async fn route(
        &self,
        req: Request<Incoming>,
        peer: SocketAddr,
        rid: &str,
        rec: &mut crate::accesslog::Record,
    ) -> S3Result<Resp> {
        let (parts, body) = req.into_parts();
        let raw_query = parts.uri.query().unwrap_or("");
        rec.client_ip = Some(self.client(&parts.headers, peer).ip);
        let (bucket, key, vhost) = self.resolve(&parts.uri, &parts.headers)?;
        rec.bucket.clone_from(&bucket);
        rec.key.clone_from(&key);
        // Built-in endpoints. `_` cannot start a bucket name, so these never shadow a bucket;
        // with virtual-hosted addressing they are only matched when no bucket was resolved.
        if !vhost && parts.uri.path() == "/_health" {
            let mut r = Resp::ok();
            r.body = match self.store.health().await {
                Ok(()) => Body::full(Bytes::from_static(b"ok\n")),
                Err(e) => {
                    r.status = StatusCode::SERVICE_UNAVAILABLE;
                    Body::full(Bytes::from(format!("unavailable: {}\n", e.message)))
                }
            };
            return Ok(r);
        }
        if !vhost && parts.uri.path() == "/_metrics" {
            if let Some(token) = &self.metrics_token {
                let given = header(&parts.headers, "authorization").and_then(|h| h.strip_prefix("Bearer ")).unwrap_or("");
                if !util::ct_eq(given.trim().as_bytes(), token.as_bytes()) {
                    return Err(err::AccessDenied());
                }
            }
            let mut r = Resp::ok();
            r.set("content-type", "text/plain; version=0.0.4");
            let mut text = self.metrics.render(&self.store, self.metrics_token.is_some());
            if let Some(log) = &self.access_log {
                use std::fmt::Write;
                let _ = writeln!(
                    text,
                    "# TYPE s3rs_access_log_dropped_total counter\ns3rs_access_log_dropped_total {}",
                    log.dropped.load(Ordering::Relaxed)
                );
            }
            r.body = Body::full(text);
            return Ok(r);
        }
        if !vhost && parts.uri.path() == "/_admin/backup" {
            return self.admin_backup(&parts, peer).await;
        }
        if !vhost && (parts.uri.path() == "/_admin/keys" || parts.uri.path().starts_with("/_admin/keys/")) {
            return self.admin_keys(&parts, body, peer).await;
        }
        if !vhost && self.console && (parts.uri.path() == "/_console" || parts.uri.path().starts_with("/_console/")) {
            return self.console_asset(&parts);
        }
        // A browser opening the endpoint without credentials is sent to the console.
        if !vhost
            && self.console
            && self.auth.is_some()
            && parts.method == Method::GET
            && parts.uri.path() == "/"
            && raw_query.is_empty()
            && !auth::has_credentials(&parts, raw_query)
            && header(&parts.headers, "accept").is_some_and(|a| a.contains("text/html"))
        {
            let mut r = Resp::new(StatusCode::FOUND);
            r.set("location", "/_console/");
            return Ok(r);
        }
        if parts.method == Method::OPTIONS {
            return self.preflight(&parts, bucket.as_deref());
        }
        if parts.method == Method::POST
            && key.is_none()
            && let Some(b) = &bucket
            && let Some(boundary) = header(&parts.headers, "content-type").and_then(crate::post::boundary)
        {
            return self.post_object(&parts, body, b, &boundary, peer, rid).await;
        }
        let (mut payload, principal) = match &self.auth {
            None => (auth::payload_mode(&parts)?, Principal::Everyone),
            Some(a) if auth::has_credentials(&parts, raw_query) => {
                a.verify(&parts, raw_query, if vhost { bucket.as_deref() } else { None })?
            }
            Some(_) => (auth::payload_mode(&parts)?, Principal::Anonymous),
        };
        if let Principal::User(c) = &principal {
            rec.user = Some(c.access_key.clone());
        }
        self.throttle(&principal, self.client(&parts.headers, peer).ip)?;
        let query = parse_query(raw_query);
        let body = BodyStream::new(body, &mut payload);
        let auth_type = if r_has_auth_header(&parts) { "REST-HEADER" } else { "REST-QUERY-STRING" };
        let client = self.client(&parts.headers, peer);
        let mut r = Req { parts, query, payload, body, principal, client, auth_type, rid: rid.to_string(), replica: false };
        let m = r.parts.method.clone();
        // One classification decides both what is authorized and what runs.
        let op = match (&bucket, &key) {
            (None, _) => None,
            (Some(_), None) => Some(Err(ops::classify_bucket(&m, &r.query)?)),
            (Some(_), Some(_)) => Some(Ok(ops::classify_object(&m, &r.query, r.header("x-amz-copy-source").is_some())?)),
        };
        let mut replica = false;
        {
            let ctx = self.req_ctx(&r);
            let (b, k) = (bucket.as_deref(), key.as_deref());
            let versioned = r.q("versionId").is_some_and(|v| !v.is_empty());
            let action = match op {
                None if r.q("events").is_some() => Some("s3:ListenNotification"),
                None => Some("s3:ListAllMyBuckets"),
                Some(Err(bop)) => bop.action(),
                Some(Ok(oop)) => oop.action(versioned),
            };
            if let Some(action) = action {
                self.authorize(&r.principal, action, b, k, &ctx)?;
            }
            // As in S3, reading an object's attributes also needs permission to read the object
            // (the ETag is usually the content's MD5).
            if matches!(op, Some(Ok(ObjectOp::GetAttributes))) {
                let read = if versioned { "s3:GetObjectVersion" } else { "s3:GetObject" };
                self.authorize(&r.principal, read, b, k, &ctx)?;
            }
            // Writes from replication (another server) need the replication permissions; they are
            // marked so they are not replicated back.
            if r.header(store::REPLICA_HEADER).is_some_and(|v| v.eq_ignore_ascii_case("REPLICA")) {
                let action = match op {
                    Some(Ok(o))
                        if o.creates_object()
                            || matches!(
                                o,
                                ObjectOp::UploadPart
                                    | ObjectOp::UploadPartCopy
                                    | ObjectOp::CompleteUpload
                                    | ObjectOp::AbortUpload
                            ) =>
                    {
                        "s3:ReplicateObject"
                    }
                    Some(Ok(ObjectOp::Delete)) => "s3:ReplicateDelete",
                    Some(Ok(ObjectOp::PutTagging | ObjectOp::DeleteTagging)) => "s3:ReplicateTags",
                    _ => return Err(err::InvalidRequest().with_message("x-amz-replication-status can't be set on this request")),
                };
                self.authorize(&r.principal, action, b, k, &ctx)?;
                replica = true;
            }
            // Uploads that set retention, a legal hold or tags also need those permissions.
            if matches!(op, Some(Ok(oop)) if oop.creates_object()) {
                let h = &r.parts.headers;
                if h.contains_key(lock::MODE) || h.contains_key(lock::UNTIL) {
                    self.authorize(&r.principal, "s3:PutObjectRetention", b, k, &ctx)?;
                }
                if h.contains_key(lock::HOLD) {
                    self.authorize(&r.principal, "s3:PutObjectLegalHold", b, k, &ctx)?;
                }
                if h.contains_key("x-amz-tagging") {
                    self.authorize(&r.principal, "s3:PutObjectTagging", b, k, &ctx)?;
                }
            }
        }
        r.replica = replica;

        let Some(bucket) = bucket else {
            return match m {
                Method::GET if r.q("events").is_some() => self.listen(&r, None),
                Method::GET => self.list_buckets(&r),
                _ => Err(err::MethodNotAllowed()),
            };
        };
        match (key, op) {
            (None, Some(Err(bop))) => self.bucket_op(&mut r, bop, &bucket).await,
            (Some(key), Some(Ok(oop))) => {
                check_key(&key)?;
                self.object_op(&mut r, oop, &bucket, &key).await
            }
            _ => Err(S3Error::internal("request classification mismatch")),
        }
    }

    async fn bucket_op(&self, r: &mut Req, op: BucketOp, bucket: &str) -> S3Result<Resp> {
        match op {
            BucketOp::GetLocation => {
                self.store.require_bucket(bucket)?;
                let mut x = Xml(String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
                x.0.push_str(&format!("<LocationConstraint xmlns=\"{}\">", xml::NS));
                if self.region != "us-east-1" {
                    util::xml_escape(&self.region, &mut x.0);
                }
                x.0.push_str("</LocationConstraint>");
                Ok(Resp::xml(x.0))
            }
            BucketOp::GetConfig("versioning") => {
                let mut x = Xml::new("VersioningConfiguration");
                match self.store.versioning(bucket)? {
                    store::Versioning::Enabled => x.elem("Status", "Enabled"),
                    store::Versioning::Suspended => x.elem("Status", "Suspended"),
                    store::Versioning::Unversioned => &mut x,
                };
                Ok(Resp::xml(x.finish("VersioningConfiguration")))
            }
            BucketOp::ListUploads => self.list_uploads(r, bucket),
            BucketOp::ListVersions => self.list_versions(r, bucket),
            BucketOp::GetConfig(sub) => {
                self.store.require_bucket(bucket)?;
                match sub {
                    "acl" => Ok(Resp::xml(acl_doc(self.bucket_access(bucket)?.acl))),
                    "policy" => {
                        let doc = self.store.bucket_config(bucket, "policy")?.ok_or_else(err::NoSuchBucketPolicy)?;
                        let mut resp = Resp::ok();
                        resp.set("content-type", "application/json");
                        resp.body = Body::full(doc);
                        Ok(resp)
                    }
                    "policyStatus" => {
                        let public = self.bucket_access(bucket)?.policy.as_ref().is_some_and(iam::Policy::is_public);
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
                    "lifecycle" => {
                        let doc = self.store.bucket_config(bucket, "lifecycle")?.ok_or_else(err::NoSuchLifecycleConfiguration)?;
                        Ok(Resp::xml(String::from_utf8_lossy(&doc).into_owned()))
                    }
                    "encryption" => {
                        let doc = self
                            .store
                            .bucket_config(bucket, "encryption")?
                            .ok_or_else(err::ServerSideEncryptionConfigurationNotFoundError)?;
                        Ok(Resp::xml(String::from_utf8_lossy(&doc).into_owned()))
                    }
                    "object-lock" => {
                        let doc = self
                            .store
                            .bucket_config(bucket, "object-lock")?
                            .ok_or_else(err::ObjectLockConfigurationNotFoundError)?;
                        Ok(Resp::xml(String::from_utf8_lossy(&doc).into_owned()))
                    }
                    "website" => {
                        let doc = self.store.bucket_config(bucket, "website")?.ok_or_else(err::NoSuchWebsiteConfiguration)?;
                        Ok(Resp::xml(String::from_utf8_lossy(&doc).into_owned()))
                    }
                    "usage" | "quota" => {
                        let q =
                            self.store.bucket_config(bucket, "quota")?.and_then(|v| store::Quota::decode(&v)).unwrap_or_default();
                        let root = if sub == "usage" { "BucketUsage" } else { "BucketQuota" };
                        let mut x = Xml::new(root);
                        if sub == "usage" {
                            let (objects, bytes) = self.store.bucket_usage(bucket)?;
                            x.elem("Objects", objects.to_string()).elem("Bytes", bytes.to_string());
                            // Unfinished multipart uploads count towards the byte quota too.
                            x.elem("MultipartBytes", self.store.bucket_part_bytes(bucket)?.to_string());
                        }
                        if q.max_objects > 0 {
                            x.elem("MaxObjects", q.max_objects.to_string());
                        }
                        if q.max_bytes > 0 {
                            x.elem("MaxBytes", q.max_bytes.to_string());
                        }
                        Ok(Resp::xml(x.finish(root)))
                    }
                    "logging" => {
                        let target = self
                            .store
                            .bucket_config(bucket, "logging")?
                            .and_then(|v| xml::parse(&String::from_utf8_lossy(&v)))
                            .and_then(|d| crate::bucketlog::parse_config(&d).ok().flatten());
                        Ok(Resp::xml(crate::bucketlog::config_xml(target.as_ref())))
                    }
                    "notification" => Ok(Resp::xml(match self.store.bucket_config(bucket, "notification")? {
                        Some(doc) => String::from_utf8_lossy(&doc).into_owned(),
                        None => Xml::new("NotificationConfiguration").finish("NotificationConfiguration"),
                    })),
                    "accelerate" => Ok(Resp::xml(Xml::new("AccelerateConfiguration").finish("AccelerateConfiguration"))),
                    "replication" => {
                        let doc = self
                            .store
                            .bucket_config(bucket, "replication")?
                            .ok_or_else(err::ReplicationConfigurationNotFoundError)?;
                        Ok(Resp::xml(String::from_utf8_lossy(&doc).into_owned()))
                    }
                    "publicAccessBlock" => {
                        let doc = self
                            .store
                            .bucket_config(bucket, "public-access-block")?
                            .ok_or_else(err::NoSuchPublicAccessBlockConfiguration)?;
                        Ok(Resp::xml(String::from_utf8_lossy(&doc).into_owned()))
                    }
                    "ownershipControls" => match self.bucket_access(bucket)?.ownership {
                        Some(o) => Ok(Resp::xml(o.to_xml())),
                        None => Err(err::OwnershipControlsNotFoundError()),
                    },
                    "requestPayment" => {
                        let mut x = Xml::new("RequestPaymentConfiguration");
                        x.elem("Payer", "BucketOwner");
                        Ok(Resp::xml(x.finish("RequestPaymentConfiguration")))
                    }
                    _ => Err(err::NotImplemented()),
                }
            }
            BucketOp::ListObjects => self.list_objects(r, bucket),
            BucketOp::Head => {
                self.store.require_bucket(bucket)?;
                let mut resp = Resp::ok();
                resp.set("x-amz-bucket-region", &self.region);
                Ok(resp)
            }
            BucketOp::PutConfig("acl") => {
                self.store.require_bucket(bucket)?;
                let acl = match r.header("x-amz-acl") {
                    Some(a) => CannedAcl::parse(a)?,
                    None => acl_from_xml(&self.read_xml(r).await?)?,
                };
                self.check_acl(bucket, r.header("x-amz-acl").unwrap_or(xml_acl_name(acl)))?;
                let value = (acl != CannedAcl::Private).then(|| acl.as_str().as_bytes().to_vec());
                self.set_bucket_config(bucket, "acl", value).await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("policy") => {
                let body = self.read_body(r, 20 * 1024).await?;
                let policy = iam::Policy::parse(&String::from_utf8_lossy(&body), iam::Kind::Bucket, Some(bucket))?;
                if policy.is_public() && self.bucket_access(bucket)?.public_block.block_policy {
                    return Err(err::AccessDenied()
                        .with_message("The bucket's public access block (BlockPublicPolicy) refuses public policies"));
                }
                self.set_bucket_config(bucket, "policy", Some(body.to_vec())).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            BucketOp::PutConfig("cors") => {
                let body = self.read_body(r, MAX_XML_BODY).await?;
                let doc = xml::parse(&String::from_utf8_lossy(&body)).ok_or_else(err::MalformedXML)?;
                access::parse_cors(&doc)?;
                self.set_bucket_config(bucket, "cors", Some(body.to_vec())).await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("tagging") => {
                let doc = self.read_xml(r).await?;
                let tags = access::parse_tagging_xml(&doc, 50)?;
                self.set_bucket_config(bucket, "tagging", Some(access::tagging_xml(&tags).into_bytes())).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            BucketOp::PutConfig("encryption") => {
                let doc = self.read_xml(r).await?;
                let alg = (doc.name == "ServerSideEncryptionConfiguration")
                    .then(|| doc.child("Rule")?.child("ApplyServerSideEncryptionByDefault")?.child_text("SSEAlgorithm"))
                    .flatten()
                    .map(str::trim)
                    .ok_or_else(err::MalformedXML)?;
                match alg {
                    "AES256" => {}
                    a if a.starts_with("aws:kms") => {
                        return Err(err::NotImplemented().with_message("SSE-KMS is not supported; use AES256"));
                    }
                    _ => return Err(err::MalformedXML()),
                }
                self.master()?;
                let mut x = Xml::new("ServerSideEncryptionConfiguration");
                x.open("Rule").open("ApplyServerSideEncryptionByDefault").elem("SSEAlgorithm", "AES256");
                x.close("ApplyServerSideEncryptionByDefault").elem("BucketKeyEnabled", "false").close("Rule");
                self.set_bucket_config(bucket, "encryption", Some(x.finish("ServerSideEncryptionConfiguration").into_bytes()))
                    .await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("lifecycle") => {
                let body = self.read_body(r, MAX_XML_BODY).await?;
                let mut doc = xml::parse(&String::from_utf8_lossy(&body)).ok_or_else(err::MalformedXML)?;
                crate::lifecycle::parse(&doc)?;
                let stored = crate::lifecycle::with_ids(&mut doc).map(String::into_bytes).unwrap_or_else(|| body.to_vec());
                self.set_bucket_config(bucket, "lifecycle", Some(stored)).await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("object-lock") => {
                let cfg = lock::BucketLock::parse_xml(&self.read_xml(r).await?)?;
                self.set_bucket_config(bucket, "object-lock", Some(cfg.to_xml().into_bytes())).await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("website") => {
                let body = self.read_body(r, MAX_XML_BODY).await?;
                let doc = xml::parse(&String::from_utf8_lossy(&body)).ok_or_else(err::MalformedXML)?;
                crate::website::Config::parse(&doc)?;
                self.set_bucket_config(bucket, "website", Some(body.to_vec())).await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("versioning") => {
                let doc = self.read_xml(r).await?;
                if doc.name != "VersioningConfiguration" {
                    return Err(err::MalformedXML());
                }
                let status: &'static [u8] = match doc.child_text("Status").map(str::trim) {
                    Some("Enabled") => b"Enabled",
                    Some("Suspended") => b"Suspended",
                    // No status leaves the configuration unchanged.
                    None => {
                        self.store.require_bucket(bucket)?;
                        return Ok(Resp::ok());
                    }
                    Some(_) => return Err(err::MalformedXML()),
                };
                if doc.child_text("MfaDelete").map(str::trim) == Some("Enabled") {
                    return Err(err::NotImplemented().with_message("MFA delete is not supported"));
                }
                self.set_bucket_config(bucket, "versioning", Some(status.to_vec())).await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("notification") => {
                let doc = self.read_xml(r).await?;
                let rules = events::parse_config(&doc, &self.events.target_ids())?;
                let value = (!rules.is_empty()).then(|| events::config_xml(&rules).into_bytes());
                let res = self.set_bucket_config(bucket, "notification", value).await;
                self.events.invalidate(bucket);
                res?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("quota") => {
                let doc = self.read_xml(r).await?;
                if doc.name != "BucketQuota" {
                    return Err(err::MalformedXML());
                }
                let num = |n: &str| -> S3Result<u64> {
                    doc.child_text(n).map_or(Ok(0), |v| {
                        v.trim().parse().map_err(|_| err::InvalidArgument().with_message(format!("{n} must be a whole number")))
                    })
                };
                let q = store::Quota { max_objects: num("MaxObjects")?, max_bytes: num("MaxBytes")? };
                let value = (q != store::Quota::default()).then(|| q.encode());
                self.set_bucket_config(bucket, "quota", value).await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("replication") => {
                self.store.require_bucket(bucket)?;
                // Replication writes to other servers with the server's own credentials for
                // them, so a key limited to some buckets (or by a policy) must not be able to
                // point it at arbitrary destination buckets.
                let unrestricted = match &r.principal {
                    Principal::Everyone => true,
                    Principal::User(c) => c.buckets.is_none() && c.policy.is_none() && !c.read_only,
                    Principal::Anonymous => false,
                };
                if !unrestricted {
                    return Err(err::AccessDenied()
                        .with_message("Replication can only be configured with an access key that is not limited to some buckets or by a policy"));
                }
                let body = self.read_body(r, MAX_XML_BODY).await?;
                let text = std::str::from_utf8(&body).map_err(|_| err::MalformedXML())?;
                let doc = xml::parse(text).ok_or_else(err::MalformedXML)?;
                let rules = crate::replication::parse_config(&doc, &self.replication.target_ids())?;
                self.set_bucket_config(bucket, "replication", Some(body.to_vec())).await?;
                // Existing objects: queue them in the background, resuming after a restart.
                let backfill = rules.iter().any(|r| r.enabled && r.existing);
                self.set_bucket_config(bucket, "replication-backfill", backfill.then(Vec::new)).await?;
                if backfill {
                    tokio::spawn(crate::replication::Replicator::backfill(self.store.clone(), bucket.to_string()));
                }
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("logging") => {
                self.store.require_bucket(bucket)?;
                let doc = self.read_xml(r).await?;
                let target = crate::bucketlog::parse_config(&doc)?;
                if let Some(t) = &target {
                    // The logs are written with the server's authority, so whoever turns logging
                    // on must be allowed to write to the target.
                    self.store
                        .require_bucket(&t.bucket)
                        .map_err(|_| err::InvalidArgument().with_message("The target bucket for logging does not exist"))?;
                    let ctx = self.req_ctx(r);
                    self.authorize(&r.principal, "s3:PutObject", Some(&t.bucket), Some(&t.prefix), &ctx)?;
                }
                let value = target.as_ref().map(|t| crate::bucketlog::config_xml(Some(t)).into_bytes());
                self.set_bucket_config(bucket, "logging", value).await?;
                self.bucket_log.invalidate(bucket, target.is_some());
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("publicAccessBlock") => {
                self.store.require_bucket(bucket)?;
                let pab = access::PublicAccessBlock::parse(&self.read_xml(r).await?)?;
                self.set_bucket_config(bucket, "public-access-block", Some(pab.to_xml().into_bytes())).await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig("ownershipControls") => {
                self.store.require_bucket(bucket)?;
                let o = access::Ownership::parse_xml(&self.read_xml(r).await?)?;
                if o == access::Ownership::BucketOwnerEnforced && self.bucket_access(bucket)?.acl != CannedAcl::Private {
                    return Err(err::InvalidBucketAclWithObjectOwnership());
                }
                self.set_bucket_config(bucket, "ownership", Some(o.as_str().as_bytes().to_vec())).await?;
                Ok(Resp::ok())
            }
            BucketOp::PutConfig(_) => Err(err::NotImplemented()),
            BucketOp::Create => {
                if !valid_bucket_name(bucket) {
                    return Err(err::InvalidBucketName());
                }
                // Body is an optional CreateBucketConfiguration; we only have one region.
                let acl = r.header("x-amz-acl").map(CannedAcl::parse).transpose()?;
                let ownership = r.header("x-amz-object-ownership").map(access::Ownership::parse).transpose()?;
                if ownership == Some(access::Ownership::BucketOwnerEnforced) && acl.is_some_and(|a| a != CannedAcl::Private) {
                    return Err(err::InvalidBucketAclWithObjectOwnership());
                }
                let with_lock = r.header("x-amz-bucket-object-lock-enabled").is_some_and(|v| v.eq_ignore_ascii_case("true"));
                let _ = r.body.read_all(MAX_XML_BODY).await?;
                match self.store.submit(Op::CreateBucket(bucket.to_string())).await {
                    // As S3 does in us-east-1: creating a bucket you already own succeeds (and
                    // changes nothing).
                    Err(e) if e.code == "BucketAlreadyOwnedByYou" && self.region == "us-east-1" => {
                        let mut resp = Resp::ok();
                        resp.set("location", &format!("/{bucket}"));
                        return Ok(resp);
                    }
                    r => r?,
                };
                self.invalidate_access(bucket);
                if with_lock {
                    self.set_bucket_config(bucket, "versioning", Some(b"Enabled".to_vec())).await?;
                    let cfg = lock::BucketLock::default().to_xml().into_bytes();
                    self.set_bucket_config(bucket, "object-lock", Some(cfg)).await?;
                }
                if let Some(acl) = acl.filter(|a| *a != CannedAcl::Private) {
                    self.set_bucket_config(bucket, "acl", Some(acl.as_str().as_bytes().to_vec())).await?;
                }
                if let Some(o) = ownership {
                    self.set_bucket_config(bucket, "ownership", Some(o.as_str().as_bytes().to_vec())).await?;
                }
                let mut resp = Resp::ok();
                resp.set("location", &format!("/{bucket}"));
                Ok(resp)
            }
            BucketOp::DeleteConfig(sub @ ("publicAccessBlock" | "ownershipControls")) => {
                self.store.require_bucket(bucket)?;
                let kind = if sub == "publicAccessBlock" { "public-access-block" } else { "ownership" };
                self.set_bucket_config(bucket, kind, None).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            BucketOp::DeleteConfig("replication") => {
                self.store.require_bucket(bucket)?;
                self.set_bucket_config(bucket, "replication-backfill", None).await?;
                self.set_bucket_config(bucket, "replication", None).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            BucketOp::DeleteConfig(kind @ ("policy" | "cors" | "tagging" | "lifecycle" | "encryption" | "website" | "quota")) => {
                let kind: &'static str = store::CONFIG_KINDS.iter().find(|k| **k == kind).unwrap();
                self.set_bucket_config(bucket, kind, None).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            BucketOp::DeleteConfig(_) => {
                self.store.require_bucket(bucket)?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            BucketOp::Delete => {
                let r = self.store.submit(Op::DeleteBucket(bucket.to_string())).await;
                self.invalidate_access(bucket);
                self.events.invalidate(bucket);
                r?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            BucketOp::DeleteObjects => self.delete_objects(r, bucket).await,
            BucketOp::Listen => self.listen(r, Some(bucket)),
        }
    }

    async fn object_op(&self, r: &mut Req, op: ObjectOp, bucket: &str, key: &str) -> S3Result<Resp> {
        if op == ObjectOp::Unsupported {
            return Err(err::NotImplemented());
        }
        let version = r.q("versionId").filter(|v| !v.is_empty()).map(str::to_string);
        if let Some(v) = &version
            && !store::valid_version_id(v)
        {
            return Err(err::InvalidArgument().with_message("Invalid version id specified"));
        }
        let vref = version.as_deref();
        match op {
            ObjectOp::ListParts => self.list_parts(r, bucket, key),
            // Objects have no ACLs of their own: what applies to them is their bucket's ACL.
            ObjectOp::GetAcl => {
                self.lookup(bucket, key, vref)?;
                Ok(Resp::xml(acl_doc(self.bucket_access(bucket)?.acl)))
            }
            ObjectOp::GetTagging => {
                let (meta, _) = self.lookup(bucket, key, vref)?;
                let mut resp = Resp::xml(access::tagging_xml(&meta.tags));
                set_version_header(&mut resp, &meta);
                Ok(resp)
            }
            ObjectOp::GetRetention | ObjectOp::GetLegalHold => {
                self.require_lock(bucket)?;
                let (meta, _) = self.lookup(bucket, key, vref)?;
                if meta.delete_marker {
                    return Err(err::MethodNotAllowed());
                }
                let state = lock::State::of(&meta.headers);
                let doc = if op == ObjectOp::GetRetention {
                    let ret = state.retention.ok_or_else(err::NoSuchObjectLockConfiguration)?;
                    let mut x = Xml::new("Retention");
                    x.elem("Mode", ret.mode.as_str()).elem("RetainUntilDate", iso8601(ret.until * 1000));
                    x.finish("Retention")
                } else {
                    let on = state.legal_hold.ok_or_else(err::NoSuchObjectLockConfiguration)?;
                    let mut x = Xml::new("LegalHold");
                    x.elem("Status", if on { "ON" } else { "OFF" });
                    x.finish("LegalHold")
                };
                Ok(Resp::xml(doc))
            }
            ObjectOp::GetAttributes => self.object_attributes(r, bucket, key, vref),
            ObjectOp::Get | ObjectOp::Head => {
                let mut resp = self.get_object(r, bucket, key, op == ObjectOp::Head).await?;
                if self.console {
                    // Stored HTML/SVG must not run as the console's origin (where a signed-in
                    // console keeps its credentials): render it in an opaque, sandboxed origin.
                    resp.set("content-security-policy", crate::console::OBJECT_CSP).set("x-content-type-options", "nosniff");
                }
                Ok(resp)
            }
            ObjectOp::UploadPart | ObjectOp::UploadPartCopy => self.upload_part(r, bucket, key).await,
            ObjectOp::PutAcl => {
                self.lookup(bucket, key, vref)?;
                let acl = match r.header("x-amz-acl") {
                    Some(a) => CannedAcl::parse(a)?,
                    None => acl_from_xml(&self.read_xml(r).await?)?,
                };
                self.check_acl(bucket, r.header("x-amz-acl").unwrap_or(xml_acl_name(acl)))?;
                // Accepting a different ACL and ignoring it would let a caller believe an object
                // in a public bucket was now private.
                let current = self.bucket_access(bucket)?.acl;
                if acl != current {
                    return Err(err::NotImplemented().with_message(format!(
                        "Object ACLs are not supported: objects have their bucket's ACL ({}). Use the bucket ACL or a bucket policy.",
                        current.as_str()
                    )));
                }
                Ok(Resp::ok())
            }
            ObjectOp::PutTagging => {
                let doc = self.read_xml(r).await?;
                let tags = access::parse_tagging_xml(&doc, 10)?;
                self.store
                    .submit(Op::SetObjectTags {
                        bucket: bucket.into(),
                        key: key.into(),
                        version: version.clone(),
                        tags,
                        replica: r.replica,
                    })
                    .await?;
                let mut resp = Resp::ok();
                if let Some(v) = &version {
                    resp.set("x-amz-version-id", v);
                }
                Ok(resp)
            }
            ObjectOp::PutRetention | ObjectOp::PutLegalHold => {
                let doc = self.read_xml(r).await?;
                let (retention, legal_hold) = if op == ObjectOp::PutRetention {
                    if doc.name != "Retention" {
                        return Err(err::MalformedXML());
                    }
                    // An empty Retention element removes the retention (GOVERNANCE + bypass only).
                    let ret = match (doc.child_text("Mode"), doc.child_text("RetainUntilDate")) {
                        // In a document, an unknown mode is malformed XML (in headers it is an
                        // invalid argument).
                        (Some(m), Some(u)) => {
                            lock::Mode::parse(m).map_err(|_| err::MalformedXML())?;
                            Some(lock::parse_retention(m, u, now_ms() / 1000)?)
                        }
                        (None, None) => None,
                        _ => return Err(err::MalformedXML()),
                    };
                    (Some(ret), None)
                } else {
                    if doc.name != "LegalHold" {
                        return Err(err::MalformedXML());
                    }
                    let status = doc.child_text("Status").ok_or_else(err::MalformedXML)?;
                    (None, Some(lock::parse_legal_hold(status).map_err(|_| err::MalformedXML())?))
                };
                let op = Op::SetObjectLock {
                    bucket: bucket.into(),
                    key: key.into(),
                    version: version.clone(),
                    retention,
                    legal_hold,
                    bypass: self.bypass_governance(r, bucket, key),
                };
                let out = self.store.submit(op).await?;
                let mut resp = Resp::ok();
                if let OpOut::Object(m) = &out {
                    set_version_header(&mut resp, m);
                }
                Ok(resp)
            }
            ObjectOp::Copy => self.copy_object(r, bucket, key).await,
            ObjectOp::Put => self.put_object(r, bucket, key).await,
            ObjectOp::CreateUpload => self.create_upload(r, bucket, key).await,
            ObjectOp::CompleteUpload => self.complete_upload(r, bucket, key).await,
            ObjectOp::AbortUpload => {
                let upload = parse_upload_id(r)?;
                self.store.submit(Op::Abort { bucket: bucket.into(), key: key.into(), upload }).await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            ObjectOp::DeleteTagging => {
                self.store
                    .submit(Op::SetObjectTags {
                        bucket: bucket.into(),
                        key: key.into(),
                        version: version.clone(),
                        tags: vec![],
                        replica: r.replica,
                    })
                    .await?;
                Ok(Resp::new(StatusCode::NO_CONTENT))
            }
            ObjectOp::Delete => {
                let items = vec![(key.to_string(), version.clone())];
                let op = Op::DeleteObjects {
                    bucket: bucket.into(),
                    items: items.clone(),
                    conds: vec![delete_cond(
                        r.header("if-match"),
                        r.header("x-amz-if-match-size"),
                        r.header("x-amz-if-match-last-modified-time"),
                    )?],
                    bypass: self.bypass_governance(r, bucket, key),
                    replica: r.replica,
                };
                let (op, notify) = self.removed_events(r, bucket, &items, op);
                let OpOut::Deleted(mut res) = self.store.submit(op).await? else {
                    return Err(S3Error::internal("unexpected writer reply"));
                };
                if let Some(n) = notify {
                    n.done();
                }
                let outcome = res.pop().ok_or_else(|| S3Error::internal("missing delete result"))??;
                let mut resp = Resp::new(StatusCode::NO_CONTENT);
                if let Some(v) = &outcome.version_id {
                    resp.set("x-amz-version-id", v);
                }
                if outcome.delete_marker {
                    resp.set("x-amz-delete-marker", "true");
                }
                Ok(resp)
            }
            ObjectOp::Unsupported => Err(err::NotImplemented()),
        }
    }

    // -------------------------------------------------------------- listing

    /// ListBuckets, optionally paginated (`max-buckets`, `continuation-token`) and filtered by
    /// `prefix`.
    fn list_buckets(&self, r: &Req) -> S3Result<Resp> {
        let max = match r.q("max-buckets") {
            None => usize::MAX,
            Some(v) => v
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=10_000).contains(n))
                .ok_or_else(|| err::InvalidArgument().with_message("max-buckets must be an integer between 1 and 10000"))?,
        };
        let prefix = r.q("prefix").unwrap_or("");
        let after = match r.q("continuation-token").filter(|t| !t.is_empty()) {
            Some(t) => Some(
                unbase64(t)
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or_else(|| err::InvalidArgument().with_message("The continuation token provided is incorrect"))?,
            ),
            None => None,
        };
        let mut buckets = self
            .store
            .list_buckets()?
            .into_iter()
            .filter(|(n, _)| r.principal.can_access(n) && n.starts_with(prefix))
            .filter(|(n, _)| after.as_ref().is_none_or(|a| n > a))
            .peekable();
        let mut x = Xml::new("ListAllMyBucketsResult");
        x.owner("Owner").open("Buckets");
        let mut last = None;
        for (name, created) in buckets.by_ref().take(max) {
            x.open("Bucket")
                .elem("Name", &name)
                .elem("CreationDate", iso8601(created))
                .elem("BucketRegion", &self.region)
                .close("Bucket");
            last = Some(name);
        }
        x.close("Buckets");
        if buckets.peek().is_some()
            && let Some(last) = last
        {
            x.elem("ContinuationToken", base64(last.as_bytes()));
        }
        if r.q("prefix").is_some() {
            x.elem("Prefix", prefix);
        }
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
        let mut res = self.store.list_objects(bucket, prefix, delimiter, marker.filter(|m| !m.is_empty()), max)?;
        // Asking for no keys is answered as a complete (empty) listing, as on S3.
        if max == 0 {
            (res.truncated, res.next_marker) = (false, None);
        }
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
        let key_marker = r.q("key-marker").filter(|m| !m.is_empty());
        let vid_marker = r.q("version-id-marker").filter(|m| !m.is_empty());
        if vid_marker.is_some() && key_marker.is_none() {
            return Err(err::InvalidArgument().with_message("A version-id marker cannot be specified without a key marker."));
        }
        let mut res = self.store.list_object_versions(bucket, prefix, delimiter, key_marker, vid_marker, max)?;
        if max == 0 {
            res.truncated = false;
        }
        let mut x = Xml::new("ListVersionsResult");
        x.elem("Name", bucket)
            .elem("Prefix", enc.e(prefix))
            .elem("KeyMarker", enc.e(key_marker.unwrap_or("")))
            .elem("VersionIdMarker", vid_marker.unwrap_or(""))
            .elem("MaxKeys", max.to_string());
        if !delimiter.is_empty() {
            x.elem("Delimiter", enc.e(delimiter));
        }
        if enc.0 {
            x.elem("EncodingType", "url");
        }
        x.elem("IsTruncated", res.truncated.to_string());
        if res.truncated
            && let Some((k, v)) = &res.next
        {
            x.elem("NextKeyMarker", enc.e(k));
            if let Some(v) = v {
                x.elem("NextVersionIdMarker", v);
            }
        }
        for e in &res.entries {
            let m = &e.meta;
            let vid = m.version.as_deref().unwrap_or("null");
            if m.delete_marker {
                x.open("DeleteMarker")
                    .elem("Key", enc.e(&e.key))
                    .elem("VersionId", vid)
                    .elem("IsLatest", e.is_latest.to_string())
                    .elem("LastModified", iso8601(m.mtime_ms))
                    .owner("Owner")
                    .close("DeleteMarker");
            } else {
                x.open("Version")
                    .elem("Key", enc.e(&e.key))
                    .elem("VersionId", vid)
                    .elem("IsLatest", e.is_latest.to_string())
                    .elem("LastModified", iso8601(m.mtime_ms))
                    .elem("ETag", &m.etag)
                    .elem("Size", m.size.to_string())
                    .elem("StorageClass", "STANDARD")
                    .owner("Owner")
                    .close("Version");
            }
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
                .elem("Size", p.size.to_string());
            if let Some((a, v)) = &p.checksum {
                x.elem(a.xml_name(), v);
            }
            x.close("Part");
        }
        Ok(Resp::xml(x.finish("ListPartsResult")))
    }

    // -------------------------------------------------------------- objects

    fn master(&self) -> S3Result<WrapKey> {
        self.master_key.clone().ok_or_else(|| {
            err::InvalidArgument().with_message("Server-side encryption is not configured on this server (see --encryption-key).")
        })
    }

    /// Honour `x-amz-bypass-governance-retention` only for callers allowed
    /// `s3:BypassGovernanceRetention` (never anonymous ones).
    fn bypass_governance(&self, r: &Req, bucket: &str, key: &str) -> bool {
        wants_bypass(r)
            && !matches!(r.principal, Principal::Anonymous)
            && self.authorize(&r.principal, "s3:BypassGovernanceRetention", Some(bucket), Some(key), &self.req_ctx(r)).is_ok()
    }

    /// GetObjectAttributes: the attributes named in `x-amz-object-attributes`.
    fn object_attributes(&self, r: &Req, bucket: &str, key: &str, version: Option<&str>) -> S3Result<Resp> {
        let wanted: Vec<String> = r
            .parts
            .headers
            .get_all("x-amz-object-attributes")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(|a| a.trim().to_string())
            .filter(|a| !a.is_empty())
            .collect();
        const KNOWN: &[&str] = &["ETag", "Checksum", "ObjectParts", "StorageClass", "ObjectSize"];
        if wanted.is_empty() || wanted.iter().any(|a| !KNOWN.contains(&a.as_str())) {
            return Err(err::InvalidArgument().with_message(
                "x-amz-object-attributes must list one or more of ETag, Checksum, ObjectParts, StorageClass, ObjectSize",
            ));
        }
        let (meta, _) = self.lookup(bucket, key, version)?;
        if meta.delete_marker {
            return Err(err::NoSuchKey().with_header("x-amz-delete-marker", "true"));
        }
        // SSE-C objects reveal nothing without their key.
        self.read_key(&meta.headers, &r.parts.headers, "x-amz-")?;
        let has = |a: &str| wanted.iter().any(|w| w == a);
        let mut x = Xml::new("GetObjectAttributesResponse");
        if has("ETag") {
            x.elem("ETag", meta.etag.trim_matches('"'));
        }
        if has("Checksum")
            && let Some((algo, value)) = &meta.checksum
        {
            x.open("Checksum")
                .elem(algo.xml_name(), value)
                .elem("ChecksumType", crate::checksum::Kind::of(value).name())
                .close("Checksum");
        }
        if has("ObjectParts")
            && let Storage::Segments(segs) = &meta.storage
            && meta.etag.contains('-')
        {
            // Parts are numbered 1..N in their order in the object (as for GET ?partNumber=).
            let num = |name: &str| -> S3Result<Option<usize>> {
                r.header(name)
                    .map(|v| {
                        v.trim()
                            .parse::<usize>()
                            .map_err(|_| err::InvalidArgument().with_message(format!("{name} must be a non-negative integer")))
                    })
                    .transpose()
            };
            let max = num("x-amz-max-parts")?.unwrap_or(1000).clamp(1, 1000);
            let marker = num("x-amz-part-number-marker")?.unwrap_or(0);
            let parts: Vec<(usize, u64)> =
                segs.iter().enumerate().map(|(i, (_, len))| (i + 1, *len)).skip(marker).take(max).collect();
            let truncated = marker + parts.len() < segs.len();
            x.open("ObjectParts").elem("PartsCount", segs.len().to_string()).elem("PartNumberMarker", marker.to_string());
            if truncated && let Some((last, _)) = parts.last() {
                x.elem("NextPartNumberMarker", last.to_string());
            }
            x.elem("MaxParts", max.to_string()).elem("IsTruncated", truncated.to_string());
            let sums = part_checksums(&meta);
            for (n, size) in &parts {
                x.open("Part").elem("PartNumber", n.to_string()).elem("Size", size.to_string());
                if let (Some((a, _)), Some(v)) = (&meta.checksum, sums.get(n - 1)) {
                    x.elem(a.xml_name(), v);
                }
                x.close("Part");
            }
            x.close("ObjectParts");
        }
        if has("StorageClass") {
            x.elem("StorageClass", "STANDARD");
        }
        if has("ObjectSize") {
            x.elem("ObjectSize", meta.size.to_string());
        }
        let mut resp = Resp::xml(x.finish("GetObjectAttributesResponse"));
        resp.set("last-modified", &http_date(meta.mtime_ms));
        set_version_header(&mut resp, &meta);
        Ok(resp)
    }

    // -------------------------------------------------------------- event notifications

    fn event(&self, principal: &Principal, ip: IpAddr, rid: &str, name: &'static str, bucket: &str, key: &str) -> events::Event {
        events::Event {
            name,
            bucket: bucket.to_string(),
            key: key.to_string(),
            size: 0,
            etag: String::new(),
            version: None,
            principal: match principal {
                Principal::User(c) => c.access_key.clone(),
                _ => String::new(),
            },
            source_ip: ip.to_string(),
            request_id: rid.to_string(),
            time_ms: now_ms(),
            sequencer: 0,
        }
    }

    /// `op`, wrapped so that the "created" event of the object it writes (`template` filled in
    /// from the result) is queued in the same transaction.
    fn created_events(&self, template: events::Event, bucket: &str, op: Op) -> (Op, Option<events::Notify>) {
        self.events.wrap(bucket, op, move |out| match out {
            OpOut::Object(m) => vec![events::Event {
                size: m.size,
                etag: m.etag.clone(),
                version: m.version.clone(),
                sequencer: m.seq,
                time_ms: now_ms(),
                ..template.clone()
            }],
            _ => Vec::new(),
        })
    }

    /// `op` (a DeleteObjects of `items`), wrapped so that the "removed" events of what it
    /// deletes are queued in the same transaction.
    fn removed_events(&self, r: &Req, bucket: &str, items: &[(String, Option<String>)], op: Op) -> (Op, Option<events::Notify>) {
        let template = self.event(&r.principal, r.client.ip, &r.rid, "ObjectRemoved:Delete", bucket, "");
        let items = items.to_vec();
        self.events.wrap(bucket, op, move |out| match out {
            OpOut::Deleted(results) => items
                .iter()
                .zip(results)
                .filter_map(|((key, requested), res)| removed_event(&template, key, requested.as_deref(), res.as_ref().ok()?))
                .collect(),
            _ => Vec::new(),
        })
    }

    /// MinIO-compatible ListenBucketNotification: a never-ending JSON-lines stream of events
    /// (`?events=s3:ObjectCreated:*&prefix=...&suffix=...`), with a space every 10 seconds to
    /// keep idle connections open.
    fn listen(&self, r: &Req, bucket: Option<&str>) -> S3Result<Resp> {
        let names: Vec<String> = r.query.iter().filter(|(k, _)| k == "events").map(|(_, v)| v.clone()).collect();
        if names.is_empty() || names.iter().any(|n| !events::valid_event(n)) {
            return Err(
                err::InvalidArgument().with_message("Specify one or more supported events, e.g. events=s3:ObjectCreated:*")
            );
        }
        if let Some(b) = bucket {
            self.store.require_bucket(b)?;
        }
        let filter = events::ListenFilter {
            bucket: bucket.map(str::to_string),
            events: names,
            prefix: r.q("prefix").unwrap_or("").to_string(),
            suffix: r.q("suffix").unwrap_or("").to_string(),
        };
        let server =
            self.me.get().and_then(std::sync::Weak::upgrade).ok_or_else(|| S3Error::internal("server not initialized"))?;
        let mut rx = self.events.subscribe();
        let mut closing = self.events.closing();
        let region = self.region.clone();
        // Every event is re-authorized for the subscriber (its bucket limits, policies and
        // bucket policies, which may change while the stream is open); decisions are cached
        // per bucket for a few seconds.
        let (principal, headers, query, client, auth_type) =
            (r.principal.clone(), r.parts.headers.clone(), r.query.clone(), r.client, r.auth_type);
        let mut allowed: HashMap<String, (bool, Instant)> = HashMap::new();
        let mut may_see = move |bucket: &str| -> bool {
            if let Some((ok, at)) = allowed.get(bucket)
                && at.elapsed() < std::time::Duration::from_secs(5)
            {
                return *ok;
            }
            let ctx = server.ctx(&principal, &headers, &query, client, auth_type);
            let ok = server.authorize(&principal, "s3:ListenBucketNotification", Some(bucket), None, &ctx).is_ok();
            if allowed.len() > 10_000 {
                allowed.clear();
            }
            allowed.insert(bucket.to_string(), (ok, Instant::now()));
            ok
        };
        let (tx, body) = tokio::sync::mpsc::channel::<Bytes>(64);
        tokio::spawn(async move {
            let mut ping = tokio::time::interval(std::time::Duration::from_secs(10));
            ping.tick().await;
            loop {
                let chunk = tokio::select! {
                    ev = rx.recv() => match ev {
                        Ok(ev) if filter.matches(&ev) && may_see(&ev.bucket) => {
                            let mut line = ev.to_json(&region, "");
                            line.push('\n');
                            Bytes::from(line)
                        }
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    },
                    _ = ping.tick() => Bytes::from_static(b" "),
                    _ = closing.wait_for(|v| *v) => break,
                };
                // The client went away: stop listening.
                if tx.send(chunk).await.is_err() {
                    break;
                }
            }
        });
        let mut resp = Resp::ok();
        resp.set("content-type", "application/json").set("cache-control", "no-cache");
        resp.body = Body::Live(body);
        Ok(resp)
    }

    fn require_lock(&self, bucket: &str) -> S3Result<lock::BucketLock> {
        self.bucket_access(bucket)?.lock.ok_or_else(lock::missing_config)
    }

    /// Object Lock headers for a new version: the request's own retention / legal hold, else
    /// the bucket's default retention.
    fn new_lock_headers(&self, h: &HeaderMap, bucket: &str) -> S3Result<Vec<(String, String)>> {
        let (mode, until, hold) = (header(h, lock::MODE), header(h, lock::UNTIL), header(h, lock::HOLD));
        let cfg = match self.bucket_access(bucket)?.lock {
            Some(c) => c,
            None if has_lock_headers(h) => return Err(lock::missing_config()),
            None => return Ok(Vec::new()),
        };
        let now = now_ms() / 1000;
        let retention = match (mode, until) {
            (Some(m), Some(u)) => Some(lock::parse_retention(m, u, now)?),
            (None, None) => cfg.default.map(|(mode, p)| lock::Retention { mode, until: now + p.secs() }),
            _ => {
                return Err(err::InvalidArgument()
                    .with_message("x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied"));
            }
        };
        let legal_hold = hold.map(lock::parse_legal_hold).transpose()?;
        let mut out = Vec::new();
        lock::State { retention, legal_hold }.store(&mut out);
        Ok(out)
    }

    /// Encryption for a new object (or multipart upload): the wrapping key and the headers to
    /// store with the object (which are also returned on reads, as S3 does).
    fn write_encryption(&self, h: &HeaderMap, bucket: &str, sse_field: Option<&str>) -> S3Result<Encryption> {
        let sse = sse_field.or_else(|| header(h, "x-amz-server-side-encryption"));
        if let Some(alg) = header(h, "x-amz-server-side-encryption-customer-algorithm") {
            if alg != "AES256" {
                return Err(err::InvalidArgument().with_message("The encryption algorithm specified is not supported."));
            }
            if sse.is_some() {
                return Err(err::InvalidArgument().with_message(
                    "Server Side Encryption with Customer provided key is incompatible with the encryption method specified",
                ));
            }
            let key = crypt::parse_customer_key(
                header(h, "x-amz-server-side-encryption-customer-key").unwrap_or(""),
                Some(header(h, "x-amz-server-side-encryption-customer-key-md5").unwrap_or("")),
            )?;
            let stored = vec![(SSE_C_ALG.to_string(), "AES256".to_string()), (SSE_C_MD5.to_string(), crypt::key_md5_b64(&key))];
            return Ok(Some((WrapKey::new(KeyKind::Customer, key), stored)));
        }
        let requested = match sse {
            Some("AES256") => true,
            Some(other) if other.starts_with("aws:kms") => {
                return Err(err::NotImplemented().with_message("SSE-KMS is not supported; use AES256 or SSE-C"));
            }
            Some(_) => return Err(err::InvalidArgument().with_message("The encryption method specified is not supported")),
            None => self.encrypt_by_default || self.bucket_access(bucket)?.default_sse,
        };
        if !requested {
            return Ok(None);
        }
        Ok(Some((self.master()?, vec![(SSE.to_string(), "AES256".to_string())])))
    }

    /// The key needed to read data stored with `stored` headers. SSE-C requires the request to
    /// carry the same customer key (`prefix` is "x-amz-", or "x-amz-copy-source-" for copy sources).
    fn read_key(&self, stored: &[(String, String)], h: &HeaderMap, prefix: &str) -> S3Result<Option<WrapKey>> {
        let get = |name: &str| stored.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
        if let Some(md5) = get(SSE_C_MD5) {
            let hdr = |n: &str| header(h, &format!("{prefix}server-side-encryption-customer-{n}"));
            let (Some(_), Some(k)) = (hdr("algorithm"), hdr("key")) else {
                return Err(err::InvalidRequest().with_message(
                    "The object was stored using a form of Server Side Encryption. The correct parameters must be provided to retrieve the object.",
                ));
            };
            let key = crypt::parse_customer_key(k, hdr("key-md5"))?;
            if crypt::key_md5_b64(&key) != md5 {
                return Err(err::AccessDenied().with_message("The provided customer key does not match the object's key."));
            }
            return Ok(Some(WrapKey::new(KeyKind::Customer, key)));
        }
        if get(SSE).is_some() {
            return Ok(Some(
                self.master_key
                    .clone()
                    .ok_or_else(|| S3Error::internal("object is encrypted but no --encryption-key is configured"))?,
            ));
        }
        Ok(None)
    }

    /// Write the server access logs that are due to their target buckets (all of them on
    /// shutdown).
    pub async fn flush_bucket_logs(&self, all: bool) {
        for (target, source, data) in self.bucket_log.take_due(all) {
            let key = crate::bucketlog::object_key(&target, &source, &self.region, now_ms() / 1000);
            match self.put_internal(&target.bucket, &key, Bytes::from(data), "text/plain").await {
                Ok(()) => {
                    self.bucket_log.stats.written.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    self.bucket_log.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    elog!("bucket logging: writing {}/{key} for {source} failed: {}", target.bucket, e.message);
                }
            }
        }
    }

    /// Store an object written by the server itself (log files), with the bucket's default
    /// encryption and Object Lock retention, as an upload would get.
    async fn put_internal(&self, bucket: &str, key: &str, data: Bytes, content_type: &str) -> S3Result<()> {
        struct Once(Option<Bytes>);
        impl io::Source for Once {
            async fn next(&mut self) -> S3Result<Option<Bytes>> {
                Ok(self.0.take())
            }
        }
        let enc = self.write_encryption(&HeaderMap::new(), bucket, None)?;
        let mut headers = vec![("content-type".to_string(), content_type.to_string())];
        headers.extend(enc.as_ref().map(|(_, h)| h.clone()).unwrap_or_default());
        headers.extend(self.new_lock_headers(&HeaderMap::new(), bucket)?);
        headers.sort();
        let versioned = self.bucket_access(bucket)?.versioning == store::Versioning::Enabled;
        let expect = Expect {
            len: Some(data.len() as u64),
            max_len: MAX_OBJECT_SIZE,
            allow_inline: !versioned,
            encrypt: enc.as_ref().map(|(k, _)| k.clone()),
            ..Default::default()
        };
        let ing = io::ingest(&self.store, Once(Some(data)), expect).await?;
        let (storage, inline, files) = ing.storage();
        let meta = ObjectMeta {
            size: ing.size,
            mtime_ms: now_ms(),
            etag: etag_of(ing.md5, enc.as_ref().map(|(k, _)| k)),
            headers,
            checksum: None,
            storage,
            tags: vec![],
            version: None,
            seq: 0,
            delete_marker: false,
        };
        self.store
            .submit_owning(Op::PutObject { bucket: bucket.into(), key: key.into(), meta, inline, cond: None }, files)
            .await?;
        Ok(())
    }

    /// Enforce the request rate limits: per access key for signed requests, per client address
    /// otherwise.
    fn throttle(&self, principal: &Principal, ip: IpAddr) -> S3Result<()> {
        let refused = match principal {
            Principal::User(c) => self.key_limit.as_ref().map(|l| l.check(&c.access_key)),
            _ => self.anon_limit.as_ref().map(|l| l.check(&ip.to_string())),
        };
        match refused {
            Some(Err(wait)) => {
                self.metrics.throttled.fetch_add(1, Ordering::Relaxed);
                Err(S3Error::new("SlowDown", StatusCode::SERVICE_UNAVAILABLE, "Please reduce your request rate.")
                    .with_header("retry-after", wait.as_secs().max(1).to_string()))
            }
            _ => Ok(()),
        }
    }

    /// The current object, or a specific version when `version` is given.
    fn lookup(&self, bucket: &str, key: &str, version: Option<&str>) -> S3Result<(ObjectMeta, Option<Bytes>)> {
        match version {
            Some(v) => self.store.get_object_version(bucket, key, v),
            None => self.store.get_object(bucket, key),
        }
    }

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
        Ok(Expect { len, max_len, sha256, md5, checksum, allow_inline, encrypt: None })
    }

    async fn put_object(&self, r: &mut Req, bucket: &str, key: &str) -> S3Result<Resp> {
        // Versioned buckets keep every version, so small objects go to data files rather than
        // inline in the metadata database (which would otherwise only ever grow).
        let versioned = self.bucket_access(bucket)?.versioning == store::Versioning::Enabled;
        if let Some(acl) = r.header("x-amz-acl") {
            self.check_acl(bucket, acl)?;
        }
        let tags = request_tags(r)?;
        let lock_headers = self.new_lock_headers(&r.parts.headers, bucket)?;
        let enc = self.write_encryption(&r.parts.headers, bucket, None)?;
        let mut expect = self.expect(r, MAX_OBJECT_SIZE, !versioned)?;
        expect.encrypt = enc.as_ref().map(|(k, _)| k.clone());
        // Refuse uploads that cannot fit before receiving them. Conditional writes skip this, so
        // a failed precondition is reported as such (the writer still enforces the quota).
        let conditional = r.header("if-match").is_some() || r.header("if-none-match").is_some();
        if let Some(len) = expect.len
            && !conditional
            && let Err(e) = self.store.quota_allows(bucket, store::Incoming::Object(key), len)
        {
            io::discard_small(&mut r.body, Some(len)).await;
            return Err(e);
        }
        let body = std::mem::replace(&mut r.body, BodyStream::empty());
        let ing = io::ingest(&self.store, body, expect).await?;
        let etag = etag_of(ing.md5, enc.as_ref().map(|(k, _)| k));
        let mut headers = stored_headers(&r.parts.headers)?;
        headers.extend(enc.map(|(_, h)| h).unwrap_or_default());
        headers.extend(lock_headers);
        self.metrics.add_bytes_in(ing.size);
        let (storage, inline, files) = ing.storage();
        let meta = ObjectMeta {
            size: ing.size,
            mtime_ms: now_ms(),
            etag: etag.clone(),
            headers: headers.clone(),
            checksum: ing.checksum.clone(),
            storage,
            tags,
            version: None,
            seq: 0,
            delete_marker: false,
        };
        let cond = write_cond(&r.parts.headers);
        let template = self.event(&r.principal, r.client.ip, &r.rid, "ObjectCreated:Put", bucket, key);
        let op = Op::PutObject { bucket: bucket.into(), key: key.into(), meta, inline, cond };
        let (op, notify) = self.created_events(template, bucket, op);
        let out = self.store.submit_owning(op, files).await?;
        if let Some(n) = notify {
            n.done();
        }
        let mut resp = Resp::ok();
        resp.set("etag", &etag);
        set_sse_headers(&mut resp, &headers);
        if let OpOut::Object(m) = &out {
            set_version_header(&mut resp, m);
            self.set_expiration(&mut resp, bucket, key, m);
        }
        if let Some((a, v)) = &ing.checksum {
            resp.set(a.header(), v);
        }
        Ok(resp)
    }

    /// May this canned ACL be set in the bucket (on it, or on an object)? Public ACLs are refused
    /// by BlockPublicAcls, and any ACL but the owner's by BucketOwnerEnforced.
    fn check_acl(&self, bucket: &str, acl: &str) -> S3Result<()> {
        let a = self.bucket_access(bucket)?;
        let acl = acl.trim();
        if a.ownership == Some(access::Ownership::BucketOwnerEnforced) && acl != "bucket-owner-full-control" {
            return Err(err::AccessControlListNotSupported());
        }
        if a.public_block.block_acls && matches!(acl, "public-read" | "public-read-write" | "authenticated-read") {
            return Err(
                err::AccessDenied().with_message("The bucket's public access block (BlockPublicAcls) refuses public ACLs")
            );
        }
        Ok(())
    }

    /// `x-amz-expiration` for an object a lifecycle rule will expire.
    fn set_expiration(&self, resp: &mut Resp, bucket: &str, key: &str, meta: &ObjectMeta) {
        if let Ok(a) = self.bucket_access(bucket)
            && let Some(rules) = &a.lifecycle
            && let Some((at, id)) = crate::lifecycle::expiration(rules, key, meta)
        {
            resp.set("x-amz-expiration", &format!("expiry-date=\"{}\", rule-id=\"{id}\"", http_date(at * 1000)));
        }
    }

    async fn get_object(&self, r: &Req, bucket: &str, key: &str, head: bool) -> S3Result<Resp> {
        let h = &r.parts.headers;
        // SSE-S3 is chosen when writing; reads that ask for it are refused, as on S3.
        if header(h, SSE).is_some() {
            return Err(
                err::InvalidArgument().with_message("x-amz-server-side-encryption header is not supported for this operation.")
            );
        }
        let key_name = key;
        for attempt in 0..3 {
            let (meta, inline) = self.lookup(bucket, key, r.q("versionId").filter(|v| !v.is_empty()))?;
            // SSE-C: the key is required before anything about the object (even its ETag via
            // conditional headers) is revealed.
            let key = self.read_key(&meta.headers, h, "x-amz-")?;
            let mut resp = Resp::ok();
            resp.set("etag", &meta.etag).set("last-modified", &http_date(meta.mtime_ms)).set("accept-ranges", "bytes");
            set_version_header(&mut resp, &meta);
            if check_read_conditions(h, &meta)? {
                resp.status = StatusCode::NOT_MODIFIED;
                return Ok(resp);
            }
            let mut ctype = false;
            for (k, v) in meta.headers.iter().filter(|(k, _)| !k.starts_with(store::INTERNAL_PREFIX)) {
                ctype |= k == "content-type";
                resp.set(k, v);
            }
            if !ctype {
                resp.set("content-type", "binary/octet-stream");
            }
            if !meta.tags.is_empty() {
                resp.set("x-amz-tagging-count", &meta.tags.len().to_string());
            }
            // Expiration rules apply to current versions only.
            if r.q("versionId").is_none() {
                self.set_expiration(&mut resp, bucket, key_name, &meta);
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
                    return Err(err::InvalidPart().with_message("The requested partnumber is not satisfiable"));
                }
                let start: u64 = segs[..pn - 1].iter().sum();
                if segs[pn - 1] > 0 {
                    range = Some((start, start + segs[pn - 1] - 1));
                }
                resp.set("x-amz-mp-parts-count", &segs.len().to_string());
                // The part's own checksum (a single-part object's is the object's).
                if let Some((a, v)) = &meta.checksum {
                    let part =
                        if meta.etag.contains('-') { part_checksums(&meta).get(pn - 1).copied() } else { Some(v.as_str()) };
                    if let Some(p) = part {
                        resp.set("x-amz-checksum-type", crate::checksum::Kind::of(v).name());
                        resp.set(a.header(), p);
                    }
                }
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
                        resp.set("x-amz-checksum-type", crate::checksum::Kind::of(v).name());
                    }
                    (0, meta.size)
                }
            };
            resp.set("content-length", &len.to_string());
            if head {
                return Ok(resp);
            }
            match io::read_body(&self.store, &meta, inline, start, len, key).await {
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

    /// Parse `x-amz-copy-source`: (bucket, key, version id).
    fn copy_source(&self, r: &Req) -> S3Result<(String, String, Option<String>)> {
        let raw = r.header("x-amz-copy-source").ok_or_else(err::InvalidArgument)?;
        let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
        let version = parse_query(query).into_iter().find(|(k, _)| k == "versionId").map(|(_, v)| v);
        if let Some(v) = &version
            && !store::valid_version_id(v)
        {
            return Err(err::InvalidArgument().with_message("Invalid version id specified"));
        }
        let path = uri_decode(path, false).ok_or_else(|| err::InvalidArgument().with_message("Invalid copy source encoding"))?;
        let path = path.strip_prefix('/').unwrap_or(&path);
        match path.split_once('/') {
            Some((b, k)) if !b.is_empty() && !k.is_empty() => {
                check_key(k)?;
                let action = if version.is_some() { "s3:GetObjectVersion" } else { "s3:GetObject" };
                self.authorize(&r.principal, action, Some(b), Some(k), &self.req_ctx(r))
                    .map_err(|e| e.with_message("Access to the copy source was denied"))?;
                Ok((b.to_string(), k.to_string(), version))
            }
            _ => {
                Err(err::InvalidArgument()
                    .with_message("Copy Source must mention the source bucket and key: sourcebucket/sourcekey"))
            }
        }
    }

    async fn copy_object(&self, r: &mut Req, bucket: &str, key: &str) -> S3Result<Resp> {
        let (sb, sk, sv) = self.copy_source(r)?;
        if let Some(acl) = r.header("x-amz-acl") {
            self.check_acl(bucket, acl)?;
        }
        let dest_versioned = self.bucket_access(bucket)?.versioning == store::Versioning::Enabled;
        let replace = r.header("x-amz-metadata-directive").is_some_and(|d| d.eq_ignore_ascii_case("REPLACE"));
        let replace_tags = r.header("x-amz-tagging-directive").is_some_and(|d| d.eq_ignore_ascii_case("REPLACE"));
        let requested_enc = self.write_encryption(&r.parts.headers, bucket, None)?;
        let explicit_enc = r.header(SSE).is_some() || r.header(SSE_C_ALG).is_some();
        let lock_headers = self.new_lock_headers(&r.parts.headers, bucket)?;
        // A checksum algorithm for the copy: computed from the data unless the source already
        // has that (full-object) checksum.
        let want_checksum = match r.header("x-amz-checksum-algorithm") {
            Some(a) => Some(ChecksumAlgo::from_name(a.trim()).ok_or_else(|| {
                err::InvalidRequest().with_message("x-amz-checksum-algorithm must be CRC32, CRC32C, CRC64NVME, SHA1 or SHA256")
            })?),
            None => None,
        };
        let _ = r.body.read_all(MAX_XML_BODY).await?;
        for attempt in 0..3 {
            let (src, inline) = self.lookup(&sb, &sk, sv.as_deref())?;
            let src_key = self.read_key(&src.headers, &r.parts.headers, "x-amz-copy-source-")?;
            check_copy_conditions(&r.parts.headers, &src)?;
            // Copies of SSE-S3 objects stay encrypted unless the request chooses otherwise.
            let dst_enc = match &requested_enc {
                Some(e) => Some(e.clone()),
                None if src_key.as_ref().is_some_and(|k| k.kind == KeyKind::Master) => {
                    Some((self.master()?, vec![(SSE.to_string(), "AES256".to_string())]))
                }
                None => None,
            };
            let dst_key = dst_enc.as_ref().map(|(k, _)| k.clone());
            // Stored bytes can be shared only when they are readable with the destination's key.
            let same_key = match (&src_key, &dst_key) {
                (None, None) => true,
                (Some(a), Some(b)) => a.same(b),
                _ => false,
            };
            if sb == bucket && sk == key && !replace && sv.is_none() && !explicit_enc && want_checksum.is_none() {
                return Err(err::InvalidRequest().with_message(
                    "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
                ));
            }
            let recompute = want_checksum.filter(|a| {
                src.checksum
                    .as_ref()
                    .is_none_or(|(have, v)| have != a || crate::checksum::Kind::of(v) != crate::checksum::Kind::FullObject)
            });
            let mut checksum = src.checksum.clone();
            let (storage, files, new_md5) = match &src.storage {
                // Re-encrypting, computing a new checksum, or versioned buckets (which keep small
                // objects in files): write a new data file from the plaintext.
                Storage::Inline(_) | Storage::Segments(_)
                    if !same_key || recompute.is_some() || (dest_versioned && matches!(src.storage, Storage::Inline(_))) =>
                {
                    let (st, src2, data, size) = (self.store.clone(), src.clone(), inline.clone(), src.size);
                    let (sk2, dk2) = (src_key.clone(), dst_key.clone());
                    let res = tokio::task::spawn_blocking(move || {
                        io::copy_range_blocking(&st, &src2, data.as_ref(), 0, size, sk2.as_ref(), dk2.as_ref(), recompute)
                    })
                    .await
                    .map_err(S3Error::internal)?;
                    match res {
                        Ok((id, md5, sum)) => {
                            // The copy is one part now: a composite (per-part) checksum no
                            // longer describes it.
                            if sum.is_some() || checksum.as_ref().is_some_and(|(_, v)| v.contains('-')) {
                                checksum = sum;
                            }
                            (Storage::Segments(vec![(id, size)]), vec![id], Some(md5))
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound && attempt < 2 => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
                Storage::Inline(_) => (Storage::Inline(util::new_seq_id()), vec![], None),
                Storage::Segments(segs) => {
                    let (st, segs) = (self.store.clone(), segs.clone());
                    match tokio::task::spawn_blocking(move || io::link_segments_blocking(&st, &segs))
                        .await
                        .map_err(S3Error::internal)?
                    {
                        Ok(new) => {
                            let files = new.iter().map(|(id, _)| *id).collect();
                            (Storage::Segments(new), files, None)
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound && attempt < 2 => continue,
                        Err(e) => return Err(e.into()),
                    }
                }
            };
            // Encryption and Object Lock settings belong to the new version, not the source.
            let mut headers = if replace { stored_headers(&r.parts.headers)? } else { inheritable(&src.headers) };
            headers.extend(dst_enc.as_ref().map(|(_, h)| h.clone()).unwrap_or_default());
            headers.extend(lock_headers.iter().cloned());
            // Shared segments keep the source's parts, and with them the parts' checksums.
            if new_md5.is_none() {
                headers.extend(src.headers.iter().filter(|(k, _)| k == store::PART_CHECKSUMS).cloned());
            }
            let tags = if replace_tags { request_tags(r)? } else { src.tags.clone() };
            let meta = ObjectMeta {
                size: src.size,
                mtime_ms: now_ms(),
                // Re-encrypted copies get an ETag for their own key (it differs for SSE-C).
                etag: match new_md5 {
                    Some(md5) => etag_of(md5, dst_key.as_ref()),
                    None => src.etag.clone(),
                },
                headers,
                checksum: checksum.clone(),
                storage,
                tags,
                version: None,
                seq: 0,
                delete_marker: false,
            };
            let mtime = meta.mtime_ms;
            let cond = write_cond(&r.parts.headers);
            let template = self.event(&r.principal, r.client.ip, &r.rid, "ObjectCreated:Copy", bucket, key);
            let op = Op::PutObject { bucket: bucket.into(), key: key.into(), meta, inline, cond };
            let (op, notify) = self.created_events(template, bucket, op);
            let out = self.store.submit_owning(op, files).await?;
            if let Some(n) = notify {
                n.done();
            }
            let mut x = Xml::new("CopyObjectResult");
            let new_etag = match &out {
                OpOut::Object(m) => m.etag.clone(),
                _ => src.etag.clone(),
            };
            x.elem("LastModified", iso8601(mtime)).elem("ETag", &new_etag);
            if let Some((a, v)) = &checksum {
                x.elem(a.xml_name(), v);
                x.elem("ChecksumType", crate::checksum::Kind::of(v).name());
            }
            let mut resp = Resp::xml(x.finish("CopyObjectResult"));
            set_sse_headers(&mut resp, dst_enc.as_ref().map(|(_, h)| h.as_slice()).unwrap_or(&[]));
            if let Some(v) = src.version.as_deref().or(sv.as_deref()) {
                resp.set("x-amz-copy-source-version-id", v);
            }
            if let OpOut::Object(m) = &out {
                set_version_header(&mut resp, m);
            }
            return Ok(resp);
        }
        Err(err::NoSuchKey())
    }

    async fn create_upload(&self, r: &mut Req, bucket: &str, key: &str) -> S3Result<Resp> {
        let _ = r.body.read_all(MAX_XML_BODY).await?;
        let id = util::new_id();
        if let Some(acl) = r.header("x-amz-acl") {
            self.check_acl(bucket, acl)?;
        }
        let tags = request_tags(r)?;
        // The upload's encryption applies to every part and to the completed object.
        let enc = self.write_encryption(&r.parts.headers, bucket, None)?;
        let mut headers = stored_headers(&r.parts.headers)?;
        headers.extend(enc.map(|(_, h)| h).unwrap_or_default());
        headers.extend(self.new_lock_headers(&r.parts.headers, bucket)?);
        // A checksum algorithm (and type) for the parts and the whole object.
        let algo = match r.header("x-amz-checksum-algorithm") {
            Some(a) => Some(ChecksumAlgo::from_name(a.trim()).ok_or_else(|| {
                err::InvalidRequest().with_message("x-amz-checksum-algorithm must be CRC32, CRC32C, CRC64NVME, SHA1 or SHA256")
            })?),
            None => None,
        };
        let kind = match r.header("x-amz-checksum-type") {
            Some(t) => Some(
                crate::checksum::Kind::parse(t)
                    .ok_or_else(|| err::InvalidRequest().with_message("x-amz-checksum-type must be COMPOSITE or FULL_OBJECT"))?,
            ),
            None => None,
        };
        let checksum = match (algo, kind) {
            (Some(a), k) => Some((
                a,
                crate::checksum::Kind::for_algo(a, k).ok_or_else(|| {
                    err::InvalidRequest().with_message(format!(
                        "The {} checksum type is not supported with {}",
                        k.map_or("", |k| k.name()),
                        a.name()
                    ))
                })?,
            )),
            (None, Some(_)) => {
                return Err(err::InvalidRequest().with_message("x-amz-checksum-type requires x-amz-checksum-algorithm"));
            }
            (None, None) => None,
        };
        if let Some((a, k)) = checksum {
            headers.push((store::UPLOAD_CHECKSUM_ALGO.into(), a.name().into()));
            headers.push((store::UPLOAD_CHECKSUM_TYPE.into(), k.name().into()));
        }
        let meta = UploadMeta { bucket: bucket.into(), key: key.into(), initiated_ms: now_ms(), headers: headers.clone(), tags };
        self.store.submit(Op::CreateUpload { id, meta }).await?;
        let mut x = Xml::new("InitiateMultipartUploadResult");
        x.elem("Bucket", bucket).elem("Key", key).elem("UploadId", util::id_hex(id));
        let mut resp = Resp::xml(x.finish("InitiateMultipartUploadResult"));
        set_sse_headers(&mut resp, &headers);
        if let Some((a, k)) = checksum {
            resp.set("x-amz-checksum-algorithm", a.name()).set("x-amz-checksum-type", k.name());
        }
        Ok(resp)
    }

    async fn upload_part(&self, r: &mut Req, bucket: &str, key: &str) -> S3Result<Resp> {
        let upload = parse_upload_id(r)?;
        let part: u32 =
            r.q("partNumber").and_then(|p| p.parse().ok()).filter(|p| (1..=MAX_PARTS).contains(p)).ok_or_else(|| {
                err::InvalidArgument().with_message("Part number must be an integer between 1 and 10000, inclusive")
            })?;
        let u = self.store.get_upload(upload)?.filter(|u| u.bucket == bucket && u.key == key).ok_or_else(err::NoSuchUpload)?;
        // Parts are encrypted like the upload: master key, or the same customer key every time.
        let part_key = self.read_key(&u.headers, &r.parts.headers, "x-amz-").map_err(|e| match e.code {
            "AccessDenied" => err::InvalidRequest().with_message("The provided customer key does not match the upload's key."),
            _ => e,
        })?;

        if r.header("x-amz-copy-source").is_some() {
            return self.upload_part_copy(r, bucket, key, upload, part, part_key, &u.headers).await;
        }
        let mut expect = self.expect(r, MAX_PART_SIZE, false)?;
        if let Some(len) = expect.len
            && let Err(e) = self.store.quota_allows(bucket, store::Incoming::Part { upload, part }, len)
        {
            io::discard_small(&mut r.body, Some(len)).await;
            return Err(e);
        }
        // Parts of an upload with a checksum algorithm get that checksum (computed if the
        // request doesn't carry it).
        if let Some(algo) = upload_checksum_algo(&u.headers) {
            match &expect.checksum {
                None => expect.checksum = Some((algo, None)),
                Some((a, _)) if *a != algo => {
                    return Err(err::InvalidRequest().with_message(format!(
                        "The upload's checksum algorithm is {}; the part has a {} checksum",
                        algo.name(),
                        a.name()
                    )));
                }
                Some(_) => {}
            }
        }
        let expect_key = part_key.clone();
        expect.encrypt = part_key;
        let body = std::mem::replace(&mut r.body, BodyStream::empty());
        let ing = io::ingest(&self.store, body, expect).await?;
        self.metrics.add_bytes_in(ing.size);
        let Data::File(file) = ing.data else { return Err(S3Error::internal("part stored inline")) };
        // For SSE-C uploads the part ETag is keyed (it must not reveal the plaintext MD5).
        let part_digest = crypt::etag_digest(expect_key.as_ref(), ing.md5);
        let meta = PartMeta { size: ing.size, md5: part_digest, mtime_ms: now_ms(), file, checksum: ing.checksum.clone() };
        self.store.submit_owning(Op::PutPart { upload, bucket: bucket.into(), key: key.into(), part, meta }, vec![file]).await?;
        let mut resp = Resp::ok();
        resp.set("etag", &format!("\"{}\"", util::hex(&part_digest)));
        set_sse_headers(&mut resp, &u.headers);
        if let Some((a, v)) = &ing.checksum {
            resp.set(a.header(), v);
        }
        Ok(resp)
    }

    #[allow(clippy::too_many_arguments)]
    async fn upload_part_copy(
        &self,
        r: &mut Req,
        bucket: &str,
        key: &str,
        upload: u128,
        part: u32,
        part_key: Option<WrapKey>,
        upload_headers: &[(String, String)],
    ) -> S3Result<Resp> {
        let (sb, sk, sv) = self.copy_source(r)?;
        let _ = r.body.read_all(MAX_XML_BODY).await?;
        for attempt in 0..3 {
            let (src, inline) = self.lookup(&sb, &sk, sv.as_deref())?;
            let src_key = self.read_key(&src.headers, &r.parts.headers, "x-amz-copy-source-")?;
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
            let (st, src2, dk) = (self.store.clone(), src.clone(), part_key.clone());
            let algo = upload_checksum_algo(upload_headers);
            let res = tokio::task::spawn_blocking(move || {
                io::copy_range_blocking(&st, &src2, inline.as_ref(), start, len, src_key.as_ref(), dk.as_ref(), algo)
            })
            .await
            .map_err(S3Error::internal)?;
            let (file, md5, checksum) = match res {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && attempt < 2 => continue,
                Err(e) => return Err(e.into()),
            };
            let md5 = crypt::etag_digest(part_key.as_ref(), md5);
            let meta = PartMeta { size: len, md5, mtime_ms: now_ms(), file, checksum: checksum.clone() };
            let mtime = meta.mtime_ms;
            self.store
                .submit_owning(Op::PutPart { upload, bucket: bucket.into(), key: key.into(), part, meta }, vec![file])
                .await?;
            let mut x = Xml::new("CopyPartResult");
            x.elem("LastModified", iso8601(mtime)).elem("ETag", format!("\"{}\"", util::hex(&md5)));
            if let Some((a, v)) = &checksum {
                x.elem(a.xml_name(), v);
            }
            let mut resp = Resp::xml(x.finish("CopyPartResult"));
            set_sse_headers(&mut resp, upload_headers);
            return Ok(resp);
        }
        Err(err::NoSuchKey())
    }

    /// Browser-based upload: `POST /bucket` with a multipart form (and usually a signed policy).
    async fn post_object(
        &self,
        parts: &Parts,
        body: Incoming,
        bucket: &str,
        boundary: &str,
        peer: SocketAddr,
        rid: &str,
    ) -> S3Result<Resp> {
        let client = self.client(&parts.headers, peer);
        // Browser uploads authenticate only after the form is read: limit them per address.
        self.throttle(&Principal::Anonymous, client.ip)?;
        let mut payload = Payload::Unsigned;
        let stream = BodyStream::new(body, &mut payload);
        let (form, file) = crate::post::parse_form(stream, boundary).await?;
        let f = &form.fields;
        let key = form_key(
            f.get("key").ok_or_else(|| err::InvalidArgument().with_message("Bucket POST must contain a field named 'key'."))?,
            form.file_name.as_deref(),
        );
        if key.is_empty() {
            return Err(err::InvalidArgument().with_message("User key must have a length greater than 0."));
        }
        check_key(&key)?;

        // A signed policy identifies the uploader; an unsigned form is anonymous.
        let who = match (&self.auth, f.get("policy")) {
            (None, _) => Principal::Everyone,
            (Some(a), Some(policy)) => a.verify_post_policy(f, policy)?,
            (Some(_), None) => Principal::Anonymous,
        };
        let ctx = self.ctx(&who, &parts.headers, &[], client, "POST");
        self.authorize(&who, "s3:PutObject", Some(bucket), Some(&key), &ctx)?;
        if f.contains_key("tagging") {
            self.authorize(&who, "s3:PutObjectTagging", Some(bucket), Some(&key), &ctx)?;
        }
        let range = match f.get("policy") {
            // Conditions on the key apply to it with `${filename}` filled in.
            Some(policy) => {
                let mut fields = f.clone();
                fields.insert("key".into(), key.clone());
                crate::post::PostPolicy::parse(policy)?.check(&fields, bucket)?
            }
            None => None,
        };
        self.store.require_bucket(bucket)?;
        if let Some(acl) = f.get("acl") {
            self.check_acl(bucket, acl)?;
        }

        let tags = match f.get("tagging") {
            Some(doc) => access::parse_tagging_xml(&xml::parse(doc).ok_or_else(err::MalformedXML)?, 10)?,
            None => Vec::new(),
        };
        let mut headers = Vec::new();
        for (name, value) in f {
            if matches!(name.as_str(), "content-type" | "cache-control" | "content-disposition" | "content-encoding" | "expires")
                || name.starts_with("x-amz-meta-")
            {
                headers.push((name.clone(), value.clone()));
            }
        }
        if !f.contains_key("content-type")
            && let Some(ct) = &form.file_content_type
        {
            headers.push(("content-type".into(), ct.clone()));
        }
        if f.keys().any(|k| k.starts_with(SSE_C_ALG.trim_end_matches("algorithm"))) {
            return Err(err::NotImplemented().with_message("SSE-C is not supported for POST uploads"));
        }
        let enc = self.write_encryption(&HeaderMap::new(), bucket, f.get(SSE).map(String::as_str))?;
        headers.retain(|(k, _)| !k.starts_with(SSE));
        headers.extend(enc.as_ref().map(|(_, h)| h.clone()).unwrap_or_default());
        headers.extend(self.new_lock_headers(&HeaderMap::new(), bucket)?);
        headers.sort();

        let (min, max) = range.unwrap_or((0, MAX_OBJECT_SIZE));
        let versioned = self.bucket_access(bucket)?.versioning == store::Versioning::Enabled;
        let expect = Expect {
            max_len: max.min(MAX_OBJECT_SIZE),
            allow_inline: !versioned,
            encrypt: enc.map(|(k, _)| k),
            checksum: ChecksumAlgo::ALL.iter().find_map(|a| f.get(a.header()).map(|v| (*a, Some(v.trim().to_string())))),
            ..Default::default()
        };
        let ing = io::ingest(&self.store, file, expect).await?;
        let (storage, inline, files) = ing.storage();
        if ing.size < min {
            self.store.discard(files);
            return Err(err::EntityTooSmall());
        }
        self.metrics.add_bytes_in(ing.size);
        let etag = ing.etag();
        let meta = ObjectMeta {
            size: ing.size,
            mtime_ms: now_ms(),
            etag: etag.clone(),
            headers,
            checksum: ing.checksum.clone(),
            storage,
            tags,
            version: None,
            seq: 0,
            delete_marker: false,
        };
        let template = self.event(&who, client.ip, rid, "ObjectCreated:Post", bucket, &key);
        let op = Op::PutObject { bucket: bucket.into(), key: key.clone(), meta, inline, cond: None };
        let (op, notify) = self.created_events(template, bucket, op);
        let out = self.store.submit_owning(op, files).await?;
        if let Some(n) = notify {
            n.done();
        }
        let version = match &out {
            OpOut::Object(m) => m.version.clone(),
            _ => None,
        };

        let location = format!("{}/{bucket}/{}", self.base_url(parts, client), uri_encode(&key, true));
        let redirect = f.get("success_action_redirect").or_else(|| f.get("redirect")).filter(|u| !u.is_empty());
        if let Some(url) = redirect {
            let sep = if url.contains('?') { '&' } else { '?' };
            let target = format!(
                "{url}{sep}bucket={}&key={}&etag={}",
                uri_encode(bucket, false),
                uri_encode(&key, false),
                uri_encode(&etag, false)
            );
            let mut resp = Resp::new(StatusCode::SEE_OTHER);
            resp.set("location", &target).set("etag", &etag);
            return Ok(resp);
        }
        let mut resp = match f.get("success_action_status").map(String::as_str) {
            Some("201") => {
                let mut x = Xml::bare("PostResponse");
                x.elem("Location", &location).elem("Bucket", bucket).elem("Key", &key).elem("ETag", &etag);
                let mut r = Resp::xml(x.finish("PostResponse"));
                r.status = StatusCode::CREATED;
                r
            }
            Some("200") => Resp::ok(),
            _ => Resp::new(StatusCode::NO_CONTENT),
        };
        resp.set("etag", &etag).set("location", &location);
        if let Some((a, v)) = &ing.checksum {
            resp.set(a.header(), v);
        }
        if let Some(v) = &version {
            resp.set("x-amz-version-id", v);
        }
        Ok(resp)
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
            let checksum = ChecksumAlgo::ALL.iter().find_map(|a| p.child_text(a.xml_name())).map(str::to_string);
            parts.push((n, etag, checksum));
        }
        let checksum = ChecksumAlgo::ALL.iter().find_map(|a| r.header(a.header()).map(|v| (*a, v.trim().to_string())));
        // An SSE-C key sent along must be the upload's.
        if r.header(SSE_C_ALG).is_some()
            && let Some(u) = self.store.get_upload(upload)?
        {
            self.read_key(&u.headers, &r.parts.headers, "x-amz-").map_err(|e| match e.code {
                "AccessDenied" => {
                    err::InvalidRequest().with_message("The provided customer key does not match the upload's key.")
                }
                _ => e,
            })?;
            if !u.headers.iter().any(|(k, _)| k == SSE_C_MD5) {
                return Err(err::InvalidRequest().with_message("The upload is not encrypted with a customer-provided key."));
            }
        }
        let cond = write_cond(&r.parts.headers);
        let op = Op::Complete { bucket: bucket.into(), key: key.into(), upload, parts, checksum, cond };
        let template = self.event(&r.principal, r.client.ip, &r.rid, "ObjectCreated:CompleteMultipartUpload", bucket, key);
        let (op, notify) = self.created_events(template, bucket, op);
        let meta = match self.store.submit(op).await {
            Ok(OpOut::Object(meta)) => {
                self.completed.lock().unwrap().remember(upload, bucket, key, &meta);
                if let Some(n) = notify {
                    n.done();
                }
                meta
            }
            Ok(_) => return Err(S3Error::internal("unexpected writer reply")),
            // Completing an upload that was just completed (a client retrying after a lost
            // response) succeeds again, as on S3.
            Err(e) if e.code == "NoSuchUpload" => self.completed.lock().unwrap().get(upload, bucket, key).ok_or(e)?,
            Err(e) => return Err(e),
        };
        let mut x = Xml::new("CompleteMultipartUploadResult");
        x.elem("Location", format!("{}/{bucket}/{}", self.base_url(&r.parts, r.client), uri_encode(key, true)))
            .elem("Bucket", bucket)
            .elem("Key", key)
            .elem("ETag", &meta.etag);
        if let Some((a, v)) = &meta.checksum {
            x.elem(a.xml_name(), v).elem("ChecksumType", crate::checksum::Kind::of(v).name());
        }
        let mut resp = Resp::xml(x.finish("CompleteMultipartUploadResult"));
        set_sse_headers(&mut resp, &meta.headers);
        set_version_header(&mut resp, &meta);
        Ok(resp)
    }

    async fn delete_objects(&self, r: &mut Req, bucket: &str) -> S3Result<Resp> {
        let doc = self.read_xml(r).await?;
        if doc.name != "Delete" {
            return Err(err::MalformedXML());
        }
        let quiet = doc.child_text("Quiet").is_some_and(|q| q.trim().eq_ignore_ascii_case("true"));
        let mut objects: Vec<(String, Option<String>, Option<store::DeleteCond>)> = Vec::new();
        for o in doc.children_named("Object") {
            let Some(key) = o.child_text("Key") else { continue };
            let version = o.child_text("VersionId").map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
            let cond = delete_cond(o.child_text("ETag"), o.child_text("Size"), o.child_text("LastModifiedTime"))?;
            objects.push((key.to_string(), version, cond));
        }
        if objects.len() > 1000 {
            return Err(err::MalformedXML().with_message("The request must contain no more than 1000 keys"));
        }
        let (valid, invalid): (Vec<_>, Vec<_>) = objects.into_iter().partition(|(k, _, _)| !k.is_empty() && check_key(k).is_ok());
        // Each key is authorized on its own, as on S3; refused keys are reported as errors.
        let ctx = self.req_ctx(r);
        let (valid, denied): (Vec<_>, Vec<_>) = valid.into_iter().partition(|(k, v, _)| {
            let action = if v.is_some() { "s3:DeleteObjectVersion" } else { "s3:DeleteObject" };
            self.authorize(&r.principal, action, Some(bucket), Some(k), &ctx).is_ok()
        });
        let conds = valid.iter().map(|(_, _, c)| c.clone()).collect();
        let valid: Vec<(String, Option<String>)> = valid.into_iter().map(|(k, v, _)| (k, v)).collect();
        let bypass = wants_bypass(r)
            && !matches!(r.principal, Principal::Anonymous)
            && valid
                .iter()
                .all(|(k, _)| self.authorize(&r.principal, "s3:BypassGovernanceRetention", Some(bucket), Some(k), &ctx).is_ok());
        let op = Op::DeleteObjects { bucket: bucket.into(), items: valid.clone(), conds, bypass, replica: false };
        let (op, notify) = self.removed_events(r, bucket, &valid, op);
        let OpOut::Deleted(results) = self.store.submit(op).await? else {
            return Err(S3Error::internal("unexpected writer reply"));
        };
        if let Some(n) = notify {
            n.done();
        }
        let mut x = Xml::new("DeleteResult");
        for ((k, requested), res) in valid.iter().zip(results) {
            match res {
                Ok(_) if quiet => {}
                Ok(o) => {
                    x.open("Deleted").elem("Key", k);
                    if let Some(v) = requested {
                        x.elem("VersionId", v);
                    }
                    if o.delete_marker {
                        x.elem("DeleteMarker", "true");
                        if let Some(v) = &o.version_id {
                            x.elem("DeleteMarkerVersionId", v);
                        }
                    }
                    x.close("Deleted");
                }
                Err(e) => {
                    x.open("Error").elem("Key", k).opt("VersionId", requested.as_deref());
                    x.elem("Code", e.code).elem("Message", &e.message).close("Error");
                }
            }
        }
        for (k, v, _) in denied {
            x.open("Error").elem("Key", &k).opt("VersionId", v.as_deref());
            x.elem("Code", "AccessDenied").elem("Message", "Access Denied").close("Error");
        }
        for (k, _, _) in invalid {
            x.open("Error").elem("Key", &k).elem("Code", "InvalidArgument").elem("Message", "Invalid key").close("Error");
        }
        Ok(Resp::xml(x.finish("DeleteResult")))
    }
}

/// The canned ACL an ACL document amounts to (one granting only the owner full control is the
/// owner's, which BucketOwnerEnforced allows).
fn xml_acl_name(acl: CannedAcl) -> &'static str {
    if acl == CannedAcl::Private { "bucket-owner-full-control" } else { acl.as_str() }
}

/// The event for one deleted key (`requested`: the version the client asked to delete), or
/// none if nothing was there to delete.
fn removed_event(
    template: &events::Event,
    key: &str,
    requested: Option<&str>,
    o: &store::DeleteOutcome,
) -> Option<events::Event> {
    if !o.removed {
        return None;
    }
    let marker_created = requested.is_none() && o.delete_marker;
    Some(events::Event {
        name: if marker_created { "ObjectRemoved:DeleteMarkerCreated" } else { "ObjectRemoved:Delete" },
        key: key.to_string(),
        version: if marker_created { o.version_id.clone().filter(|v| v != "null") } else { requested.map(str::to_string) },
        sequencer: o.seq,
        time_ms: now_ms(),
        ..template.clone()
    })
}

/// Conditions on a delete, from headers or a DeleteObjects entry.
fn delete_cond(etag: Option<&str>, size: Option<&str>, mtime: Option<&str>) -> S3Result<Option<store::DeleteCond>> {
    let size = match size {
        Some(v) => Some(v.trim().parse().map_err(|_| err::InvalidArgument().with_message("Invalid size condition"))?),
        None => None,
    };
    let mtime = match mtime {
        Some(v) => Some(
            util::parse_http_date(v)
                .or_else(|| util::parse_iso8601(v.trim()))
                .ok_or_else(|| err::InvalidArgument().with_message("Invalid last-modified-time condition"))?,
        ),
        None => None,
    };
    let etag = etag.map(str::to_string);
    Ok((etag.is_some() || size.is_some() || mtime.is_some()).then_some(store::DeleteCond { etag, size, mtime }))
}

/// HTML error page for the website endpoint.
fn website_error(e: &S3Error, head: bool, rid: &str) -> Resp {
    let mut r = Resp::new(e.status);
    if !head {
        r.set("content-type", "text/html; charset=utf-8");
        let reason = e.status.canonical_reason().unwrap_or("Error");
        r.body = Body::full(crate::website::error_page(e.status.as_u16(), reason, e.code, &e.message, rid));
    }
    r
}

/// Tags from the `x-amz-tagging` request header.
fn request_tags(r: &Req) -> S3Result<Vec<(String, String)>> {
    r.header("x-amz-tagging").map(access::parse_tagging_header).transpose().map(Option::unwrap_or_default)
}

/// Expand `${filename}` in a form-upload key.
fn form_key(key: &str, filename: Option<&str>) -> String {
    let base = filename.map(|f| f.rsplit(['/', '\\']).next().unwrap_or(f)).unwrap_or("");
    key.replace("${filename}", base)
}

/// Encryption chosen for a write: the wrapping key and the headers stored with the object.
type Encryption = Option<(WrapKey, Vec<(String, String)>)>;

const SSE: &str = "x-amz-server-side-encryption";
const SSE_C_ALG: &str = "x-amz-server-side-encryption-customer-algorithm";
const SSE_C_MD5: &str = "x-amz-server-side-encryption-customer-key-md5";

/// Quoted ETag for an object with this plaintext MD5 (keyed for SSE-C; see crypt::etag_digest).
fn etag_of(md5: [u8; 16], key: Option<&WrapKey>) -> String {
    format!("\"{}\"", util::hex(&crypt::etag_digest(key, md5)))
}

/// The checksums of a multipart object's parts, in order (empty when they are not known).
fn part_checksums(meta: &ObjectMeta) -> Vec<&str> {
    meta.headers
        .iter()
        .find(|(k, _)| k == store::PART_CHECKSUMS)
        .map(|(_, list)| list.split(',').filter(|v| !v.is_empty()).collect())
        .unwrap_or_default()
}

/// Stored headers a copy takes over from its source (not encryption or Object Lock state).
fn inheritable(h: &[(String, String)]) -> Vec<(String, String)> {
    h.iter()
        .filter(|(k, _)| {
            !k.starts_with(SSE)
                && !lock::is_lock_header(k)
                && k != store::REPLICA_HEADER
                && !k.starts_with(store::INTERNAL_PREFIX)
        })
        .cloned()
        .collect()
}

/// The checksum algorithm an upload was created with.
fn upload_checksum_algo(headers: &[(String, String)]) -> Option<ChecksumAlgo> {
    headers.iter().find(|(k, _)| k == store::UPLOAD_CHECKSUM_ALGO).and_then(|(_, v)| ChecksumAlgo::from_name(v))
}

/// Uploads completed recently, so a client that retries a CompleteMultipartUpload (after
/// losing the response) gets the same answer, as on S3.
#[derive(Default)]
struct Completed(HashMap<u128, (String, String, ObjectMeta)>);

impl Completed {
    fn remember(&mut self, upload: u128, bucket: &str, key: &str, meta: &ObjectMeta) {
        if self.0.len() >= 10_000 {
            self.0.clear();
        }
        self.0.insert(upload, (bucket.to_string(), key.to_string(), meta.clone()));
    }

    fn get(&self, upload: u128, bucket: &str, key: &str) -> Option<ObjectMeta> {
        self.0.get(&upload).filter(|(b, k, _)| b == bucket && k == key).map(|(_, _, m)| m.clone())
    }
}

fn r_has_auth_header(parts: &Parts) -> bool {
    parts.headers.contains_key(hyper::header::AUTHORIZATION)
}

fn has_lock_headers(h: &HeaderMap) -> bool {
    [lock::MODE, lock::UNTIL, lock::HOLD].iter().any(|n| h.contains_key(*n))
}

/// Whether the request sent `x-amz-bypass-governance-retention: true`.
fn wants_bypass(r: &Req) -> bool {
    r.header(lock::BYPASS).is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Echo the encryption headers of a write back to the client.
fn set_sse_headers(resp: &mut Resp, stored: &[(String, String)]) {
    for (k, v) in stored {
        if k.starts_with(SSE) {
            resp.set(k, v);
        }
    }
}

/// `x-amz-version-id` for responses about an object version (absent for unversioned objects).
fn set_version_header(resp: &mut Resp, meta: &ObjectMeta) {
    if let Some(v) = &meta.version {
        resp.set("x-amz-version-id", v);
    }
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
        assert!(!valid_bucket_name("foo-.bar") && !valid_bucket_name("foo.-bar"));
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
