//! Asynchronous bucket replication to other S3-compatible servers (another s3rs, AWS S3, MinIO).
//!
//! Remote servers ("targets") are listed in a file (`--replication-targets`). A bucket's
//! ReplicationConfiguration (PutBucketReplication) names destinations as
//! `arn:s3rs:replication::<TARGET>:<BUCKET>`.
//!
//! Every change to a replicated key is recorded in a queue in the metadata database, in the same
//! transaction as the change (store::REPL), so a crash never loses one and repeated changes to a
//! key collapse into one entry. A worker sends each queued key's *current* state to its
//! destinations (PUT, or DELETE when delete replication is on) and removes the entry once every
//! destination has it, unless the key changed again meanwhile. Failed keys are retried with
//! backoff; an unreachable target only delays replication. A destination that already holds an
//! identical object is not sent it again, which also stops two servers that replicate to each
//! other from bouncing a change back and forth.

use crate::auth::{hmac, sha256_hex};
use crate::body::Body;
use crate::crypt::WrapKey;
use crate::error::{S3Error, S3Result, err};
use crate::events::Url;
use crate::store::meta::{ObjectMeta, Storage};
use crate::store::{Op, OpOut, ReplEntry, Store};
use crate::util::{self, hex, uri_encode};
use crate::xml;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::client::conn::http1::SendRequest;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, watch};

pub const ARN_PREFIX: &str = "arn:s3rs:replication::";
/// Keys replicated at the same time.
const CONCURRENCY: usize = 16;
/// Queue entries read per scan.
const PAGE: usize = 256;
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// After a target refused or dropped a connection, keys for it fail at once for this long.
const TARGET_DOWN: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ------------------------------------------------------------------ configuration

/// One rule of a bucket's ReplicationConfiguration.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub id: String,
    pub enabled: bool,
    pub priority: i64,
    pub prefix: String,
    /// Objects must carry all of these tags.
    pub tags: Vec<(String, String)>,
    /// Also replicate deletes (DeleteMarkerReplication).
    pub delete_markers: bool,
    /// Also replicate the objects that existed before the rule (ExistingObjectReplication).
    pub existing: bool,
    pub target: String,
    pub bucket: String,
}

impl Rule {
    fn covers_key(&self, key: &str) -> bool {
        self.enabled && key.starts_with(self.prefix.as_str())
    }

    fn covers(&self, key: &str, tags: &[(String, String)]) -> bool {
        self.covers_key(key) && self.tags.iter().all(|t| tags.contains(t))
    }
}

/// Parse a ReplicationConfiguration document; `targets` are the configured target ids.
pub fn parse_config(doc: &xml::Node, targets: &[String]) -> S3Result<Vec<Rule>> {
    parse(doc, Some(targets))
}

/// Parse a stored configuration (targets are checked when replicating).
pub fn load(raw: &[u8]) -> Vec<Rule> {
    std::str::from_utf8(raw).ok().and_then(xml::parse).and_then(|d| parse(&d, None).ok()).unwrap_or_default()
}

fn status(n: Option<&xml::Node>) -> S3Result<bool> {
    match n.map(|n| n.child_text("Status").map(str::trim)) {
        None => Ok(false),
        Some(Some("Enabled")) => Ok(true),
        Some(Some("Disabled")) => Ok(false),
        Some(_) => Err(err::MalformedXML().with_message("Status must be Enabled or Disabled")),
    }
}

fn parse(doc: &xml::Node, targets: Option<&[String]>) -> S3Result<Vec<Rule>> {
    let malformed = |m: &str| err::MalformedXML().with_message(m.to_string());
    let invalid = |m: String| err::InvalidArgument().with_message(m);
    if doc.name != "ReplicationConfiguration" {
        return Err(err::MalformedXML());
    }
    let mut rules: Vec<Rule> = Vec::new();
    for (i, r) in doc.children_named("Rule").enumerate() {
        let id = match r.child_text("ID").map(str::trim) {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => format!("rule-{}", i + 1),
        };
        if id.len() > 255 {
            return Err(invalid("A rule ID can be at most 255 characters long".into()));
        }
        if rules.iter().any(|x| x.id == id) {
            return Err(invalid(format!("Duplicate rule ID {id}")));
        }
        let enabled = match r.child_text("Status").map(str::trim) {
            Some("Enabled") => true,
            Some("Disabled") => false,
            _ => return Err(malformed("Each Rule needs a Status of Enabled or Disabled")),
        };
        let priority = match r.child_text("Priority") {
            Some(p) => p.trim().parse::<i64>().map_err(|_| malformed("Invalid Priority"))?,
            None => 0,
        };
        let (mut prefix, mut tags) = (String::new(), Vec::new());
        if let Some(f) = r.child("Filter") {
            let scope = f.child("And").unwrap_or(f);
            if let Some(p) = scope.child_text("Prefix") {
                prefix = p.to_string();
            }
            for t in scope.children_named("Tag") {
                let (Some(k), Some(v)) = (t.child_text("Key"), t.child_text("Value")) else {
                    return Err(malformed("Each Tag needs a Key and a Value"));
                };
                if k.is_empty() || k.len() > 128 || v.len() > 256 {
                    return Err(invalid(format!("Invalid tag {k} in the filter of rule {id}")));
                }
                tags.push((k.to_string(), v.to_string()));
            }
        } else if let Some(p) = r.child_text("Prefix") {
            prefix = p.to_string();
        }
        if prefix.len() > 1024 {
            return Err(invalid(format!("The prefix of rule {id} is too long")));
        }
        let delete_markers = status(r.child("DeleteMarkerReplication"))?;
        let existing = status(r.child("ExistingObjectReplication"))?;
        if delete_markers && !tags.is_empty() {
            return Err(invalid(format!("Rule {id}: delete replication is not supported for rules with tag filters")));
        }
        let dest = r
            .child("Destination")
            .and_then(|d| d.child_text("Bucket"))
            .map(str::trim)
            .ok_or_else(|| malformed("Each Rule needs a Destination with a Bucket"))?;
        let (target, bucket) = dest.strip_prefix(ARN_PREFIX).and_then(|r| r.split_once(':')).ok_or_else(|| {
            invalid(format!(
                "Invalid destination {dest}: use {ARN_PREFIX}<TARGET>:<BUCKET>, where TARGET is a target from --replication-targets"
            ))
        })?;
        if !crate::s3::valid_bucket_name(bucket) {
            return Err(invalid(format!("Invalid destination bucket name {bucket}")));
        }
        if let Some(known) = targets
            && !known.iter().any(|t| t == target)
        {
            return Err(invalid(format!(
                "Unknown replication target {target} (targets are configured with --replication-targets)"
            )));
        }
        rules.push(Rule {
            id,
            enabled,
            priority,
            prefix,
            tags,
            delete_markers,
            existing,
            target: target.to_string(),
            bucket: bucket.to_string(),
        });
    }
    if rules.is_empty() {
        return Err(malformed("A ReplicationConfiguration needs at least one Rule"));
    }
    if rules.len() > 1000 {
        return Err(invalid("A ReplicationConfiguration can have at most 1000 rules".into()));
    }
    Ok(rules)
}

/// The rules that decide where a key's current state goes: for each destination, the matching
/// rule with the highest priority. `tags` is `None` for a key that no longer exists.
pub fn destinations<'a>(rules: &'a [Rule], key: &str, tags: Option<&[(String, String)]>) -> Vec<&'a Rule> {
    let mut best: Vec<&Rule> = Vec::new();
    for r in rules {
        let matches = match tags {
            Some(t) => r.covers(key, t),
            // A key that no longer exists has no tags: rules with tag filters (which can't
            // replicate deletes) don't apply to it.
            None => r.covers_key(key) && r.tags.is_empty(),
        };
        if !matches {
            continue;
        }
        match best.iter_mut().find(|b| b.target == r.target && b.bucket == r.bucket) {
            Some(b) if r.priority > b.priority => *b = r,
            Some(_) => {}
            None => best.push(r),
        }
    }
    best
}

// ------------------------------------------------------------------ targets

/// A remote S3-compatible server.
#[derive(Debug, Clone)]
pub struct Target {
    pub id: String,
    pub url: Url,
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
}

/// Parse a targets file: one `ID URL ACCESS_KEY SECRET_KEY [REGION]` per line; `#` comments.
pub fn parse_targets(text: &str) -> Result<Vec<Target>, String> {
    let mut out: Vec<Target> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |m: String| format!("line {}: {m}", n + 1);
        let f: Vec<&str> = line.split_whitespace().collect();
        if !(4..=5).contains(&f.len()) {
            return Err(at("expected `ID URL ACCESS_KEY SECRET_KEY [REGION]`".into()));
        }
        let id = f[0];
        if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(at(format!("invalid target id {id} (letters, digits, - and _)")));
        }
        if out.iter().any(|t| t.id == id) {
            return Err(at(format!("duplicate target id {id}")));
        }
        let url = Url::parse(f[1]).map_err(at)?;
        if url.path.contains('?') {
            return Err(at(format!("{}: the URL must not have a query", f[1])));
        }
        out.push(Target {
            id: id.to_string(),
            url,
            access_key: f[2].to_string(),
            secret_key: f[3].to_string(),
            region: f.get(4).unwrap_or(&"us-east-1").to_string(),
        });
    }
    Ok(out)
}

pub fn load_targets(path: &Path) -> Result<Vec<Target>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_targets(&text).map_err(|e| format!("{}: {e}", path.display()))
}

// ------------------------------------------------------------------ signed requests

/// Sign a request with AWS Signature Version 4. `headers` must include `host`; the date,
/// payload hash and authorization headers are added.
fn sign(
    t: &Target,
    method: &str,
    path: &str,
    query: &str,
    headers: &mut Vec<(String, String)>,
    payload_sha256: &str,
    now_secs: u64,
) {
    let amz_date = util::amz_date(now_secs);
    let date = &amz_date[..8];
    headers.push(("x-amz-date".into(), amz_date.clone()));
    headers.push(("x-amz-content-sha256".into(), payload_sha256.into()));
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let mut canonical = String::new();
    for (k, v) in headers.iter() {
        canonical.push_str(k);
        canonical.push(':');
        // SigV4 trims values and collapses runs of spaces inside them.
        canonical.push_str(&v.split_whitespace().collect::<Vec<_>>().join(" "));
        canonical.push('\n');
    }
    let signed = headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let creq = format!("{method}\n{path}\n{query}\n{canonical}\n{signed}\n{payload_sha256}");
    let scope = format!("{date}/{}/s3/aws4_request", t.region);
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(creq.as_bytes()));
    let mut key = hmac(format!("AWS4{}", t.secret_key).as_bytes(), date.as_bytes());
    for part in [t.region.as_str(), "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    let signature = hex(&hmac(&key, sts.as_bytes()));
    headers.push((
        "authorization".into(),
        format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}", t.access_key),
    ));
}

/// A canonical (sorted, encoded) query string; also used as the request's query.
fn query(pairs: &[(&str, &str)]) -> String {
    let mut p: Vec<String> = pairs.iter().map(|(k, v)| format!("{}={}", uri_encode(k, false), uri_encode(v, false))).collect();
    p.sort();
    p.join("&")
}

struct Response {
    status: u16,
    headers: hyper::HeaderMap,
    body: Bytes,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// `status Code: message` for errors.
    fn describe(&self) -> String {
        let text = String::from_utf8_lossy(&self.body);
        match xml::parse(&text) {
            Some(d) if d.name == "Error" => {
                format!("{} {}: {}", self.status, d.child_text("Code").unwrap_or(""), d.child_text("Message").unwrap_or(""))
            }
            _ => self.status.to_string(),
        }
    }
}

/// Connections to one target, reused between requests.
#[derive(Default)]
struct Pool(Mutex<Vec<(SendRequest<Body>, Instant)>>);

/// Idle connections older than this are not reused: servers close idle keep-alive connections
/// (s3rs after 30 s), and a request on one that was just closed fails.
const POOL_IDLE: Duration = Duration::from_secs(20);

struct Request<'a> {
    method: hyper::Method,
    bucket: &'a str,
    key: Option<&'a str>,
    query: String,
    headers: Vec<(String, String)>,
    body: Body,
    len: u64,
    payload_sha256: String,
}

impl<'a> Request<'a> {
    fn new(method: hyper::Method, bucket: &'a str, key: Option<&'a str>) -> Self {
        Request {
            method,
            bucket,
            key,
            query: String::new(),
            headers: Vec::new(),
            body: Body::Empty,
            len: 0,
            payload_sha256: EMPTY_SHA256.into(),
        }
    }

    fn query(mut self, pairs: &[(&str, &str)]) -> Self {
        self.query = query(pairs);
        self
    }

    /// A small body, signed.
    fn bytes(mut self, data: impl Into<Bytes>) -> Self {
        let data: Bytes = data.into();
        self.payload_sha256 = sha256_hex(&data);
        self.headers.push(("content-md5".into(), util::base64(&<md5::Md5 as md5::Digest>::digest(&data))));
        self.len = data.len() as u64;
        self.body = Body::full(data);
        self
    }

    /// A streamed body of `len` bytes (unsigned payload; integrity comes from Content-MD5 or a
    /// checksum header where one is known, and from TLS).
    fn stream(mut self, body: Body, len: u64) -> Self {
        self.payload_sha256 = "UNSIGNED-PAYLOAD".into();
        self.body = body;
        self.len = len;
        self
    }
}

// ------------------------------------------------------------------ the worker

#[derive(Default)]
pub struct Stats {
    pub replicated: AtomicU64,
    pub failed: AtomicU64,
    /// Destinations that already had the object.
    pub unchanged: AtomicU64,
    /// Objects that can't be replicated (SSE-C: the server doesn't have the key).
    pub skipped: AtomicU64,
    pub bytes: AtomicU64,
    /// The time (ms) of the oldest change not yet replicated (0: none).
    pub oldest_ms: AtomicU64,
}

pub struct Replicator {
    store: Arc<Store>,
    targets: RwLock<Arc<HashMap<String, Arc<Target>>>>,
    tls: Option<Arc<crate::tls::ClientConfig>>,
    master: Option<WrapKey>,
    pub stats: Arc<Stats>,
    pools: Mutex<HashMap<String, Arc<Pool>>>,
    /// Keys being replicated right now.
    busy: Arc<Mutex<HashSet<Vec<u8>>>>,
    /// Targets that could not be reached: requests to them fail at once until then.
    down: Mutex<HashMap<String, Instant>>,
    /// Targets being probed.
    probing: Mutex<HashSet<String>>,
    last_warning: Mutex<Option<Instant>>,
}

/// Releases a key's busy mark however its replication ends (also if the task panics).
struct Busy {
    set: Arc<Mutex<HashSet<Vec<u8>>>>,
    raw: Vec<u8>,
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.raw);
    }
}

/// How long a failed key waits before the next attempt: a quarter of the time its oldest
/// change has been waiting, from 1 s up to 5 minutes.
fn retry_delay(since_ms: u64, now_ms: u64) -> Duration {
    Duration::from_millis(now_ms.saturating_sub(since_ms) / 4).clamp(Duration::from_secs(1), MAX_BACKOFF)
}

impl Replicator {
    pub fn new(
        store: Arc<Store>,
        targets: Vec<Target>,
        tls: Option<Arc<crate::tls::ClientConfig>>,
        master: Option<WrapKey>,
    ) -> Arc<Self> {
        let r = Arc::new(Replicator {
            store,
            targets: RwLock::new(Arc::new(HashMap::new())),
            tls,
            master,
            stats: Arc::new(Stats::default()),
            pools: Mutex::new(HashMap::new()),
            busy: Arc::new(Mutex::new(HashSet::new())),
            down: Mutex::new(HashMap::new()),
            probing: Mutex::new(HashSet::new()),
            last_warning: Mutex::new(None),
        });
        r.set_targets(targets);
        r
    }

    /// Replace the targets (on SIGHUP); open connections to changed targets are dropped.
    /// https:// targets need TLS support in the build.
    pub fn replace_targets(&self, targets: Vec<Target>) -> Result<(), String> {
        if self.tls.is_none()
            && let Some(t) = targets.iter().find(|t| t.url.tls)
        {
            return Err(format!("target {} uses https://, which needs a build with --features tls", t.id));
        }
        self.set_targets(targets);
        Ok(())
    }

    fn set_targets(&self, targets: Vec<Target>) {
        let map: HashMap<String, Arc<Target>> = targets.into_iter().map(|t| (t.id.clone(), Arc::new(t))).collect();
        *self.targets.write().unwrap() = Arc::new(map);
        self.pools.lock().unwrap().clear();
        self.down.lock().unwrap().clear();
    }

    pub fn target_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.targets.read().unwrap().keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn needs_tls(targets: &[Target]) -> bool {
        targets.iter().any(|t| t.url.tls)
    }

    fn target(&self, id: &str) -> Option<Arc<Target>> {
        self.targets.read().unwrap().get(id).cloned()
    }

    fn warn(&self, msg: &str) {
        // At most one line every 10 s: an unreachable target fails every key.
        let mut last = self.last_warning.lock().unwrap();
        if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(10)) {
            *last = Some(Instant::now());
            elog!("replication: {msg}");
        }
    }

    /// Queue a bucket's existing objects (after a configuration with ExistingObjectReplication
    /// was set, or at startup when that was interrupted).
    pub async fn backfill(store: Arc<Store>, bucket: String) {
        let mut failures = 0;
        loop {
            match store.submit(Op::ReplBackfill { bucket: bucket.clone(), limit: 1000 }).await {
                Ok(OpOut::More(true)) => failures = 0,
                Ok(_) => return,
                Err(e) => {
                    failures += 1;
                    elog!("replication: queuing the existing objects of {bucket} failed: {}", e.message);
                    if failures >= 10 {
                        elog!("replication: giving up on queuing the existing objects of {bucket} until the next start");
                        return;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Process the queue until `stop` turns true.
    pub async fn run(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        match self.store.repl_backfills() {
            Ok(buckets) => {
                for b in buckets {
                    tokio::spawn(Self::backfill(self.store.clone(), b));
                }
            }
            Err(e) => elog!("replication: {}", e.message),
        }
        let permits = Arc::new(Semaphore::new(CONCURRENCY));
        let mut cursor: Option<Vec<u8>> = None;
        let (mut oldest, mut started) = (u64::MAX, 0usize);
        // The oldest change among keys waiting to be retried, refreshed now and then (it
        // takes a scan of the waiting table).
        let (mut wait_oldest, mut wait_checked) = (0u64, None::<Instant>);
        loop {
            if *stop.borrow() {
                return;
            }
            let store = self.store.clone();
            let after = cursor.clone();
            let page = match tokio::task::spawn_blocking(move || store.repl_scan(after.as_deref(), PAGE)).await {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    self.warn(&format!("reading the queue failed: {}", e.message));
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                Err(_) => return,
            };
            if page.is_empty() {
                // End of a pass: bring back the keys whose retry time has come, update the lag.
                self.requeue(util::now_ms()).await;
                if wait_checked.is_none_or(|t: Instant| t.elapsed() >= Duration::from_secs(30)) {
                    let store = self.store.clone();
                    wait_oldest = tokio::task::spawn_blocking(move || store.repl_wait_oldest())
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .unwrap_or(0);
                    wait_checked = Some(Instant::now());
                }
                let queued = if oldest == u64::MAX { 0 } else { oldest };
                let lag = match (queued, wait_oldest) {
                    (0, w) => w,
                    (q, 0) => q,
                    (q, w) => q.min(w),
                };
                self.stats.oldest_ms.store(lag, Relaxed);
                let idle = started == 0;
                (cursor, oldest, started) = (None, u64::MAX, 0);
                self.spawn_probes();
                if idle {
                    tokio::select! {
                        _ = self.store.repl_wake.notified() => {}
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                        _ = stop.changed() => return,
                    }
                }
                continue;
            }
            cursor = page.last().map(|e| e.raw.clone());
            for e in page {
                oldest = oldest.min(e.since_ms);
                let Some(busy) = self.claim(&e.raw) else { continue };
                started += 1;
                let permit = tokio::select! {
                    p = permits.clone().acquire_owned() => p.expect("semaphore is never closed"),
                    _ = stop.changed() => return,
                };
                let this = self.clone();
                tokio::spawn(async move {
                    this.process(e).await;
                    drop(busy);
                    drop(permit);
                });
            }
        }
    }

    /// Move waiting keys whose retry time is before `before_ms` back to the queue.
    async fn requeue(&self, before_ms: u64) {
        let store = self.store.clone();
        if !tokio::task::spawn_blocking(move || store.repl_due(before_ms)).await.ok().and_then(Result::ok).unwrap_or(false) {
            return;
        }
        loop {
            match self.store.submit(Op::ReplRequeue { before_ms, limit: 1000 }).await {
                Ok(OpOut::More(true)) => continue,
                Ok(_) => return,
                Err(e) => {
                    self.warn(&format!("updating the queue failed: {}", e.message));
                    return;
                }
            }
        }
    }

    /// A target that was unreachable answered again: retry every waiting key now instead of
    /// when its backoff ends.
    async fn recovered(&self, id: &str) {
        if self.down.lock().unwrap().remove(id).is_some() {
            elog!("replication: target {id} is reachable again");
            self.requeue(u64::MAX).await;
            self.store.repl_wake.notify_one();
        }
    }

    /// Probe each unreachable target whose wait is over (in the background, so a target that
    /// drops packets doesn't hold up the others), so one that comes back is noticed within
    /// seconds, however long the keys waiting for it back off.
    fn spawn_probes(self: &Arc<Self>) {
        let now = Instant::now();
        let due: Vec<String> =
            self.down.lock().unwrap().iter().filter(|(_, until)| **until <= now).map(|(id, _)| id.clone()).collect();
        for id in due {
            if !self.probing.lock().unwrap().insert(id.clone()) {
                continue;
            }
            let this = self.clone();
            tokio::spawn(async move {
                match this.target(&id) {
                    None => {
                        this.down.lock().unwrap().remove(&id);
                    }
                    Some(t) => {
                        let conn =
                            tokio::time::timeout(PROBE_TIMEOUT, crate::events::connect::<Body>(&t.url, this.tls.as_ref())).await;
                        match conn {
                            Ok(Ok(c)) => {
                                this.pools
                                    .lock()
                                    .unwrap()
                                    .entry(id.clone())
                                    .or_default()
                                    .0
                                    .lock()
                                    .unwrap()
                                    .push((c, Instant::now()));
                                this.recovered(&id).await;
                            }
                            _ => {
                                this.down.lock().unwrap().insert(id.clone(), Instant::now() + TARGET_DOWN);
                            }
                        }
                    }
                }
                this.probing.lock().unwrap().remove(&id);
            });
        }
    }

    /// Mark a key as being replicated, unless it already is.
    fn claim(&self, raw: &[u8]) -> Option<Busy> {
        self.busy.lock().unwrap().insert(raw.to_vec()).then(|| Busy { set: self.busy.clone(), raw: raw.to_vec() })
    }

    async fn process(&self, e: ReplEntry) {
        match self.replicate(&e.bucket, &e.key).await {
            Ok(()) => {
                if let Err(err) = self.store.submit(Op::ReplDone { bucket: e.bucket, key: e.key, seq: e.seq }).await {
                    self.warn(&format!("updating the queue failed: {}", err.message));
                }
            }
            Err(msg) => {
                self.stats.failed.fetch_add(1, Relaxed);
                let now = util::now_ms();
                let delay = retry_delay(e.since_ms, now);
                self.warn(&format!("{}/{}: {msg} (retrying in {}s)", e.bucket, e.key, delay.as_secs()));
                let op = Op::ReplFailed { bucket: e.bucket, key: e.key, seq: e.seq, retry_ms: now + delay.as_millis() as u64 };
                if let Err(err) = self.store.submit(op).await {
                    self.warn(&format!("updating the queue failed: {}", err.message));
                }
            }
        }
    }

    /// Bring every destination of a key up to date with its current state. A destination that
    /// fails doesn't stop the others; the key is retried (destinations that are up to date are
    /// then left alone).
    async fn replicate(&self, bucket: &str, key: &str) -> Result<(), String> {
        let store = self.store.clone();
        let (b, k) = (bucket.to_string(), key.to_string());
        let (config, object) = tokio::task::spawn_blocking(move || {
            let config = match store.bucket_config(&b, "replication") {
                Ok(c) => c,
                Err(e) if e.code == "NoSuchBucket" => None,
                Err(e) => return Err(e),
            };
            let object = match store.get_object(&b, &k) {
                Ok(o) => Some(o),
                Err(e) if matches!(e.code, "NoSuchKey" | "NoSuchBucket") => None,
                Err(e) => return Err(e),
            };
            Ok::<_, S3Error>((config, object))
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.message)?;
        // No configuration (any more), or the bucket is gone: the entry is dropped.
        let Some(config) = config else { return Ok(()) };
        // Objects that are themselves replicas (from another server) are not passed on.
        if object.as_ref().is_some_and(|(m, _)| crate::store::is_replica(&m.headers)) {
            return Ok(());
        }
        let rules = load(&config);
        let mut first_error = None;
        for rule in destinations(&rules, key, object.as_ref().map(|(m, _)| m.tags.as_slice())) {
            let result = async {
                let target = self.target(&rule.target).ok_or_else(|| format!("unknown replication target {}", rule.target))?;
                match &object {
                    Some((meta, inline)) => self.put(&target, &rule.bucket, key, meta, inline.clone()).await,
                    None if rule.delete_markers => {
                        let mut req = Request::new(hyper::Method::DELETE, &rule.bucket, Some(key));
                        req.headers.push(replica_header());
                        let r = self.send(&target, req, None).await?;
                        if !matches!(r.status, 200 | 204 | 404) {
                            return Err(format!("{}: DELETE {}/{key}: {}", target.id, rule.bucket, r.describe()));
                        }
                        self.stats.replicated.fetch_add(1, Relaxed);
                        Ok(())
                    }
                    None => Ok(()),
                }
            }
            .await;
            if let Err(e) = result {
                first_error.get_or_insert(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn put(&self, t: &Target, bucket: &str, key: &str, meta: &ObjectMeta, inline: Option<Bytes>) -> Result<(), String> {
        let stored = |name: &str| meta.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
        if stored("x-amz-server-side-encryption-customer-algorithm").is_some() {
            // SSE-C: only the client has the key.
            self.stats.skipped.fetch_add(1, Relaxed);
            return Ok(());
        }
        let sse = stored("x-amz-server-side-encryption").is_some();
        let wrap = match sse {
            true => {
                let master = self.master.as_ref().ok_or("the object is encrypted but no master key is configured")?;
                crate::crypt::server_key(&meta.headers, master)
            }
            false => None,
        };
        let what = |m: &str| format!("{}: {m} {bucket}/{key}", t.id);

        // Skip destinations that already have this object (same data and metadata); bring
        // their tags up to date if needed.
        let head = self.send(t, Request::new(hyper::Method::HEAD, bucket, Some(key)), None).await?;
        if head.status == 200 && same_object(meta, &head) {
            return self.sync_tags(t, bucket, key, meta).await;
        }
        if !matches!(head.status, 200 | 404) {
            return Err(format!("{}: {}", what("HEAD"), head.describe()));
        }

        let mut headers: Vec<(String, String)> =
            meta.headers.iter().filter(|(k, _)| replicated_header(k)).map(|(k, v)| (k.clone(), v.clone())).collect();
        if !meta.tags.is_empty() {
            headers.push((
                "x-amz-tagging".into(),
                query(&meta.tags.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>()),
            ));
        }
        if sse {
            headers.push(("x-amz-server-side-encryption".into(), "AES256".into()));
        }
        headers.push(replica_header());
        let parts: Vec<u64> = match &meta.storage {
            Storage::Segments(s) if meta.etag.contains('-') => s.iter().map(|(_, l)| *l).collect(),
            _ => Vec::new(),
        };
        if parts.is_empty() {
            let mut req = Request::new(hyper::Method::PUT, bucket, Some(key));
            req.headers = headers;
            if let Some(md5) = plain_md5(&meta.etag) {
                req.headers.push(("content-md5".into(), util::base64(&md5)));
            }
            if let Some((algo, v)) = &meta.checksum
                && !v.contains('-')
            {
                req.headers.push((algo.header().to_string(), v.clone()));
            }
            let body = self.read(meta, inline, 0, meta.size, wrap).await?;
            let r = self.send(t, req.stream(body, meta.size), Some(meta.size)).await?;
            if r.status != 200 {
                return Err(format!("{}: {}", what("PUT"), r.describe()));
            }
        } else {
            self.put_multipart(t, bucket, key, meta, headers, &parts, wrap).await?;
        }
        self.stats.replicated.fetch_add(1, Relaxed);
        self.stats.bytes.fetch_add(meta.size, Relaxed);
        Ok(())
    }

    /// Upload a multipart object with the same parts, so the destination computes the same ETag.
    #[allow(clippy::too_many_arguments)]
    async fn put_multipart(
        &self,
        t: &Target,
        bucket: &str,
        key: &str,
        meta: &ObjectMeta,
        headers: Vec<(String, String)>,
        parts: &[u64],
        wrap: Option<WrapKey>,
    ) -> Result<(), String> {
        let what = |m: &str| format!("{}: {m} {bucket}/{key}", t.id);
        // The object's checksums go along when every part's is known: the target verifies
        // them and keeps the same checksum.
        let part_sums: Vec<&str> = meta
            .headers
            .iter()
            .find(|(k, _)| k == crate::store::PART_CHECKSUMS)
            .map(|(_, list)| list.split(',').collect())
            .unwrap_or_default();
        let checksum = meta.checksum.as_ref().filter(|_| part_sums.len() == parts.len());
        let mut req = Request::new(hyper::Method::POST, bucket, Some(key)).query(&[("uploads", "")]);
        req.headers = headers;
        if let Some((algo, v)) = checksum {
            req.headers.push(("x-amz-checksum-algorithm".into(), algo.name().into()));
            req.headers.push(("x-amz-checksum-type".into(), crate::checksum::Kind::of(v).name().into()));
        }
        let r = self.send(t, req, None).await?;
        let upload_id = (r.status == 200)
            .then(|| xml::parse(&String::from_utf8_lossy(&r.body)))
            .flatten()
            .and_then(|d| d.child_text("UploadId").map(String::from))
            .ok_or_else(|| format!("{}: {}", what("CreateMultipartUpload"), r.describe()))?;
        let result = async {
            let mut etags = Vec::with_capacity(parts.len());
            let mut start = 0u64;
            for (i, len) in parts.iter().enumerate() {
                let n = (i + 1).to_string();
                let body = self.read(meta, None, start, *len, wrap.clone()).await?;
                let mut req = Request::new(hyper::Method::PUT, bucket, Some(key))
                    .query(&[("partNumber", &n), ("uploadId", &upload_id)])
                    .stream(body, *len);
                if let Some((algo, _)) = checksum {
                    req.headers.push((algo.header().into(), part_sums[i].into()));
                }
                let r = self.send(t, req, Some(*len)).await?;
                let etag = r.header("etag").filter(|_| r.status == 200).map(String::from);
                etags.push(etag.ok_or_else(|| format!("{} part {n}: {}", what("UploadPart"), r.describe()))?);
                start += len;
            }
            let mut x = crate::xml::Xml::new("CompleteMultipartUpload");
            for (i, etag) in etags.iter().enumerate() {
                x.open("Part").elem("PartNumber", (i + 1).to_string()).elem("ETag", etag);
                if let Some((algo, _)) = checksum {
                    x.elem(algo.xml_name(), part_sums[i]);
                }
                x.close("Part");
            }
            let doc = x.finish("CompleteMultipartUpload");
            let req = Request::new(hyper::Method::POST, bucket, Some(key)).query(&[("uploadId", &upload_id)]).bytes(doc);
            let r = self.send(t, req, None).await?;
            // S3 can report a failed completion in a 200 response.
            if r.status != 200 || xml::parse(&String::from_utf8_lossy(&r.body)).is_some_and(|d| d.name == "Error") {
                return Err(format!("{}: {}", what("CompleteMultipartUpload"), r.describe()));
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            // Even when the target was just marked unreachable: an abandoned upload costs storage.
            let abort = Request::new(hyper::Method::DELETE, bucket, Some(key)).query(&[("uploadId", &upload_id)]);
            let _ = self.send_once(t, abort, None).await;
        }
        result
    }

    async fn sync_tags(&self, t: &Target, bucket: &str, key: &str, meta: &ObjectMeta) -> Result<(), String> {
        let r = self.send(t, Request::new(hyper::Method::GET, bucket, Some(key)).query(&[("tagging", "")]), None).await?;
        let mut remote = match r.status {
            200 => xml::parse(&String::from_utf8_lossy(&r.body))
                .and_then(|d| crate::access::parse_tagging_xml(&d, 50).ok())
                .ok_or_else(|| format!("{}: GET {bucket}/{key}?tagging: unreadable response", t.id))?,
            404 => Vec::new(),
            _ => return Err(format!("{}: GET {bucket}/{key}?tagging: {}", t.id, r.describe())),
        };
        let mut local = meta.tags.clone();
        remote.sort();
        local.sort();
        if remote == local {
            self.stats.unchanged.fetch_add(1, Relaxed);
            return Ok(());
        }
        let mut req = if local.is_empty() {
            Request::new(hyper::Method::DELETE, bucket, Some(key)).query(&[("tagging", "")])
        } else {
            Request::new(hyper::Method::PUT, bucket, Some(key))
                .query(&[("tagging", "")])
                .bytes(crate::access::tagging_xml(&meta.tags))
        };
        req.headers.push(replica_header());
        let r = self.send(t, req, None).await?;
        if !matches!(r.status, 200 | 204) {
            return Err(format!("{}: tagging {bucket}/{key}: {}", t.id, r.describe()));
        }
        self.stats.replicated.fetch_add(1, Relaxed);
        Ok(())
    }

    /// The plaintext of `[start, start+len)` of an object.
    async fn read(
        &self,
        meta: &ObjectMeta,
        inline: Option<Bytes>,
        start: u64,
        len: u64,
        wrap: Option<WrapKey>,
    ) -> Result<Body, String> {
        match crate::io::read_body(&self.store, meta, inline, start, len, wrap).await {
            Ok(b) => Ok(b),
            // A data file vanished: the object was just replaced, and is queued again.
            Err(None) => Err("the object changed while it was being replicated".into()),
            Err(Some(e)) => Err(e.message),
        }
    }

    /// Send a signed request to a target. `len` (for uploads) extends the response timeout.
    async fn send(&self, t: &Target, req: Request<'_>, len: Option<u64>) -> Result<Response, String> {
        if self.down.lock().unwrap().get(&t.id).is_some_and(|until| *until > Instant::now()) {
            return Err(format!("{}: unreachable", t.id));
        }
        let r = self.send_once(t, req, len).await;
        match &r {
            Err(SendError::Connect(_)) => {
                self.down.lock().unwrap().insert(t.id.clone(), Instant::now() + TARGET_DOWN);
            }
            Ok(_) => self.recovered(&t.id).await,
            _ => {}
        }
        r.map_err(|e| match e {
            SendError::Connect(m) | SendError::Request(m) => m,
        })
    }

    async fn send_once(&self, t: &Target, req: Request<'_>, len: Option<u64>) -> Result<Response, SendError> {
        let pool = self.pools.lock().unwrap().entry(t.id.clone()).or_default().clone();
        let idle = {
            let mut conns = pool.0.lock().unwrap();
            conns.retain(|(c, idle)| !c.is_closed() && idle.elapsed() < POOL_IDLE);
            conns.pop().map(|(c, _)| c)
        };
        let mut conn = match idle {
            Some(c) => c,
            None => tokio::time::timeout(CONNECT_TIMEOUT, crate::events::connect::<Body>(&t.url, self.tls.as_ref()))
                .await
                .map_err(|_| SendError::Connect(format!("{}: connection timed out", t.id)))?
                .map_err(|e| SendError::Connect(format!("{}: {e}", t.id)))?,
        };
        conn.ready().await.map_err(|e| SendError::Request(format!("{}: {e}", t.id)))?;

        let base = t.url.path.trim_end_matches('/');
        let mut path = format!("{base}/{}", req.bucket);
        if let Some(k) = req.key {
            path.push('/');
            path.push_str(&uri_encode(k, true));
        }
        let mut headers = req.headers;
        headers.push(("host".into(), t.url.host_header()));
        sign(t, req.method.as_str(), &path, &req.query, &mut headers, &req.payload_sha256, util::now_ms() / 1000);
        let uri = if req.query.is_empty() { path.clone() } else { format!("{path}?{}", req.query) };
        let mut builder = hyper::Request::builder().method(req.method.clone()).uri(uri);
        for (k, v) in &headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        if req.len > 0 || matches!(req.method, hyper::Method::PUT | hyper::Method::POST) {
            builder = builder.header("content-length", req.len.to_string());
        }
        builder = builder.header("user-agent", concat!("s3rs/", env!("CARGO_PKG_VERSION"), " replication"));
        let request = builder.body(req.body).map_err(|e| SendError::Request(e.to_string()))?;
        // Uploads get time to transfer at 256 KiB/s on top of a fixed allowance (a stalled
        // transfer is cut off sooner, after 120 s without progress, by the body reader).
        let timeout = Duration::from_secs(300 + len.unwrap_or(0) / (256 << 10));
        let response = async {
            let resp = conn.send_request(request).await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let (parts, body) = resp.into_parts();
            let body = http_body_util::Limited::new(body, 1 << 20).collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok::<_, String>(Response { status, headers: parts.headers, body })
        };
        let r = tokio::time::timeout(timeout, response)
            .await
            .map_err(|_| SendError::Request(format!("{}: {} {path}: timed out", t.id, req.method)))?
            .map_err(|e| SendError::Request(format!("{}: {} {path}: {e}", t.id, req.method)))?;
        if !conn.is_closed() {
            pool.0.lock().unwrap().push((conn, Instant::now()));
        }
        Ok(r)
    }
}

enum SendError {
    /// The target could not be reached.
    Connect(String),
    Request(String),
}

/// Marks writes made by replication, so the destination doesn't replicate them back.
fn replica_header() -> (String, String) {
    (crate::store::REPLICA_HEADER.to_string(), "REPLICA".to_string())
}

/// The stored headers that travel with an object.
fn replicated_header(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "content-disposition"
            | "content-language"
            | "content-encoding"
            | "cache-control"
            | "expires"
            | "x-amz-website-redirect-location"
    ) || name.starts_with("x-amz-meta-")
}

/// The MD5 of a single-part object's content, from its ETag.
fn plain_md5(etag: &str) -> Option<Vec<u8>> {
    let e = etag.trim_matches('"');
    (e.len() == 32).then(|| util::unhex(e)).flatten()
}

/// Whether a HEAD response describes the same object (data and metadata) as `meta`.
fn same_object(meta: &ObjectMeta, head: &Response) -> bool {
    if head.header("etag").map(crate::store::norm_etag) != Some(crate::store::norm_etag(&meta.etag))
        || head.header("content-length").and_then(|v| v.parse::<u64>().ok()) != Some(meta.size)
    {
        return false;
    }
    // Header values are compared as stored: decoded leniently (non-ASCII metadata included).
    let local = |name: &str| meta.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let remote = |name: &str| head.headers.get(name).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    for name in [
        "content-disposition",
        "content-language",
        "content-encoding",
        "cache-control",
        "expires",
        "x-amz-website-redirect-location",
    ] {
        if local(name) != remote(name) {
            return false;
        }
    }
    // Servers answer a default content type for objects stored without one.
    if local("content-type").is_some_and(|c| Some(c) != remote("content-type")) {
        return false;
    }
    let mut mine: Vec<(String, String)> = meta.headers.iter().filter(|(k, _)| k.starts_with("x-amz-meta-")).cloned().collect();
    let mut theirs: Vec<(String, String)> = head
        .headers
        .iter()
        .filter(|(k, _)| k.as_str().starts_with("x-amz-meta-"))
        .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    mine.sort();
    theirs.sort();
    mine == theirs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(s: &str) -> xml::Node {
        xml::parse(s).unwrap()
    }

    #[test]
    fn parses_configurations() {
        let targets = vec!["dr".to_string()];
        let rules = parse_config(
            &doc(
                "<ReplicationConfiguration><Role>ignored</Role>\
                 <Rule><ID>logs</ID><Status>Enabled</Status><Priority>2</Priority>\
                 <Filter><Prefix>logs/</Prefix></Filter>\
                 <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication>\
                 <ExistingObjectReplication><Status>Enabled</Status></ExistingObjectReplication>\
                 <Destination><Bucket>arn:s3rs:replication::dr:backup</Bucket></Destination></Rule>\
                 <Rule><Status>Disabled</Status><Filter><And><Prefix>a</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter>\
                 <Destination><Bucket>arn:s3rs:replication::dr:other</Bucket></Destination></Rule>\
                 </ReplicationConfiguration>",
            ),
            &targets,
        )
        .unwrap();
        assert_eq!(rules.len(), 2);
        let r = &rules[0];
        assert!(r.enabled && r.delete_markers && r.existing);
        assert_eq!(
            (r.id.as_str(), r.priority, r.prefix.as_str(), r.target.as_str(), r.bucket.as_str()),
            ("logs", 2, "logs/", "dr", "backup")
        );
        assert_eq!(rules[1].id, "rule-2");
        assert_eq!(rules[1].tags, vec![("k".to_string(), "v".to_string())]);
        assert!(!rules[1].enabled && !rules[1].delete_markers);

        let bad = |x: &str| {
            parse_config(&doc(&format!("<ReplicationConfiguration>{x}</ReplicationConfiguration>")), &targets).unwrap_err()
        };
        let dest = "<Destination><Bucket>arn:s3rs:replication::dr:b-1</Bucket></Destination>";
        assert_eq!(bad("").code, "MalformedXML");
        assert_eq!(bad(&format!("<Rule>{dest}</Rule>")).code, "MalformedXML");
        assert_eq!(
            bad("<Rule><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::x</Bucket></Destination></Rule>").code,
            "InvalidArgument"
        );
        assert!(
            bad(
                "<Rule><Status>Enabled</Status><Destination><Bucket>arn:s3rs:replication::nope:bkt</Bucket></Destination></Rule>"
            )
            .message
            .contains("Unknown replication target")
        );
        assert_eq!(
            bad("<Rule><Status>Enabled</Status><Destination><Bucket>arn:s3rs:replication::dr:No_Such</Bucket></Destination></Rule>").code,
            "InvalidArgument"
        );
        assert_eq!(
            bad(&format!(
                "<Rule><ID>x</ID><Status>Enabled</Status>{dest}</Rule><Rule><ID>x</ID><Status>Enabled</Status>{dest}</Rule>"
            ))
            .code,
            "InvalidArgument"
        );
        assert_eq!(
            bad(&format!(
                "<Rule><Status>Enabled</Status><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter>\
                 <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication>{dest}</Rule>"
            ))
            .code,
            "InvalidArgument"
        );
        // Stored configurations load without the target check.
        let stored = "<ReplicationConfiguration><Rule><Status>Enabled</Status><Destination><Bucket>arn:s3rs:replication::gone:bkt</Bucket></Destination></Rule></ReplicationConfiguration>";
        assert_eq!(load(stored.as_bytes())[0].target, "gone");
        assert!(load(b"garbage").is_empty());
    }

    #[test]
    fn picks_destinations_by_priority() {
        let rule = |id: &str, prefix: &str, priority: i64, bucket: &str| Rule {
            id: id.into(),
            enabled: true,
            priority,
            prefix: prefix.into(),
            tags: vec![],
            delete_markers: false,
            existing: false,
            target: "t".into(),
            bucket: bucket.into(),
        };
        let mut tagged = rule("tagged", "", 9, "b");
        tagged.tags = vec![("env".into(), "prod".into())];
        let rules = vec![rule("all", "", 1, "b"), rule("logs", "logs/", 5, "b"), rule("other", "logs/", 0, "c"), tagged];
        let ids = |key: &str, tags: Option<&[(String, String)]>| {
            destinations(&rules, key, tags).iter().map(|r| r.id.clone()).collect::<Vec<_>>()
        };
        assert_eq!(ids("x", Some(&[])), ["all"]);
        assert_eq!(ids("logs/1", Some(&[])), ["logs", "other"]);
        assert_eq!(ids("logs/1", Some(&[("env".into(), "prod".into())])), ["tagged", "other"]);
        assert_eq!(ids("logs/1", None), ["logs", "other"]);
    }

    #[test]
    fn parses_targets() {
        let t = parse_targets(
            "# comment\n\ndr https://s3.example.com AKID secret eu-west-1\nlocal http://127.0.0.1:9100/base/ k s\n",
        )
        .unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!((t[0].id.as_str(), t[0].region.as_str(), t[0].url.tls), ("dr", "eu-west-1", true));
        assert_eq!((t[1].region.as_str(), t[1].url.port, t[1].url.path.as_str()), ("us-east-1", 9100, "/base/"));
        assert!(parse_targets("dr https://x k").unwrap_err().contains("line 1"));
        assert!(parse_targets("d/r https://x k s").is_err());
        assert!(parse_targets("a http://x k s\na http://y k s").unwrap_err().contains("duplicate"));
        assert!(parse_targets("a ftp://x k s").is_err());
    }

    /// The signer must produce what the server's verifier accepts.
    #[test]
    fn signatures_verify() {
        let t = Target {
            id: "t".into(),
            url: Url::parse("http://127.0.0.1:9000").unwrap(),
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            region: "us-east-1".into(),
        };
        let auth = crate::auth::Auth::new(vec![crate::auth::Credential {
            access_key: t.access_key.clone(),
            secret: t.secret_key.clone(),
            read_only: false,
            buckets: None,
            policy: None,
            expires_ms: None,
            session: None,
        }]);
        let q = query(&[("uploadId", "a b/c"), ("partNumber", "3")]);
        let path = format!("/bkt/{}", uri_encode("dir/ä €+x", true));
        let mut headers = vec![
            ("host".to_string(), t.url.host_header()),
            ("x-amz-meta-a".to_string(), " v ".to_string()),
            ("content-disposition".to_string(), "attachment;  filename=\"a   b\"".to_string()),
        ];
        sign(&t, "PUT", &path, &q, &mut headers, "UNSIGNED-PAYLOAD", util::now_ms() / 1000);
        let mut req = hyper::Request::builder().method("PUT").uri(format!("{path}?{q}"));
        for (k, v) in &headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let (parts, _) = req.body(()).unwrap().into_parts();
        auth.verify(&parts, &q, None).unwrap();
    }
}
