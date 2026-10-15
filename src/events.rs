//! Bucket event notifications: S3-format event records delivered to webhook targets (configured
//! per bucket with PutBucketNotificationConfiguration) and streamed to live listeners
//! (MinIO-compatible ListenBucketNotification).
//!
//! Emitting is cheap when nobody listens: with no live listener and no notification rules for
//! the bucket, `emit` returns after two atomic loads and a cache lookup.

use crate::access::glob;
use crate::error::{S3Result, err};
use crate::store::Store;
use crate::util::{self, iso8601, now_ms, uri_encode};
use crate::xml::{self, Xml};
use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{broadcast, watch};

/// Events kept per webhook target while it is unreachable; beyond that, new events are dropped.
const MAX_QUEUED: u64 = 100_000;
/// ... and at most this many bytes of them.
const MAX_QUEUED_BYTES: u64 = 128 << 20;
/// Events read from the queue at a time.
const BATCH: usize = 100;
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Connecting to a webhook may take this long.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// ARN of a webhook target in notification configurations.
pub fn target_arn(id: &str) -> String {
    format!("arn:s3rs:webhook::{id}")
}

/// One event, as it happened.
#[derive(Debug, Clone)]
pub struct Event {
    /// e.g. `ObjectCreated:Put` (without the `s3:` prefix).
    pub name: &'static str,
    pub bucket: String,
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub version: Option<String>,
    /// Access key of the caller (empty for anonymous and lifecycle).
    pub principal: String,
    pub source_ip: String,
    pub request_id: String,
    pub time_ms: u64,
    pub sequencer: u64,
}

impl Event {
    /// The S3 event record (`{"Records":[...]}` envelope included).
    pub fn to_json(&self, region: &str, config_id: &str) -> String {
        let mut j = String::with_capacity(640);
        j.push_str(r#"{"Records":[{"eventVersion":"2.1","eventSource":"aws:s3","awsRegion":"#);
        json_str(region, &mut j);
        j.push_str(r#","eventTime":"#);
        json_str(&iso8601(self.time_ms), &mut j);
        j.push_str(r#","eventName":"#);
        json_str(self.name, &mut j);
        j.push_str(r#","userIdentity":{"principalId":"#);
        json_str(&self.principal, &mut j);
        j.push_str(r#"},"requestParameters":{"sourceIPAddress":"#);
        json_str(&self.source_ip, &mut j);
        j.push_str(r#"},"responseElements":{"x-amz-request-id":"#);
        json_str(&self.request_id, &mut j);
        j.push_str(r#"},"s3":{"s3SchemaVersion":"1.0","configurationId":"#);
        json_str(config_id, &mut j);
        j.push_str(r#","bucket":{"name":"#);
        json_str(&self.bucket, &mut j);
        j.push_str(r#","ownerIdentity":{"principalId":"#);
        json_str(crate::OWNER_ID, &mut j);
        j.push_str(r#"},"arn":"#);
        json_str(&format!("arn:aws:s3:::{}", self.bucket), &mut j);
        j.push_str(r#"},"object":{"key":"#);
        // As on S3, the key is URL-encoded (spaces as '+').
        json_str(&uri_encode(&self.key, true).replace("%20", "+"), &mut j);
        j.push_str(&format!(r#","size":{}"#, self.size));
        if !self.etag.is_empty() {
            j.push_str(r#","eTag":"#);
            json_str(self.etag.trim_matches('"'), &mut j);
        }
        if let Some(v) = &self.version {
            j.push_str(r#","versionId":"#);
            json_str(v, &mut j);
        }
        j.push_str(&format!(r#","sequencer":"{:016X}"}}}}}}]}}"#, self.sequencer));
        j
    }
}

fn json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ------------------------------------------------------------------ configuration

/// One notification rule of a bucket.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub id: String,
    pub target: String,
    /// Event name patterns such as `s3:ObjectCreated:*`.
    pub events: Vec<String>,
    pub prefix: String,
    pub suffix: String,
}

impl Rule {
    fn matches(&self, ev: &Event) -> bool {
        ev.key.starts_with(&self.prefix) && ev.key.ends_with(&self.suffix) && event_matches(&self.events, ev.name)
    }
}

/// Does `name` (e.g. `ObjectCreated:Put`) match any of `patterns` (e.g. `s3:ObjectCreated:*`)?
fn event_matches(patterns: &[String], name: &str) -> bool {
    patterns.iter().any(|p| p.strip_prefix("s3:").is_some_and(|p| glob(p, name, false)))
}

const EVENT_TYPES: &[&str] = &[
    "ObjectCreated:*",
    "ObjectCreated:Put",
    "ObjectCreated:Post",
    "ObjectCreated:Copy",
    "ObjectCreated:CompleteMultipartUpload",
    "ObjectRemoved:*",
    "ObjectRemoved:Delete",
    "ObjectRemoved:DeleteMarkerCreated",
    "LifecycleExpiration:*",
    "LifecycleExpiration:Delete",
    "LifecycleExpiration:DeleteMarkerCreated",
];

pub fn valid_event(e: &str) -> bool {
    e.strip_prefix("s3:").is_some_and(|e| EVENT_TYPES.contains(&e))
}

/// Parse a NotificationConfiguration document; `targets` are the configured webhook ids.
pub fn parse_config(doc: &xml::Node, targets: &[String]) -> S3Result<Vec<Rule>> {
    parse_rules(doc, targets, true)
}

/// Parse a stored configuration: rules whose target no longer exists (removed from the
/// server's --webhook list) are skipped with a warning instead of disabling the others.
pub fn load_config(bucket: &str, doc: &xml::Node, targets: &[String]) -> Vec<Rule> {
    match parse_rules(doc, targets, false) {
        Ok(rules) => {
            let n = doc.children.len();
            if rules.len() < n {
                elog!(
                    "warning: bucket {bucket}: {} notification rule(s) refer to webhook targets that are not configured and are ignored",
                    n - rules.len()
                );
            }
            rules
        }
        Err(e) => {
            elog!("warning: bucket {bucket}: stored notification configuration is invalid: {}", e.message);
            Vec::new()
        }
    }
}

fn parse_rules(doc: &xml::Node, targets: &[String], strict: bool) -> S3Result<Vec<Rule>> {
    if doc.name != "NotificationConfiguration" {
        return Err(err::MalformedXML());
    }
    let mut rules = Vec::new();
    for (elem, arn_elem) in
        [("QueueConfiguration", "Queue"), ("TopicConfiguration", "Topic"), ("CloudFunctionConfiguration", "CloudFunction")]
    {
        for c in doc.children_named(elem) {
            let arn = c.child_text(arn_elem).map(str::trim).ok_or_else(err::MalformedXML)?;
            let known = arn.strip_prefix("arn:s3rs:webhook::").filter(|id| targets.iter().any(|t| t == id));
            if known.is_none() && !strict {
                continue;
            }
            let target = known.ok_or_else(|| {
                    err::InvalidArgument().with_message(format!(
                        "Unable to validate the following destination configurations: {arn} (configure webhook targets with --webhook)"
                    ))
                })?;
            let events: Vec<String> = c.children_named("Event").map(|e| e.text.trim().to_string()).collect();
            if events.is_empty() {
                return Err(err::MalformedXML().with_message("Each configuration needs at least one Event"));
            }
            if let Some(bad) = events.iter().find(|e| !valid_event(e)) {
                return Err(err::InvalidArgument().with_message(format!("The event is not supported for notifications: {bad}")));
            }
            let (mut prefix, mut suffix) = (String::new(), String::new());
            if let Some(key) = c.child("Filter").and_then(|f| f.child("S3Key")) {
                for fr in key.children_named("FilterRule") {
                    let value = fr.child_text("Value").unwrap_or("").to_string();
                    match fr.child_text("Name").map(|n| n.trim().to_ascii_lowercase()).as_deref() {
                        Some("prefix") => prefix = value,
                        Some("suffix") => suffix = value,
                        _ => return Err(err::InvalidArgument().with_message("FilterRule Name must be prefix or suffix")),
                    }
                }
            }
            let id = c.child_text("Id").map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
            let id = id.unwrap_or_else(|| util::id_hex(util::new_id())[..16].to_string());
            rules.push(Rule { id, target: target.to_string(), events, prefix, suffix });
        }
    }
    if rules.len() > 100 {
        return Err(err::InvalidArgument().with_message("A bucket can have at most 100 notification configurations"));
    }
    Ok(rules)
}

/// Canonical XML for stored rules (returned by GetBucketNotificationConfiguration).
pub fn config_xml(rules: &[Rule]) -> String {
    let mut x = Xml::new("NotificationConfiguration");
    for r in rules {
        x.open("QueueConfiguration").elem("Id", &r.id).elem("Queue", target_arn(&r.target));
        for e in &r.events {
            x.elem("Event", e);
        }
        if !r.prefix.is_empty() || !r.suffix.is_empty() {
            x.open("Filter").open("S3Key");
            for (name, value) in [("prefix", &r.prefix), ("suffix", &r.suffix)] {
                if !value.is_empty() {
                    x.open("FilterRule").elem("Name", name).elem("Value", value).close("FilterRule");
                }
            }
            x.close("S3Key").close("Filter");
        }
        x.close("QueueConfiguration");
    }
    x.finish("NotificationConfiguration")
}

// ------------------------------------------------------------------ bus

/// A live listener's filter (ListenBucketNotification).
pub struct ListenFilter {
    pub bucket: Option<String>,
    pub events: Vec<String>,
    pub prefix: String,
    pub suffix: String,
}

impl ListenFilter {
    pub fn matches(&self, ev: &Event) -> bool {
        self.bucket.as_ref().is_none_or(|b| *b == ev.bucket)
            && ev.key.starts_with(&self.prefix)
            && ev.key.ends_with(&self.suffix)
            && event_matches(&self.events, ev.name)
    }
}

#[derive(Default)]
pub struct Stats {
    pub delivered: AtomicU64,
    pub failed: AtomicU64,
    pub dropped: AtomicU64,
    /// Events a receiver refused for good (HTTP 4xx).
    pub rejected: AtomicU64,
    /// Events waiting to be delivered.
    pub pending: AtomicU64,
}

/// A webhook target's queue (the events themselves are in the store).
struct Queue {
    len: AtomicU64,
    bytes: AtomicU64,
}

impl Queue {
    fn add(&self, stats: &Stats, n: u64, bytes: u64) {
        self.len.fetch_add(n, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        stats.pending.fetch_add(n, Ordering::Relaxed);
    }

    fn remove(&self, stats: &Stats, n: u64, bytes: u64) {
        let sub = |a: &AtomicU64, v: u64| {
            let mut cur = a.load(Ordering::Relaxed);
            while let Err(now) = a.compare_exchange_weak(cur, cur.saturating_sub(v), Ordering::Relaxed, Ordering::Relaxed) {
                cur = now;
            }
        };
        sub(&self.len, n);
        sub(&self.bytes, bytes);
        sub(&stats.pending, n);
    }
}

pub struct Bus {
    store: Arc<Store>,
    live: broadcast::Sender<Arc<Event>>,
    targets: HashMap<String, Arc<Queue>>,
    region: String,
    /// Parsed notification rules per bucket; `None` cached for buckets without rules.
    rules: RwLock<HashMap<String, Option<Arc<Vec<Rule>>>>>,
    seq: AtomicU64,
    /// The minute of the last "dropped events" log line.
    drop_warned: AtomicU64,
    pub stats: Arc<Stats>,
    /// Set on shutdown so open listen streams end.
    closing: watch::Sender<bool>,
}

impl Bus {
    /// `targets` are (id, URL); a delivery task is started for each. `tls` is needed for
    /// `https://` targets.
    pub fn new(
        store: Arc<Store>,
        region: String,
        targets: Vec<(String, Endpoint)>,
        secret: Option<String>,
        tls: Option<Arc<crate::tls::ClientConfig>>,
        timeout: Duration,
    ) -> Arc<Bus> {
        let stats = Arc::new(Stats::default());
        // Events queued before a restart are delivered; those for targets that were removed
        // from the configuration are dropped.
        let mut counts = store.event_queues().unwrap_or_else(|e| {
            elog!("warning: cannot read the event queue: {}", e.message);
            HashMap::new()
        });
        // New events queue behind the old ones even if the clock went back across the restart.
        let first_seq = counts.values().map(|q| q.2 + 1).max().unwrap_or(0).max(now_ms() << 20);
        for (target, (n, _, _)) in counts.clone() {
            if !targets.iter().any(|(id, _)| *id == target) {
                elog!("webhook {target} is no longer configured: dropping its {n} queued event(s)");
                if let Ok(keys) = store.event_keys(&target) {
                    store.submit_detached(crate::store::Op::DeleteEvents(keys));
                }
                counts.remove(&target);
            }
        }
        let mut queues = HashMap::new();
        for (id, endpoint) in targets {
            let (n, bytes, _) = counts.get(&id).copied().unwrap_or_default();
            if n > 0 {
                elog!("webhook {id}: {n} queued event(s) from before the restart");
            }
            let queue = Arc::new(Queue { len: AtomicU64::new(0), bytes: AtomicU64::new(0) });
            queue.add(&stats, n, bytes);
            let tls = if endpoint.tls() { tls.clone() } else { None };
            let target = Target { id: id.clone(), endpoint, tls, secret: secret.clone(), timeout };
            tokio::spawn(deliver(target, store.clone(), queue.clone(), stats.clone()));
            queues.insert(id, queue);
        }
        Arc::new(Bus {
            store,
            live: broadcast::channel(4096).0,
            targets: queues,
            region,
            rules: RwLock::new(HashMap::new()),
            seq: AtomicU64::new(first_seq),
            drop_warned: AtomicU64::new(0),
            stats,
            closing: watch::channel(false).0,
        })
    }

    pub fn target_ids(&self) -> Vec<String> {
        self.targets.keys().cloned().collect()
    }

    /// Forget cached rules for a bucket (its notification configuration changed or it was deleted).
    pub fn invalidate(&self, bucket: &str) {
        self.rules.write().unwrap().remove(bucket);
    }

    fn rules_for(&self, bucket: &str) -> Option<Arc<Vec<Rule>>> {
        if let Some(r) = self.rules.read().unwrap().get(bucket) {
            return r.clone();
        }
        let rules = self
            .store
            .bucket_config(bucket, "notification")
            .ok()
            .flatten()
            .and_then(|v| xml::parse(&String::from_utf8_lossy(&v)))
            .map(|d| load_config(bucket, &d, &self.target_ids()))
            .filter(|r| !r.is_empty())
            .map(Arc::new);
        let mut cache = self.rules.write().unwrap();
        if cache.len() > 10_000 {
            cache.clear();
        }
        cache.insert(bucket.to_string(), rules.clone());
        rules
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.live.subscribe()
    }

    /// Resolves once the server starts shutting down.
    pub fn closing(&self) -> watch::Receiver<bool> {
        self.closing.subscribe()
    }

    pub fn shutdown(&self) {
        self.closing.send_replace(true);
    }

    /// Prepare the events of a write: `make` turns the operation's result into its events.
    /// Returns the operation to submit instead, wrapped so that its webhook events are queued
    /// in the same transaction as the change (so a crash can't separate them, and queue order
    /// is commit order), and a `Notify` to call `done` on once it succeeded.
    pub fn wrap(
        self: &Arc<Self>,
        bucket: &str,
        op: crate::store::Op,
        make: impl Fn(&crate::store::OpOut) -> Vec<Event> + Send + Sync + 'static,
    ) -> (crate::store::Op, Option<Notify>) {
        let listeners = self.live.receiver_count() > 0;
        let rules = if self.targets.is_empty() { None } else { self.rules_for(bucket) };
        if !listeners && rules.is_none() {
            return (op, None);
        }
        let shared: Arc<Mutex<Outcome>> = Arc::default();
        let (bus, out) = (self.clone(), shared.clone());
        let rows = Arc::new(move |result: &crate::store::OpOut| {
            let mut o = Outcome::default();
            let mut rows = Vec::new();
            for mut ev in make(result) {
                // Events carry the writer's commit order; the counter only covers events without one.
                if ev.sequencer == 0 {
                    ev.sequencer = bus.seq.fetch_add(1, Ordering::Relaxed);
                }
                for rule in rules.iter().flat_map(|r| r.iter()).filter(|r| r.matches(&ev)) {
                    let Some(queue) = bus.targets.get(&rule.target) else { continue };
                    let body = ev.to_json(&bus.region, &rule.id).into_bytes();
                    if queue.len.load(Ordering::Relaxed) >= MAX_QUEUED
                        || queue.bytes.load(Ordering::Relaxed) + body.len() as u64 > MAX_QUEUED_BYTES
                    {
                        // The target has been down for a long time. Count it rather than fill the disk.
                        o.dropped += 1;
                        continue;
                    }
                    o.queued.push((queue.clone(), body.len() as u64));
                    let mut key = rule.target.as_bytes().to_vec();
                    key.push(0);
                    key.extend_from_slice(&bus.seq.fetch_add(1, Ordering::Relaxed).to_be_bytes());
                    rows.push((key, body));
                }
                o.events.push(Arc::new(ev));
            }
            // Queued events never take the space kept free for deletes: on a nearly full disk
            // they are dropped (and counted) instead.
            let bytes: u64 = o.queued.iter().map(|(_, b)| b).sum();
            if !rows.is_empty()
                && let Err(e) = bus.store.space.check(bytes)
            {
                o.dropped += rows.len() as u64;
                o.queued.clear();
                o.error = Some(e.message);
                rows.clear();
            }
            // A batch retried after a failed commit runs this again: keep the last outcome.
            *out.lock().unwrap() = o;
            rows
        });
        (crate::store::Op::WithEvents(Box::new(op), rows), Some(Notify { bus: self.clone(), outcome: shared }))
    }
}

/// What `Bus::wrap`'s events came to, for `Notify::done`.
#[derive(Default)]
struct Outcome {
    events: Vec<Arc<Event>>,
    queued: Vec<(Arc<Queue>, u64)>,
    dropped: u64,
    error: Option<String>,
}

/// Finishes a wrapped write's events once it is committed.
pub struct Notify {
    bus: Arc<Bus>,
    outcome: Arc<Mutex<Outcome>>,
}

impl Notify {
    /// The write succeeded: count its queued events and tell live listeners.
    pub fn done(self) {
        let o = std::mem::take(&mut *self.outcome.lock().unwrap());
        let bus = &self.bus;
        for (q, bytes) in &o.queued {
            q.add(&bus.stats, 1, *bytes);
        }
        if o.dropped > 0 {
            bus.stats.dropped.fetch_add(o.dropped, Ordering::Relaxed);
            let now = now_ms() / 60_000;
            if let Some(e) = &o.error
                && bus.drop_warned.swap(now, Ordering::Relaxed) != now
            {
                elog!("webhooks: dropped {} event(s): {e}", o.dropped);
            }
        }
        if bus.live.receiver_count() > 0 {
            for ev in o.events {
                let _ = bus.live.send(ev);
            }
        }
    }
}

// ------------------------------------------------------------------ webhook delivery

/// A parsed `http[s]://host[:port]/path` URL.
#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with '/'.
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, String> {
        let (tls, rest) = match (s.strip_prefix("https://"), s.strip_prefix("http://")) {
            (Some(rest), _) => (true, rest),
            (None, Some(rest)) => (false, rest),
            _ => return Err(format!("{s}: URLs must start with http:// or https://")),
        };
        let default_port = if tls { 443 } else { 80 };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let bad = |what: &str| format!("{s}: invalid {what}");
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            // [ipv6] or [ipv6]:port
            let (addr, after) = rest.split_once(']').ok_or_else(|| bad("host"))?;
            addr.parse::<std::net::Ipv6Addr>().map_err(|_| bad("IPv6 address"))?;
            let port = match after {
                "" => default_port,
                p => p.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).ok_or_else(|| bad("port"))?,
            };
            (format!("[{addr}]"), port)
        } else {
            let (h, p) = match authority.split_once(':') {
                Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad("port"))?),
                None => (authority, default_port),
            };
            if h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
                return Err(bad("host"));
            }
            (h.to_string(), p)
        };
        if port == 0 {
            return Err(bad("port"));
        }
        if tls {
            crate::tls::check_server_name(host.trim_start_matches('[').trim_end_matches(']'))
                .map_err(|e| format!("{s}: invalid TLS server name ({e})"))?;
        }
        if path.contains('#') || path.parse::<hyper::http::uri::PathAndQuery>().is_err() {
            return Err(bad("path"));
        }
        Ok(Url { tls, host, port, path: path.to_string() })
    }

    pub fn host_header(&self) -> String {
        if self.port == if self.tls { 443 } else { 80 } { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }
}

/// Where a target's events go: a webhook URL, or a NATS subject / Redis list or channel.
#[derive(Debug, Clone, PartialEq)]
pub enum Endpoint {
    Http(Url),
    Other(crate::targets::Endpoint),
}

impl Endpoint {
    pub fn parse(s: &str) -> Result<Endpoint, String> {
        match crate::targets::Endpoint::parse(s) {
            Some(e) => e.map(Endpoint::Other),
            None => Url::parse(s).map(Endpoint::Http).map_err(|e| format!("{e} (or nats://, redis://)")),
        }
    }

    /// Needs the TLS client configuration (https:// webhooks).
    pub fn tls(&self) -> bool {
        matches!(self, Endpoint::Http(u) if u.tls)
    }

    /// For logs (without credentials).
    pub fn describe(&self) -> String {
        match self {
            Endpoint::Http(u) => format!("{}://{}:{}{}", if u.tls { "https" } else { "http" }, u.host, u.port, u.path),
            Endpoint::Other(e) => e.describe(),
        }
    }
}

type Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

/// Open an HTTP/1.1 connection to `url`'s host (with TLS for https://).
pub async fn connect<B>(
    url: &Url,
    tls: Option<&Arc<crate::tls::ClientConfig>>,
) -> Result<hyper::client::conn::http1::SendRequest<B>, String>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let host = url.host.trim_start_matches('[').trim_end_matches(']');
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect((host, url.port)))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let _ = stream.set_nodelay(true);
    let sender = if url.tls {
        let stream = crate::tls::connect(tls.ok_or("no TLS client configuration")?, host, stream).await?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    } else {
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    };
    Ok(sender)
}

/// A notification target and how to reach it.
struct Target {
    id: String,
    endpoint: Endpoint,
    tls: Option<Arc<crate::tls::ClientConfig>>,
    secret: Option<String>,
    /// How long the receiver may take to answer.
    timeout: Duration,
}

async fn post(sender: &mut Option<Sender>, t: &Target, url: &Url, body: &Bytes) -> Result<u16, String> {
    let reused = sender.as_ref().is_some_and(|s| !s.is_closed());
    match post_once(sender, t, url, body).await {
        // A kept-alive connection the receiver had already closed: try a fresh one at once.
        Err(_) if reused => post_once(sender, t, url, body).await,
        r => r,
    }
}

/// Send one event to the target.
async fn send(
    sender: &mut Option<Sender>,
    other: &mut Option<crate::targets::Conn>,
    t: &Target,
    body: &Bytes,
) -> Result<crate::targets::Answer, String> {
    use crate::targets::Answer;
    match &t.endpoint {
        Endpoint::Http(url) => match post(sender, t, url, body).await? {
            s if (200..300).contains(&s) => Ok(Answer::Accepted),
            s if rejected(s) => Ok(Answer::Rejected(format!("HTTP {s}"))),
            s => Err(format!("HTTP {s}")),
        },
        Endpoint::Other(ep) => {
            let reused = other.is_some();
            match crate::targets::send(other, ep, body, t.timeout).await {
                // A kept-alive connection the server had closed: try a fresh one at once.
                Err(_) if reused => crate::targets::send(other, ep, body, t.timeout).await,
                r => r,
            }
        }
    }
}

async fn post_once(sender: &mut Option<Sender>, t: &Target, url: &Url, body: &Bytes) -> Result<u16, String> {
    let signature = t.secret.as_ref().map(|k| format!("sha256={}", util::hex(&crate::auth::hmac(k.as_bytes(), body))));
    if sender.as_ref().is_none_or(|s| s.is_closed()) {
        *sender = Some(connect(url, t.tls.as_ref()).await?);
    }
    let s = sender.as_mut().unwrap();
    if let Err(e) = s.ready().await {
        *sender = None;
        return Err(e.to_string());
    }
    let mut req = hyper::Request::post(url.path.as_str())
        .header("host", url.host_header())
        .header("content-type", "application/json")
        .header("user-agent", concat!("s3rs/", env!("CARGO_PKG_VERSION")));
    if let Some(sig) = &signature {
        req = req.header("x-s3rs-signature", sig);
    }
    let req = req.body(Full::new(body.clone())).map_err(|e| e.to_string())?;
    match tokio::time::timeout(t.timeout, s.send_request(req)).await {
        Ok(Ok(resp)) => Ok(resp.status().as_u16()),
        Ok(Err(e)) => {
            *sender = None;
            Err(e.to_string())
        }
        Err(_) => {
            *sender = None;
            Err("request timed out".into())
        }
    }
}

/// Whether a webhook answer means the receiver will never take the event: a client error
/// other than a timeout or throttling. Such an event is dropped (and counted) so it can't hold
/// up the events behind it forever.
fn rejected(status: u16) -> bool {
    (400..500).contains(&status) && status != 408 && status != 429
}

/// Deliver one webhook target's queued events, in order, at least once: an event is removed
/// from the queue only after the target accepted it (2xx) or rejected it for good (4xx);
/// until then it is retried with backoff, and the events behind it wait.
async fn deliver(t: Target, store: Arc<Store>, queue: Arc<Queue>, stats: Arc<Stats>) {
    let id = &t.id;
    let mut sender: Option<Sender> = None;
    let mut other: Option<crate::targets::Conn> = None;
    let (mut warned_at, mut rejected_at) = (0u64, 0u64);
    let mut backoff = Duration::from_millis(500);
    let mut failing = false;
    let mut committed = store.events_committed.subscribe();
    loop {
        let st = store.clone();
        let target = id.clone();
        let batch = match tokio::task::spawn_blocking(move || st.events(&target, BATCH)).await {
            Ok(Ok(b)) => b,
            _ => Vec::new(),
        };
        if batch.is_empty() {
            // The queue is empty: correct any drift in its counters (e.g. a write whose
            // request went away between its commit and counting its events).
            let (n, b) = (queue.len.load(Ordering::Relaxed), queue.bytes.load(Ordering::Relaxed));
            if n > 0 || b > 0 {
                queue.remove(&stats, n, b);
            }
            // New events are visible once the writer commits them.
            tokio::select! {
                _ = committed.changed() => {}
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            continue;
        }
        let mut done = Vec::new();
        let (mut delivered, mut done_bytes) = (0u64, 0u64);
        let mut error = None;
        for (key, body) in batch {
            let len = body.len() as u64;
            let body = Bytes::from(body);
            match send(&mut sender, &mut other, &t, &body).await {
                Ok(crate::targets::Answer::Accepted) => delivered += 1,
                Ok(crate::targets::Answer::Rejected(why)) => {
                    stats.rejected.fetch_add(1, Ordering::Relaxed);
                    let now = now_ms() / 60_000;
                    if now != rejected_at {
                        rejected_at = now;
                        elog!("webhook {id}: the receiver rejected an event ({why}); dropping it");
                    }
                }
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
            done.push(key);
            done_bytes += len;
        }
        if !done.is_empty() {
            stats.delivered.fetch_add(delivered, Ordering::Relaxed);
            queue.remove(&stats, done.len() as u64, done_bytes);
            if let Err(e) = store.submit(crate::store::Op::DeleteEvents(done)).await {
                elog!("webhook {id}: updating the event queue failed: {}", e.message);
            }
        }
        match error {
            None => {
                if failing {
                    elog!("webhook {id}: delivering again");
                }
                failing = false;
                backoff = Duration::from_millis(500);
            }
            Some(e) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                failing = true;
                // At most one log line per minute per target.
                let now = now_ms() / 60_000;
                if now != warned_at {
                    warned_at = now;
                    elog!(
                        "webhook {id}: delivery failed ({e}); {} event(s) queued, retrying in {}s",
                        queue.len.load(Ordering::Relaxed),
                        backoff.as_secs_f64().ceil()
                    );
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(
            Url::parse("http://hooks.internal:8080/s3?x=1").unwrap(),
            Url { tls: false, host: "hooks.internal".into(), port: 8080, path: "/s3?x=1".into() }
        );
        let u = Url::parse("https://hooks.example.com/s3").unwrap();
        assert!(u.tls && u.port == 443 && u.host_header() == "hooks.example.com");
        assert_eq!(Url::parse("https://h:8443/").unwrap().host_header(), "h:8443");
        #[cfg(feature = "tls")]
        for bad in ["https://127.1/", "https://a..b/", "https://-x-/"] {
            assert!(Url::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Url::parse("https://[::1]:8443/").is_ok() && Url::parse("https://10.0.0.1/").is_ok());
        assert_eq!(Url::parse("http://h").unwrap().path, "/");
        assert_eq!(Url::parse("http://[::1]:9/").unwrap().host, "[::1]");
        assert!(Url::parse("ftp://h/").is_err());
        assert!(Url::parse("http://user@h/").is_err());
        for bad in [
            "http://:80/",
            "http://h:80:90/",
            "http://[::1/x",
            "http://h:0/",
            "http://h/a b",
            "http://h/a\r\nX: y",
            "http://h/#f",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Url::parse("http://[::1]/x").unwrap().port, 80);
    }

    #[test]
    fn config_roundtrip_and_matching() {
        let doc = xml::parse(
            "<NotificationConfiguration><QueueConfiguration><Id>img</Id><Queue>arn:s3rs:webhook::hook</Queue>\
             <Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>prefix</Name><Value>images/</Value></FilterRule>\
             <FilterRule><Name>Suffix</Name><Value>.jpg</Value></FilterRule></S3Key></Filter></QueueConfiguration>\
             <TopicConfiguration><Topic>arn:s3rs:webhook::hook</Topic><Event>s3:ObjectRemoved:Delete</Event></TopicConfiguration>\
             </NotificationConfiguration>",
        )
        .unwrap();
        let rules = parse_config(&doc, &["hook".into()]).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(parse_config(&xml::parse(&config_xml(&rules)).unwrap(), &["hook".into()]).unwrap(), rules);
        let ev = |name, key: &str| Event {
            name,
            bucket: "b".into(),
            key: key.into(),
            size: 1,
            etag: "\"e\"".into(),
            version: None,
            principal: String::new(),
            source_ip: String::new(),
            request_id: String::new(),
            time_ms: 0,
            sequencer: 1,
        };
        assert!(rules[0].matches(&ev("ObjectCreated:Put", "images/a.jpg")));
        assert!(!rules[0].matches(&ev("ObjectCreated:Put", "images/a.png")));
        assert!(!rules[0].matches(&ev("ObjectRemoved:Delete", "images/a.jpg")));
        assert!(rules[1].matches(&ev("ObjectRemoved:Delete", "x")));
        assert!(!rules[1].matches(&ev("ObjectRemoved:DeleteMarkerCreated", "x")));
        // Unknown targets and events are rejected when configuring...
        assert!(parse_config(&doc, &["other".into()]).is_err());
        // ...but a stored configuration keeps the rules whose target still exists.
        let mixed = xml::parse(
            "<NotificationConfiguration><QueueConfiguration><Id>a</Id><Queue>arn:s3rs:webhook::gone</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration>\
             <QueueConfiguration><Id>b</Id><Queue>arn:s3rs:webhook::hook</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>",
        )
        .unwrap();
        let kept = load_config("bkt", &mixed, &["hook".into()]);
        assert_eq!(kept.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["b"]);
        let bad = xml::parse("<NotificationConfiguration><QueueConfiguration><Queue>arn:s3rs:webhook::hook</Queue><Event>s3:Nope</Event></QueueConfiguration></NotificationConfiguration>").unwrap();
        assert!(parse_config(&bad, &["hook".into()]).is_err());
        // The record is valid JSON with an encoded key.
        let j = ev("ObjectCreated:Put", "a b/ü\"x").to_json("us-east-1", "img");
        let parsed = crate::access::parse_json(&j).expect("valid json");
        let obj = parsed
            .get("Records")
            .and_then(|r| if let crate::access::Json::Arr(a) = r { a.first().cloned() } else { None })
            .unwrap();
        let key = obj.get("s3").and_then(|s| s.get("object")).and_then(|o| o.get("key")).cloned();
        assert_eq!(key, Some(crate::access::Json::Str("a+b/%C3%BC%22x".into())));
    }
}
