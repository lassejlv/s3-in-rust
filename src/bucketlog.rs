//! Server access logging per bucket (PutBucketLogging): requests to a bucket are written, in S3's
//! server access log format, as log objects into a target bucket. Lines are buffered and written
//! about once a minute (or per MiB). Like S3's, delivery is best effort: lines still buffered
//! when the server dies are lost.

use crate::accesslog::Entry;
use crate::error::{S3Result, err};
use crate::store::Store;
use crate::xml::{self, Xml};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Buffered lines are written after this long, or once they reach FLUSH_BYTES.
const FLUSH_AFTER: Duration = Duration::from_secs(60);
const FLUSH_BYTES: usize = 1 << 20;
/// Buffered bytes across all targets beyond which new lines are dropped (a target that can't be
/// written to must not grow memory without bound).
const MAX_BUFFERED: usize = 64 << 20;

/// Where a bucket's logs go.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub bucket: String,
    pub prefix: String,
    /// `PartitionedPrefix`: keys `<prefix>s3rs/<region>/<source bucket>/YYYY/MM/DD/<name>`.
    pub partitioned: bool,
    /// `PartitionDateSource` is `DeliveryTime` (else `EventTime`). Lines are written within a
    /// minute of their request, so both date the partition by the time the object is written.
    pub delivery_time: bool,
}

/// Parse a BucketLoggingStatus document: `None` turns logging off.
pub fn parse_config(doc: &xml::Node) -> S3Result<Option<Target>> {
    if doc.name != "BucketLoggingStatus" {
        return Err(err::MalformedXML());
    }
    let Some(e) = doc.child("LoggingEnabled") else { return Ok(None) };
    let bucket = e.child_text("TargetBucket").map(str::trim).filter(|b| !b.is_empty()).ok_or_else(err::MalformedXML)?;
    let prefix = e.child_text("TargetPrefix").unwrap_or("").to_string();
    if prefix.len() > 512 {
        return Err(err::InvalidArgument().with_message("The TargetPrefix is too long"));
    }
    if e.child("TargetGrants").is_some_and(|g| !g.children.is_empty()) {
        return Err(err::NotImplemented().with_message("TargetGrants are not supported; use the target bucket's policy"));
    }
    let part = e.child("TargetObjectKeyFormat").and_then(|f| f.child("PartitionedPrefix"));
    let delivery_time = match part.and_then(|p| p.child_text("PartitionDateSource")).map(str::trim) {
        None | Some("EventTime") => false,
        Some("DeliveryTime") => true,
        Some(_) => return Err(err::MalformedXML().with_message("PartitionDateSource must be EventTime or DeliveryTime")),
    };
    Ok(Some(Target { bucket: bucket.to_string(), prefix, partitioned: part.is_some(), delivery_time }))
}

pub fn config_xml(t: Option<&Target>) -> String {
    let mut x = Xml::new("BucketLoggingStatus");
    if let Some(t) = t {
        x.open("LoggingEnabled").elem("TargetBucket", &t.bucket).elem("TargetPrefix", &t.prefix);
        x.open("TargetObjectKeyFormat");
        if t.partitioned {
            let source = if t.delivery_time { "DeliveryTime" } else { "EventTime" };
            x.open("PartitionedPrefix").elem("PartitionDateSource", source).close("PartitionedPrefix");
        } else {
            x.open("SimplePrefix").close("SimplePrefix");
        }
        x.close("TargetObjectKeyFormat").close("LoggingEnabled");
    }
    x.finish("BucketLoggingStatus")
}

/// The name of a new log object.
pub fn object_key(t: &Target, source_bucket: &str, region: &str, now_secs: u64) -> String {
    let stamp = crate::util::iso8601(now_secs * 1000); // 2024-01-02T03:04:05.000Z
    let (date, time) = (&stamp[..10], &stamp[11..19]);
    let unique = crate::util::hex(&crate::util::new_id().to_le_bytes()[..8]).to_uppercase();
    let name = format!("{date}-{}-{unique}", time.replace(':', "-"));
    if t.partitioned {
        format!("{}s3rs/{region}/{source_bucket}/{}/{name}", t.prefix, date.replace('-', "/"))
    } else {
        format!("{}{name}", t.prefix)
    }
}

/// S3's operation name, e.g. `REST.GET.OBJECT`, `REST.PUT.ACL`, `REST.POST.UPLOADS`.
fn operation(method: &str, query: &str, has_key: bool) -> String {
    const SUBS: &[(&str, &str)] = &[
        ("uploads", "UPLOADS"),
        ("uploadId", "UPLOAD"),
        ("acl", "ACL"),
        ("tagging", "TAGGING"),
        ("versioning", "VERSIONING"),
        ("policy", "BUCKETPOLICY"),
        ("cors", "CORS"),
        ("lifecycle", "LIFECYCLE"),
        ("logging", "LOGGING_STATUS"),
        ("notification", "NOTIFICATION"),
        ("replication", "REPLICATION"),
        ("encryption", "ENCRYPTION"),
        ("website", "WEBSITE"),
        ("location", "LOCATION"),
        ("versions", "BUCKETVERSIONS"),
        ("delete", "MULTI_OBJECT_DELETE"),
        ("retention", "OBJECT_LOCK_RETENTION"),
        ("legal-hold", "OBJECT_LOCK_LEGAL_HOLD"),
        ("object-lock", "OBJECT_LOCK_CONFIGURATION"),
        ("attributes", "OBJECT_ATTRIBUTES"),
    ];
    let names: Vec<&str> = query.split('&').map(|p| p.split('=').next().unwrap_or("")).collect();
    let part = names.contains(&"partNumber") && names.contains(&"uploadId");
    let resource = if part {
        "PART"
    } else if let Some((_, r)) = SUBS.iter().find(|(q, _)| names.contains(q)) {
        r
    } else if has_key {
        "OBJECT"
    } else {
        "BUCKET"
    };
    format!("REST.{method}.{resource}")
}

/// A field that may be empty: `-` then. Spaces would break the format, so they're escaped.
fn field(v: Option<&str>) -> String {
    match v {
        Some(v) if !v.is_empty() => v.replace(' ', "%20"),
        _ => "-".into(),
    }
}

/// One line of S3's server access log format.
pub fn format_line(e: &Entry, bucket: &str, now_ms: u64) -> String {
    let time = httpdate::fmt_http_date(std::time::UNIX_EPOCH + Duration::from_millis(now_ms));
    // "Tue, 15 Nov 1994 08:12:31 GMT" -> "15/Nov/1994:08:12:31 +0000"
    let parts: Vec<&str> = time.split([' ', ',']).filter(|s| !s.is_empty()).collect();
    let time = match parts.as_slice() {
        [_, d, mon, y, hms, _] => format!("{d}/{mon}/{y}:{hms} +0000"),
        _ => time.clone(),
    };
    let quoted = |s: &str| s.replace('"', "\\\"");
    let key = e.record.key.as_deref().map(|k| crate::util::uri_encode(k, true));
    let uri = if e.query.is_empty() { e.path.to_string() } else { format!("{}?{}", e.path, e.query) };
    let bytes = e.bytes_out.filter(|n| *n > 0).map(|n| n.to_string());
    format!(
        "s3rs {bucket} [{time}] {ip} {requester} {rid} {op} {key} \"{method} {uri} HTTP/1.1\" {status} {error} {bytes} - {ms} - \"-\" \"{ua}\" - - {sig} - {auth} - - - -\n",
        ip = e.record.client_ip.unwrap_or(e.remote_ip),
        requester = field(e.record.user.as_deref()),
        rid = e.request_id,
        op = operation(e.method, e.query, e.record.key.is_some()),
        key = field(key.as_deref()),
        method = e.method,
        uri = quoted(&uri),
        status = e.status,
        error = field(e.error),
        bytes = field(bytes.as_deref()),
        ms = e.duration.as_millis(),
        ua = quoted(e.user_agent.unwrap_or("-")),
        sig = if e.record.user.is_some() { "SigV4" } else { "-" },
        auth = if e.record.user.is_some() {
            if e.query.contains("X-Amz-Signature=") { "QueryString" } else { "AuthHeader" }
        } else {
            "-"
        },
    )
}

struct Buffer {
    data: Vec<u8>,
    since: Instant,
}

#[derive(Default)]
pub struct Stats {
    /// Log objects written.
    pub written: AtomicU64,
    /// Lines dropped (a target that couldn't be written to, or too much buffered).
    pub dropped: AtomicU64,
}

pub struct Logger {
    store: Arc<Store>,
    /// Whether any bucket has logging on (otherwise requests don't need log records at all).
    any: AtomicBool,
    targets: RwLock<HashMap<String, Option<Arc<Target>>>>,
    buffers: Mutex<HashMap<(Arc<Target>, String), Buffer>>,
    buffered: AtomicU64,
    pub stats: Arc<Stats>,
}

impl Logger {
    pub fn new(store: Arc<Store>) -> Arc<Logger> {
        let any = store.buckets_with_config("logging").map(|b| !b.is_empty()).unwrap_or(false);
        Arc::new(Logger {
            store,
            any: AtomicBool::new(any),
            targets: RwLock::new(HashMap::new()),
            buffers: Mutex::new(HashMap::new()),
            buffered: AtomicU64::new(0),
            stats: Arc::new(Stats::default()),
        })
    }

    pub fn enabled(&self) -> bool {
        self.any.load(Relaxed)
    }

    /// A bucket's logging configuration changed.
    pub fn invalidate(&self, bucket: &str, enabled: bool) {
        self.targets.write().unwrap().remove(bucket);
        if enabled {
            self.any.store(true, Relaxed);
        }
    }

    fn target(&self, bucket: &str) -> Option<Arc<Target>> {
        if let Some(t) = self.targets.read().unwrap().get(bucket) {
            return t.clone();
        }
        let t = self
            .store
            .bucket_config(bucket, "logging")
            .ok()
            .flatten()
            .and_then(|v| xml::parse(&String::from_utf8_lossy(&v)))
            .and_then(|d| parse_config(&d).ok().flatten())
            .map(Arc::new);
        let mut cache = self.targets.write().unwrap();
        if cache.len() > 10_000 {
            cache.clear();
        }
        cache.insert(bucket.to_string(), t.clone());
        t
    }

    /// Record a finished request (called when its access log entry is written).
    pub fn record(&self, e: &Entry) {
        if !self.enabled() {
            return;
        }
        let Some(bucket) = e.record.bucket.as_deref() else { return };
        let Some(target) = self.target(bucket) else { return };
        if self.buffered.load(Relaxed) as usize > MAX_BUFFERED {
            self.stats.dropped.fetch_add(1, Relaxed);
            return;
        }
        let line = format_line(e, bucket, crate::util::now_ms());
        self.buffered.fetch_add(line.len() as u64, Relaxed);
        let mut buffers = self.buffers.lock().unwrap();
        let b = buffers.entry((target, bucket.to_string())).or_insert_with(|| Buffer { data: Vec::new(), since: Instant::now() });
        b.data.extend_from_slice(line.as_bytes());
    }

    /// Take the buffers that are due (all of them with `all`).
    pub fn take_due(&self, all: bool) -> Vec<(Arc<Target>, String, Vec<u8>)> {
        let mut buffers = self.buffers.lock().unwrap();
        let due: Vec<(Arc<Target>, String)> = buffers
            .iter()
            .filter(|(_, b)| all || b.data.len() >= FLUSH_BYTES || b.since.elapsed() >= FLUSH_AFTER)
            .map(|(k, _)| k.clone())
            .collect();
        due.into_iter()
            .filter_map(|k| {
                let b = buffers.remove(&k)?;
                self.buffered.fetch_sub((b.data.len() as u64).min(self.buffered.load(Relaxed)), Relaxed);
                Some((k.0, k.1, b.data))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accesslog::Record;

    #[test]
    fn configs_and_keys() {
        let on = xml::parse(
            "<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>web/</TargetPrefix>\
             <TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat>\
             </LoggingEnabled></BucketLoggingStatus>",
        )
        .unwrap();
        let t = parse_config(&on).unwrap().unwrap();
        assert_eq!((t.bucket.as_str(), t.prefix.as_str(), t.partitioned), ("logs", "web/", true));
        assert_eq!(parse_config(&xml::parse(&config_xml(Some(&t))).unwrap()).unwrap().unwrap(), t);
        assert!(parse_config(&xml::parse("<BucketLoggingStatus/>").unwrap()).unwrap().is_none());
        assert!(parse_config(&xml::parse("<Other/>").unwrap()).is_err());
        let k = object_key(&t, "site", "us-east-1", 1_700_000_000);
        assert!(k.starts_with("web/s3rs/us-east-1/site/2023/11/14/2023-11-14-22-13-20-"), "{k}");
        let simple = Target { partitioned: false, ..t };
        assert!(object_key(&simple, "site", "r", 1_700_000_000).starts_with("web/2023-11-14-22-13-20-"));
    }

    #[test]
    fn lines() {
        let record =
            Record { bucket: Some("b".into()), key: Some("a b/c.txt".into()), user: Some("AKID".into()), client_ip: None };
        let e = Entry {
            endpoint: "api",
            request_id: "RID",
            remote_ip: "10.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/b/a%20b/c.txt",
            query: "",
            status: 200,
            error: None,
            bytes_in: None,
            bytes_out: Some(42),
            duration: Duration::from_millis(7),
            user_agent: Some("aws-cli/2 \"x\""),
            record: &record,
            aborted: false,
        };
        let line = format_line(&e, "b", 1_700_000_000_000);
        assert!(
            line.starts_with(
                "s3rs b [14/Nov/2023:22:13:20 +0000] 10.0.0.1 AKID RID REST.GET.OBJECT a%20b/c.txt \"GET /b/a%20b/c.txt HTTP/1.1\" 200 - 42 - 7 - \"-\" \"aws-cli/2 \\\"x\\\"\""
            ),
            "{line}"
        );
        assert!(line.ends_with(" SigV4 - AuthHeader - - - -\n"), "{line}");
        assert_eq!(operation("PUT", "partNumber=1&uploadId=x", true), "REST.PUT.PART");
        assert_eq!(operation("POST", "uploads", true), "REST.POST.UPLOADS");
        assert_eq!(operation("GET", "list-type=2", false), "REST.GET.BUCKET");
        assert_eq!(operation("PUT", "acl", false), "REST.PUT.ACL");
    }
}
