//! Access log: one line per request on stdout, as text or JSON (for log pipelines).
//!
//! Lines are handed to a dedicated thread through a queue bounded in lines and bytes and written
//! in batches, so a slow log sink never slows requests down or grows memory; if the queue is full,
//! lines are dropped and counted (`s3rs_access_log_dropped_total`). Client-supplied fields are
//! truncated, so a line stays small whatever the request carries.

use std::fmt::Write as _;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Format {
    Text,
    Json,
}

impl Format {
    pub fn parse(v: &str) -> Result<Option<Format>, String> {
        match v.to_ascii_lowercase().as_str() {
            "off" | "none" | "" => Ok(None),
            "text" => Ok(Some(Format::Text)),
            "json" => Ok(Some(Format::Json)),
            _ => Err(format!("`{v}`: expected json, text or off")),
        }
    }
}

/// What is known about a request; filled in by the router as it goes.
#[derive(Default)]
pub struct Record {
    pub bucket: Option<String>,
    pub key: Option<String>,
    /// Access key of an authenticated request.
    pub user: Option<String>,
    /// Client address (as reported by a trusted proxy with --behind-proxy).
    pub client_ip: Option<IpAddr>,
}

pub struct Entry<'a> {
    pub endpoint: &'static str,
    pub request_id: &'a str,
    pub remote_ip: IpAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub status: u16,
    pub error: Option<&'a str>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub duration: Duration,
    pub user_agent: Option<&'a str>,
    pub record: &'a Record,
    /// The response body was cut short (the client went away, or the stream failed).
    pub aborted: bool,
}

/// A request's log line, written when it is dropped: after the response body has been sent
/// (with the bytes actually sent and the full duration), or, if the client goes away before
/// the response, with status 499 ("client closed request").
pub struct PendingLog {
    log: Arc<AccessLog>,
    endpoint: &'static str,
    request_id: String,
    remote_ip: IpAddr,
    method: String,
    path: String,
    query: String,
    user_agent: Option<String>,
    bytes_in: Option<u64>,
    pub record: Record,
    status: u16,
    error: Option<&'static str>,
    bytes_out: u64,
    aborted: bool,
    started: std::time::Instant,
}

impl PendingLog {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        log: Arc<AccessLog>,
        endpoint: &'static str,
        request_id: &str,
        remote_ip: IpAddr,
        method: &str,
        path: &str,
        query: &str,
        user_agent: Option<&str>,
        bytes_in: Option<u64>,
    ) -> Self {
        PendingLog {
            log,
            endpoint,
            request_id: request_id.to_string(),
            remote_ip,
            method: clip(method, MAX_SHORT).into_owned(),
            path: clip(path, MAX_PATH).into_owned(),
            query: clip(query, MAX_QUERY).into_owned(),
            user_agent: user_agent.map(|u| clip(u, MAX_UA).into_owned()),
            bytes_in,
            record: Record::default(),
            status: 499,
            error: None,
            bytes_out: 0,
            aborted: false,
            started: std::time::Instant::now(),
        }
    }

    pub fn respond(&mut self, status: u16, error: Option<&'static str>) {
        self.status = status;
        self.error = error;
    }

    pub fn sent(&mut self, n: u64) {
        self.bytes_out += n;
    }

    pub fn set_aborted(&mut self) {
        self.aborted = true;
    }
}

impl Drop for PendingLog {
    fn drop(&mut self) {
        self.log.log(&Entry {
            endpoint: self.endpoint,
            request_id: &self.request_id,
            remote_ip: self.remote_ip,
            method: &self.method,
            path: &self.path,
            query: &self.query,
            status: self.status,
            error: self.error,
            bytes_in: self.bytes_in,
            bytes_out: Some(self.bytes_out),
            duration: self.started.elapsed(),
            user_agent: self.user_agent.as_deref(),
            record: &self.record,
            aborted: self.aborted,
        });
    }
}

pub struct AccessLog {
    format: Format,
    tx: mpsc::SyncSender<Msg>,
    /// Bytes of lines queued but not yet written.
    queued: Arc<AtomicUsize>,
    pub dropped: AtomicU64,
}

enum Msg {
    Line(String),
    /// Reply once everything before it is written.
    Flush(mpsc::Sender<()>),
}

const QUEUE: usize = 65_536;
const QUEUE_BYTES: usize = 16 << 20;

/// `s` cut to at most `max` bytes (at a character boundary), marked with `…` when cut.
fn clip(s: &str, max: usize) -> std::borrow::Cow<'_, str> {
    if s.len() <= max {
        return s.into();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end]).into()
}

impl AccessLog {
    pub fn new(format: Format) -> AccessLog {
        let (tx, rx) = mpsc::sync_channel::<Msg>(QUEUE);
        let queued = Arc::new(AtomicUsize::new(0));
        let written = queued.clone();
        std::thread::Builder::new()
            .name("s3rs-accesslog".into())
            .spawn(move || {
                let mut out = std::io::BufWriter::with_capacity(64 * 1024, std::io::stdout().lock());
                // Write whatever is queued, then flush before waiting for more.
                while let Ok(first) = rx.recv() {
                    let mut waiting = Vec::new();
                    for msg in std::iter::once(first).chain(std::iter::from_fn(|| rx.try_recv().ok())) {
                        match msg {
                            Msg::Line(line) => {
                                let _ = out.write_all(line.as_bytes());
                                written.fetch_sub(line.len(), Relaxed);
                            }
                            Msg::Flush(done) => waiting.push(done),
                        }
                    }
                    let _ = out.flush();
                    for done in waiting {
                        let _ = done.send(());
                    }
                }
                let _ = out.flush();
            })
            .expect("spawn access log thread");
        AccessLog { format, tx, queued, dropped: AtomicU64::new(0) }
    }

    pub fn log(&self, e: &Entry) {
        let line = match self.format {
            Format::Text => text(e),
            Format::Json => json(e),
        };
        let n = line.len();
        if self.queued.fetch_add(n, Relaxed) + n > QUEUE_BYTES {
            self.queued.fetch_sub(n, Relaxed);
            self.dropped.fetch_add(1, Relaxed);
            return;
        }
        if self.tx.try_send(Msg::Line(line)).is_err() {
            self.queued.fetch_sub(n, Relaxed);
            self.dropped.fetch_add(1, Relaxed);
        }
    }

    /// Wait (at most a few seconds, even if stdout is stuck) until every line logged so far is
    /// written.
    pub fn flush(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (done, wait) = mpsc::channel();
        let mut msg = Msg::Flush(done);
        loop {
            match self.tx.try_send(msg) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Full(m)) if std::time::Instant::now() < deadline => {
                    msg = m;
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
        let _ = wait.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
    }
}

/// Field length limits (bytes): a valid key is at most 1024 bytes.
const MAX_PATH: usize = 2048;
const MAX_QUERY: usize = 2048;
const MAX_UA: usize = 512;
const MAX_SHORT: usize = 128;

/// Query parameters that carry secrets (presigned URL signatures, session tokens).
const SECRET_PARAMS: &[&str] = &["x-amz-signature", "signature", "x-amz-security-token"];

/// The query string with secret values replaced.
pub fn redact_query(q: &str) -> String {
    q.split('&')
        .map(|p| {
            let name = p.split('=').next().unwrap_or("");
            // Compare decoded names: `X-Amz-Signatur%65` is the same parameter to the server.
            let decoded = crate::util::uri_decode(name, true).unwrap_or_else(|| name.to_string());
            if SECRET_PARAMS.iter().any(|s| decoded.eq_ignore_ascii_case(s)) { format!("{name}=REDACTED") } else { p.to_string() }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn ip(e: &Entry) -> IpAddr {
    e.record.client_ip.unwrap_or(e.remote_ip)
}

fn text(e: &Entry) -> String {
    let q = if e.query.is_empty() { String::new() } else { format!("?{}", clip(&redact_query(e.query), MAX_QUERY)) };
    let mut s = format!(
        "{} {} {} {}{q} -> {} ({:.2}ms)",
        ip(e),
        clip(e.record.user.as_deref().unwrap_or("-"), MAX_SHORT),
        clip(e.method, MAX_SHORT),
        clip(e.path, MAX_PATH),
        e.status,
        e.duration.as_secs_f64() * 1000.0
    );
    if let Some(code) = e.error {
        let _ = write!(s, " {code}");
    }
    if e.aborted {
        s.push_str(" aborted");
    }
    let _ = write!(s, " id={}", e.request_id);
    s.push('\n');
    s
}

pub(crate) fn json_str(out: &mut String, v: &str) {
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json(e: &Entry) -> String {
    let mut s = String::with_capacity(320);
    s.push_str("{\"time\":");
    json_str(&mut s, &crate::util::iso8601(crate::util::now_ms()));
    let mut field = |name: &str, v: Option<&str>| {
        if let Some(v) = v {
            let _ = write!(s, ",\"{name}\":");
            json_str(&mut s, v);
        }
    };
    field("request_id", Some(e.request_id));
    field("endpoint", Some(e.endpoint));
    field("remote_ip", Some(&ip(e).to_string()));
    field("user", e.record.user.as_deref().map(|v| clip(v, MAX_SHORT)).as_deref());
    field("method", Some(&clip(e.method, MAX_SHORT)));
    field("path", Some(&clip(e.path, MAX_PATH)));
    let q = clip(&redact_query(e.query), MAX_QUERY).into_owned();
    field("query", (!e.query.is_empty()).then_some(q.as_str()));
    field("bucket", e.record.bucket.as_deref().map(|v| clip(v, MAX_SHORT)).as_deref());
    field("key", e.record.key.as_deref().map(|v| clip(v, MAX_PATH)).as_deref());
    field("error", e.error);
    field("user_agent", e.user_agent.map(|v| clip(v, MAX_UA)).as_deref());
    let _ = write!(s, ",\"status\":{}", e.status);
    if e.aborted {
        s.push_str(",\"aborted\":true");
    }
    if let Some(n) = e.bytes_in {
        let _ = write!(s, ",\"bytes_in\":{n}");
    }
    if let Some(n) = e.bytes_out {
        let _ = write!(s, ",\"bytes_out\":{n}");
    }
    let _ = writeln!(s, ",\"duration_ms\":{:.3}}}", e.duration.as_secs_f64() * 1000.0);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secrets_and_escapes_json() {
        assert_eq!(
            redact_query("X-Amz-Credential=AK%2F2024&X-Amz-Signature=abc&list-type=2"),
            "X-Amz-Credential=AK%2F2024&X-Amz-Signature=REDACTED&list-type=2"
        );
        assert_eq!(redact_query("Signature=x&AWSAccessKeyId=AK"), "Signature=REDACTED&AWSAccessKeyId=AK");
        assert_eq!(redact_query("X-Amz-Signatur%65=s&x=1"), "X-Amz-Signatur%65=REDACTED&x=1");
        assert_eq!(clip("aé", 2), "a…");
        assert_eq!(clip("abc", 3), "abc");
        let rec = Record { bucket: Some("b".into()), key: Some("a\"b\n\u{1}".into()), user: Some("ak".into()), client_ip: None };
        let e = Entry {
            endpoint: "api",
            request_id: "R1",
            remote_ip: "10.0.0.1".parse().unwrap(),
            method: "GET",
            path: "/b/a%22b",
            query: "X-Amz-Signature=s",
            status: 404,
            error: Some("NoSuchKey"),
            bytes_in: None,
            bytes_out: Some(12),
            duration: Duration::from_micros(1500),
            user_agent: Some("aws-cli/2"),
            record: &rec,
            aborted: false,
        };
        let j = json(&e);
        assert!(j.ends_with("}\n") && !j[..j.len() - 1].contains('\n'), "{j}");
        assert!(j.contains(r#""key":"a\"b\n\u0001""#), "{j}");
        assert!(j.contains(r#""query":"X-Amz-Signature=REDACTED""#), "{j}");
        assert!(j.contains(r#""status":404"#) && j.contains(r#""bytes_out":12"#) && j.contains(r#""duration_ms":1.500"#), "{j}");
        let t = text(&e);
        assert!(t.starts_with("10.0.0.1 ak GET /b/a%22b?X-Amz-Signature=REDACTED -> 404 (1.50ms) NoSuchKey id=R1"), "{t}");
    }
}
