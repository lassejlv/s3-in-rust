//! Access log: one line per request on stdout, as text or JSON (for log pipelines).
//!
//! Lines are handed to a dedicated thread through a bounded queue and written in batches, so a
//! slow log sink never slows requests down; if the queue is full, lines are dropped and counted
//! (`s3rs_access_log_dropped_total`).

use std::fmt::Write as _;
use std::io::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
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
}

pub struct AccessLog {
    format: Format,
    tx: mpsc::SyncSender<Msg>,
    pub dropped: AtomicU64,
}

enum Msg {
    Line(String),
    /// Reply once everything before it is written.
    Flush(mpsc::Sender<()>),
}

const QUEUE: usize = 65_536;

impl AccessLog {
    pub fn new(format: Format) -> AccessLog {
        let (tx, rx) = mpsc::sync_channel::<Msg>(QUEUE);
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
        AccessLog { format, tx, dropped: AtomicU64::new(0) }
    }

    pub fn log(&self, e: &Entry) {
        let line = match self.format {
            Format::Text => text(e),
            Format::Json => json(e),
        };
        if self.tx.try_send(Msg::Line(line)).is_err() {
            self.dropped.fetch_add(1, Relaxed);
        }
    }

    /// Wait (briefly) until every line logged so far is written.
    pub fn flush(&self) {
        let (done, wait) = mpsc::channel();
        if self.tx.send(Msg::Flush(done)).is_ok() {
            let _ = wait.recv_timeout(Duration::from_secs(5));
        }
    }
}

/// Query parameters that carry secrets (presigned URL signatures, session tokens).
const SECRET_PARAMS: &[&str] = &["x-amz-signature", "signature", "x-amz-security-token"];

/// The query string with secret values replaced.
pub fn redact_query(q: &str) -> String {
    q.split('&')
        .map(|p| {
            let name = p.split('=').next().unwrap_or("");
            if SECRET_PARAMS.iter().any(|s| name.eq_ignore_ascii_case(s)) { format!("{name}=REDACTED") } else { p.to_string() }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn ip(e: &Entry) -> IpAddr {
    e.record.client_ip.unwrap_or(e.remote_ip)
}

fn text(e: &Entry) -> String {
    let q = if e.query.is_empty() { String::new() } else { format!("?{}", redact_query(e.query)) };
    let mut s = format!(
        "{} {} {} {}{q} -> {} ({:.2}ms)",
        ip(e),
        e.record.user.as_deref().unwrap_or("-"),
        e.method,
        e.path,
        e.status,
        e.duration.as_secs_f64() * 1000.0
    );
    if let Some(code) = e.error {
        let _ = write!(s, " {code}");
    }
    let _ = write!(s, " id={}", e.request_id);
    s.push('\n');
    s
}

fn json_str(out: &mut String, v: &str) {
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
    field("user", e.record.user.as_deref());
    field("method", Some(e.method));
    field("path", Some(e.path));
    let q = redact_query(e.query);
    field("query", (!e.query.is_empty()).then_some(q.as_str()));
    field("bucket", e.record.bucket.as_deref());
    field("key", e.record.key.as_deref());
    field("error", e.error);
    field("user_agent", e.user_agent);
    let _ = write!(s, ",\"status\":{}", e.status);
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
