//! Event notification targets other than webhooks: NATS subjects and Redis lists or channels.
//! Both speak small text protocols over TCP, implemented here directly:
//!
//! - `nats://[user:pass@ | token@]host[:4222]/subject` publishes each event to the subject
//!   (`PUB`), and counts it delivered once the server has answered the `PING` sent after it.
//! - `redis://[[user]:pass@]host[:6379]/key[?db=N]` appends each event to a list (`RPUSH`);
//!   with `?publish` it is published on the channel `key` instead (`PUBLISH`).
//!
//! Events go through the same durable, ordered, at-least-once queue as webhooks.

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;

/// The longest protocol line read from a server (NATS INFO lines are a few KiB).
const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Nats { subject: String },
    Redis { key: String, publish: bool, db: Option<u32> },
}

/// A NATS or Redis endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct Endpoint {
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

impl Endpoint {
    /// `None` if `s` is not a nats:// or redis:// URL.
    pub fn parse(s: &str) -> Option<Result<Endpoint, String>> {
        let (scheme, rest) = s.split_once("://")?;
        let default_port = match scheme {
            "nats" => 4222,
            "redis" => 6379,
            _ => return None,
        };
        Some(parse(s, scheme, rest, default_port))
    }

    /// For logs: the password is not shown.
    pub fn describe(&self) -> String {
        let auth = match (&self.user, &self.password) {
            (Some(u), Some(_)) => format!("{u}:***@"),
            (None, Some(_)) => "***@".to_string(),
            (Some(u), None) => format!("{u}@"),
            (None, None) => String::new(),
        };
        let (scheme, path) = match &self.kind {
            Kind::Nats { subject } => ("nats", subject.clone()),
            Kind::Redis { key, publish, db } => {
                let mut q = Vec::new();
                if *publish {
                    q.push("publish".to_string());
                }
                if let Some(d) = db {
                    q.push(format!("db={d}"));
                }
                ("redis", if q.is_empty() { key.clone() } else { format!("{key}?{}", q.join("&")) })
            }
        };
        format!("{scheme}://{auth}{}:{}/{path}", self.host, self.port)
    }
}

fn parse(s: &str, scheme: &str, rest: &str, default_port: u16) -> Result<Endpoint, String> {
    let bad = |what: &str| format!("{s}: invalid {what}");
    let (authority, path) = rest.split_once('/').ok_or_else(|| format!("{s}: missing the /subject or /key"))?;
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let decode = |v: &str| crate::util::uri_decode(v, false).ok_or_else(|| bad("credentials"));
    let (user, password) = match userinfo {
        None => (None, None),
        Some(u) => match u.split_once(':') {
            Some((user, pass)) => ((!user.is_empty()).then(|| decode(user)).transpose()?, Some(decode(pass)?)),
            // nats://token@host: a token alone.
            None => (None, Some(decode(u)?)),
        },
    };
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (addr, after) = r.split_once(']').ok_or_else(|| bad("host"))?;
        addr.parse::<std::net::Ipv6Addr>().map_err(|_| bad("IPv6 address"))?;
        let port = match after {
            "" => default_port,
            p => p.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or_else(|| bad("port"))?,
        };
        (addr.to_string(), port)
    } else {
        let (h, p) = match hostport.split_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad("port"))?),
            None => (hostport, default_port),
        };
        if h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            return Err(bad("host"));
        }
        (h.to_string(), p)
    };
    if port == 0 {
        return Err(bad("port"));
    }
    let (name, query) = path.split_once('?').unwrap_or((path, ""));
    let name = crate::util::uri_decode(name, false).ok_or_else(|| bad("name"))?;
    if name.is_empty() || name.len() > 1024 || !name.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("{s}: the subject or key must be non-empty printable ASCII without spaces"));
    }
    let kind = match scheme {
        "nats" => {
            if !query.is_empty() {
                return Err(bad("query (nats:// takes none)"));
            }
            if name.split('.').any(str::is_empty) || name.contains(['*', '>']) {
                return Err(bad("subject (no wildcards or empty tokens)"));
            }
            Kind::Nats { subject: name }
        }
        _ => {
            let (mut publish, mut db) = (false, None);
            for q in query.split('&').filter(|q| !q.is_empty()) {
                match q.split_once('=') {
                    None if q == "publish" => publish = true,
                    Some(("db", n)) => db = Some(n.parse().map_err(|_| bad("db"))?),
                    _ => return Err(bad("query (use publish and/or db=N)")),
                }
            }
            Kind::Redis { key: name, publish, db }
        }
    };
    Ok(Endpoint { kind, host, port, user, password })
}

/// An open connection to a target.
pub struct Conn {
    io: BufStream<TcpStream>,
}

/// What the server said about one event.
pub enum Answer {
    Accepted,
    /// The server will never take this event (it is dropped so the queue can move on).
    Rejected(String),
}

async fn read_line(io: &mut BufStream<TcpStream>) -> Result<String, String> {
    let mut line = Vec::new();
    loop {
        let buf = io.fill_buf().await.map_err(|e| e.to_string())?;
        if buf.is_empty() {
            return Err("the server closed the connection".into());
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(i) => {
                line.extend_from_slice(&buf[..i]);
                io.consume(i + 1);
                break;
            }
            None => {
                let n = buf.len();
                line.extend_from_slice(buf);
                io.consume(n);
            }
        }
        if line.len() > MAX_LINE {
            return Err("the server sent an overlong line".into());
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// RESP: a command as an array of bulk strings.
fn resp(args: &[&[u8]]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    out
}

async fn redis_ok(io: &mut BufStream<TcpStream>, what: &str) -> Result<(), String> {
    let line = read_line(io).await?;
    if line.starts_with('+') { Ok(()) } else { Err(format!("{what}: {}", line.trim_start_matches('-'))) }
}

async fn open(ep: &Endpoint) -> Result<Conn, String> {
    let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((ep.host.as_str(), ep.port)))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let _ = stream.set_nodelay(true);
    let mut io = BufStream::new(stream);
    match &ep.kind {
        Kind::Nats { .. } => {
            let info = read_line(&mut io).await?;
            if !info.starts_with("INFO ") {
                return Err(format!("not a NATS server (it said {:?})", info.chars().take(40).collect::<String>()));
            }
            let s = |v: &str| crate::access::Json::Str(v.to_string());
            let mut fields = vec![
                ("verbose".to_string(), crate::access::Json::Bool(false)),
                ("pedantic".to_string(), crate::access::Json::Bool(false)),
                ("name".to_string(), s("s3rs")),
                ("lang".to_string(), s("rust")),
                ("version".to_string(), s(env!("CARGO_PKG_VERSION"))),
                ("protocol".to_string(), crate::access::Json::Num(1.0)),
            ];
            match (&ep.user, &ep.password) {
                (Some(u), Some(p)) => fields.extend([("user".to_string(), s(u)), ("pass".to_string(), s(p))]),
                (None, Some(t)) => fields.push(("auth_token".to_string(), s(t))),
                _ => {}
            }
            let connect = format!("CONNECT {}\r\nPING\r\n", crate::access::Json::Obj(fields).to_text());
            io.write_all(connect.as_bytes()).await.map_err(|e| e.to_string())?;
            io.flush().await.map_err(|e| e.to_string())?;
            nats_pong(&mut io).await?;
        }
        Kind::Redis { db, .. } => {
            if let Some(p) = &ep.password {
                let cmd = match &ep.user {
                    Some(u) => resp(&[b"AUTH", u.as_bytes(), p.as_bytes()]),
                    None => resp(&[b"AUTH", p.as_bytes()]),
                };
                io.write_all(&cmd).await.map_err(|e| e.to_string())?;
                io.flush().await.map_err(|e| e.to_string())?;
                redis_ok(&mut io, "AUTH").await?;
            }
            if let Some(n) = db {
                io.write_all(&resp(&[b"SELECT", n.to_string().as_bytes()])).await.map_err(|e| e.to_string())?;
                io.flush().await.map_err(|e| e.to_string())?;
                redis_ok(&mut io, "SELECT").await?;
            }
        }
    }
    Ok(Conn { io })
}

/// Read NATS protocol lines until the PONG that answers our PING.
async fn nats_pong(io: &mut BufStream<TcpStream>) -> Result<Answer, String> {
    loop {
        let line = read_line(io).await?;
        match line.split(' ').next().unwrap_or("") {
            "PONG" => return Ok(Answer::Accepted),
            "PING" => {
                io.write_all(b"PONG\r\n").await.map_err(|e| e.to_string())?;
                io.flush().await.map_err(|e| e.to_string())?;
            }
            "+OK" | "INFO" | "" => {}
            "-ERR" if line.contains("Maximum Payload") => return Ok(Answer::Rejected(line)),
            "-ERR" => return Err(line),
            _ => return Err(format!("unexpected answer {:?}", line.chars().take(60).collect::<String>())),
        }
    }
}

/// Send one event, opening the connection if needed. On an error the connection is dropped (and
/// reopened for the next attempt).
pub async fn send(conn: &mut Option<Conn>, ep: &Endpoint, body: &[u8], timeout: Duration) -> Result<Answer, String> {
    let result = tokio::time::timeout(timeout, async {
        if conn.is_none() {
            *conn = Some(open(ep).await?);
        }
        let io = &mut conn.as_mut().unwrap().io;
        match &ep.kind {
            Kind::Nats { subject } => {
                let mut msg = format!("PUB {subject} {}\r\n", body.len()).into_bytes();
                msg.extend_from_slice(body);
                msg.extend_from_slice(b"\r\nPING\r\n");
                io.write_all(&msg).await.map_err(|e| e.to_string())?;
                io.flush().await.map_err(|e| e.to_string())?;
                nats_pong(io).await
            }
            Kind::Redis { key, publish, .. } => {
                let cmd: &[u8] = if *publish { b"PUBLISH" } else { b"RPUSH" };
                io.write_all(&resp(&[cmd, key.as_bytes(), body])).await.map_err(|e| e.to_string())?;
                io.flush().await.map_err(|e| e.to_string())?;
                let line = read_line(io).await?;
                match line.as_bytes().first() {
                    Some(b':') => Ok(Answer::Accepted),
                    _ => Err(line.trim_start_matches('-').to_string()),
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err("timed out".into()));
    if result.is_err() {
        *conn = None;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let e = Endpoint::parse("nats://alice:s%40cret@nats.internal/s3.events").unwrap().unwrap();
        assert_eq!(e.kind, Kind::Nats { subject: "s3.events".into() });
        assert_eq!(
            (e.host.as_str(), e.port, e.user.as_deref(), e.password.as_deref()),
            ("nats.internal", 4222, Some("alice"), Some("s@cret"))
        );
        assert_eq!(e.describe(), "nats://alice:***@nats.internal:4222/s3.events");
        let t = Endpoint::parse("nats://tok@[::1]:5222/a").unwrap().unwrap();
        assert_eq!((t.host.as_str(), t.port, t.user.as_deref(), t.password.as_deref()), ("::1", 5222, None, Some("tok")));
        let r = Endpoint::parse("redis://:pw@127.0.0.1/s3-events?db=2").unwrap().unwrap();
        assert_eq!(r.kind, Kind::Redis { key: "s3-events".into(), publish: false, db: Some(2) });
        assert_eq!((r.port, r.user.as_deref(), r.password.as_deref()), (6379, None, Some("pw")));
        assert_eq!(r.describe(), "redis://***@127.0.0.1:6379/s3-events?db=2");
        let p = Endpoint::parse("redis://cache:6380/ch?publish").unwrap().unwrap();
        assert_eq!(p.kind, Kind::Redis { key: "ch".into(), publish: true, db: None });
        assert!(Endpoint::parse("http://h/x").is_none() && Endpoint::parse("nope").is_none());
        for bad in [
            "nats://h",
            "nats://h/",
            "nats://h/a b",
            "nats://h/a.*",
            "nats://h/a..b",
            "nats://h:0/a",
            "nats://h/a?x",
            "redis://h/k?db=x",
            "redis://h/k?other",
            "redis://h h/k",
        ] {
            assert!(Endpoint::parse(bad).unwrap().is_err(), "{bad}");
        }
    }

    #[test]
    fn resp_encoding() {
        assert_eq!(resp(&[b"RPUSH", b"k", b"a\r\nb"]), b"*3\r\n$5\r\nRPUSH\r\n$1\r\nk\r\n$4\r\na\r\nb\r\n".to_vec());
    }
}
