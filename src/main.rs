//! s3rs — a fast, lightweight, S3-compatible object storage server in pure Rust.
#![deny(clippy::print_stderr)]

/// `eprintln!` that never panics: stderr may be a file on a full disk, or a closed pipe, and a
/// failed diagnostic must not take down the thread that wrote it.
macro_rules! elog {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}

mod access;
mod accesslog;
mod auth;
mod body;
mod bucketlog;
mod checksum;
mod chunked;
mod conn;
mod console;
mod crypt;
mod error;
mod events;
#[cfg(test)]
mod fuzz;
mod iam;
mod io;
mod keys;
mod lifecycle;
mod lock;
mod metrics;
mod ops;
mod post;
mod ratelimit;
mod replication;
mod s3;
mod store;
mod tls;
mod util;
mod website;
mod xml;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

pub const OWNER_ID: &str = "s3rs";

/// How long a graceful shutdown waits for in-flight requests.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

const USAGE: &str = "\
s3rs - fast, lightweight S3-compatible object storage

USAGE:
    s3rs [OPTIONS]               Run the server
    s3rs fsck [--help]           Check a stopped server's data directory
    s3rs backup [--help]         Archive a stopped server's data directory
    s3rs healthcheck [--help]    Probe a running server (for container health checks)

OPTIONS (each also settable through the environment variable shown):
    -l, --listen <ADDR>          Address to listen on            [S3RS_LISTEN, default 0.0.0.0:9000]
    -d, --data-dir <PATH>        Data directory                  [S3RS_DATA_DIR, default ./data]
        --access-key <KEY>       Access key id                   [S3RS_ACCESS_KEY]
        --secret-key <SECRET>    Secret access key               [S3RS_SECRET_KEY]
        --credentials-file <P>   Extra keys, one `access_key:secret_key[:ro|rw[:buckets]]` per
                                 line; buckets is a comma-separated list of name patterns
                                                                 [S3RS_CREDENTIALS_FILE]
        --anonymous              Disable authentication (only for trusted networks)
        --cors-origins <LIST>    Comma-separated origins allowed by default for buckets
                                 without their own CORS configuration, e.g. `*`
                                                                 [S3RS_CORS_ORIGINS]
        --encryption-key <K>     Master key for server-side encryption (SSE-S3): 64 hex chars
                                 or base64 (e.g. from `openssl rand -hex 32`)
                                                                 [S3RS_ENCRYPTION_KEY]
        --encryption-key-file <P> Read the master key from a file [S3RS_ENCRYPTION_KEY_FILE]
        --encrypt-by-default     Encrypt every new object with the master key
                                                                 [S3RS_ENCRYPT_BY_DEFAULT=1]
        --webhook <ID=URL>       Event notification target (repeatable), e.g.
                                 `thumbnails=https://worker.internal/s3-events`; buckets
                                 refer to it as arn:s3rs:webhook::<ID>
                                                                 [S3RS_WEBHOOKS, comma-separated]
        --webhook-secret <S>     Sign webhook bodies (X-S3rs-Signature: sha256=<hmac>)
                                                                 [S3RS_WEBHOOK_SECRET]
        --webhook-timeout <SECS> How long a webhook may take to answer (default 10)
                                                                 [S3RS_WEBHOOK_TIMEOUT]
        --tls-cert <PATH>        Serve HTTPS: PEM certificate chain (reloaded on SIGHUP)
                                                                 [S3RS_TLS_CERT]
        --tls-key <PATH>         PEM private key for --tls-cert  [S3RS_TLS_KEY]
        --webhook-ca <PATH>      Extra PEM CA certificates trusted for https:// webhooks and
                                 replication targets             [S3RS_WEBHOOK_CA]
        --replication-targets <P> Remote servers for bucket replication, one
                                 `ID URL ACCESS_KEY SECRET_KEY [REGION]` per line (reloaded
                                 on SIGHUP); buckets refer to them as
                                 arn:s3rs:replication::<ID>:<BUCKET>
                                                                 [S3RS_REPLICATION_TARGETS]
        --behind-proxy           Trust X-Forwarded-For / X-Forwarded-Proto from a reverse proxy
                                 (client IP and HTTPS for policy conditions and redirects)
                                                                 [S3RS_BEHIND_PROXY=1]
        --no-console             Do not serve the web console at /_console/
                                                                 [S3RS_NO_CONSOLE=1]
        --admin-token <T>        Enable the admin API (GET /_admin/backup) for
                                 `Authorization: Bearer <T>`     [S3RS_ADMIN_TOKEN]
        --metrics-token <T>      Require `Authorization: Bearer <T>` for /_metrics
                                                                 [S3RS_METRICS_TOKEN]
        --region <REGION>        Region reported to clients      [S3RS_REGION, default us-east-1]
        --domain <DOMAIN>        Enable virtual-hosted-style requests for <bucket>.<DOMAIN>
                                                                 [S3RS_DOMAIN]
        --website-listen <ADDR>  Serve static websites (anonymous GET/HEAD) on this address;
                                 the bucket is the Host name, or <bucket> for <bucket>.<DOMAIN>
                                 when --website-domain is set    [S3RS_WEBSITE_LISTEN]
        --website-domain <D>     Domain whose subdomains name website buckets
                                                                 [S3RS_WEBSITE_DOMAIN]
        --inline-threshold <N>   Objects up to N bytes are stored inside the metadata DB
                                                                 [S3RS_INLINE_THRESHOLD, default 65536]
        --cache-mb <N>           Metadata cache size in MiB      [S3RS_CACHE_MB, default 256]
        --rate-limit <N>         Requests per second per access key (bursts of 2 s worth;
                                 more get 503 SlowDown)          [S3RS_RATE_LIMIT, default off]
        --rate-limit-anonymous <N> Requests per second per client address for unsigned
                                 requests (public buckets, websites, browser uploads)
                                                                 [S3RS_RATE_LIMIT_ANONYMOUS, default off]
        --max-connections <N>    Stop accepting connections beyond N (new ones wait in the
                                 kernel's queue) [S3RS_MAX_CONNECTIONS, default from the
                                 file descriptor limit, at most 10000]
        --min-free-space <SIZE>  Refuse uploads when the data disk's free space would drop below
                                 SIZE (e.g. 512M, 2G; 0 = off) [S3RS_MIN_FREE_SPACE,
                                 default 2% of the disk, 16M..256M]
        --no-fsync               Do not fsync data or metadata (faster, less durable)
                                                                 [S3RS_NO_FSYNC=1]
        --lifecycle-interval <S> Seconds between lifecycle sweeps [S3RS_LIFECYCLE_INTERVAL, default 3600]
        --access-log <FORMAT>    Log every request to stdout: json or text
                                                                 [S3RS_ACCESS_LOG, default off]
    -v, --verbose                Same as --access-log text       [S3RS_VERBOSE=1]
    -V, --version                Print the version
    -h, --help                   Show this help
";

#[derive(Clone)]
struct Config {
    listen: SocketAddr,
    data_dir: PathBuf,
    access_key: Option<String>,
    secret_key: Option<String>,
    credentials_file: Option<PathBuf>,
    anonymous: bool,
    cors_origins: Vec<String>,
    metrics_token: Option<String>,
    admin_token: Option<String>,
    console: bool,
    behind_proxy: bool,
    webhooks: Vec<(String, events::Url)>,
    webhook_secret: Option<String>,
    webhook_timeout: u64,
    webhook_ca: Option<PathBuf>,
    replication_targets: Option<PathBuf>,
    rate_limit: Option<u32>,
    rate_limit_anonymous: Option<u32>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    encryption_key: Option<[u8; 32]>,
    encrypt_by_default: bool,
    region: String,
    domain: Option<String>,
    website_listen: Option<SocketAddr>,
    website_domain: Option<String>,
    inline_threshold: usize,
    cache_mb: usize,
    min_free: Option<u64>,
    max_connections: Option<usize>,
    fsync: bool,
    access_log: Option<accesslog::Format>,
    lifecycle_interval: u64,
    /// Length of a lifecycle "day" in seconds; only meant to be shortened for testing.
    lifecycle_day_secs: u64,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// The master key from S3RS_ENCRYPTION_KEY or the file named by S3RS_ENCRYPTION_KEY_FILE.
fn env_key() -> Result<Option<[u8; 32]>, String> {
    if let Some(k) = env("S3RS_ENCRYPTION_KEY") {
        return parse_key(&k).map(Some).map_err(|e| format!("S3RS_ENCRYPTION_KEY: {e}"));
    }
    match env("S3RS_ENCRYPTION_KEY_FILE") {
        Some(p) => {
            let text = std::fs::read_to_string(&p).map_err(|e| format!("S3RS_ENCRYPTION_KEY_FILE {p}: {e}"))?;
            parse_key(text.trim()).map(Some).map_err(|e| format!("S3RS_ENCRYPTION_KEY_FILE {p}: {e}"))
        }
        None => Ok(None),
    }
}

/// Boolean switch from the environment: 1/true/yes/on or 0/false/no/off (unset means off).
fn env_flag(name: &str) -> Result<bool, String> {
    match env(name).map(|v| v.to_ascii_lowercase()).as_deref() {
        None | Some("0" | "false" | "no" | "off") => Ok(false),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some(v) => Err(format!("{name}: expected 1/0, true/false, yes/no or on/off, got `{v}`")),
    }
}

fn parse_args() -> Result<Config, String> {
    let mut c = Config {
        listen: env("S3RS_LISTEN").unwrap_or_else(|| "0.0.0.0:9000".into()).parse().map_err(|e| format!("S3RS_LISTEN: {e}"))?,
        data_dir: env("S3RS_DATA_DIR").unwrap_or_else(|| "./data".into()).into(),
        access_key: env("S3RS_ACCESS_KEY"),
        secret_key: env("S3RS_SECRET_KEY"),
        credentials_file: env("S3RS_CREDENTIALS_FILE").map(PathBuf::from),
        anonymous: false,
        cors_origins: env("S3RS_CORS_ORIGINS").map(|v| split_list(&v)).unwrap_or_default(),
        metrics_token: env("S3RS_METRICS_TOKEN"),
        admin_token: env("S3RS_ADMIN_TOKEN"),
        console: !env_flag("S3RS_NO_CONSOLE")?,
        behind_proxy: env_flag("S3RS_BEHIND_PROXY")?,
        webhooks: env("S3RS_WEBHOOKS").map(|v| parse_webhooks(&v)).transpose()?.unwrap_or_default(),
        webhook_secret: env("S3RS_WEBHOOK_SECRET"),
        webhook_timeout: env("S3RS_WEBHOOK_TIMEOUT")
            .map(|v| v.parse().map_err(|_| "S3RS_WEBHOOK_TIMEOUT must be a number of seconds".to_string()))
            .transpose()?
            .unwrap_or(10),
        webhook_ca: env("S3RS_WEBHOOK_CA").map(PathBuf::from),
        replication_targets: env("S3RS_REPLICATION_TARGETS").map(PathBuf::from),
        rate_limit: env("S3RS_RATE_LIMIT").map(|v| parse_rate("S3RS_RATE_LIMIT", &v)).transpose()?.flatten(),
        rate_limit_anonymous: env("S3RS_RATE_LIMIT_ANONYMOUS")
            .map(|v| parse_rate("S3RS_RATE_LIMIT_ANONYMOUS", &v))
            .transpose()?
            .flatten(),
        tls_cert: env("S3RS_TLS_CERT").map(PathBuf::from),
        tls_key: env("S3RS_TLS_KEY").map(PathBuf::from),
        encryption_key: env_key()?,
        encrypt_by_default: env_flag("S3RS_ENCRYPT_BY_DEFAULT")?,
        region: env("S3RS_REGION").unwrap_or_else(|| "us-east-1".into()),
        domain: env("S3RS_DOMAIN").map(|d| d.to_ascii_lowercase()),
        website_listen: env("S3RS_WEBSITE_LISTEN")
            .map(|v| v.parse())
            .transpose()
            .map_err(|e| format!("S3RS_WEBSITE_LISTEN: {e}"))?,
        website_domain: env("S3RS_WEBSITE_DOMAIN").map(|d| d.to_ascii_lowercase()),
        inline_threshold: env("S3RS_INLINE_THRESHOLD")
            .map_or(Ok(65536), |v| v.parse())
            .map_err(|e| format!("S3RS_INLINE_THRESHOLD: {e}"))?,
        cache_mb: env("S3RS_CACHE_MB").map_or(Ok(256), |v| v.parse()).map_err(|e| format!("S3RS_CACHE_MB: {e}"))?,
        max_connections: env("S3RS_MAX_CONNECTIONS")
            .map(|v| v.parse())
            .transpose()
            .map_err(|e| format!("S3RS_MAX_CONNECTIONS: {e}"))?,
        min_free: env("S3RS_MIN_FREE_SPACE")
            .map(|v| parse_size(&v))
            .transpose()
            .map_err(|e| format!("S3RS_MIN_FREE_SPACE: {e}"))?,
        fsync: !env_flag("S3RS_NO_FSYNC")?,
        access_log: match env("S3RS_ACCESS_LOG") {
            Some(v) => accesslog::Format::parse(&v).map_err(|e| format!("S3RS_ACCESS_LOG: {e}"))?,
            None if env_flag("S3RS_VERBOSE")? => Some(accesslog::Format::Text),
            None => None,
        },
        lifecycle_interval: env("S3RS_LIFECYCLE_INTERVAL")
            .map_or(Ok(3600), |v| v.parse())
            .map_err(|e| format!("S3RS_LIFECYCLE_INTERVAL: {e}"))?,
        lifecycle_day_secs: env("S3RS_LIFECYCLE_DAY_SECS")
            .map_or(Ok(86_400), |v| v.parse())
            .map_err(|e| format!("S3RS_LIFECYCLE_DAY_SECS: {e}"))?,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let (flag, inline_val) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let mut val = || inline_val.clone().or_else(|| args.next()).ok_or_else(|| format!("{flag} requires a value"));
        match flag.as_str() {
            "-l" | "--listen" => c.listen = val()?.parse().map_err(|e| format!("--listen: {e}"))?,
            "-d" | "--data-dir" => c.data_dir = val()?.into(),
            "--access-key" => c.access_key = Some(val()?),
            "--secret-key" => c.secret_key = Some(val()?),
            "--credentials-file" => c.credentials_file = Some(val()?.into()),
            "--anonymous" => c.anonymous = true,
            "--cors-origins" => c.cors_origins = split_list(&val()?),
            "--metrics-token" => c.metrics_token = Some(val()?),
            "--admin-token" => c.admin_token = Some(val()?),
            "--no-console" => c.console = false,
            "--behind-proxy" => c.behind_proxy = true,
            "--webhook" => {
                let w = parse_webhook(&val()?)?;
                if c.webhooks.iter().any(|(id, _)| *id == w.0) {
                    return Err(format!("--webhook: duplicate id `{}`", w.0));
                }
                c.webhooks.push(w);
            }
            "--webhook-secret" => c.webhook_secret = Some(val()?),
            "--webhook-timeout" => {
                c.webhook_timeout = val()?.parse().map_err(|_| "--webhook-timeout must be a number of seconds".to_string())?
            }
            "--webhook-ca" => c.webhook_ca = Some(val()?.into()),
            "--replication-targets" => c.replication_targets = Some(val()?.into()),
            "--rate-limit" => c.rate_limit = parse_rate("--rate-limit", &val()?)?,
            "--rate-limit-anonymous" => c.rate_limit_anonymous = parse_rate("--rate-limit-anonymous", &val()?)?,
            "--tls-cert" => c.tls_cert = Some(val()?.into()),
            "--tls-key" => c.tls_key = Some(val()?.into()),
            "--encryption-key" => c.encryption_key = Some(parse_key(&val()?).map_err(|e| format!("--encryption-key: {e}"))?),
            "--encryption-key-file" => {
                let path = val()?;
                let text = std::fs::read_to_string(&path).map_err(|e| format!("--encryption-key-file {path}: {e}"))?;
                c.encryption_key = Some(parse_key(text.trim()).map_err(|e| format!("--encryption-key-file {path}: {e}"))?);
            }
            "--encrypt-by-default" => c.encrypt_by_default = true,
            "--region" => c.region = val()?,
            "--domain" => c.domain = Some(val()?.to_ascii_lowercase()),
            "--website-listen" => {
                c.website_listen = Some(val()?.parse().map_err(|e| format!("--website-listen: {e}"))?);
            }
            "--website-domain" => c.website_domain = Some(val()?.to_ascii_lowercase()),
            "--inline-threshold" => c.inline_threshold = val()?.parse().map_err(|e| format!("--inline-threshold: {e}"))?,
            "--cache-mb" => c.cache_mb = val()?.parse().map_err(|e| format!("--cache-mb: {e}"))?,
            "--max-connections" => c.max_connections = Some(val()?.parse().map_err(|e| format!("--max-connections: {e}"))?),
            "--min-free-space" => c.min_free = Some(parse_size(&val()?).map_err(|e| format!("--min-free-space: {e}"))?),
            "--no-fsync" => c.fsync = false,
            "--lifecycle-interval" => c.lifecycle_interval = val()?.parse().map_err(|e| format!("--lifecycle-interval: {e}"))?,
            "-v" | "--verbose" => c.access_log = Some(accesslog::Format::Text),
            "--access-log" => c.access_log = accesslog::Format::parse(&val()?).map_err(|e| format!("--access-log: {e}"))?,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("s3rs {}{}", env!("CARGO_PKG_VERSION"), if cfg!(feature = "tls") { " (tls)" } else { "" });
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }
    Ok(c)
}

/// Refuse empty tokens (an empty bearer token would match a request without one) and the
/// placeholder values from deploy/s3rs.env. Tokens are compared trimmed.
fn check_secrets(mut c: Config) -> Result<Config, String> {
    for (name, v) in [("--metrics-token", &mut c.metrics_token), ("--admin-token", &mut c.admin_token)] {
        if let Some(t) = v {
            *t = t.trim().to_string();
            if t.is_empty() {
                return Err(format!("{name} must not be empty"));
            }
        }
    }
    let placeholder = |v: &Option<String>| v.as_deref().is_some_and(|v| v.trim().eq_ignore_ascii_case("change-me"));
    for (name, v) in
        [("the secret key", &c.secret_key), ("the metrics token", &c.metrics_token), ("the admin token", &c.admin_token)]
    {
        if placeholder(v) {
            return Err(format!("{name} is still the placeholder `change-me`; set a real value"));
        }
    }
    Ok(c)
}

/// A size in bytes, optionally with a K/M/G/T suffix (powers of 1024), e.g. `512M`.
fn parse_size(v: &str) -> Result<u64, String> {
    let v = v.trim();
    let (num, mult) = match v.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => {
            let shift = match c.to_ascii_uppercase() {
                'K' => 10,
                'M' => 20,
                'G' => 30,
                'T' => 40,
                _ => return Err(format!("`{v}`: unknown size suffix (use K, M, G or T)")),
            };
            (&v[..i], 1u64 << shift)
        }
        _ => (v, 1),
    };
    num.trim().parse::<u64>().ok().and_then(|n| n.checked_mul(mult)).ok_or_else(|| format!("`{v}` is not a valid size"))
}

/// `S3RS_WEBHOOKS`: comma-separated `id=url` entries with unique ids.
/// A requests-per-second limit; 0 means none.
fn parse_rate(what: &str, v: &str) -> Result<Option<u32>, String> {
    let n: u32 = v.trim().parse().map_err(|_| format!("{what}: expected a number of requests per second, got `{v}`"))?;
    Ok((n > 0).then_some(n))
}

fn parse_webhooks(v: &str) -> Result<Vec<(String, events::Url)>, String> {
    let mut out: Vec<(String, events::Url)> = Vec::new();
    for w in split_list(v) {
        let w = parse_webhook(&w)?;
        if out.iter().any(|(id, _)| *id == w.0) {
            return Err(format!("S3RS_WEBHOOKS: duplicate id `{}`", w.0));
        }
        out.push(w);
    }
    Ok(out)
}

/// `id=http://host[:port]/path`
fn parse_webhook(s: &str) -> Result<(String, events::Url), String> {
    let (id, url) = s.split_once('=').ok_or_else(|| format!("--webhook {s}: expected ID=URL"))?;
    let id = id.trim();
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(format!("--webhook {s}: the id may only contain letters, digits, '-' and '_'"));
    }
    Ok((id.to_string(), events::Url::parse(url.trim()).map_err(|e| format!("--webhook: {e}"))?))
}

/// A 256-bit key given as 64 hex characters or base64.
fn parse_key(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    let bytes = if s.len() == 64 { util::unhex(s) } else { util::unbase64(s) };
    bytes
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| "expected a 256-bit key as 64 hex characters or base64 (e.g. `openssl rand -hex 32`)".to_string())
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

/// Parse a credentials file, one key per line (`#` starts a comment):
/// `access_key:secret_key[:ro|rw|policy=<file.json>[:bucket-pattern,bucket-pattern...]]`.
/// Policy file paths are relative to the credentials file.
fn load_credentials(path: &std::path::Path, into: &mut Vec<auth::Credential>) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.splitn(4, ':');
        let (Some(ak), Some(sk)) = (f.next(), f.next()) else {
            return Err(format!("{}:{}: expected access_key:secret_key[:ro]", path.display(), n + 1));
        };
        let (ak, sk) = (ak.trim(), sk.trim());
        let (read_only, policy) = match f.next().map(str::trim) {
            None | Some("rw") => (false, None),
            Some("ro") => (true, None),
            Some(p) if p.starts_with("policy=") => {
                let file = path.parent().unwrap_or(std::path::Path::new(".")).join(&p["policy=".len()..]);
                let doc = std::fs::read_to_string(&file)
                    .map_err(|e| format!("{}:{}: cannot read policy {}: {e}", path.display(), n + 1, file.display()))?;
                let policy = iam::Policy::parse(&doc, iam::Kind::Identity, None)
                    .map_err(|e| format!("{}:{}: invalid policy {}: {}", path.display(), n + 1, file.display(), e.message))?;
                (false, Some(Arc::new(policy)))
            }
            Some(other) => {
                return Err(format!("{}:{}: unknown permission `{other}` (use ro, rw or policy=<file>)", path.display(), n + 1));
            }
        };
        if ak.is_empty() || sk.is_empty() {
            return Err(format!("{}:{}: empty access key or secret", path.display(), n + 1));
        }
        let buckets = f.next().map(split_list).filter(|b| !b.is_empty());
        if into.iter().any(|c| c.access_key == ak) {
            return Err(format!("{}:{}: duplicate access key `{ak}`", path.display(), n + 1));
        }
        into.push(auth::Credential {
            access_key: ak.to_string(),
            secret: sk.to_string(),
            read_only,
            buckets,
            policy,
            expires_ms: None,
        });
    }
    Ok(())
}

/// All access keys: the main one (flags / environment) plus the credentials file.
fn collect_credentials(cfg: &Config) -> Result<Vec<auth::Credential>, String> {
    let mut creds = Vec::new();
    match (&cfg.access_key, &cfg.secret_key) {
        (Some(a), Some(s)) => creds.push(auth::Credential {
            access_key: a.clone(),
            secret: s.clone(),
            read_only: false,
            buckets: None,
            policy: None,
            expires_ms: None,
        }),
        (None, None) => {}
        _ => return Err("both an access key and a secret key are required".into()),
    }
    if let Some(path) = &cfg.credentials_file {
        load_credentials(path, &mut creds)?;
    }
    Ok(creds)
}

/// `s3rs fsck [--data-dir DIR] [--deep] [--repair] [--encryption-key K | --encryption-key-file F]`
/// `s3rs backup [-d DIR] [-o FILE]`: archive a stopped server's data directory (a running one
/// is backed up with GET /_admin/backup).
fn backup(args: &[String]) -> ! {
    let mut dir: PathBuf = env("S3RS_DATA_DIR").unwrap_or_else(|| "./data".into()).into();
    let mut output: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next().cloned().unwrap_or_else(|| {
                elog!("{a} requires a value");
                std::process::exit(2)
            })
        };
        match a.as_str() {
            "-d" | "--data-dir" => dir = val().into(),
            "-o" | "--output" => output = Some(val()),
            "-h" | "--help" => {
                println!(
                    "usage: s3rs backup [-d DATA_DIR] -o FILE|-\n\nWrites a tar of a stopped server's data directory; extract it into an empty directory to restore."
                );
                std::process::exit(0);
            }
            other => {
                elog!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let Some(output) = output else {
        elog!("s3rs backup: -o FILE (or - for stdout) is required");
        std::process::exit(2);
    };
    let result = if output == "-" {
        store::backup::offline(&dir, &mut std::io::BufWriter::new(std::io::stdout().lock()))
    } else {
        let tmp = format!("{output}.partial");
        let r = std::fs::File::create(&tmp)
            .map_err(|e| format!("{tmp}: {e}"))
            .and_then(|f| {
                let mut w = std::io::BufWriter::new(f);
                let plan = store::backup::offline(&dir, &mut w)?;
                w.into_inner().map_err(|e| e.to_string())?.sync_all().map_err(|e| e.to_string())?;
                Ok(plan)
            })
            .and_then(|plan| std::fs::rename(&tmp, &output).map(|_| plan).map_err(|e| e.to_string()));
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        r
    };
    match result {
        Ok(plan) => {
            elog!("backup: wrote {} file(s), {} bytes", plan.entries.len(), plan.tar_size());
            if !plan.missing.is_empty() {
                elog!("warning: {} referenced data file(s) are missing; run s3rs fsck", plan.missing.len());
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(e) => {
            elog!("error: {e}");
            std::process::exit(2);
        }
    }
}

fn fsck(args: &[String]) -> ! {
    let mut dir: PathBuf = env("S3RS_DATA_DIR").unwrap_or_else(|| "./data".into()).into();
    let (mut deep, mut repair) = (false, false);
    let mut key = env_key().transpose();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next().cloned().unwrap_or_else(|| {
                elog!("{a} requires a value");
                std::process::exit(2)
            })
        };
        match a.as_str() {
            "-d" | "--data-dir" => dir = val().into(),
            "--deep" => deep = true,
            "--repair" => repair = true,
            "--encryption-key" => key = Some(parse_key(&val())),
            "--encryption-key-file" => {
                let p = val();
                key = Some(std::fs::read_to_string(&p).map_err(|e| format!("{p}: {e}")).and_then(|t| parse_key(t.trim())));
            }
            "-h" | "--help" => {
                println!(
                    "usage: s3rs fsck [--data-dir DIR] [--deep] [--repair] [--encryption-key K | --encryption-key-file F]

Checks a data directory while the server is stopped:
  - every object version's data exists with the right size
  - orphaned data files and usage counters that disagree with the stored objects
  --deep    also re-reads all data and verifies each ETag (and decrypts SSE-S3 objects
            when the encryption key is given)
  --repair  removes orphaned data files and rebuilds usage counters (never touches objects)"
                );
                std::process::exit(0);
            }
            other => {
                elog!("unknown fsck argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let key = match key.transpose() {
        Ok(k) => k,
        Err(e) => {
            elog!("error: encryption key: {e}");
            std::process::exit(2);
        }
    };
    let started = std::time::Instant::now();
    let r = match store::fsck::run(&dir, deep, key, repair) {
        Ok(r) => r,
        Err(e) => {
            elog!("error: {e}");
            std::process::exit(2);
        }
    };
    println!("checked {} object version(s), {} bytes, in {:.1}s", r.versions, r.bytes, started.elapsed().as_secs_f64());
    if deep {
        println!("deep: {} verified, {} skipped (SSE-C, or SSE-S3 without --encryption-key)", r.deep_verified, r.deep_skipped);
    }
    for p in &r.problems {
        println!("PROBLEM {p}");
    }
    for m in &r.usage_mismatches {
        println!("USAGE {m}{}", if repair { " (rebuilt)" } else { "" });
    }
    let removed = if !repair {
        ""
    } else if r.orphans_kept {
        " (kept: unreadable metadata may refer to them)"
    } else {
        " (removed)"
    };
    if r.orphans > 0 {
        println!("orphans: {} data file(s), {} bytes{removed}", r.orphans, r.orphan_bytes);
    }
    if r.orphan_inline > 0 {
        println!("orphans: {} inline data row(s){removed}", r.orphan_inline);
    }
    let fixed = repair && r.problems.is_empty();
    if r.ok() || fixed {
        println!("{}", if r.ok() { "OK" } else { "REPAIRED" });
        std::process::exit(0);
    }
    println!(
        "{} problem(s) found",
        r.problems.len() + r.usage_mismatches.len() + usize::from(r.orphans > 0) + usize::from(r.orphan_inline > 0)
    );
    std::process::exit(1);
}

/// `s3rs healthcheck [-l ADDR] [--tls]`: GET /_health from a server on this host, for container
/// health checks (the images have no curl). Exits 0 when it answers `ok`.
fn healthcheck(args: &[String]) -> ! {
    use std::io::{Read, Write};
    let mut listen = env("S3RS_LISTEN").unwrap_or_else(|| "0.0.0.0:9000".into());
    let mut tls = env("S3RS_TLS_CERT").is_some();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-l" | "--listen" => match it.next() {
                Some(v) => listen = v.clone(),
                None => {
                    elog!("{a} requires a value");
                    std::process::exit(2);
                }
            },
            "--tls" => tls = true,
            "-h" | "--help" => {
                println!(
                    "usage: s3rs healthcheck [-l ADDR] [--tls]

Asks the server listening on ADDR (default: S3RS_LISTEN; an unspecified address means this
host) for /_health and exits 0 if it is healthy, 1 if not. Uses HTTPS when --tls is given or
S3RS_TLS_CERT is set; the certificate is not verified."
                );
                std::process::exit(0);
            }
            other => {
                elog!("unknown healthcheck argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let probe = || -> Result<String, String> {
        let mut addr: SocketAddr = listen.parse().map_err(|e| format!("{listen}: {e}"))?;
        if addr.ip().is_unspecified() {
            addr.set_ip(if addr.is_ipv4() { Ipv4Addr::LOCALHOST.into() } else { Ipv6Addr::LOCALHOST.into() });
        }
        let timeout = Duration::from_secs(10);
        let stream = std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("{addr}: {e}"))?;
        stream.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
        stream.set_write_timeout(Some(timeout)).map_err(|e| e.to_string())?;
        let request = b"GET /_health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let mut response = Vec::new();
        if tls {
            let mut s = tls::probe_stream(stream)?;
            s.write_all(request).map_err(|e| format!("{addr}: {e}"))?;
            // A server that closes without close_notify still sent the whole response.
            if let Err(e) = s.read_to_end(&mut response)
                && e.kind() != std::io::ErrorKind::UnexpectedEof
            {
                return Err(format!("{addr}: {e}"));
            }
        } else {
            let mut s = stream;
            s.write_all(request).map_err(|e| format!("{addr}: {e}"))?;
            s.read_to_end(&mut response).map_err(|e| format!("{addr}: {e}"))?;
        }
        let text = String::from_utf8_lossy(&response);
        let status = text.split(' ').nth(1).unwrap_or("");
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.trim()).unwrap_or("");
        match (status, body) {
            ("200", "ok") => Ok(body.to_string()),
            ("", _) if !tls => Err(format!("{addr}: no HTTP response (if the server uses HTTPS, pass --tls)")),
            ("", _) => Err(format!("{addr}: no HTTP response")),
            _ => Err(format!("{addr}: {status} {body}")),
        }
    };
    match probe() {
        Ok(_) => {
            println!("ok");
            std::process::exit(0)
        }
        Err(e) => {
            println!("unhealthy: {e}");
            std::process::exit(1)
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("healthcheck") {
        healthcheck(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("fsck") {
        fsck(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("backup") {
        backup(&args[1..]);
    }
    let cfg = match parse_args().and_then(check_secrets) {
        Ok(c) => c,
        Err(e) => {
            elog!("{e}");
            std::process::exit(2);
        }
    };
    let creds = match collect_credentials(&cfg) {
        Ok(c) => c,
        Err(e) => {
            elog!("error: {e}");
            std::process::exit(2);
        }
    };
    let auth = if !creds.is_empty() {
        Some(auth::Auth::new(creds.clone()))
    } else if cfg.anonymous {
        None
    } else {
        elog!(
            "error: set --access-key/--secret-key (or S3RS_ACCESS_KEY/S3RS_SECRET_KEY), use --credentials-file, or pass --anonymous"
        );
        std::process::exit(2);
    };

    if cfg.encrypt_by_default && cfg.encryption_key.is_none() {
        elog!("error: --encrypt-by-default requires --encryption-key");
        std::process::exit(2);
    }
    let tls = match (&cfg.tls_cert, &cfg.tls_key) {
        (None, None) => None,
        (Some(cert), Some(key)) => match tls::Server::load(cert.clone(), key.clone()) {
            Ok(t) => Some(Arc::new(t)),
            Err(e) => {
                elog!("error: TLS: {e}");
                std::process::exit(2);
            }
        },
        _ => {
            elog!("error: --tls-cert and --tls-key must be given together");
            std::process::exit(2);
        }
    };
    let webhook_tls = if cfg.webhooks.iter().any(|(_, u)| u.tls) || cfg.webhook_ca.is_some() {
        match tls::client_config(cfg.webhook_ca.as_deref()) {
            Ok(c) => Some(c),
            Err(e) => {
                let what = if cfg.webhooks.iter().any(|(_, u)| u.tls) { "https:// webhooks" } else { "--webhook-ca" };
                elog!("error: {what}: {e}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    let store = match store::Store::open(store::StoreConfig {
        root: cfg.data_dir.clone(),
        fsync: cfg.fsync,
        inline_threshold: cfg.inline_threshold,
        cache_bytes: cfg.cache_mb * 1024 * 1024,
        min_free: cfg.min_free,
    }) {
        Ok(s) => s,
        Err(e) => {
            elog!("error: cannot open data directory {}: {e}", cfg.data_dir.display());
            std::process::exit(1);
        }
    };

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    rt.block_on(serve(cfg, store, auth, creds, tls, webhook_tls));
}

async fn bind(addr: SocketAddr) -> TcpListener {
    match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            elog!("error: cannot listen on {addr}: {e}");
            std::process::exit(1);
        }
    }
}

/// Holds a connection slot and counts the connection while it is open.
struct ConnGuard {
    _slot: tokio::sync::OwnedSemaphorePermit,
    count: Arc<std::sync::atomic::AtomicI64>,
}

impl ConnGuard {
    fn new(slot: tokio::sync::OwnedSemaphorePermit, count: Arc<std::sync::atomic::AtomicI64>) -> Self {
        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ConnGuard { _slot: slot, count }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Raise the soft open-file limit to the hard limit (servers need far more than the common
/// default of 1024). Returns the resulting limit.
#[cfg(unix)]
fn raise_fd_limit() -> Option<u64> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit/setrlimit only read and write the struct passed to them.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return None;
        }
        if lim.rlim_cur < lim.rlim_max {
            let want = libc::rlimit { rlim_cur: lim.rlim_max, rlim_max: lim.rlim_max };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &want) == 0 {
                lim.rlim_cur = lim.rlim_max;
            }
        }
    }
    #[allow(clippy::unnecessary_cast)] // rlim_t is not u64 on every platform
    Some(lim.rlim_cur as u64)
}

#[cfg(not(unix))]
fn raise_fd_limit() -> Option<u64> {
    None
}

/// Accept on an optional listener (never completes when there is none).
async fn accept_opt(l: &Option<TcpListener>) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
    match l {
        Some(l) => l.accept().await,
        None => std::future::pending().await,
    }
}

async fn serve(
    cfg: Config,
    store: Arc<store::Store>,
    auth: Option<auth::Auth>,
    creds: Vec<auth::Credential>,
    tls: Option<Arc<tls::Server>>,
    webhook_tls: Option<Arc<tls::ClientConfig>>,
) {
    let listener = bind(cfg.listen).await;
    let website_listener = match cfg.website_listen {
        Some(a) => Some(bind(a).await),
        None => None,
    };
    let repl_targets = match &cfg.replication_targets {
        Some(p) => match replication::load_targets(p) {
            Ok(t) => t,
            Err(e) => {
                elog!("error: --replication-targets: {e}");
                std::process::exit(2);
            }
        },
        None => Vec::new(),
    };
    // Also without https:// targets now: SIGHUP may add some.
    let repl_tls = if cfg.replication_targets.is_some() {
        match tls::client_config(cfg.webhook_ca.as_deref()) {
            Ok(c) => Some(c),
            Err(e) if replication::Replicator::needs_tls(&repl_targets) || cfg.webhook_ca.is_some() => {
                elog!("error: replication targets: {e}");
                std::process::exit(2);
            }
            // A build without TLS: http:// targets only.
            Err(_) => None,
        }
    } else {
        None
    };
    let anonymous = auth.is_none();
    let opts = s3::Options {
        region: cfg.region.clone(),
        domain: cfg.domain.clone(),
        access_log: cfg.access_log,
        cors_origins: cfg.cors_origins.clone(),
        metrics_token: cfg.metrics_token.clone(),
        admin_token: cfg.admin_token.clone(),
        master_key: cfg.encryption_key,
        encrypt_by_default: cfg.encrypt_by_default,
        website_domain: cfg.website_domain.clone(),
        console: cfg.console,
        behind_proxy: cfg.behind_proxy,
        tls: tls.is_some(),
        events: events::Bus::new(
            store.clone(),
            cfg.region.clone(),
            cfg.webhooks.clone(),
            cfg.webhook_secret.clone(),
            webhook_tls,
            Duration::from_secs(cfg.webhook_timeout.max(1)),
        ),
        replication: replication::Replicator::new(
            store.clone(),
            repl_targets.clone(),
            repl_tls,
            cfg.encryption_key.map(|k| crypt::WrapKey::new(crypt::KeyKind::Master, k)),
        ),
        rate_limit: cfg.rate_limit,
        rate_limit_anonymous: cfg.rate_limit_anonymous,
    };
    let file_keys = if auth.is_some() { creds } else { Vec::new() };
    let server = Arc::new(s3::Server::new(store.clone(), auth, opts));
    server.set_self();
    // Keys created through the admin API are stored in the database.
    match server.set_file_credentials(file_keys) {
        Ok(n) if server.auth.is_some() => elog!("{n} access key(s) in effect"),
        Ok(_) => {}
        Err(e) => {
            elog!("error: cannot read the stored access keys: {e}");
            std::process::exit(2);
        }
    }
    if cfg.lifecycle_interval > 0 {
        tokio::spawn(lifecycle::run(
            store.clone(),
            Duration::from_secs(cfg.lifecycle_interval),
            cfg.lifecycle_day_secs.max(1),
            server.metrics.lifecycle.clone(),
            server.events.clone(),
        ));
    }
    let scheme = if tls.is_some() { "https" } else { "http" };
    elog!(
        "s3rs {} listening on {scheme}://{} (data: {}, region: {}, auth: {}, fsync: {}, encryption: {})",
        env!("CARGO_PKG_VERSION"),
        cfg.listen,
        cfg.data_dir.display(),
        cfg.region,
        if anonymous { "DISABLED" } else { "sigv4" },
        cfg.fsync,
        match (cfg.encryption_key.is_some(), cfg.encrypt_by_default) {
            (false, _) => "SSE-C only",
            (true, false) => "SSE-S3 + SSE-C",
            (true, true) => "all objects (SSE-S3 default)",
        }
    );
    let reserve = store.space.reserve();
    if reserve > 0 {
        elog!("uploads are refused when the data disk has less than {} MiB free", reserve >> 20);
    }
    if cfg.console {
        elog!("s3rs web console on {scheme}://{}/_console/", cfg.listen);
    }
    for (id, url) in &cfg.webhooks {
        let s = if url.tls { "https" } else { "http" };
        elog!("webhook target {id}: {s}://{}:{}{} (arn:s3rs:webhook::{id})", url.host, url.port, url.path);
    }
    for t in &repl_targets {
        let s = if t.url.tls { "https" } else { "http" };
        elog!(
            "replication target {}: {s}://{}:{}{} (arn:s3rs:replication::{}:<bucket>)",
            t.id,
            t.url.host,
            t.url.port,
            t.url.path,
            t.id
        );
    }
    if let Some(a) = cfg.website_listen {
        elog!("s3rs website endpoint on {scheme}://{a}");
    }

    let mut builder = auto::Builder::new(TokioExecutor::new());
    // The timer makes hyper enforce its timeouts: a request's headers (and the next request on a
    // kept-alive connection) must arrive within 30s, and HTTP/2 peers must answer pings.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .keep_alive(true)
        .max_buf_size(1024 * 1024);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20))
        // Each stream can hold a data file open; --max-connections assumes about one per connection.
        .max_concurrent_streams(128)
        .initial_stream_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(16 * 1024 * 1024);
    let builder = Arc::new(builder);
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();

    #[cfg(unix)]
    if server.auth.is_some() || tls.is_some() || cfg.replication_targets.is_some() {
        let server = server.clone();
        let cfg = cfg.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) else { return };
            while hup.recv().await.is_some() {
                if let Some(t) = &tls {
                    match t.reload() {
                        Ok(()) => elog!("reloaded the TLS certificate"),
                        Err(e) => elog!("TLS RELOAD FAILED, still using the previous certificate: {e}"),
                    }
                }
                if let Some(p) = &cfg.replication_targets {
                    let n = replication::load_targets(p).and_then(|t| {
                        let n = t.len();
                        server.replication.replace_targets(t).map(|_| n)
                    });
                    match n {
                        Ok(n) => elog!("reloaded {n} replication target(s)"),
                        Err(e) => elog!("REPLICATION TARGETS RELOAD FAILED, still using the previous ones: {e}"),
                    }
                }
                if server.auth.is_none() {
                    continue;
                }
                match collect_credentials(&cfg).and_then(|creds| server.set_file_credentials(creds).map_err(|e| e.to_string())) {
                    Ok(n) => {
                        if n == 0 {
                            elog!("reloaded: NO access keys are configured now; every signed request will be refused");
                        } else {
                            elog!("reloaded {n} access key(s)");
                        }
                    }
                    // Keeping the old keys can keep a key alive that the edit meant to remove,
                    // so say so loudly.
                    Err(e) => elog!("RELOAD FAILED, still using the previous keys (including any you removed): {e}"),
                }
            }
        });
    }

    // Each connection holds a socket and, while it transfers an object, a data file.
    let nofile = raise_fd_limit();
    let max_conns =
        cfg.max_connections.unwrap_or_else(|| nofile.map_or(4096, |n| (n.saturating_sub(64) / 2) as usize).clamp(64, 10_000));
    server.metrics.max_connections.store(max_conns as u64, std::sync::atomic::Ordering::Relaxed);
    elog!(
        "accepting up to {max_conns} connections{}",
        nofile.map(|n| format!(" (file descriptor limit {n})")).unwrap_or_default()
    );
    let conn_slots = Arc::new(tokio::sync::Semaphore::new(max_conns));
    let conn_count = server.metrics.connections.clone();

    // Tells connections still in their TLS handshake to give up, so they don't delay the drain.
    let (stopping_tx, stopping) = tokio::sync::watch::channel(false);
    tokio::spawn(server.replication.clone().run(stopping.clone()));
    {
        let server = server.clone();
        let mut stopping = stopping.clone();
        tokio::spawn(async move {
            loop {
                let stop = tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => false,
                    _ = stopping.changed() => *stopping.borrow(),
                };
                if stop {
                    return;
                }
                server.flush_bucket_logs(false).await;
                server.purge_expired_keys().await;
            }
        });
    }
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        // At the connection limit, stop accepting until a connection closes.
        let slot = tokio::select! {
            _ = &mut shutdown => break,
            s = conn_slots.clone().acquire_owned() => s.expect("semaphore is never closed"),
        };
        let (accepted, website) = tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => (r, false),
            r = accept_opt(&website_listener) => (r, true),
        };
        let (stream, peer) = match accepted {
            Ok(c) => c,
            Err(e) => {
                // Typically EMFILE; back off instead of spinning.
                elog!("accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let open = ConnGuard::new(slot, conn_count.clone());
        let server = server.clone();
        let builder = builder.clone();
        let watcher = graceful.watcher();
        let acceptor = tls.as_ref().map(|t| t.acceptor());
        let mut stopping = stopping.clone();
        tokio::spawn(async move {
            let _open = open;
            let svc = service_fn(move |req| {
                let server = server.clone();
                async move {
                    Ok::<_, Infallible>(if website {
                        server.handle_website(req, peer).await
                    } else {
                        server.handle(req, peer).await
                    })
                }
            });
            match acceptor {
                None => {
                    let io = conn::FirstByteDeadline::new(stream, conn::FIRST_BYTE_TIMEOUT);
                    let conn = builder.serve_connection(TokioIo::new(io), svc).into_owned();
                    let _ = watcher.watch(conn).await;
                }
                Some(acceptor) => {
                    // Failed handshakes (scanners, plain HTTP, expired client trust) are routine
                    // on a public port, so they are not logged.
                    let handshake = tokio::time::timeout(tls::HANDSHAKE_TIMEOUT, acceptor.accept(stream));
                    let stream = tokio::select! {
                        r = handshake => match r {
                            Ok(Ok(s)) => s,
                            _ => return,
                        },
                        _ = stopping.wait_for(|s| *s) => return,
                    };
                    let io = conn::FirstByteDeadline::new(stream, conn::FIRST_BYTE_TIMEOUT);
                    let conn = builder.serve_connection(TokioIo::new(io), svc).into_owned();
                    let _ = watcher.watch(conn).await;
                }
            }
        });
    }
    let _ = stopping_tx.send(true);
    drop(listener);
    drop(website_listener);
    // End open event streams so they don't hold up the drain.
    server.events.shutdown();
    elog!("shutting down: draining in-flight requests (up to {}s)", SHUTDOWN_GRACE.as_secs());
    let drained = tokio::select! {
        _ = graceful.shutdown() => true,
        _ = tokio::time::sleep(SHUTDOWN_GRACE) => {
            elog!("grace period over; closing remaining connections");
            false
        }
    };
    server.flush_bucket_logs(true).await;
    let _ = store.submit(store::Op::Flush).await;
    server.flush_logs();
    // Only a complete drain is a clean shutdown; otherwise cancelled uploads may leave orphaned
    // data files, which the next start's recovery scan removes.
    if drained {
        store.mark_clean_shutdown();
    }
    elog!("bye");
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
