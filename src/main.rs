//! s3rs — a fast, lightweight, S3-compatible object storage server in pure Rust.

mod access;
mod auth;
mod body;
mod chunked;
mod crypt;
mod error;
mod io;
mod lifecycle;
mod metrics;
mod post;
mod s3;
mod store;
mod util;
mod xml;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::net::SocketAddr;
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
    s3rs [OPTIONS]

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
        --encryption-key-file <P> Read the master key from a file
        --encrypt-by-default     Encrypt every new object with the master key
                                                                 [S3RS_ENCRYPT_BY_DEFAULT=1]
        --metrics-token <T>      Require `Authorization: Bearer <T>` for /_metrics
                                                                 [S3RS_METRICS_TOKEN]
        --region <REGION>        Region reported to clients      [S3RS_REGION, default us-east-1]
        --domain <DOMAIN>        Enable virtual-hosted-style requests for <bucket>.<DOMAIN>
                                                                 [S3RS_DOMAIN]
        --inline-threshold <N>   Objects up to N bytes are stored inside the metadata DB
                                                                 [S3RS_INLINE_THRESHOLD, default 65536]
        --cache-mb <N>           Metadata cache size in MiB      [S3RS_CACHE_MB, default 256]
        --no-fsync               Do not fsync data or metadata (faster, less durable)
                                                                 [S3RS_NO_FSYNC=1]
        --lifecycle-interval <S> Seconds between lifecycle sweeps [S3RS_LIFECYCLE_INTERVAL, default 3600]
    -v, --verbose                Log every request               [S3RS_VERBOSE=1]
    -h, --help                   Show this help
";

struct Config {
    listen: SocketAddr,
    data_dir: PathBuf,
    access_key: Option<String>,
    secret_key: Option<String>,
    credentials_file: Option<PathBuf>,
    anonymous: bool,
    cors_origins: Vec<String>,
    metrics_token: Option<String>,
    encryption_key: Option<[u8; 32]>,
    encrypt_by_default: bool,
    region: String,
    domain: Option<String>,
    inline_threshold: usize,
    cache_mb: usize,
    fsync: bool,
    verbose: bool,
    lifecycle_interval: u64,
    /// Length of a lifecycle "day" in seconds; only meant to be shortened for testing.
    lifecycle_day_secs: u64,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
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
        encryption_key: env("S3RS_ENCRYPTION_KEY")
            .map(|k| parse_key(&k))
            .transpose()
            .map_err(|e| format!("S3RS_ENCRYPTION_KEY: {e}"))?,
        encrypt_by_default: env_flag("S3RS_ENCRYPT_BY_DEFAULT")?,
        region: env("S3RS_REGION").unwrap_or_else(|| "us-east-1".into()),
        domain: env("S3RS_DOMAIN"),
        inline_threshold: env("S3RS_INLINE_THRESHOLD")
            .map_or(Ok(65536), |v| v.parse())
            .map_err(|e| format!("S3RS_INLINE_THRESHOLD: {e}"))?,
        cache_mb: env("S3RS_CACHE_MB").map_or(Ok(256), |v| v.parse()).map_err(|e| format!("S3RS_CACHE_MB: {e}"))?,
        fsync: !env_flag("S3RS_NO_FSYNC")?,
        verbose: env_flag("S3RS_VERBOSE")?,
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
            "--encryption-key" => c.encryption_key = Some(parse_key(&val()?).map_err(|e| format!("--encryption-key: {e}"))?),
            "--encryption-key-file" => {
                let path = val()?;
                let text = std::fs::read_to_string(&path).map_err(|e| format!("--encryption-key-file {path}: {e}"))?;
                c.encryption_key = Some(parse_key(text.trim()).map_err(|e| format!("--encryption-key-file {path}: {e}"))?);
            }
            "--encrypt-by-default" => c.encrypt_by_default = true,
            "--region" => c.region = val()?,
            "--domain" => c.domain = Some(val()?),
            "--inline-threshold" => c.inline_threshold = val()?.parse().map_err(|e| format!("--inline-threshold: {e}"))?,
            "--cache-mb" => c.cache_mb = val()?.parse().map_err(|e| format!("--cache-mb: {e}"))?,
            "--no-fsync" => c.fsync = false,
            "--lifecycle-interval" => c.lifecycle_interval = val()?.parse().map_err(|e| format!("--lifecycle-interval: {e}"))?,
            "-v" | "--verbose" => c.verbose = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
        }
    }
    Ok(c)
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
/// `access_key:secret_key[:ro|rw[:bucket-pattern,bucket-pattern...]]`.
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
        let read_only = match f.next().map(str::trim) {
            None | Some("rw") => false,
            Some("ro") => true,
            Some(other) => return Err(format!("{}:{}: unknown permission `{other}` (use ro or rw)", path.display(), n + 1)),
        };
        if ak.is_empty() || sk.is_empty() {
            return Err(format!("{}:{}: empty access key or secret", path.display(), n + 1));
        }
        let buckets = f.next().map(split_list).filter(|b| !b.is_empty());
        if into.iter().any(|c| c.access_key == ak) {
            return Err(format!("{}:{}: duplicate access key `{ak}`", path.display(), n + 1));
        }
        into.push(auth::Credential { access_key: ak.to_string(), secret: sk.to_string(), read_only, buckets });
    }
    Ok(())
}

fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let mut creds = Vec::new();
    match (&cfg.access_key, &cfg.secret_key) {
        (Some(a), Some(s)) => {
            creds.push(auth::Credential { access_key: a.clone(), secret: s.clone(), read_only: false, buckets: None });
        }
        (None, None) => {}
        _ => {
            eprintln!("error: both an access key and a secret key are required");
            std::process::exit(2);
        }
    }
    if let Some(path) = &cfg.credentials_file
        && let Err(e) = load_credentials(path, &mut creds)
    {
        eprintln!("error: {e}");
        std::process::exit(2);
    }
    let auth = if !creds.is_empty() {
        Some(auth::Auth::new(creds))
    } else if cfg.anonymous {
        None
    } else {
        eprintln!(
            "error: set --access-key/--secret-key (or S3RS_ACCESS_KEY/S3RS_SECRET_KEY), use --credentials-file, or pass --anonymous"
        );
        std::process::exit(2);
    };

    if cfg.encrypt_by_default && cfg.encryption_key.is_none() {
        eprintln!("error: --encrypt-by-default requires --encryption-key");
        std::process::exit(2);
    }

    let store = match store::Store::open(store::StoreConfig {
        root: cfg.data_dir.clone(),
        fsync: cfg.fsync,
        inline_threshold: cfg.inline_threshold,
        cache_bytes: cfg.cache_mb * 1024 * 1024,
    }) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot open data directory {}: {e}", cfg.data_dir.display());
            std::process::exit(1);
        }
    };

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    rt.block_on(serve(cfg, store, auth));
}

async fn serve(cfg: Config, store: Arc<store::Store>, auth: Option<auth::Auth>) {
    let listener = match TcpListener::bind(cfg.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot listen on {}: {e}", cfg.listen);
            std::process::exit(1);
        }
    };
    let anonymous = auth.is_none();
    let opts = s3::Options {
        region: cfg.region.clone(),
        domain: cfg.domain.clone(),
        verbose: cfg.verbose,
        cors_origins: cfg.cors_origins.clone(),
        metrics_token: cfg.metrics_token.clone(),
        master_key: cfg.encryption_key,
        encrypt_by_default: cfg.encrypt_by_default,
    };
    let server = Arc::new(s3::Server::new(store.clone(), auth, opts));
    if cfg.lifecycle_interval > 0 {
        tokio::spawn(lifecycle::run(
            store.clone(),
            Duration::from_secs(cfg.lifecycle_interval),
            cfg.lifecycle_day_secs.max(1),
            server.metrics.lifecycle.clone(),
        ));
    }
    eprintln!(
        "s3rs listening on http://{} (data: {}, region: {}, auth: {}, fsync: {}, encryption: {})",
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

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().keep_alive(true).max_buf_size(1024 * 1024);
    builder
        .http2()
        .max_concurrent_streams(256)
        .initial_stream_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(16 * 1024 * 1024);
    let builder = Arc::new(builder);
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        let (stream, _) = tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    // Typically EMFILE; back off instead of spinning.
                    eprintln!("accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        let server = server.clone();
        let builder = builder.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let server = server.clone();
                async move { Ok::<_, Infallible>(server.handle(req).await) }
            });
            let conn = builder.serve_connection(TokioIo::new(stream), svc).into_owned();
            let _ = watcher.watch(conn).await;
        });
    }
    drop(listener);
    eprintln!("shutting down: draining in-flight requests (up to {}s)", SHUTDOWN_GRACE.as_secs());
    let drained = tokio::select! {
        _ = graceful.shutdown() => true,
        _ = tokio::time::sleep(SHUTDOWN_GRACE) => {
            eprintln!("grace period over; closing remaining connections");
            false
        }
    };
    let _ = store.submit(store::Op::Flush).await;
    // Only a complete drain is a clean shutdown; otherwise cancelled uploads may leave orphaned
    // data files, which the next start's recovery scan removes.
    if drained {
        store.mark_clean_shutdown();
    }
    eprintln!("bye");
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
