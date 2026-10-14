//! s3rs — a fast, lightweight, S3-compatible object storage server in pure Rust.

mod access;
mod auth;
mod body;
mod chunked;
mod error;
mod io;
mod metrics;
mod s3;
mod store;
mod util;
mod xml;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::collections::HashMap;
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
        --credentials-file <P>   Extra keys, one `access_key:secret_key[:ro]` per line
                                                                 [S3RS_CREDENTIALS_FILE]
        --anonymous              Disable authentication (only for trusted networks)
        --cors-origins <LIST>    Comma-separated origins allowed by default for buckets
                                 without their own CORS configuration, e.g. `*`
                                                                 [S3RS_CORS_ORIGINS]
        --region <REGION>        Region reported to clients      [S3RS_REGION, default us-east-1]
        --domain <DOMAIN>        Enable virtual-hosted-style requests for <bucket>.<DOMAIN>
                                                                 [S3RS_DOMAIN]
        --inline-threshold <N>   Objects up to N bytes are stored inside the metadata DB
                                                                 [S3RS_INLINE_THRESHOLD, default 65536]
        --cache-mb <N>           Metadata cache size in MiB      [S3RS_CACHE_MB, default 256]
        --no-fsync               Do not fsync data or metadata (faster, less durable)
    -v, --verbose                Log every request
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
    region: String,
    domain: Option<String>,
    inline_threshold: usize,
    cache_mb: usize,
    fsync: bool,
    verbose: bool,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
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
        region: env("S3RS_REGION").unwrap_or_else(|| "us-east-1".into()),
        domain: env("S3RS_DOMAIN"),
        inline_threshold: env("S3RS_INLINE_THRESHOLD")
            .map_or(Ok(65536), |v| v.parse())
            .map_err(|e| format!("S3RS_INLINE_THRESHOLD: {e}"))?,
        cache_mb: env("S3RS_CACHE_MB").map_or(Ok(256), |v| v.parse()).map_err(|e| format!("S3RS_CACHE_MB: {e}"))?,
        fsync: true,
        verbose: false,
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
            "--region" => c.region = val()?,
            "--domain" => c.domain = Some(val()?),
            "--inline-threshold" => c.inline_threshold = val()?.parse().map_err(|e| format!("--inline-threshold: {e}"))?,
            "--cache-mb" => c.cache_mb = val()?.parse().map_err(|e| format!("--cache-mb: {e}"))?,
            "--no-fsync" => c.fsync = false,
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

fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

/// Parse a credentials file: `access_key:secret_key[:ro|:rw]` per line, `#` comments.
fn load_credentials(path: &std::path::Path, into: &mut HashMap<String, auth::Credential>) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.splitn(3, ':');
        let (Some(ak), Some(sk)) = (f.next(), f.next()) else {
            return Err(format!("{}:{}: expected access_key:secret_key[:ro]", path.display(), n + 1));
        };
        let read_only = match f.next().map(str::trim) {
            None | Some("rw") => false,
            Some("ro") => true,
            Some(other) => return Err(format!("{}:{}: unknown permission `{other}` (use ro or rw)", path.display(), n + 1)),
        };
        if ak.is_empty() || sk.is_empty() {
            return Err(format!("{}:{}: empty access key or secret", path.display(), n + 1));
        }
        into.insert(ak.to_string(), auth::Credential { secret: sk.to_string(), read_only });
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
    let mut creds = HashMap::new();
    match (&cfg.access_key, &cfg.secret_key) {
        (Some(a), Some(s)) => {
            creds.insert(a.clone(), auth::Credential { secret: s.clone(), read_only: false });
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
    };
    let server = Arc::new(s3::Server::new(store.clone(), auth, opts));
    eprintln!(
        "s3rs listening on http://{} (data: {}, region: {}, auth: {}, fsync: {})",
        cfg.listen,
        cfg.data_dir.display(),
        cfg.region,
        if anonymous { "DISABLED" } else { "sigv4" },
        cfg.fsync
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
    tokio::select! {
        _ = graceful.shutdown() => {}
        _ = tokio::time::sleep(SHUTDOWN_GRACE) => eprintln!("grace period over; closing remaining connections"),
    }
    let _ = store.submit(store::Op::Flush).await;
    store.mark_clean_shutdown();
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
