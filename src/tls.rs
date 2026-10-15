//! Native TLS (rustls), built with `--features tls`: the HTTPS listeners, with certificates
//! reloadable on SIGHUP, and the client side of `https://` webhooks.
//!
//! The feature is optional because rustls' crypto provider (ring) contains C and assembly; the
//! default build has no C code. Without it, the same API exists but refuses to start TLS.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long a client may take to complete the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(feature = "tls")]
pub use imp::*;
#[cfg(not(feature = "tls"))]
pub use stub::*;

#[cfg(feature = "tls")]
mod imp {
    use super::*;
    use rustls::crypto::CryptoProvider;
    use rustls::{RootCertStore, ServerConfig};
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use std::sync::{Arc, RwLock};
    use tokio::net::TcpStream;

    pub use rustls::ClientConfig;

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// A readable PEM error (some variants otherwise print their marker as a byte array).
    fn pem_error(path: &Path, e: rustls_pki_types::pem::Error) -> String {
        use rustls_pki_types::pem::Error;
        let what = match e {
            Error::MissingSectionEnd { end_marker } => {
                format!("missing `-----END {}-----` (truncated file?)", String::from_utf8_lossy(&end_marker))
            }
            Error::NoItemsFound => "no PEM items found (encrypted keys are not supported)".to_string(),
            e => e.to_string(),
        };
        format!("{}: {what}", path.display())
    }

    fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|e| pem_error(path, e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| pem_error(path, e))?;
        if certs.is_empty() {
            return Err(format!("{}: no PEM certificates found", path.display()));
        }
        Ok(certs)
    }

    /// The TLS configuration of the listeners. The certificate and key are re-read on `reload`;
    /// connections already open keep the configuration they started with.
    pub struct Server {
        cert: PathBuf,
        key: PathBuf,
        current: RwLock<Arc<ServerConfig>>,
    }

    impl Server {
        pub fn load(cert: PathBuf, key: PathBuf) -> Result<Server, String> {
            let cfg = build_server(&cert, &key)?;
            Ok(Server { cert, key, current: RwLock::new(Arc::new(cfg)) })
        }

        /// Re-read the certificate and key. On failure the previous ones stay in use.
        pub fn reload(&self) -> Result<(), String> {
            let cfg = build_server(&self.cert, &self.key)?;
            *self.current.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(cfg);
            Ok(())
        }

        /// An acceptor with the current certificate.
        pub fn acceptor(&self) -> Acceptor {
            Acceptor(tokio_rustls::TlsAcceptor::from(self.current.read().unwrap_or_else(|e| e.into_inner()).clone()))
        }
    }

    pub struct Acceptor(tokio_rustls::TlsAcceptor);

    impl Acceptor {
        pub async fn accept(self, stream: TcpStream) -> std::io::Result<tokio_rustls::server::TlsStream<TcpStream>> {
            self.0.accept(stream).await
        }
    }

    fn build_server(cert: &Path, key: &Path) -> Result<ServerConfig, String> {
        let certs = read_certs(cert)?;
        let key_path = key;
        let key = PrivateKeyDer::from_pem_file(key).map_err(|e| pem_error(key, e))?;
        // with_single_cert also checks that the key belongs to the certificate.
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("{} with key {}: {e}", cert.display(), key_path.display()))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(cfg)
    }

    /// Client configuration for `https://` webhooks: the Mozilla root certificates, plus the
    /// CA certificates in `extra_ca` (for receivers with certificates from a private CA).
    pub fn client_config(extra_ca: Option<&Path>) -> Result<Arc<ClientConfig>, String> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = extra_ca {
            for c in read_certs(path)? {
                roots.add(c).map_err(|e| format!("{}: {e}", path.display()))?;
            }
        }
        let mut cfg = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }

    /// Check that `host` (a DNS name or IP address, without brackets) can be verified by TLS.
    pub fn check_server_name(host: &str) -> Result<(), String> {
        ServerName::try_from(host).map(|_| ()).map_err(|e| format!("{host}: {e}"))
    }

    /// Start TLS on a connected stream to `host` (a DNS name or IP address).
    pub async fn connect(
        cfg: &Arc<ClientConfig>,
        host: &str,
        stream: TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
        let name = ServerName::try_from(host.to_string()).map_err(|e| format!("{host}: {e}"))?;
        tokio::time::timeout(HANDSHAKE_TIMEOUT, tokio_rustls::TlsConnector::from(cfg.clone()).connect(name, stream))
            .await
            .map_err(|_| "TLS handshake timed out".to_string())?
            .map_err(|e| format!("TLS: {e}"))
    }
}

#[cfg(not(feature = "tls"))]
mod stub {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpStream;

    const UNSUPPORTED: &str = "this build of s3rs has no TLS support; build it with `cargo build --release --features tls`";

    pub struct ClientConfig;

    pub struct Server;

    impl Server {
        pub fn load(_cert: PathBuf, _key: PathBuf) -> Result<Server, String> {
            Err(UNSUPPORTED.into())
        }

        pub fn reload(&self) -> Result<(), String> {
            Err(UNSUPPORTED.into())
        }

        pub fn acceptor(&self) -> Acceptor {
            Acceptor
        }
    }

    pub struct Acceptor;

    impl Acceptor {
        pub async fn accept(self, _stream: TcpStream) -> std::io::Result<TcpStream> {
            Err(std::io::Error::other(UNSUPPORTED))
        }
    }

    pub fn check_server_name(_host: &str) -> Result<(), String> {
        Ok(())
    }

    pub fn client_config(_extra_ca: Option<&Path>) -> Result<Arc<ClientConfig>, String> {
        Err(UNSUPPORTED.into())
    }

    pub async fn connect(_cfg: &Arc<ClientConfig>, _host: &str, _stream: TcpStream) -> Result<TcpStream, String> {
        Err(UNSUPPORTED.into())
    }
}
