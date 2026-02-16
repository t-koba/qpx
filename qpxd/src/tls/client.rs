use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub(crate) trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub(crate) type BoxTlsStream = Box<dyn IoStream>;

#[cfg(feature = "tls-rustls")]
mod imp {
    use super::*;
    use std::net::IpAddr;
    use std::sync::{Arc, OnceLock};

    pub(super) async fn connect_tls_http1(domain: &str, stream: TcpStream) -> Result<BoxTlsStream> {
        let connector = tokio_rustls::TlsConnector::from(shared_rustls_client_http1().clone());
        let server_name = server_name_for_host(domain)?;
        let tls = connector.connect(server_name, stream).await?;
        Ok(Box::new(tls))
    }

    pub(super) async fn connect_tls_h2_h1(
        domain: &str,
        stream: TcpStream,
    ) -> Result<(BoxTlsStream, bool)> {
        let connector = tokio_rustls::TlsConnector::from(shared_rustls_client_h2_h1().clone());
        let server_name = server_name_for_host(domain)?;
        let tls = connector.connect(server_name, stream).await?;
        let negotiated_h2 = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| p == b"h2")
            .unwrap_or(false);
        Ok((Box::new(tls), negotiated_h2))
    }

    fn server_name_for_host(host: &str) -> Result<rustls::pki_types::ServerName<'static>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(rustls::pki_types::ServerName::IpAddress(ip.into()));
        }
        rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| anyhow::anyhow!("invalid server name for TLS: {}", host))
    }

    fn shared_rustls_client_http1() -> &'static Arc<rustls::ClientConfig> {
        use rustls::RootCertStore;
        use webpki_roots::TLS_SERVER_ROOTS;
        static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        CONFIG.get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            // Avoid negotiating HTTP/2 when the caller expects an HTTP/1.1 tunnel/handshake.
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        })
    }

    fn shared_rustls_client_h2_h1() -> &'static Arc<rustls::ClientConfig> {
        use rustls::RootCertStore;
        use webpki_roots::TLS_SERVER_ROOTS;
        static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        CONFIG.get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Arc::new(config)
        })
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
mod imp {
    use super::*;
    use std::sync::OnceLock;

    pub(super) async fn connect_tls_http1(domain: &str, stream: TcpStream) -> Result<BoxTlsStream> {
        let connector = shared_native_tls_client_http1()?;
        let tls = connector.connect(domain, stream).await?;
        Ok(Box::new(tls))
    }

    pub(super) async fn connect_tls_h2_h1(
        domain: &str,
        stream: TcpStream,
    ) -> Result<(BoxTlsStream, bool)> {
        let connector = shared_native_tls_client_h2_h1()?;
        let tls = connector.connect(domain, stream).await?;

        // `negotiated_alpn` requires `native-tls` feature "alpn".
        let negotiated_h2 = tls
            .get_ref()
            .negotiated_alpn()
            .ok()
            .flatten()
            .map(|p| p == b"h2")
            .unwrap_or(false);

        Ok((Box::new(tls), negotiated_h2))
    }

    fn shared_native_tls_client_http1() -> Result<&'static tokio_native_tls::TlsConnector> {
        static CONFIG: OnceLock<tokio_native_tls::TlsConnector> = OnceLock::new();
        Ok(CONFIG.get_or_init(|| {
            let mut builder = native_tls::TlsConnector::builder();
            builder.request_alpns(&["http/1.1"]);
            tokio_native_tls::TlsConnector::from(builder.build().expect("native tls build"))
        }))
    }

    fn shared_native_tls_client_h2_h1() -> Result<&'static tokio_native_tls::TlsConnector> {
        static CONFIG: OnceLock<tokio_native_tls::TlsConnector> = OnceLock::new();
        Ok(CONFIG.get_or_init(|| {
            let mut builder = native_tls::TlsConnector::builder();
            builder.request_alpns(&["h2", "http/1.1"]);
            tokio_native_tls::TlsConnector::from(builder.build().expect("native tls build"))
        }))
    }
}

#[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
mod imp {
    use super::*;

    pub(super) async fn connect_tls_http1(
        _domain: &str,
        _stream: TcpStream,
    ) -> Result<BoxTlsStream> {
        Err(anyhow::anyhow!(
            "TLS client connect requires either feature tls-rustls or tls-native"
        ))
    }

    pub(super) async fn connect_tls_h2_h1(
        _domain: &str,
        _stream: TcpStream,
    ) -> Result<(BoxTlsStream, bool)> {
        Err(anyhow::anyhow!(
            "TLS client connect requires either feature tls-rustls or tls-native"
        ))
    }
}

pub(crate) async fn connect_tls_http1(domain: &str, stream: TcpStream) -> Result<BoxTlsStream> {
    imp::connect_tls_http1(domain, stream).await
}

pub(crate) async fn connect_tls_h2_h1(
    domain: &str,
    stream: TcpStream,
) -> Result<(BoxTlsStream, bool)> {
    imp::connect_tls_h2_h1(domain, stream).await
}
