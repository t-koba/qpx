use anyhow::{Result, anyhow};
use qpx_core::tls::{CompiledUpstreamTlsTrust, UpstreamCertificateInfo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Duration;

/// Run the shared TLS certificate preview handshake with an explicit caller timeout.
///
/// The raw [`qpx_http::tls::builder::preview_client_certificate`] helper performs
/// no timing of its own; each production preview call site supplies the upstream
/// timeout it already uses for the surrounding upstream connection so a silent
/// peer cannot park the handshake before policy reevaluation. Dropping the timed-out
/// future also drops the owned upstream stream, releasing the task and socket.
pub(crate) async fn preview_client_certificate_with_timeout<S>(
    domain: &str,
    stream: S,
    verify: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
    timeout_dur: Duration,
) -> Result<UpstreamCertificateInfo>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::time::timeout(
        timeout_dur,
        qpx_http::tls::builder::preview_client_certificate(domain, stream, verify, trust),
    )
    .await
    .map_err(|_| anyhow!("upstream certificate preview timed out"))?
}

#[cfg(all(test, any(feature = "tls-rustls", feature = "tls-native")))]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    const SILENT_PREVIEW_TIMEOUT: Duration = Duration::from_millis(200);
    const WAIT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn silent_peer_preview_times_out_and_releases_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut first = vec![0u8; 16_384];
            let read = timeout(WAIT, sock.read(&mut first))
                .await
                .expect("ClientHello wait timed out")
                .expect("ClientHello read failed");
            assert!(read > 0, "expected ClientHello bytes from preview");
            assert_eq!(first[0], 0x16, "expected TLS handshake record from preview");
            let mut eof = [0u8; 1];
            let next = timeout(WAIT, sock.read(&mut eof))
                .await
                .expect("EOF wait timed out")
                .expect("EOF read failed");
            assert_eq!(next, 0, "expected EOF after preview timeout");
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let started = tokio::time::Instant::now();
        let err = match preview_client_certificate_with_timeout(
            "localhost",
            stream,
            false,
            None,
            SILENT_PREVIEW_TIMEOUT,
        )
        .await
        {
            Ok(_) => panic!("silent peer preview should time out"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("timed out"),
            "expected timeout error, got {err:?}"
        );
        assert!(
            started.elapsed() < WAIT,
            "preview timeout should fire well before test wait"
        );
        timeout(WAIT, server)
            .await
            .expect("server join timed out")
            .expect("server task failed");
    }

    #[cfg(feature = "tls-rustls")]
    #[tokio::test]
    async fn preview_succeeds_against_local_tls_server() {
        use qpx_core::tls::init_rustls_crypto_provider;
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::Arc;

        init_rustls_crypto_provider().expect("crypto provider");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed cert");
        let cert_der = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .expect("server config");
        config.alpn_protocols.clear();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let _tls = acceptor.accept(stream).await.expect("tls accept");
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let cert = preview_client_certificate_with_timeout("localhost", stream, false, None, WAIT)
            .await
            .expect("preview against local TLS server should succeed");
        assert!(cert.present, "expected certificate metadata");
        assert!(
            cert.san_dns.contains(&"localhost".to_string()),
            "expected localhost SAN, got {:?}",
            cert.san_dns
        );
        assert!(
            cert.fingerprint_sha256.is_some(),
            "expected certificate fingerprint"
        );
        timeout(WAIT, server)
            .await
            .expect("server join timed out")
            .expect("server task failed");
    }
}
