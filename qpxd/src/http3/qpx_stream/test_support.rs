use anyhow::{Result, anyhow};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Clone)]
struct CaptureStream(mpsc::Sender<qpx_h3::RequestStream>);

impl qpx_h3::RequestHandler for CaptureStream {
    fn settings(&self) -> qpx_h3::Settings {
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _: qpx_h3::Request,
        _: qpx_h3::ConnectionInfo,
        stream: qpx_h3::RequestStream,
    ) -> qpx_h3::H3Result<()> {
        self.0
            .send(stream)
            .await
            .map_err(|_| anyhow!("stream capture closed"))?;
        Ok(())
    }

    async fn handle_connect_stream(
        &self,
        _: qpx_core::http_message::Request<()>,
        stream: qpx_h3::RequestStream,
        _: qpx_h3::ConnectionInfo,
        _: qpx_h3::Protocol,
        _: Option<qpx_h3::StreamDatagrams>,
    ) -> qpx_h3::H3Result<()> {
        self.0
            .send(stream)
            .await
            .map_err(|_| anyhow!("stream capture closed"))?;
        Ok(())
    }
}

// The caller owns the tasks so setup failures and test timeouts abort them too.
pub(crate) async fn qpx_loopback(
    tasks: &mut tokio::task::JoinSet<()>,
    client_stream_receive_window: Option<u32>,
) -> Result<(
    quinn::Endpoint,
    quinn::Connection,
    mpsc::Receiver<qpx_h3::RequestStream>,
)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let der = cert.cert.der().clone();
    let provider = quinn::rustls::crypto::ring::default_provider();
    let mut tls = quinn::rustls::ServerConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?)),
        "127.0.0.1:0".parse()?,
    )?;
    let addr = endpoint.local_addr()?;
    let (tx, rx) = mpsc::channel(1);
    tasks.spawn(async move {
        let incoming = endpoint.accept().await.unwrap();
        qpx_h3::serve_connection(incoming, addr.port(), CaptureStream(tx))
            .await
            .unwrap();
    });
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(der)?;
    let mut tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    if let Some(window) = client_stream_receive_window {
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(quinn::VarInt::from_u32(window));
        transport.receive_window(quinn::VarInt::from_u32(window.saturating_mul(4)));
        client_config.transport_config(Arc::new(transport));
    }
    client.set_default_client_config(client_config);
    let conn = client.connect(addr, "localhost")?.await?;
    Ok((client, conn, rx))
}
