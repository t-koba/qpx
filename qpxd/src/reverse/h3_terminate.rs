use crate::http3::listener::{H3ConnInfo, H3ConnectKind, H3Limits, H3RequestHandler};
use crate::http3::quic::build_h3_server_config_from_tls;
use crate::http3::server::{send_h3_static_response, H3ServerRequestStream};
use crate::runtime::Runtime;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hyper::{Body, Request, Response};
use qpx_core::config::ReverseConfig;
use qpx_core::tls::{load_cert_chain, load_private_key};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::warn;

pub(super) async fn run_http3_terminate(
    reverse: ReverseConfig,
    listen_addr: SocketAddr,
    router: Arc<super::router::ReverseRouter>,
    runtime: Runtime,
    security_policy: Arc<super::security::ReverseTlsHostPolicy>,
) -> Result<()> {
    let tls_config = build_reverse_tls_config(&reverse)?;
    let server_config = build_h3_server_config_from_tls(tls_config, 1024, 1024)?;
    let endpoint = quinn::Endpoint::server(server_config, listen_addr)?;

    let handler = ReverseH3Handler {
        router,
        runtime,
        security_policy,
    };
    crate::http3::listener::serve_endpoint(
        endpoint,
        listen_addr.port(),
        handler,
        "reverse-terminate",
    )
    .await
}

fn build_reverse_tls_config(reverse: &ReverseConfig) -> Result<quinn::rustls::ServerConfig> {
    let tls = reverse
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("reverse TLS config required for HTTP/3 terminate"))?;
    if tls.certificates.is_empty() {
        return Err(anyhow!(
            "at least one certificate is required for HTTP/3 terminate"
        ));
    }
    let resolver = Arc::new(QuicSniResolver::new(tls)?);

    let provider = quinn::rustls::crypto::ring::default_provider();
    let tls_config = quinn::rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure TLS versions for HTTP/3"))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(tls_config)
}

#[derive(Debug)]
struct QuicSniResolver {
    certs: HashMap<String, Arc<quinn::rustls::sign::CertifiedKey>>,
}

impl QuicSniResolver {
    fn new(tls: &qpx_core::config::ReverseTlsConfig) -> Result<Self> {
        let mut certs = HashMap::new();
        for cert in &tls.certificates {
            let cert_path = cert.cert.as_deref().unwrap_or("").trim();
            if cert_path.is_empty() {
                return Err(anyhow!("reverse.tls.certificates[].cert must not be empty"));
            }
            let key_path = cert.key.as_deref().unwrap_or("").trim();
            if key_path.is_empty() {
                return Err(anyhow!("reverse.tls.certificates[].key must not be empty"));
            }
            let chain = load_cert_chain(Path::new(cert_path))?;
            let key = load_private_key(Path::new(key_path))?;
            let signing_key = quinn::rustls::crypto::ring::sign::any_supported_type(&key)
                .map_err(|_| anyhow!("unsupported key"))?;
            let certified = Arc::new(quinn::rustls::sign::CertifiedKey::new(chain, signing_key));
            certs.insert(cert.sni.to_ascii_lowercase(), certified);
        }
        Ok(Self { certs })
    }
}

impl quinn::rustls::server::ResolvesServerCert for QuicSniResolver {
    fn resolve(
        &self,
        client_hello: quinn::rustls::server::ClientHello<'_>,
    ) -> Option<Arc<quinn::rustls::sign::CertifiedKey>> {
        client_hello
            .server_name()
            .and_then(|name| self.certs.get(&name.to_ascii_lowercase()).cloned())
    }
}

#[derive(Clone)]
struct ReverseH3Handler {
    router: Arc<super::router::ReverseRouter>,
    runtime: Runtime,
    security_policy: Arc<super::security::ReverseTlsHostPolicy>,
}

#[async_trait]
impl H3RequestHandler for ReverseH3Handler {
    fn limits(&self) -> H3Limits {
        let state = self.runtime.state();
        let limits = state.config.runtime.clone();
        H3Limits {
            max_request_body_bytes: limits.max_h3_request_body_bytes,
            max_response_body_bytes: limits.max_h3_response_body_bytes,
            read_timeout: Duration::from_millis(limits.h3_read_timeout_ms),
            proxy_name: Arc::<str>::from(state.config.identity.proxy_name.as_str()),
            error_body: Arc::<str>::from(state.messages.reverse_error.as_str()),
        }
    }

    async fn handle_http(&self, req: Request<Body>, conn: H3ConnInfo) -> Response<Body> {
        let reverse_conn = super::transport::ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
        );
        match super::transport::handle_request(
            req,
            self.router.clone(),
            self.runtime.clone(),
            reverse_conn,
            self.security_policy.clone(),
        )
        .await
        {
            Ok(resp) => resp,
            Err(impossible) => match impossible {},
        }
    }

    async fn handle_connect(
        &self,
        _req_head: http1::Request<()>,
        mut req_stream: H3ServerRequestStream,
        _conn: H3ConnInfo,
        _kind: H3ConnectKind,
    ) -> Result<()> {
        let state = self.runtime.state();
        let proxy_name = state.config.identity.proxy_name.as_str();
        if let Err(err) = send_h3_static_response(
            &mut req_stream,
            http1::StatusCode::METHOD_NOT_ALLOWED,
            state.messages.reverse_error.as_bytes(),
            &http::Method::CONNECT,
            proxy_name,
            state.config.runtime.max_h3_response_body_bytes,
        )
        .await
        {
            warn!(error = ?err, "failed to send reverse HTTP/3 CONNECT rejection response");
        }
        Ok(())
    }
}
