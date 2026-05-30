mod provisioner;
mod store;

pub use provisioner::run_manager;
pub use store::AcmeCertStore;
#[cfg(feature = "http3")]
pub use store::AcmeQuicCertStore;
use store::Http01TokenStore;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use qpx_core::config::Config;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};

type Http01Body = BoxBody<Bytes, std::convert::Infallible>;
const ACME_HTTP01_MAX_CONCURRENCY: usize = 128;
const ACME_HTTP01_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const ACME_HTTP01_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub trait ConfigProvider: Send + Sync {
    fn current_operational_config(&self) -> Arc<Config>;
}
pub struct AcmeRuntime {
    pub(crate) operational_config_provider: Arc<dyn ConfigProvider>,
    pub(crate) directory_url: String,
    pub(crate) renew_before_days: u64,
    pub(crate) contact_email: Option<String>,
    pub(crate) tos_agreed: bool,
    pub(crate) http01_listen: SocketAddr,
    pub(crate) certs_dir: PathBuf,
    pub(crate) account_path: PathBuf,
    pub(crate) store: Arc<AcmeCertStore>,
    #[cfg(feature = "http3")]
    pub(crate) quic_store: Arc<AcmeQuicCertStore>,
    pub(crate) tokens: Arc<Http01TokenStore>,
}

static STATE: OnceLock<Arc<AcmeRuntime>> = OnceLock::new();

pub fn cert_store() -> Option<&'static AcmeCertStore> {
    STATE.get().map(|s| s.store.as_ref())
}

#[cfg(feature = "http3")]
pub fn quic_cert_store() -> Option<&'static AcmeQuicCertStore> {
    STATE.get().map(|s| s.quic_store.as_ref())
}

pub fn init(
    config: &Config,
    config_provider: Arc<dyn ConfigProvider>,
) -> Result<Option<Arc<AcmeRuntime>>> {
    let Some(acme) = config.acme.as_ref().filter(|a| a.enabled) else {
        return Ok(None);
    };

    let state_root = config
        .state_dir
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("state_dir missing (required for ACME)"))?;
    let http01_listen = acme
        .http01_listen
        .as_deref()
        .ok_or_else(|| anyhow!("acme.http01_listen missing"))?
        .parse::<SocketAddr>()
        .map_err(|e| anyhow!("acme.http01_listen is invalid: {e}"))?;

    let state_dir = PathBuf::from(state_root).join("acme");
    let certs_dir = state_dir.join("certs");
    let account_path = state_dir.join("account.json");
    provisioner::ensure_dir(&state_dir, 0o700)
        .with_context(|| format!("failed to create ACME state dir {}", state_dir.display()))?;
    provisioner::ensure_dir(&certs_dir, 0o700)
        .with_context(|| format!("failed to create ACME certs dir {}", certs_dir.display()))?;

    let rt = Arc::new(AcmeRuntime {
        operational_config_provider: config_provider,
        directory_url: provisioner::acme_directory_url(acme),
        renew_before_days: acme.renew_before_days,
        contact_email: acme.email.clone(),
        tos_agreed: acme.terms_of_service_agreed,
        http01_listen,
        certs_dir,
        account_path,
        store: Arc::new(AcmeCertStore::new()),
        #[cfg(feature = "http3")]
        quic_store: Arc::new(AcmeQuicCertStore::new()),
        tokens: Arc::new(Http01TokenStore::new()),
    });

    let _ = STATE.set(rt.clone());
    provisioner::preload_certs(rt.as_ref())?;
    Ok(Some(rt))
}
pub async fn run_http01_server(state: Arc<AcmeRuntime>) -> Result<()> {
    let addr = state.http01_listen;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind acme.http01_listen={addr}"))?;
    run_http01_server_with_listener(listener, state).await
}

pub async fn run_http01_server_with_std_listener(
    listener: std::net::TcpListener,
    state: Arc<AcmeRuntime>,
) -> Result<()> {
    listener
        .set_nonblocking(true)
        .context("failed to set inherited acme http-01 listener nonblocking")?;
    let listener = TcpListener::from_std(listener)
        .context("failed to adopt inherited acme http-01 listener")?;
    run_http01_server_with_listener(listener, state).await
}

async fn run_http01_server_with_listener(
    listener: TcpListener,
    state: Arc<AcmeRuntime>,
) -> Result<()> {
    let addr = listener.local_addr().unwrap_or(state.http01_listen);
    let tokens = state.tokens.clone();
    let concurrency = Arc::new(Semaphore::new(ACME_HTTP01_MAX_CONCURRENCY));
    info!(listen = %addr, "acme http-01 challenge server started");
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| anyhow!("acme http-01 accept failed: {e}"))?;
        let permit = match concurrency.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(peer = %peer, "acme http-01 connection cap exceeded");
                drop(stream);
                continue;
            }
        };
        let tokens = tokens.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |req: Request<Incoming>| {
                let tokens = tokens.clone();
                async move { Ok::<_, std::convert::Infallible>(handle_http01(req, &tokens)) }
            });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .keep_alive(false)
                .header_read_timeout(Some(ACME_HTTP01_HEADER_READ_TIMEOUT));
            let conn = builder.serve_connection(TokioIo::new(stream), service);
            let result = tokio::time::timeout(ACME_HTTP01_REQUEST_TIMEOUT, conn).await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    warn!(peer = %peer, error = ?err, "acme http-01 connection failed");
                }
                Err(_) => {
                    warn!(peer = %peer, "acme http-01 connection timed out");
                }
            }
        });
    }
}

fn empty_body() -> Http01Body {
    Empty::<Bytes>::new().boxed()
}

fn full_body(body: impl Into<Bytes>) -> Http01Body {
    Full::new(body.into()).boxed()
}

fn handle_http01(req: Request<Incoming>, tokens: &Http01TokenStore) -> Response<Http01Body> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(empty_body())
            .unwrap();
    }
    let path = req.uri().path();
    let prefix = "/.well-known/acme-challenge/";
    if !path.starts_with(prefix) {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())
            .unwrap();
    }
    let token = &path[prefix.len()..];
    if token.is_empty() || token.contains('/') {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(empty_body())
            .unwrap();
    }
    match tokens.get(token) {
        Some(key_auth) => Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(if req.method() == Method::HEAD {
                empty_body()
            } else {
                full_body(key_auth)
            })
            .unwrap(),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())
            .unwrap(),
    }
}
