use crate::tls::client::BoxTlsStream;
use anyhow::{anyhow, Context, Result};
use hyper::{Body, Request, Response};
use metrics::counter;
use qpx_core::config::ExporterConfig;
use qpx_core::exporter::{
    unix_timestamp_nanos, CaptureDirection, CaptureEvent, CapturePlane, EVENT_PREFACE_LINE,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::warn;

#[cfg(feature = "tls-rustls")]
use qpx_core::tls::{build_client_config, load_cert_chain, load_private_key};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone)]
struct ExportClientConfig {
    endpoint: String,
    token: Option<String>,
    tls: Option<ExportClientTlsConfig>,
}

#[derive(Clone)]
enum ExportClientTlsConfig {
    #[cfg(feature = "tls-rustls")]
    Rustls {
        connector: tokio_rustls::TlsConnector,
        server_name: String,
    },
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    Native {
        connector: tokio_native_tls::TlsConnector,
        server_name: String,
    },
}

#[derive(Clone)]
pub struct ExporterSink {
    tx: mpsc::Sender<CaptureEvent>,
    session_counter: Arc<AtomicU64>,
    capture_plaintext: bool,
    capture_encrypted: bool,
    max_chunk_bytes: usize,
}

#[derive(Clone)]
pub struct ExportSession {
    tx: mpsc::Sender<CaptureEvent>,
    session_id: String,
    client: String,
    server: String,
    capture_plaintext: bool,
    capture_encrypted: bool,
    max_chunk_bytes: usize,
}

impl ExporterSink {
    pub fn from_config(config: &ExporterConfig) -> Result<Self> {
        let (tx, rx) = mpsc::channel(config.max_queue_events);
        let token = config
            .auth
            .as_ref()
            .and_then(|a| a.token_env.as_deref())
            .map(|env| -> Result<String> {
                let value = std::env::var(env).with_context(|| {
                    format!("exporter.auth.token_env is set but {env} is missing")
                })?;
                let value = value.trim().to_string();
                if value.is_empty() {
                    return Err(anyhow!("{env} is set but empty"));
                }
                Ok(value)
            })
            .transpose()?;

        let tls = match config.tls.as_ref().filter(|t| t.enabled) {
            Some(tls) => {
                let authority: http::uri::Authority = config
                    .endpoint
                    .parse()
                    .map_err(|_| anyhow!("exporter.endpoint is invalid (expected host:port)"))?;
                let server_name = tls
                    .server_name
                    .as_deref()
                    .unwrap_or(authority.host())
                    .trim()
                    .to_string();
                if server_name.is_empty() {
                    return Err(anyhow!(
                        "exporter.tls.server_name must not be empty when set"
                    ));
                }

                #[cfg(feature = "tls-rustls")]
                {
                    let ca_path = tls.ca_cert.as_deref().map(std::path::Path::new);
                    let client_chain = tls
                        .client_cert
                        .as_deref()
                        .map(std::path::Path::new)
                        .map(load_cert_chain)
                        .transpose()?;
                    let client_key = tls
                        .client_key
                        .as_deref()
                        .map(std::path::Path::new)
                        .map(load_private_key)
                        .transpose()?;
                    let client_config = build_client_config(
                        ca_path,
                        client_chain,
                        client_key,
                        tls.insecure_skip_verify,
                    )?;
                    Some(ExportClientTlsConfig::Rustls {
                        connector: tokio_rustls::TlsConnector::from(client_config),
                        server_name,
                    })
                }

                #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
                {
                    use native_tls::Certificate;
                    use std::fs;

                    let mut builder = native_tls::TlsConnector::builder();
                    if tls.insecure_skip_verify {
                        builder
                            .danger_accept_invalid_certs(true)
                            .danger_accept_invalid_hostnames(true);
                    }
                    if let Some(ca_path) = tls
                        .ca_cert
                        .as_deref()
                        .map(|p| p.trim())
                        .filter(|p| !p.is_empty())
                    {
                        let pem = fs::read(ca_path).with_context(|| {
                            format!("failed to read exporter.tls.ca_cert {}", ca_path)
                        })?;
                        let cert = Certificate::from_pem(&pem).map_err(|_| {
                            anyhow!("invalid PEM in exporter.tls.ca_cert {}", ca_path)
                        })?;
                        builder.add_root_certificate(cert);
                    }
                    if let Some(pkcs12_path) = tls
                        .client_pkcs12
                        .as_deref()
                        .map(|p| p.trim())
                        .filter(|p| !p.is_empty())
                    {
                        let password = match tls.client_pkcs12_password_env.as_deref() {
                            Some(env) => std::env::var(env)
                                .with_context(|| format!("exporter.tls.client_pkcs12_password_env is set but {env} is missing"))?,
                            None => String::new(),
                        };
                        let der = fs::read(pkcs12_path).with_context(|| {
                            format!("failed to read exporter.tls.client_pkcs12 {}", pkcs12_path)
                        })?;
                        let identity =
                            native_tls::Identity::from_pkcs12(&der, password.as_str())
                                .map_err(|_| anyhow!("invalid pkcs12 identity {}", pkcs12_path))?;
                        builder.identity(identity);
                    }
                    let connector = tokio_native_tls::TlsConnector::from(builder.build()?);
                    Some(ExportClientTlsConfig::Native {
                        connector,
                        server_name,
                    })
                }

                #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
                {
                    return Err(anyhow!(
                        "exporter.tls is enabled, but this build has no TLS backend enabled"
                    ));
                }
            }
            None => None,
        };

        let client_cfg = ExportClientConfig {
            endpoint: config.endpoint.clone(),
            token,
            tls,
        };
        let capture_plaintext = config.capture.plaintext;
        let capture_encrypted = config.capture.encrypted;
        let max_chunk_bytes = config.capture.max_chunk_bytes.max(1);
        tokio::spawn(async move {
            run_export_loop(client_cfg, rx).await;
        });
        Ok(Self {
            tx,
            session_counter: Arc::new(AtomicU64::new(1)),
            capture_plaintext,
            capture_encrypted,
            max_chunk_bytes,
        })
    }

    pub fn session(&self, client: impl ToString, server: impl ToString) -> ExportSession {
        let session_index = self.session_counter.fetch_add(1, Ordering::Relaxed);
        let session_id = format!("{}-{}", unix_timestamp_nanos(), session_index);
        ExportSession {
            tx: self.tx.clone(),
            session_id,
            client: client.to_string(),
            server: server.to_string(),
            capture_plaintext: self.capture_plaintext,
            capture_encrypted: self.capture_encrypted,
            max_chunk_bytes: self.max_chunk_bytes,
        }
    }
}

impl ExportSession {
    pub fn emit_encrypted_pair(&self, client_to_server: bool, payload: &[u8]) {
        if !self.capture_encrypted {
            return;
        }
        let direction = bool_to_direction(client_to_server);
        self.emit(
            CapturePlane::ClientProxyEncrypted,
            direction.clone(),
            payload,
        );
        self.emit(CapturePlane::ProxyServerEncrypted, direction, payload);
    }

    pub fn emit_plaintext(&self, client_to_server: bool, payload: &[u8]) {
        if !self.capture_plaintext {
            return;
        }
        let direction = bool_to_direction(client_to_server);
        self.emit(CapturePlane::ClientServerPlaintext, direction, payload);
    }

    fn emit(&self, plane: CapturePlane, direction: CaptureDirection, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        for chunk in payload.chunks(self.max_chunk_bytes.max(1)) {
            let event = CaptureEvent::new(
                self.session_id.clone(),
                plane.clone(),
                direction.clone(),
                self.client.clone(),
                self.server.clone(),
                chunk,
            );
            match self.tx.try_send(event) {
                Ok(()) => {
                    counter!("qpx_exporter_events_enqueued_total").increment(1);
                }
                Err(_) => {
                    counter!("qpx_exporter_events_dropped_total").increment(1);
                }
            }
        }
    }
}

type ExportIo = BoxTlsStream;

async fn run_export_loop(cfg: ExportClientConfig, mut rx: mpsc::Receiver<CaptureEvent>) {
    let mut stream: Option<ExportIo> = None;
    while let Some(event) = rx.recv().await {
        let line = match serde_json::to_vec(&event) {
            Ok(value) => value,
            Err(err) => {
                warn!(error = ?err, "failed to serialize exporter event");
                continue;
            }
        };

        if stream.is_none() {
            match connect_exporter(&cfg).await {
                Ok(io) => stream = Some(io),
                Err(err) => {
                    counter!("qpx_exporter_connect_failures_total").increment(1);
                    warn!(error = ?err, endpoint = %cfg.endpoint, "exporter connect failed");
                    continue;
                }
            }
        }

        let Some(conn) = stream.as_mut() else {
            continue;
        };
        let write_result = timeout(WRITE_TIMEOUT, async {
            conn.write_all(&line).await?;
            conn.write_all(b"\n").await
        })
        .await;

        match write_result {
            Ok(Ok(())) => {
                counter!("qpx_exporter_events_sent_total").increment(1);
                counter!("qpx_exporter_bytes_sent_total").increment((line.len() + 1) as u64);
            }
            Ok(Err(err)) => {
                counter!("qpx_exporter_write_failures_total").increment(1);
                warn!(error = ?err, endpoint = %cfg.endpoint, "exporter write failed");
                stream = None;
            }
            Err(_) => {
                counter!("qpx_exporter_write_failures_total").increment(1);
                warn!(endpoint = %cfg.endpoint, "exporter write timed out");
                stream = None;
            }
        }
    }
}

async fn connect_exporter(cfg: &ExportClientConfig) -> Result<ExportIo> {
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(cfg.endpoint.as_str()))
        .await
        .context("connect timed out")??;
    let mut io: ExportIo = match cfg.tls.as_ref() {
        #[cfg(feature = "tls-rustls")]
        Some(ExportClientTlsConfig::Rustls {
            connector,
            server_name,
        }) => {
            let server_name = rustls_server_name_for_host(server_name.as_str())?;
            let tls = timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
                .await
                .context("tls connect timed out")??;
            Box::new(tls)
        }
        #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
        Some(ExportClientTlsConfig::Native {
            connector,
            server_name,
        }) => {
            let tls = timeout(
                CONNECT_TIMEOUT,
                connector.connect(server_name.as_str(), tcp),
            )
            .await
            .context("tls connect timed out")??;
            Box::new(tls)
        }
        #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
        Some(_) => {
            return Err(anyhow!(
                "exporter TLS is configured but this build has no TLS backend enabled"
            ));
        }
        None => Box::new(tcp),
    };

    io.write_all(format!("{EVENT_PREFACE_LINE}\n").as_bytes())
        .await?;
    if let Some(token) = cfg.token.as_deref() {
        io.write_all(format!("AUTH {token}\n").as_bytes()).await?;
    }
    Ok(io)
}

#[cfg(feature = "tls-rustls")]
fn rustls_server_name_for_host(host: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    use std::net::IpAddr;

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(rustls::pki_types::ServerName::IpAddress(ip.into()));
    }
    rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("invalid server name for TLS: {}", host))
}

pub fn serialize_request_preview(req: &Request<Body>) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(req.method().as_str());
    out.push(' ');
    out.push_str(req.uri().to_string().as_str());
    out.push(' ');
    out.push_str(http_version_label(req.version()));
    out.push_str("\r\n");
    for (name, value) in req.headers() {
        out.push_str(name.as_str());
        out.push_str(": ");
        if let Ok(text) = value.to_str() {
            out.push_str(text);
        }
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

pub fn serialize_response_preview(response: &Response<Body>) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(http_version_label(response.version()));
    out.push(' ');
    out.push_str(response.status().as_str());
    if let Some(reason) = response.status().canonical_reason() {
        out.push(' ');
        out.push_str(reason);
    }
    out.push_str("\r\n");
    for (name, value) in response.headers() {
        out.push_str(name.as_str());
        out.push_str(": ");
        if let Ok(text) = value.to_str() {
            out.push_str(text);
        }
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn bool_to_direction(client_to_server: bool) -> CaptureDirection {
    if client_to_server {
        CaptureDirection::ClientToServer
    } else {
        CaptureDirection::ServerToClient
    }
}

fn http_version_label(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2",
        http::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}
