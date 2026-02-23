use anyhow::Result;
use hyper::{Body, Request, Response};
use metrics::counter;
use qpx_core::config::ExporterConfig;
use qpx_core::exporter::{unix_timestamp_nanos, CaptureDirection, CaptureEvent, CapturePlane};
use qpx_core::shm_ring::ShmRingBuffer;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

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

        let shm_path = if config.shm_path.trim().is_empty() {
            ShmRingBuffer::default_capture_shm_path()
                .to_string_lossy()
                .into_owned()
        } else {
            config.shm_path.clone()
        };
        let shm_size_bytes = config.shm_size_mb * 1024 * 1024;
        let lossy = config.lossy;

        // Initialize ring buffer. This must successfully open/create it.
        let ring = ShmRingBuffer::create_or_open(&shm_path, shm_size_bytes)?;

        let capture_plaintext = config.capture.plaintext;
        let capture_encrypted = config.capture.encrypted;
        let max_chunk_bytes = config.capture.max_chunk_bytes.max(1);

        tokio::spawn(async move {
            run_export_loop(ring, lossy, rx).await;
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

async fn run_export_loop(
    mut ring: ShmRingBuffer,
    lossy: bool,
    mut rx: mpsc::Receiver<CaptureEvent>,
) {
    // Thread name setting is removed because qpxd doesn't have a generic `util` module for it.
    let mut serialized = Vec::<u8>::new();
    while let Some(event) = rx.recv().await {
        if let Err(err) = event.encode_wire(&mut serialized) {
            warn!(error = ?err, "failed to encode exporter event");
            continue;
        }

        loop {
            match ring.try_push(&serialized) {
                Ok(true) => {
                    // Success!
                    counter!("qpx_exporter_events_sent_total").increment(1);
                    counter!("qpx_exporter_bytes_sent_total").increment(serialized.len() as u64);
                    break;
                }
                Ok(false) => {
                    // Buffer is full.
                    if lossy {
                        // In lossy mode, we just drop the event to prioritize performance.
                        counter!("qpx_exporter_events_dropped_total").increment(1);
                        break;
                    } else {
                        // Lossless mode. Wait and try again.
                        // Note: This backpressures the mpsc channel, which backpressures the proxy pipeline.
                        counter!("qpx_exporter_write_blocked_total").increment(1);
                        if let Err(e) = ring.wait_for_space(serialized.len()).await {
                            warn!(error = ?e, "fatal error waiting for shared memory ring space");
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!(error = ?e, "fatal error pushing to shared memory ring buffer");
                    break;
                }
            }
        }
    }
}

fn should_include_export_preview_header(name: &str) -> bool {
    // Default to an allowlist to avoid leaking custom secret headers (e.g. x-api-key).
    matches!(
        name,
        "host"
            | "user-agent"
            | "accept"
            | "accept-language"
            | "accept-encoding"
            | "cache-control"
            | "pragma"
            | "content-type"
            | "content-length"
            | "etag"
            | "last-modified"
            | "expires"
            | "location"
            | "via"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-request-id"
            | "traceparent"
            | "tracestate"
    )
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
        let name = name.as_str();
        if !should_include_export_preview_header(name) {
            continue;
        }
        out.push_str(name);
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
        let name = name.as_str();
        if !should_include_export_preview_header(name) {
            continue;
        }
        out.push_str(name);
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
