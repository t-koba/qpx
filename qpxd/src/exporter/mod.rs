use crate::http::body::size::{
    observed_request_prefix_chunks_async, observed_response_prefix_chunks_async,
};
use crate::http::protocol::common::http_version_label;
use anyhow::Result;
use bytes::Bytes;
use hyper::{Request, Response};
use qpx_core::config::ExporterConfig;
use qpx_core::exporter::{CaptureDirection, CaptureEvent, CapturePlane, unix_timestamp_nanos};
use qpx_core::shm_ring::ShmRingBuffer;
use qpx_http::body::Body;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::warn;

mod metrics;
mod redaction;
#[cfg(test)]
mod tests;

use self::redaction::CaptureRedaction;

const PREVIEW_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct ExporterSink {
    tx: mpsc::Sender<CaptureEvent>,
    session_counter: Arc<AtomicU64>,
    capture_plaintext: bool,
    capture_encrypted: bool,
    max_chunk_bytes: usize,
    redaction: Arc<CaptureRedaction>,
}

#[derive(Clone)]
pub struct ExportSession {
    tx: mpsc::Sender<CaptureEvent>,
    session_id: String,
    client: String,
    server: String,
    capture_plaintext: bool,
    capture_encrypted: bool,
    max_plaintext_bytes: Option<usize>,
    max_chunk_bytes: usize,
    redaction: Arc<CaptureRedaction>,
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
        let redaction = Arc::new(CaptureRedaction::from_config(&config.capture.redact));

        tokio::spawn(async move {
            run_export_loop(ring, lossy, rx).await;
        });

        Ok(Self {
            tx,
            session_counter: Arc::new(AtomicU64::new(1)),
            capture_plaintext,
            capture_encrypted,
            max_chunk_bytes,
            redaction,
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
            max_plaintext_bytes: None,
            max_chunk_bytes: self.max_chunk_bytes,
            redaction: self.redaction.clone(),
        }
    }

    pub fn session_with_capture(
        &self,
        client: impl ToString,
        server: impl ToString,
        capture: &crate::runtime::CompiledCapturePlan,
    ) -> ExportSession {
        let session_index = self.session_counter.fetch_add(1, Ordering::Relaxed);
        let session_id = format!("{}-{}", unix_timestamp_nanos(), session_index);
        let client = client.to_string();
        let server = server.to_string();
        let capture_plaintext = capture
            .plaintext
            .as_ref()
            .map(|plaintext| {
                (plaintext.headers || plaintext.body.is_enabled())
                    && sample_allows(
                        session_id.as_str(),
                        client.as_str(),
                        server.as_str(),
                        plaintext.sample_percent,
                    )
            })
            .unwrap_or(false);
        let scoped_redaction = capture
            .plaintext
            .as_ref()
            .map(|plaintext| Arc::new(CaptureRedaction::from_config(&plaintext.redact)))
            .unwrap_or_else(|| self.redaction.clone());
        ExportSession {
            tx: self.tx.clone(),
            session_id,
            client,
            server,
            capture_plaintext,
            capture_encrypted: capture.encrypted,
            max_plaintext_bytes: capture
                .plaintext
                .as_ref()
                .filter(|plaintext| plaintext.body.is_full())
                .and_then(|plaintext| plaintext.max_body_bytes),
            max_chunk_bytes: self.max_chunk_bytes,
            redaction: scoped_redaction,
        }
    }
}

fn sample_allows(
    session_id: &str,
    client: &str,
    server: &str,
    sample_percent: Option<u32>,
) -> bool {
    let Some(sample_percent) = sample_percent else {
        return true;
    };
    if sample_percent >= 100 {
        return true;
    }
    if sample_percent == 0 {
        return false;
    }
    qpx_http::sharding::modulo(&(session_id, client, server), 100) < sample_percent as usize
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
        if self.tx.capacity() == 0 {
            return metrics::increment(metrics::EVENTS_DROPPED);
        }
        let direction = bool_to_direction(client_to_server);
        let payload = self
            .redaction
            .redact_plaintext_for_export(payload, self.max_plaintext_bytes);
        self.emit(
            CapturePlane::ClientServerPlaintext,
            direction,
            payload.as_ref(),
        );
    }

    pub fn emit_plaintext_bytes(&self, client_to_server: bool, payload: Bytes) {
        if !self.capture_plaintext {
            return;
        }
        if payload.is_empty() {
            return;
        }
        if self.tx.capacity() == 0 {
            return metrics::increment(metrics::EVENTS_DROPPED);
        }
        if self.redaction.is_noop()
            && self
                .max_plaintext_bytes
                .is_none_or(|max| payload.len() <= max)
        {
            let direction = bool_to_direction(client_to_server);
            self.emit_bytes(CapturePlane::ClientServerPlaintext, direction, payload);
            return;
        }
        self.emit_plaintext(client_to_server, payload.as_ref());
    }

    fn emit(&self, plane: CapturePlane, direction: CaptureDirection, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        if self.tx.capacity() == 0 {
            return metrics::increment(metrics::EVENTS_DROPPED);
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
            self.enqueue_event(event);
        }
    }

    fn emit_bytes(&self, plane: CapturePlane, direction: CaptureDirection, payload: Bytes) {
        if payload.is_empty() {
            return;
        }
        if self.tx.capacity() == 0 {
            return metrics::increment(metrics::EVENTS_DROPPED);
        }
        let chunk_size = self.max_chunk_bytes.max(1);
        if payload.len() <= chunk_size {
            self.enqueue_event(CaptureEvent::new_bytes(
                self.session_id.clone(),
                plane,
                direction,
                self.client.clone(),
                self.server.clone(),
                payload,
            ));
            return;
        }
        let mut offset = 0usize;
        while offset < payload.len() {
            let end = offset.saturating_add(chunk_size).min(payload.len());
            let chunk = payload.slice(offset..end);
            let event = CaptureEvent::new_bytes(
                self.session_id.clone(),
                plane.clone(),
                direction.clone(),
                self.client.clone(),
                self.server.clone(),
                chunk,
            );
            self.enqueue_event(event);
            offset = end;
        }
    }

    fn enqueue_event(&self, event: CaptureEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {
                metrics::increment(metrics::EVENTS_ENQUEUED);
            }
            Err(_) => {
                metrics::increment(metrics::EVENTS_DROPPED);
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
    let mut prefix = Vec::<u8>::new();
    while let Some(event) = rx.recv().await {
        if let Err(err) = event.encode_wire_prefix(&mut prefix) {
            warn!(error = ?err, "failed to encode exporter event");
            continue;
        }
        let wire_len = match event.wire_len() {
            Ok(len) => len,
            Err(err) => {
                warn!(error = ?err, "failed to size exporter event");
                continue;
            }
        };
        let payload = event.payload_bytes();

        loop {
            match ring.try_push_vectored(&[prefix.as_slice(), payload]) {
                Ok(true) => {
                    // Success!
                    metrics::increment(metrics::EVENTS_SENT);
                    metrics::increment_by(metrics::BYTES_SENT, wire_len as u64);
                    break;
                }
                Ok(false) => {
                    // Buffer is full.
                    if lossy {
                        // In lossy mode, we just drop the event to prioritize performance.
                        metrics::increment(metrics::EVENTS_DROPPED);
                        break;
                    } else {
                        // Lossless mode. Wait and try again.
                        // Note: This backpressures the mpsc channel, which backpressures the proxy pipeline.
                        metrics::increment(metrics::WRITE_BLOCKED);
                        if let Err(e) = ring.wait_for_space(wire_len).await {
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

pub(crate) fn serialize_request_preview_async(
    req: &Request<Body>,
) -> impl std::future::Future<Output = Vec<u8>> + Send + 'static {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();
    let headers = req.headers().clone();
    let body = observed_request_prefix_chunks_async(req, PREVIEW_BODY_BYTES);
    async move {
        let mut out = String::new();
        out.push_str(method.as_str());
        out.push(' ');
        out.push_str(
            uri.path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or_else(|| uri.path()),
        );
        out.push(' ');
        out.push_str(http_version_label(version));
        out.push_str("\r\n");
        for (name, value) in &headers {
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
        if let Some(chunks) = body.await {
            push_utf8_preview_chunks(&mut out, &chunks);
        }
        out.into_bytes()
    }
}

pub(crate) fn serialize_response_preview_async(
    response: &Response<Body>,
) -> impl std::future::Future<Output = Vec<u8>> + Send + 'static {
    let version = response.version();
    let status = response.status();
    let headers = response.headers().clone();
    let body = observed_response_prefix_chunks_async(response, PREVIEW_BODY_BYTES);
    async move {
        let mut out = String::new();
        out.push_str(http_version_label(version));
        out.push(' ');
        out.push_str(status.as_str());
        if let Some(reason) = status.canonical_reason() {
            out.push(' ');
            out.push_str(reason);
        }
        out.push_str("\r\n");
        for (name, value) in &headers {
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
        if let Some(chunks) = body.await {
            push_utf8_preview_chunks(&mut out, &chunks);
        }
        out.into_bytes()
    }
}

fn push_utf8_preview_chunks(out: &mut String, chunks: &[Bytes]) {
    for chunk in chunks {
        out.push_str(std::str::from_utf8(chunk.as_ref()).unwrap_or("<non-utf8 body>"));
    }
}

fn bool_to_direction(client_to_server: bool) -> CaptureDirection {
    if client_to_server {
        CaptureDirection::ClientToServer
    } else {
        CaptureDirection::ServerToClient
    }
}
