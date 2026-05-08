use crate::http::body::Body;
use crate::http::body_size::{observed_request_bytes, observed_response_bytes};
use crate::http::common::http_version_label;
use anyhow::Result;
use hyper::{Request, Response};
use metrics::counter;
use qpx_core::config::{CaptureRedactionConfig, ExporterConfig};
use qpx_core::exporter::{unix_timestamp_nanos, CaptureDirection, CaptureEvent, CapturePlane};
use qpx_core::shm_ring::ShmRingBuffer;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
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

#[derive(Clone)]
struct CaptureRedaction {
    headers: Vec<String>,
    query_keys: Vec<String>,
    json_paths: Vec<Vec<String>>,
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
                (plaintext.headers || plaintext.body)
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
                .filter(|plaintext| plaintext.body)
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
    let mut hasher = DefaultHasher::new();
    session_id.hash(&mut hasher);
    client.hash(&mut hasher);
    server.hash(&mut hasher);
    hasher.finish() % 100 < sample_percent as u64
}

impl CaptureRedaction {
    fn from_config(config: &CaptureRedactionConfig) -> Self {
        Self {
            headers: config
                .headers
                .iter()
                .map(|header| header.to_ascii_lowercase())
                .collect(),
            query_keys: config
                .query_keys
                .iter()
                .map(|key| key.to_ascii_lowercase())
                .collect(),
            json_paths: config
                .json_paths
                .iter()
                .filter_map(|path| compile_json_path(path))
                .collect(),
        }
    }

    fn redact_plaintext(&self, payload: &[u8]) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(payload) else {
            return payload.to_vec();
        };
        let mut out = String::with_capacity(text.len());
        for (idx, line) in text.split_inclusive('\n').enumerate() {
            if idx == 0 {
                out.push_str(self.redact_request_line(line).as_str());
                continue;
            }
            if let Some((name, _)) = line.split_once(':') {
                if self
                    .headers
                    .iter()
                    .any(|header| header.eq_ignore_ascii_case(name.trim()))
                {
                    out.push_str(name);
                    out.push_str(": <redacted>\r\n");
                    continue;
                }
            }
            out.push_str(line);
        }
        self.redact_json_body(out).into_bytes()
    }

    fn redact_request_line(&self, line: &str) -> String {
        let mut parts = line.splitn(3, ' ');
        let Some(method) = parts.next() else {
            return line.to_string();
        };
        let Some(target) = parts.next() else {
            return line.to_string();
        };
        let Some(version) = parts.next() else {
            return line.to_string();
        };
        let Some((path, query)) = target.split_once('?') else {
            return line.to_string();
        };
        let redacted_query = query
            .split('&')
            .map(|pair| {
                let key = pair.split_once('=').map(|(key, _)| key).unwrap_or(pair);
                if self
                    .query_keys
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(key))
                {
                    format!("{key}=<redacted>")
                } else {
                    pair.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        format!("{method} {path}?{redacted_query} {version}")
    }

    fn redact_json_body(&self, text: String) -> String {
        if self.json_paths.is_empty() {
            return text;
        }
        let Some((head, body, separator)) = split_http_message(text.as_str()) else {
            return text;
        };
        if !head.lines().any(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-type: application/json")
        }) {
            return text;
        }
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(body.trim_end()) else {
            return text;
        };
        for path in &self.json_paths {
            redact_json_value(&mut value, path);
        }
        let Ok(redacted_body) = serde_json::to_string(&value) else {
            return text;
        };
        format!("{head}{separator}{redacted_body}")
    }
}

fn compile_json_path(path: &str) -> Option<Vec<String>> {
    let path = path.trim().strip_prefix("$.")?;
    if path.is_empty() {
        return None;
    }
    Some(path.split('.').map(str::to_string).collect())
}

fn split_http_message(text: &str) -> Option<(&str, &str, &'static str)> {
    if let Some((head, body)) = text.split_once("\r\n\r\n") {
        return Some((head, body, "\r\n\r\n"));
    }
    text.split_once("\n\n")
        .map(|(head, body)| (head, body, "\n\n"))
}

fn redact_json_value(value: &mut serde_json::Value, path: &[String]) {
    let Some((head, tail)) = path.split_first() else {
        *value = serde_json::Value::String("<redacted>".to_string());
        return;
    };
    match value {
        serde_json::Value::Object(map) => {
            if let Some(next) = map.get_mut(head) {
                redact_json_value(next, tail);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_value(item, path);
            }
        }
        _ => {}
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
        let payload = self.redaction.redact_plaintext(payload);
        let payload = match self.max_plaintext_bytes {
            Some(max) => &payload[..payload.len().min(max)],
            None => payload.as_slice(),
        };
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
    if let Some(body) = observed_request_bytes(req) {
        out.push_str(std::str::from_utf8(body.as_ref()).unwrap_or("<non-utf8 body>"));
    }
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
    if let Some(body) = observed_response_bytes(response) {
        out.push_str(std::str::from_utf8(body.as_ref()).unwrap_or("<non-utf8 body>"));
    }
    out.into_bytes()
}

fn bool_to_direction(client_to_server: bool) -> CaptureDirection {
    if client_to_server {
        CaptureDirection::ClientToServer
    } else {
        CaptureDirection::ServerToClient
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_plaintext_headers_and_query_keys() {
        let redaction = CaptureRedaction::from_config(&CaptureRedactionConfig {
            headers: vec!["authorization".to_string()],
            query_keys: vec!["token".to_string()],
            json_paths: vec![
                "$.password".to_string(),
                "$.nested.access_token".to_string(),
            ],
        });
        let out = redaction.redact_plaintext(
            b"POST /api?token=secret&ok=yes HTTP/1.1\r\nauthorization: bearer secret\r\nhost: example.com\r\ncontent-type: application/json\r\n\r\n{\"password\":\"secret\",\"nested\":{\"access_token\":\"abc\"},\"ok\":true}",
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("token=<redacted>"));
        assert!(text.contains("authorization: <redacted>"));
        assert!(text.contains("host: example.com"));
        assert!(!text.contains("bearer secret"));
        assert!(text.contains("\"password\":\"<redacted>\""));
        assert!(text.contains("\"access_token\":\"<redacted>\""));
        assert!(!text.contains("\"secret\""));
        assert!(!text.contains("\"abc\""));
    }

    #[test]
    fn scoped_session_can_enable_targeted_capture() {
        let (tx, _rx) = mpsc::channel(1);
        let sink = ExporterSink {
            tx,
            session_counter: Arc::new(AtomicU64::new(1)),
            capture_plaintext: false,
            capture_encrypted: false,
            max_chunk_bytes: 1024,
            redaction: Arc::new(CaptureRedaction::from_config(
                &CaptureRedactionConfig::default(),
            )),
        };

        let capture = crate::runtime::CompiledCapturePlan {
            encrypted: false,
            plaintext: Some(crate::runtime::CompiledPlaintextCapturePlan {
                headers: true,
                body: true,
                sample_percent: Some(100),
                max_body_bytes: Some(4),
                redact: CaptureRedactionConfig {
                    headers: vec!["x-secret".to_string()],
                    query_keys: Vec::new(),
                    json_paths: Vec::new(),
                },
            }),
        };
        let session = sink.session_with_capture("client", "server", &capture);

        assert!(session.capture_plaintext);
        assert!(!session.capture_encrypted);
        assert_eq!(session.max_plaintext_bytes, Some(4));
        assert!(session
            .redaction
            .headers
            .iter()
            .any(|header| header == "x-secret"));
    }

    #[test]
    fn scoped_session_respects_zero_percent_sampling() {
        let (tx, _rx) = mpsc::channel(1);
        let sink = ExporterSink {
            tx,
            session_counter: Arc::new(AtomicU64::new(1)),
            capture_plaintext: false,
            capture_encrypted: false,
            max_chunk_bytes: 1024,
            redaction: Arc::new(CaptureRedaction::from_config(
                &CaptureRedactionConfig::default(),
            )),
        };
        let capture = crate::runtime::CompiledCapturePlan {
            encrypted: false,
            plaintext: Some(crate::runtime::CompiledPlaintextCapturePlan {
                headers: true,
                body: false,
                sample_percent: Some(0),
                max_body_bytes: None,
                redact: CaptureRedactionConfig::default(),
            }),
        };

        let session = sink.session_with_capture("client", "server", &capture);

        assert!(!session.capture_plaintext);
    }
}
