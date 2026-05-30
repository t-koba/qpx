use crate::exporter::ExportSession;
use crate::http::body::{Body, Sender};
use bytes::Bytes;
use hyper::{Request, Response};
use tokio::time::{Duration, timeout};

pub(crate) fn sample_request_body_for_export(
    req: Request<Body>,
    sample_bytes: usize,
    channel_capacity: usize,
    read_timeout: Duration,
    session: ExportSession,
    client_to_server: bool,
) -> Request<Body> {
    let sample_bytes = sample_bytes.max(1);
    let (parts, mut source) = req.into_parts();
    let (mut sender, body) = Body::channel_with_capacity(channel_capacity.max(1));
    tokio::spawn(async move {
        copy_body_with_sample(
            &mut source,
            &mut sender,
            sample_bytes,
            read_timeout,
            session,
            client_to_server,
        )
        .await;
    });
    Request::from_parts(parts, body)
}

pub(crate) fn capture_request_body_for_export(
    req: Request<Body>,
    max_capture_bytes: usize,
    channel_capacity: usize,
    read_timeout: Duration,
    session: ExportSession,
    client_to_server: bool,
) -> Request<Body> {
    let max_capture_bytes = max_capture_bytes.max(1);
    let (parts, mut source) = req.into_parts();
    let (mut sender, body) = Body::channel_with_capacity(channel_capacity.max(1));
    tokio::spawn(async move {
        copy_body_with_full_capture(
            &mut source,
            &mut sender,
            max_capture_bytes,
            read_timeout,
            session,
            client_to_server,
        )
        .await;
    });
    Request::from_parts(parts, body)
}

pub(crate) fn sample_response_body_for_export(
    response: Response<Body>,
    sample_bytes: usize,
    channel_capacity: usize,
    read_timeout: Duration,
    session: ExportSession,
) -> Response<Body> {
    let sample_bytes = sample_bytes.max(1);
    let (parts, mut source) = response.into_parts();
    let (mut sender, body) = Body::channel_with_capacity(channel_capacity.max(1));
    tokio::spawn(async move {
        copy_body_with_sample(
            &mut source,
            &mut sender,
            sample_bytes,
            read_timeout,
            session,
            false,
        )
        .await;
    });
    Response::from_parts(parts, body)
}

pub(crate) fn capture_response_body_for_export(
    response: Response<Body>,
    max_capture_bytes: usize,
    channel_capacity: usize,
    read_timeout: Duration,
    session: ExportSession,
) -> Response<Body> {
    let max_capture_bytes = max_capture_bytes.max(1);
    let (parts, mut source) = response.into_parts();
    let (mut sender, body) = Body::channel_with_capacity(channel_capacity.max(1));
    tokio::spawn(async move {
        copy_body_with_full_capture(
            &mut source,
            &mut sender,
            max_capture_bytes,
            read_timeout,
            session,
            false,
        )
        .await;
    });
    Response::from_parts(parts, body)
}

async fn copy_body_with_sample(
    source: &mut Body,
    sender: &mut Sender,
    sample_bytes: usize,
    read_timeout: Duration,
    session: ExportSession,
    client_to_server: bool,
) {
    let mut sample = Vec::with_capacity(sample_bytes.min(8192));
    let mut sample_emitted = false;
    loop {
        let chunk = tokio::select! {
            _ = sender.closed() => return,
            chunk = timeout(read_timeout, source.data()) => chunk,
        };
        let chunk = match chunk {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(_))) | Err(_) => {
                sender.abort();
                return;
            }
            Ok(None) => break,
        };
        append_sample(&mut sample, sample_bytes, &chunk);
        if sample.len() == sample_bytes && !sample_emitted {
            session.emit_plaintext(client_to_server, sample.as_slice());
            sample_emitted = true;
        }
        if sender.send_data(chunk).await.is_err() {
            return;
        }
    }

    if !sample.is_empty() && !sample_emitted {
        session.emit_plaintext(client_to_server, sample.as_slice());
    }

    let trailers = tokio::select! {
        _ = sender.closed() => return,
        trailers = timeout(read_timeout, source.trailers()) => trailers,
    };
    match trailers {
        Ok(Ok(Some(trailers))) => {
            let _ = sender.send_trailers(trailers).await;
        }
        Ok(Ok(None)) => {}
        Ok(Err(_)) | Err(_) => sender.abort(),
    }
}

async fn copy_body_with_full_capture(
    source: &mut Body,
    sender: &mut Sender,
    max_capture_bytes: usize,
    read_timeout: Duration,
    session: ExportSession,
    client_to_server: bool,
) {
    let mut captured = 0usize;
    loop {
        let chunk = tokio::select! {
            _ = sender.closed() => return,
            chunk = timeout(read_timeout, source.data()) => chunk,
        };
        let chunk = match chunk {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(_))) | Err(_) => {
                sender.abort();
                return;
            }
            Ok(None) => break,
        };
        if captured < max_capture_bytes {
            let remaining = max_capture_bytes - captured;
            let capture_len = remaining.min(chunk.len());
            if capture_len > 0 {
                if capture_len == chunk.len() {
                    session.emit_plaintext_bytes(client_to_server, chunk.clone());
                } else {
                    session.emit_plaintext(client_to_server, &chunk[..capture_len]);
                }
                captured = captured.saturating_add(capture_len);
            }
        }
        if sender.send_data(chunk).await.is_err() {
            return;
        }
    }

    let trailers = tokio::select! {
        _ = sender.closed() => return,
        trailers = timeout(read_timeout, source.trailers()) => trailers,
    };
    match trailers {
        Ok(Ok(Some(trailers))) => {
            let _ = sender.send_trailers(trailers).await;
        }
        Ok(Ok(None)) => {}
        Ok(Err(_)) | Err(_) => sender.abort(),
    }
}

fn append_sample(sample: &mut Vec<u8>, sample_bytes: usize, chunk: &Bytes) {
    if sample.len() >= sample_bytes {
        return;
    }
    let remaining = sample_bytes - sample.len();
    sample.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use crate::exporter::ExporterSink;
    use crate::http::capture::stream::*;
    #[cfg(unix)]
    use qpx_core::config::{CaptureRedactionConfig, ExporterConfig};
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::Duration;

    #[tokio::test]
    #[cfg(unix)]
    async fn capture_stream_sample_preserves_body_and_emits_prefix() {
        let shm_path = unique_test_shm_path();
        let config = ExporterConfig {
            enabled: true,
            shm_path: shm_path.to_string_lossy().into_owned(),
            shm_size_mb: 1,
            lossy: true,
            max_queue_events: 8,
            capture: qpx_core::config::ExporterCaptureConfig {
                plaintext: true,
                encrypted: false,
                max_chunk_bytes: 1024,
                redact: CaptureRedactionConfig::default(),
            },
        };
        let sink = ExporterSink::from_config(&config).expect("sink");
        let session = sink.session("client", "server");
        let req = Request::builder()
            .uri("http://example.test/upload")
            .body(Body::from("abcdef"))
            .expect("request");

        let mut req =
            sample_request_body_for_export(req, 3, 1, Duration::from_secs(1), session, true);

        let body = crate::http::body::to_bytes(req.body_mut())
            .await
            .expect("body");
        assert_eq!(body.as_ref(), b"abcdef");
        let _ = std::fs::remove_file(shm_path);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn capture_stream_sample_preserves_response_body() {
        let shm_path = unique_test_shm_path();
        let config = ExporterConfig {
            enabled: true,
            shm_path: shm_path.to_string_lossy().into_owned(),
            shm_size_mb: 1,
            lossy: true,
            max_queue_events: 8,
            capture: qpx_core::config::ExporterCaptureConfig {
                plaintext: true,
                encrypted: false,
                max_chunk_bytes: 1024,
                redact: CaptureRedactionConfig::default(),
            },
        };
        let sink = ExporterSink::from_config(&config).expect("sink");
        let session = sink.session("client", "server");
        let response = Response::builder()
            .status(200)
            .body(Body::from("response-body"))
            .expect("response");

        let mut response =
            sample_response_body_for_export(response, 4, 1, Duration::from_secs(1), session);

        let body = crate::http::body::to_bytes(response.body_mut())
            .await
            .expect("body");
        assert_eq!(body.as_ref(), b"response-body");
        let _ = std::fs::remove_file(shm_path);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn full_capture_preserves_request_body() {
        let shm_path = unique_test_shm_path();
        let config = ExporterConfig {
            enabled: true,
            shm_path: shm_path.to_string_lossy().into_owned(),
            shm_size_mb: 1,
            lossy: true,
            max_queue_events: 8,
            capture: qpx_core::config::ExporterCaptureConfig {
                plaintext: true,
                encrypted: false,
                max_chunk_bytes: 1024,
                redact: CaptureRedactionConfig::default(),
            },
        };
        let sink = ExporterSink::from_config(&config).expect("sink");
        let session = sink.session("client", "server");
        let req = Request::builder()
            .uri("http://example.test/upload")
            .body(Body::from("abcdef"))
            .expect("request");

        let mut req =
            capture_request_body_for_export(req, 4, 1, Duration::from_secs(1), session, true);

        let body = crate::http::body::to_bytes(req.body_mut())
            .await
            .expect("body");
        assert_eq!(body.as_ref(), b"abcdef");
        let _ = std::fs::remove_file(shm_path);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn full_capture_preserves_response_body() {
        let shm_path = unique_test_shm_path();
        let config = ExporterConfig {
            enabled: true,
            shm_path: shm_path.to_string_lossy().into_owned(),
            shm_size_mb: 1,
            lossy: true,
            max_queue_events: 8,
            capture: qpx_core::config::ExporterCaptureConfig {
                plaintext: true,
                encrypted: false,
                max_chunk_bytes: 1024,
                redact: CaptureRedactionConfig::default(),
            },
        };
        let sink = ExporterSink::from_config(&config).expect("sink");
        let session = sink.session("client", "server");
        let response = Response::builder()
            .status(200)
            .body(Body::from("response-body"))
            .expect("response");

        let mut response =
            capture_response_body_for_export(response, 8, 1, Duration::from_secs(1), session);

        let body = crate::http::body::to_bytes(response.body_mut())
            .await
            .expect("body");
        assert_eq!(body.as_ref(), b"response-body");
        let _ = std::fs::remove_file(shm_path);
    }

    #[test]
    fn sample_append_caps_at_limit() {
        let mut sample = Vec::new();
        append_sample(&mut sample, 4, &Bytes::from_static(b"ab"));
        append_sample(&mut sample, 4, &Bytes::from_static(b"cdef"));
        assert_eq!(sample.as_slice(), b"abcd");
    }

    #[cfg(unix)]
    fn unique_test_shm_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "qpx-capture-stream-{}-{}.shm",
            std::process::id(),
            qpx_core::exporter::unix_timestamp_nanos()
        ))
    }
}
