// Extracted from rpc/mod.rs; keep public re-exports in mod.rs.
use crate::http::body::Body;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::{HeaderMap, Response, StatusCode};
use qpx_core::config::RpcLocalResponseConfig;
use serde_json::json;

pub(crate) fn build_rpc_local_response(
    config: &RpcLocalResponseConfig,
    payload: &[u8],
) -> Result<Response<Body>> {
    match config.protocol.trim().to_ascii_lowercase().as_str() {
        "grpc" => build_grpc_local_response(config, payload),
        "grpc_web" => build_grpc_web_local_response(config, payload),
        "connect" => build_connect_local_response(config),
        other => Err(anyhow!("unsupported rpc local response protocol: {other}")),
    }
}

fn build_grpc_local_response(
    config: &RpcLocalResponseConfig,
    payload: &[u8],
) -> Result<Response<Body>> {
    let http_status = StatusCode::from_u16(config.http_status.unwrap_or(200))
        .map_err(|_| anyhow!("invalid grpc local response HTTP status"))?;
    let mut response = Response::builder()
        .status(http_status)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(build_grpc_body(config, payload)?)?;
    apply_rpc_headers(response.headers_mut(), &config.headers)?;
    Ok(response)
}

fn build_grpc_web_local_response(
    config: &RpcLocalResponseConfig,
    payload: &[u8],
) -> Result<Response<Body>> {
    let http_status = StatusCode::from_u16(config.http_status.unwrap_or(200))
        .map_err(|_| anyhow!("invalid grpc_web local response HTTP status"))?;
    let mut response = Response::builder()
        .status(http_status)
        .header(http::header::CONTENT_TYPE, "application/grpc-web+proto")
        .body(build_grpc_web_body(config, payload)?)?;
    apply_rpc_headers(response.headers_mut(), &config.headers)?;
    Ok(response)
}

fn build_connect_local_response(config: &RpcLocalResponseConfig) -> Result<Response<Body>> {
    let http_status = StatusCode::from_u16(config.http_status.unwrap_or(503))
        .map_err(|_| anyhow!("invalid connect local response HTTP status"))?;
    let mut body = serde_json::to_vec(&json!({
        "code": config.status.clone().unwrap_or_else(|| "unavailable".to_string()),
        "message": config.message.clone().unwrap_or_default(),
    }))?;
    if !config.trailers.is_empty() {
        return Err(anyhow!(
            "connect rpc local responses do not support trailers"
        ));
    }
    let mut response = Response::builder()
        .status(http_status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(std::mem::take(&mut body)))?;
    apply_rpc_headers(response.headers_mut(), &config.headers)?;
    Ok(response)
}

fn build_grpc_body(config: &RpcLocalResponseConfig, payload: &[u8]) -> Result<Body> {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        http::header::HeaderName::from_static("grpc-status"),
        http::HeaderValue::from_str(config.status.as_deref().unwrap_or("0"))?,
    );
    if let Some(message) = config.message.as_deref() {
        let encoded =
            percent_encoding::utf8_percent_encode(message, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        trailers.insert(
            http::header::HeaderName::from_static("grpc-message"),
            http::HeaderValue::from_str(encoded.as_str())?,
        );
    }
    for (name, value) in &config.trailers {
        let header = http::header::HeaderName::from_bytes(name.as_bytes())?;
        let value = http::HeaderValue::from_str(value)?;
        trailers.insert(header, value);
    }

    let (mut sender, body) = Body::channel_with_capacity(16);
    let payload = Bytes::copy_from_slice(payload);
    tokio::spawn(async move {
        if !payload.is_empty() {
            let _ = sender.send_data(frame_grpc_message(payload).into()).await;
        }
        let _ = sender.send_trailers(trailers).await;
    });
    Ok(body)
}

fn build_grpc_web_body(config: &RpcLocalResponseConfig, payload: &[u8]) -> Result<Body> {
    let mut out = Vec::new();
    if !payload.is_empty() {
        out.extend_from_slice(&frame_grpc_message(Bytes::copy_from_slice(payload)));
    }

    let mut trailers = Vec::new();
    trailers.extend_from_slice(b"grpc-status: ");
    trailers.extend_from_slice(config.status.as_deref().unwrap_or("0").as_bytes());
    trailers.extend_from_slice(b"\r\n");
    if let Some(message) = config.message.as_deref() {
        let encoded =
            percent_encoding::utf8_percent_encode(message, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        trailers.extend_from_slice(b"grpc-message: ");
        trailers.extend_from_slice(encoded.as_bytes());
        trailers.extend_from_slice(b"\r\n");
    }
    for (name, value) in &config.trailers {
        trailers.extend_from_slice(name.as_bytes());
        trailers.extend_from_slice(b": ");
        trailers.extend_from_slice(value.as_bytes());
        trailers.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(&frame_grpc_web_trailers(&trailers));
    Ok(Body::from(out))
}

fn apply_rpc_headers(
    headers: &mut HeaderMap,
    custom: &std::collections::HashMap<String, String>,
) -> Result<()> {
    for (name, value) in custom {
        let header = http::header::HeaderName::from_bytes(name.as_bytes())?;
        let value = http::HeaderValue::from_str(value)?;
        headers.insert(header, value);
    }
    Ok(())
}

pub(super) fn frame_grpc_message(bytes: Bytes) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.push(0);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    out
}

pub(super) fn frame_grpc_web_trailers(trailers: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + trailers.len());
    out.push(0x80);
    out.extend_from_slice(&(trailers.len() as u32).to_be_bytes());
    out.extend_from_slice(trailers);
    out
}
