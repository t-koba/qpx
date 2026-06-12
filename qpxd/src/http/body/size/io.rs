use super::Body;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_LENGTH;
use std::time::Duration;
use tokio::time::timeout;

pub(super) async fn read_body_data(
    body: &mut Body,
    read_timeout: Duration,
) -> Result<Option<Result<Bytes, qpx_http::body::BodyError>>> {
    timeout(read_timeout, body.data())
        .await
        .map_err(|_| anyhow!("observed body read timed out"))
}

pub(super) async fn read_body_trailers(
    body: &mut Body,
    read_timeout: Duration,
) -> Result<Option<HeaderMap>> {
    timeout(read_timeout, body.trailers())
        .await
        .map_err(|_| anyhow!("observed body trailers read timed out"))?
        .map_err(Into::into)
}

pub(super) fn parse_content_length(headers: &http::HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}
