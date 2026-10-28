use super::Body;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use std::time::Duration;
use tokio::time::timeout;

pub(crate) async fn read_body_data(
    body: &mut Body,
    read_timeout: Duration,
) -> Result<Option<Result<Bytes, qpx_http::body::BodyError>>> {
    timeout(read_timeout, body.data())
        .await
        .map_err(|_| anyhow!("observed body read timed out"))
}

pub(crate) async fn read_body_trailers(
    body: &mut Body,
    read_timeout: Duration,
) -> Result<Option<HeaderMap>> {
    timeout(read_timeout, body.trailers())
        .await
        .map_err(|_| anyhow!("observed body trailers read timed out"))?
        .map_err(Into::into)
}

/// The size the header set declares, read through the owner.
///
/// The declaration is read by `qpx_core::http_content_length`, so the hint
/// is the length the field declares: a comma list of equal members is one
/// length, and a declaration that names no length - one that is not text,
/// one whose members are not digits, or one whose members disagree - gives
/// no hint, so the body is observed rather than sized from the declaration.
pub(super) fn declared_size_hint(headers: &qpx_core::http_message::Headers) -> Option<u64> {
    headers.declared_content_length().ok().flatten()
}
