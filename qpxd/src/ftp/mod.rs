use anyhow::{Context, Result, anyhow};
use hyper::{Method, Response, StatusCode};
use qpx_core::config::FtpConfig;
use qpx_core::http_message::Request as OwnerRequest;
use qpx_http::body::Body;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use thiserror::Error;
use tokio::net::lookup_host;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tracing::warn;
use url::Url;

mod control;
mod get_put;
mod transfer;

#[cfg(test)]
mod tests;

use control::{FtpDeadline, ensure_safe_ftp_path, open_list_with_mode_fallback};
use get_put::{open_get_file_with_mode_fallback, put_file_with_mode_fallback};
use transfer::{FtpResponseTransform, spawn_ftp_response_body};

pub(crate) fn fuzz_parse_ftp_response_parser(bytes: &[u8]) {
    control::fuzz_parse_ftp_response_parser(bytes);
}

#[derive(Debug, Error)]
#[error("ftp request body exceeds configured limit: {0} bytes")]
pub(super) struct RequestBodyTooLarge(usize);

#[derive(Debug, Error)]
#[error("ftp response body exceeds configured limit: {0} bytes")]
pub(super) struct ResponseBodyTooLarge(usize);

#[derive(Debug, Error)]
#[error("ftp upstream operation timed out")]
pub(super) struct OperationTimedOut;

#[derive(Debug, Error)]
#[error("ftp too many concurrent operations")]
struct TooManyConcurrentOperations;

pub(super) const MAX_FTP_CONTROL_LINE: usize = 8 * 1024;
pub(super) const FTP_RESPONSE_STREAM_CHANNEL_CAPACITY: usize = 8;
pub(super) const MAX_FTP_DEADLINE: StdDuration = StdDuration::from_secs(30 * 24 * 60 * 60);

/// FTP-only ingress value. Never include credentials in Debug or request metadata.
pub(crate) struct FtpCredentials {
    user: String,
    pass: String,
}

impl Default for FtpCredentials {
    fn default() -> Self {
        Self {
            user: "anonymous".into(),
            pass: "anonymous@".into(),
        }
    }
}

impl std::fmt::Debug for FtpCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FtpCredentials(<redacted>)")
    }
}

/// Only forward ingress calls this, before generic validation or observation.
/// Other schemes remain untouched so the generic userinfo rejection still applies.
pub(crate) fn extract_forward_credentials<B>(req: &mut OwnerRequest<B>) -> Result<FtpCredentials> {
    let mut credentials = FtpCredentials::default();
    if !req
        .uri()
        .scheme_str()
        .is_some_and(|s| s.eq_ignore_ascii_case("ftp"))
        || req.method() == Method::CONNECT
    {
        return Ok(credentials);
    }
    if let Some(authority) = req.uri().authority()
        && let Some((userinfo, host)) = authority.as_str().rsplit_once('@')
    {
        if userinfo.contains('@') {
            return Err(anyhow!("invalid FTP credentials"));
        }
        let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, "anonymous@"));
        let decode = |value: &str| -> Result<String> {
            let bytes = value.as_bytes();
            let mut index = 0;
            while index < bytes.len() {
                if bytes[index] == b'%' {
                    if index + 2 >= bytes.len()
                        || !bytes[index + 1].is_ascii_hexdigit()
                        || !bytes[index + 2].is_ascii_hexdigit()
                    {
                        return Err(anyhow!("invalid FTP credentials"));
                    }
                    index += 3;
                } else {
                    index += 1;
                }
            }
            let value = percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .map_err(|_| anyhow!("invalid FTP credentials"))?;
            if value.chars().any(char::is_control) {
                return Err(anyhow!("invalid FTP credentials"));
            }
            Ok(value.into_owned())
        };
        if !user.is_empty() {
            credentials.user = decode(user)?;
        }
        credentials.pass = decode(pass)?;
        let clean_authority = host
            .parse::<http::uri::Authority>()
            .map_err(|_| anyhow!("invalid FTP authority"))?;
        let mut parts = req.uri().clone().into_parts();
        parts.authority = Some(clean_authority);
        *req.uri_mut() = http::Uri::from_parts(parts).map_err(|_| anyhow!("invalid FTP URI"))?;
    }
    // Do not legitimize an invalid Host containing userinfo. Generic preflight
    // will reject it; it must never be used as an alternate credential source.
    Ok(credentials)
}

pub(crate) async fn handle_ftp(
    req: OwnerRequest<Body>,
    credentials: FtpCredentials,
    limits: FtpConfig,
    unsupported_method_message: Arc<str>,
    semaphore: Arc<Semaphore>,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let uri = req.uri().to_string();
    let timeout_dur = StdDuration::from_millis(limits.timeout_ms.max(1));
    let (_, request_body) = req.into_head_and_body();
    let url = match Url::parse(uri.as_str()).context("invalid ftp url") {
        Ok(url) => url,
        Err(err) => return Ok(ftp_error(err)),
    };
    let host = match url.host_str().map(ToOwned::to_owned) {
        Some(host) => host,
        None => return Ok(ftp_error(anyhow!("missing ftp host"))),
    };
    let port = url.port().unwrap_or(21);
    let FtpCredentials { user, pass } = credentials;
    let path = url.path().trim_start_matches('/').to_string();
    let is_dir_listing = url.path().ends_with('/');
    let is_list = method.as_str().eq_ignore_ascii_case("LIST");
    if method != Method::GET && method != Method::PUT && !is_list {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from(unsupported_method_message.to_string()))?);
    }
    if let Err(err) = ensure_safe_ftp_path(if path.is_empty() {
        None
    } else {
        Some(path.as_str())
    }) {
        return Ok(ftp_error(err));
    }

    let addr = match timeout(timeout_dur, lookup_host((host.as_str(), port))).await {
        Ok(Ok(mut iter)) => match iter.next() {
            Some(addr) => addr,
            None => return Ok(ftp_error(anyhow!("unable to resolve ftp host"))),
        },
        Ok(Err(err)) => return Ok(ftp_error(err.into())),
        Err(_) => return Ok(ftp_error(anyhow::Error::new(OperationTimedOut))),
    };

    let permit = match timeout(timeout_dur, semaphore.acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(err)) => return Ok(ftp_error(err.into())),
        Err(_) => return Ok(ftp_error(anyhow::Error::new(TooManyConcurrentOperations))),
    };

    let max_download_bytes = limits.max_download_bytes;
    let max_request_body_bytes = limits.max_request_body_bytes;
    let deadline = FtpDeadline::new(timeout_dur);
    let result = handle_async(AsyncFtpJob {
        method,
        addr,
        user,
        pass,
        path,
        is_dir_listing,
        request_body,
        max_request_body_bytes,
        max_download_bytes,
        deadline,
        permit,
    })
    .await;
    Ok(result.unwrap_or_else(ftp_error))
}

struct AsyncFtpJob {
    method: Method,
    addr: SocketAddr,
    user: String,
    pass: String,
    path: String,
    is_dir_listing: bool,
    request_body: Body,
    max_request_body_bytes: usize,
    max_download_bytes: usize,
    deadline: FtpDeadline,
    permit: OwnedSemaphorePermit,
}

async fn handle_async(job: AsyncFtpJob) -> Result<Response<Body>> {
    let AsyncFtpJob {
        method,
        addr,
        user,
        pass,
        path,
        is_dir_listing,
        request_body,
        max_request_body_bytes,
        max_download_bytes,
        deadline,
        permit,
    } = job;

    let path_opt = if path.is_empty() {
        None
    } else {
        Some(path.as_str())
    };
    let is_list = method.as_str().eq_ignore_ascii_case("LIST");

    if is_list || (method == Method::GET && is_dir_listing) {
        let transfer =
            open_list_with_mode_fallback(addr, user.as_str(), pass.as_str(), path_opt, deadline)
                .await?;
        let body = spawn_ftp_response_body(
            transfer,
            FtpResponseTransform::Listing,
            max_download_bytes,
            permit,
        )?;
        return Ok(Response::builder().status(StatusCode::OK).body(body)?);
    }

    match method {
        Method::GET => {
            let transfer = open_get_file_with_mode_fallback(
                addr,
                user.as_str(),
                pass.as_str(),
                path.as_str(),
                deadline,
            )
            .await?;
            let body = spawn_ftp_response_body(
                transfer,
                FtpResponseTransform::Raw,
                max_download_bytes,
                permit,
            )?;
            Ok(Response::builder().status(StatusCode::OK).body(body)?)
        }
        Method::PUT => {
            let _permit = permit;
            put_file_with_mode_fallback(
                addr,
                user.as_str(),
                pass.as_str(),
                path.as_str(),
                request_body,
                max_request_body_bytes,
                deadline,
            )
            .await?;
            Ok(Response::builder()
                .status(StatusCode::CREATED)
                .body(Body::empty())?)
        }
        _ => unreachable!("unsupported FTP methods are returned before connection setup"),
    }
}

fn ftp_error(err: anyhow::Error) -> Response<Body> {
    warn!(error = ?err, "ftp upstream handling failed");
    let status = if err.downcast_ref::<RequestBodyTooLarge>().is_some() {
        StatusCode::PAYLOAD_TOO_LARGE
    } else if err.downcast_ref::<TooManyConcurrentOperations>().is_some() {
        StatusCode::SERVICE_UNAVAILABLE
    } else if err.downcast_ref::<OperationTimedOut>().is_some()
        || err.to_string().contains("timed out")
    {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::BAD_GATEWAY
    };
    let body = if status == StatusCode::PAYLOAD_TOO_LARGE {
        "payload too large".to_string()
    } else if status == StatusCode::SERVICE_UNAVAILABLE {
        "ftp busy".to_string()
    } else if status == StatusCode::GATEWAY_TIMEOUT {
        "ftp upstream timeout".to_string()
    } else {
        "ftp upstream failure".to_string()
    };
    Response::builder()
        .status(status)
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
