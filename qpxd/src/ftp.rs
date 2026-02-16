use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use hyper::body::HttpBody as _;
use hyper::{Body, Method, Request, Response, StatusCode};
use qpx_core::config::FtpConfig;
use std::io::{copy, Cursor, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use suppaftp::Mode;
use thiserror::Error;
use tokio::net::lookup_host;
use tokio::sync::Semaphore;
use tokio::task;
use tokio::time::timeout;
use tracing::warn;
use url::Url;

#[derive(Debug, Error)]
#[error("ftp request body exceeds configured limit: {0} bytes")]
struct RequestBodyTooLarge(usize);

#[derive(Debug, Error)]
#[error("ftp response body exceeds configured limit: {0} bytes")]
struct ResponseBodyTooLarge(usize);

#[derive(Debug, Error)]
#[error("ftp upstream operation timed out")]
struct OperationTimedOut;

#[derive(Debug, Error)]
#[error("ftp too many concurrent operations")]
struct TooManyConcurrentOperations;

pub async fn handle_ftp(
    req: Request<Body>,
    limits: FtpConfig,
    unsupported_method_message: Arc<str>,
    semaphore: Arc<Semaphore>,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let uri = req.uri().to_string();
    let timeout_dur = StdDuration::from_millis(limits.timeout_ms.max(1));
    let body_bytes =
        match collect_body_limited(req.into_body(), limits.max_request_body_bytes).await {
            Ok(bytes) => bytes,
            Err(err) => return Ok(ftp_error(err)),
        };
    let url = match Url::parse(uri.as_str()).context("invalid ftp url") {
        Ok(url) => url,
        Err(err) => return Ok(ftp_error(err)),
    };
    let host = match url.host_str().map(ToOwned::to_owned) {
        Some(host) => host,
        None => return Ok(ftp_error(anyhow!("missing ftp host"))),
    };
    let port = url.port().unwrap_or(21);
    let user = if url.username().is_empty() {
        "anonymous".to_string()
    } else {
        url.username().to_string()
    };
    let pass = url.password().unwrap_or("anonymous@").to_string();
    let path = url.path().trim_start_matches('/').to_string();
    let is_dir_listing = url.path().ends_with('/');

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
    let timeout_ms = limits.timeout_ms;
    let unsupported_method_message = unsupported_method_message.clone();
    let response = match timeout(
        timeout_dur,
        task::spawn_blocking(move || {
            // Keep the permit until the blocking FTP work ends even if the caller times out.
            let _permit = permit;
            handle_blocking(BlockingFtpJob {
                method,
                addr,
                user,
                pass,
                path,
                is_dir_listing,
                body: body_bytes,
                max_download_bytes,
                timeout_ms,
                unsupported_method_message,
            })
        }),
    )
    .await
    {
        Ok(joined) => joined?.unwrap_or_else(ftp_error),
        Err(_) => ftp_error(anyhow::Error::new(OperationTimedOut)),
    };
    Ok(response)
}

struct BlockingFtpJob {
    method: Method,
    addr: SocketAddr,
    user: String,
    pass: String,
    path: String,
    is_dir_listing: bool,
    body: Bytes,
    max_download_bytes: usize,
    timeout_ms: u64,
    unsupported_method_message: Arc<str>,
}

fn handle_blocking(job: BlockingFtpJob) -> Result<Response<Body>> {
    let BlockingFtpJob {
        method,
        addr,
        user,
        pass,
        path,
        is_dir_listing,
        body,
        max_download_bytes,
        timeout_ms,
        unsupported_method_message,
    } = job;

    let path_opt = if path.is_empty() {
        None
    } else {
        Some(path.as_str())
    };
    let is_list = method.as_str().eq_ignore_ascii_case("LIST");

    let io_timeout = StdDuration::from_millis(timeout_ms.max(1));
    let mut ftp = suppaftp::FtpStream::connect_timeout(addr, io_timeout)?;
    ftp.get_ref().set_read_timeout(Some(io_timeout))?;
    ftp.get_ref().set_write_timeout(Some(io_timeout))?;
    ftp.login(user.as_str(), pass.as_str())?;

    match method {
        _ if is_list => {
            let list = list_with_mode_fallback(&mut ftp, path_opt)?;
            let body = list.join("\n");
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(body))?)
        }
        Method::GET => {
            if is_dir_listing {
                let list = list_with_mode_fallback(&mut ftp, path_opt)?;
                let body = list.join("\n");
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(body))?)
            } else {
                let buf = get_file_with_mode_fallback(
                    &mut ftp,
                    path.as_str(),
                    max_download_bytes,
                    io_timeout,
                )?;
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(buf))?)
            }
        }
        Method::PUT => {
            put_file_with_mode_fallback(&mut ftp, path.as_str(), body.as_ref(), io_timeout)?;
            Ok(Response::builder()
                .status(StatusCode::CREATED)
                .body(Body::empty())?)
        }
        _ => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from(unsupported_method_message.to_string()))?),
    }
}

fn list_with_mode_fallback(
    ftp: &mut suppaftp::FtpStream,
    path: Option<&str>,
) -> Result<Vec<String>> {
    ftp.set_mode(Mode::Passive);
    match ftp.list(path) {
        Ok(list) => Ok(list),
        Err(passive_err) => {
            ftp.set_mode(Mode::Active);
            ftp.list(path).map_err(|active_err| {
                anyhow!(
                    "FTP LIST failed in passive and active mode: passive={}, active={}",
                    passive_err,
                    active_err
                )
            })
        }
    }
}

fn get_file_with_mode_fallback(
    ftp: &mut suppaftp::FtpStream,
    path: &str,
    max_download_bytes: usize,
    io_timeout: StdDuration,
) -> Result<Vec<u8>> {
    ftp.set_mode(Mode::Passive);
    match get_file_once(ftp, path, max_download_bytes, io_timeout) {
        Ok(data) => Ok(data),
        Err(passive_err) => {
            ftp.set_mode(Mode::Active);
            get_file_once(ftp, path, max_download_bytes, io_timeout).map_err(|active_err| {
                anyhow!(
                    "FTP GET failed in passive and active mode: passive={}, active={}",
                    passive_err,
                    active_err
                )
            })
        }
    }
}

fn get_file_once(
    ftp: &mut suppaftp::FtpStream,
    path: &str,
    max_download_bytes: usize,
    io_timeout: StdDuration,
) -> Result<Vec<u8>> {
    let mut reader = ftp.retr_as_stream(path)?;
    reader.get_ref().set_read_timeout(Some(io_timeout))?;
    let buf = read_to_end_limited(&mut reader, max_download_bytes)?;
    ftp.finalize_retr_stream(reader)?;
    Ok(buf)
}

fn put_file_with_mode_fallback(
    ftp: &mut suppaftp::FtpStream,
    path: &str,
    body: &[u8],
    io_timeout: StdDuration,
) -> Result<()> {
    ftp.set_mode(Mode::Passive);
    match put_file_once(ftp, path, body, io_timeout) {
        Ok(()) => Ok(()),
        Err(passive_err) => {
            ftp.set_mode(Mode::Active);
            put_file_once(ftp, path, body, io_timeout).map_err(|active_err| {
                anyhow!(
                    "FTP PUT failed in passive and active mode: passive={}, active={}",
                    passive_err,
                    active_err
                )
            })
        }
    }
}

fn put_file_once(
    ftp: &mut suppaftp::FtpStream,
    path: &str,
    body: &[u8],
    io_timeout: StdDuration,
) -> Result<()> {
    let mut cursor = Cursor::new(body);
    let mut stream = ftp.put_with_stream(path)?;
    stream.get_ref().set_write_timeout(Some(io_timeout))?;
    copy(&mut cursor, &mut stream)?;
    ftp.finalize_put_stream(stream)?;
    Ok(())
}

fn read_to_end_limited<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let next = out
            .len()
            .checked_add(read)
            .ok_or_else(|| anyhow!("ftp response body length overflow"))?;
        if next > max_bytes {
            return Err(anyhow::Error::new(ResponseBodyTooLarge(max_bytes)));
        }
        out.extend_from_slice(&chunk[..read]);
    }
    Ok(out)
}

async fn collect_body_limited(mut body: Body, max_bytes: usize) -> Result<Bytes> {
    let mut out = BytesMut::new();
    while let Some(frame) = body.data().await {
        let chunk = frame?;
        let next = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("ftp request body length overflow"))?;
        if next > max_bytes {
            return Err(anyhow::Error::new(RequestBodyTooLarge(max_bytes)));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
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
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_to_end_limited_accepts_within_limit() {
        let mut cursor = Cursor::new(vec![1_u8, 2, 3, 4]);
        let out = read_to_end_limited(&mut cursor, 4).expect("read");
        assert_eq!(out, vec![1_u8, 2, 3, 4]);
    }

    #[test]
    fn read_to_end_limited_rejects_over_limit() {
        let mut cursor = Cursor::new(vec![1_u8, 2, 3, 4, 5]);
        let err = read_to_end_limited(&mut cursor, 4).expect_err("must fail");
        assert!(err.downcast_ref::<ResponseBodyTooLarge>().is_some());
    }

    #[tokio::test]
    async fn collect_body_limited_rejects_over_limit() {
        let body = Body::from("12345");
        let err = collect_body_limited(body, 4).await.expect_err("must fail");
        assert!(err.downcast_ref::<RequestBodyTooLarge>().is_some());
    }
}
