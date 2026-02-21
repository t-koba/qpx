use crate::http::l7::finalize_response_for_request;
use crate::http3::codec::hyper_response_to_h3;
use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};
use hyper::{Body, Response, StatusCode};
use tokio::time::{timeout, Duration};

pub type H3ServerRequestStream = ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Debug)]
pub enum H3ReadBodyError {
    TimedOut,
    TooLarge,
    Stream(anyhow::Error),
}

pub async fn read_h3_request_body(
    req_stream: &mut H3ServerRequestStream,
    read_timeout: Duration,
    max_body_bytes: usize,
) -> std::result::Result<(Bytes, Option<http1::HeaderMap>), H3ReadBodyError> {
    let mut req_body = BytesMut::new();
    loop {
        let recv = match timeout(read_timeout, req_stream.recv_data()).await {
            Ok(recv) => recv,
            Err(_) => return Err(H3ReadBodyError::TimedOut),
        };
        let recv = match recv {
            Ok(recv) => recv,
            Err(err) => return Err(H3ReadBodyError::Stream(err.into())),
        };
        let Some(chunk) = recv else {
            break;
        };
        let mut chunk = chunk;
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        let next = match req_body.len().checked_add(bytes.len()) {
            Some(next) => next,
            None => {
                return Err(H3ReadBodyError::Stream(anyhow!(
                    "HTTP/3 request body length overflow"
                )))
            }
        };
        if next > max_body_bytes {
            return Err(H3ReadBodyError::TooLarge);
        }
        req_body.extend_from_slice(&bytes);
    }

    let trailers = match timeout(read_timeout, req_stream.recv_trailers()).await {
        Ok(trailers) => trailers,
        Err(_) => return Err(H3ReadBodyError::TimedOut),
    };
    let trailers = match trailers {
        Ok(trailers) => trailers,
        Err(err) => return Err(H3ReadBodyError::Stream(err.into())),
    };

    Ok((req_body.freeze(), trailers))
}

pub async fn send_h3_response(
    response: Response<Body>,
    request_method: &http::Method,
    req_stream: &mut H3ServerRequestStream,
    max_h3_response_body_bytes: usize,
) -> Result<()> {
    let (head, body, trailers) =
        hyper_response_to_h3(response, request_method, max_h3_response_body_bytes).await?;
    req_stream.send_response(head).await?;
    if !body.is_empty() {
        req_stream.send_data(body).await?;
    }
    if let Some(trailers) = trailers {
        req_stream.send_trailers(trailers).await?;
    }
    req_stream.finish().await?;
    Ok(())
}

pub async fn send_h3_static_response(
    req_stream: &mut H3ServerRequestStream,
    status: http1::StatusCode,
    body: &[u8],
    request_method: &http::Method,
    proxy_name: &str,
    max_h3_response_body_bytes: usize,
) -> Result<()> {
    let response = finalize_response_for_request(
        request_method,
        http::Version::HTTP_3,
        proxy_name,
        Response::builder()
            .status(StatusCode::from_u16(status.as_u16())?)
            .body(Body::from(body.to_vec()))?,
        false,
    );
    send_h3_response(response, request_method, req_stream, max_h3_response_body_bytes).await
}
