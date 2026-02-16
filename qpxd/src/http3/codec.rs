use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use http1::{Request as Http1Request, Response as Http1Response};
use hyper::body::HttpBody as _;
use hyper::{Body, Request, Response, Uri};
use tokio::spawn;

pub fn h1_headers_to_http(src: &http1::HeaderMap) -> Result<http::HeaderMap> {
    let mut headers = http::HeaderMap::new();
    for (name, value) in src {
        let name = http::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|e| anyhow!("invalid header name from HTTP/3 message: {e}"))?;
        let value = http::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| anyhow!("invalid header value from HTTP/3 message: {e}"))?;
        headers.append(name, value);
    }
    Ok(headers)
}

pub fn http_headers_to_h1(src: &http::HeaderMap) -> Result<http1::HeaderMap> {
    let mut headers = http1::HeaderMap::new();
    for (name, value) in src {
        let name = http1::header::HeaderName::from_bytes(name.as_str().as_bytes())
            .map_err(|e| anyhow!("invalid header name for HTTP/3 message: {e}"))?;
        let value = http1::HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| anyhow!("invalid header value for HTTP/3 message: {e}"))?;
        headers.append(name, value);
    }
    Ok(headers)
}

pub fn h3_request_to_hyper(
    req: Http1Request<()>,
    body: Bytes,
    trailers: Option<http1::HeaderMap>,
) -> Result<Request<Body>> {
    let (parts, _) = req.into_parts();
    let method = parts
        .method
        .as_str()
        .parse::<http::Method>()
        .map_err(|_| anyhow!("invalid HTTP/3 method"))?;
    let uri = parts
        .uri
        .to_string()
        .parse::<Uri>()
        .or_else(|_| {
            let path = parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            Uri::builder().path_and_query(path).build()
        })
        .map_err(|e| anyhow!("invalid HTTP/3 URI: {e}"))?;

    let trailers = trailers.as_ref().map(h1_headers_to_http).transpose()?;
    let mut out = Request::builder()
        .method(method)
        .uri(uri)
        .body(body_from_h3_parts(body, trailers))?;
    *out.headers_mut() = h1_headers_to_http(&parts.headers)?;
    *out.version_mut() = http::Version::HTTP_3;
    Ok(out)
}

pub async fn hyper_response_to_h3(
    response: Response<Body>,
    max_body_bytes: usize,
) -> Result<(Http1Response<()>, Bytes, Option<http1::HeaderMap>)> {
    let (parts, body) = response.into_parts();
    let status = http1::StatusCode::from_u16(parts.status.as_u16())
        .map_err(|e| anyhow!("invalid response status for HTTP/3: {e}"))?;
    let (bytes, trailers) = collect_body_limited(body, max_body_bytes).await?;
    let mut headers = parts.headers;
    if parts.status.is_informational()
        || parts.status == http::StatusCode::NO_CONTENT
        || parts.status == http::StatusCode::NOT_MODIFIED
        || parts.status == http::StatusCode::RESET_CONTENT
    {
        headers.remove(http::header::CONTENT_LENGTH);
        headers.remove(http::header::TRANSFER_ENCODING);
        headers.remove(http::header::TRAILER);
    } else if !bytes.is_empty() {
        let body_len = bytes.len() as u64;
        let content_length = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if let Some(expected) = content_length {
            if expected != body_len {
                headers.remove(http::header::CONTENT_LENGTH);
            }
        } else if headers.contains_key(http::header::CONTENT_LENGTH) {
            headers.remove(http::header::CONTENT_LENGTH);
        }
    }

    let mut out = Http1Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(&headers)?;
    let trailers = trailers.as_ref().map(http_headers_to_h1).transpose()?;
    Ok((out, bytes, trailers))
}

fn body_from_h3_parts(body: Bytes, trailers: Option<http::HeaderMap>) -> Body {
    if trailers.is_none() {
        return Body::from(body);
    }

    let (mut sender, out) = Body::channel();
    spawn(async move {
        if !body.is_empty() && sender.send_data(body).await.is_err() {
            return;
        }
        if let Some(trailers) = trailers {
            let _ = sender.send_trailers(trailers).await;
        }
    });
    out
}

async fn collect_body_limited(
    mut body: Body,
    max_body_bytes: usize,
) -> Result<(Bytes, Option<http::HeaderMap>)> {
    let mut out = BytesMut::new();
    while let Some(frame) = body.data().await {
        let chunk = frame?;
        let next = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("HTTP/3 response body length overflow"))?;
        if next > max_body_bytes {
            return Err(anyhow!(
                "HTTP/3 response body exceeds configured limit: {} bytes",
                max_body_bytes
            ));
        }
        out.extend_from_slice(&chunk);
    }
    let trailers = body.trailers().await?;
    Ok((out.freeze(), trailers))
}
