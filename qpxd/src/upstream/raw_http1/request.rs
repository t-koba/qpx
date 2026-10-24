use super::parse_declared_content_length;
use crate::http::body::{poll_body_data_now, poll_body_trailers_now};
use crate::http::codec::h1::write::{chunk_size_header, write_vectored_all};
use crate::http::codec::h1_common::serialize_headers;
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue, TRAILER, TRANSFER_ENCODING,
};
use hyper::{Method, Request, Version};
use qpx_http::body::Body;
use std::task::Poll;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub(crate) struct BodylessHttp1Request(Request<Body>);

pub(super) async fn write_http1_request<S>(
    stream: &mut S,
    req: Request<Body>,
    head: &mut BytesMut,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let (parts, mut body) = req.into_parts();
    let mut headers = parts.headers;
    let declared_length = parse_declared_content_length(&headers)?;
    let body_is_end_stream = http_body::Body::is_end_stream(&body);
    let first_chunk = if declared_length.is_none() && !body_is_end_stream {
        match poll_body_data_now(&mut body).await? {
            Poll::Ready(chunk) => chunk,
            Poll::Pending => None,
        }
    } else {
        None
    };
    let first_trailers =
        if declared_length.is_none() && first_chunk.is_none() && !body_is_end_stream {
            poll_body_trailers_now(&mut body).await?
        } else {
            None
        };
    let use_chunked = declared_length.is_none()
        && (first_chunk.is_some()
            || first_trailers.is_some()
            || !http_body::Body::is_end_stream(&body));
    let announced_trailers = first_trailers
        .as_ref()
        .and_then(announced_request_trailer_names);

    headers.remove(CONNECTION);
    headers.remove(HeaderName::from_static("proxy-connection"));
    headers.remove(TRANSFER_ENCODING);
    headers.remove(TRAILER);
    if use_chunked {
        headers.remove(CONTENT_LENGTH);
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        if let Some(names) = announced_trailers.as_deref()
            && let Ok(value) = HeaderValue::from_str(names)
        {
            headers.insert(TRAILER, value);
        }
    } else if let Some(length) = declared_length {
        // RFC 9110 section 8.6: the value a sender writes is one decimal,
        // so the declaration leaves in the field's canonical form - one
        // field line whose value is the resolved decimal - instead of the
        // value the request carried.
        headers.insert(
            CONTENT_LENGTH,
            qpx_core::http_content_length::canonical_content_length_value(length),
        );
    } else {
        headers.remove(CONTENT_LENGTH);
    }

    head.clear();
    head.reserve(512);
    let version = match parts.version {
        Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    };
    head.extend_from_slice(parts.method.as_str().as_bytes());
    head.extend_from_slice(b" ");
    append_http1_request_target(head, &parts.method, &parts.uri, &parts.extensions);
    head.extend_from_slice(b" ");
    head.extend_from_slice(version.as_bytes());
    head.extend_from_slice(b"\r\n");
    serialize_headers(&headers, head)?;
    head.extend_from_slice(b"\r\n");
    stream.write_all(head).await?;
    crate::http::codec::header_pool::recycle(headers);

    match declared_length {
        Some(length) => write_content_length_body(stream, &mut body, length).await?,
        None if use_chunked => {
            write_chunked_body(
                stream,
                &mut body,
                first_chunk,
                first_trailers,
                use_chunked || announced_trailers.is_some(),
            )
            .await?
        }
        None => {}
    }
    stream.flush().await?;
    Ok(())
}

pub(super) async fn write_prepared_bodyless_http1_request<S>(
    stream: &mut S,
    req: Request<Body>,
    head: &mut BytesMut,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let req = match classify_bodyless_http1_request(req)? {
        Ok(req) => req,
        Err(req) => return write_http1_request(stream, req, head).await,
    };
    serialize_bodyless_http1_request(req, head)?;
    stream.write_all(head).await?;
    stream.flush().await?;
    Ok(())
}

pub(crate) fn classify_bodyless_http1_request(
    req: Request<Body>,
) -> Result<std::result::Result<BodylessHttp1Request, Request<Body>>> {
    let is_bodyless = http_body::Body::is_end_stream(req.body())
        && parse_declared_content_length(req.headers())?.is_none_or(|length| length == 0);
    Ok(if is_bodyless {
        Ok(BodylessHttp1Request(req))
    } else {
        Err(req)
    })
}

pub(crate) fn serialize_bodyless_http1_request(
    req: BodylessHttp1Request,
    head: &mut BytesMut,
) -> Result<Method> {
    let req = req.0;
    debug_assert!(!req.headers().contains_key(CONNECTION));
    debug_assert!(!req.headers().contains_key("proxy-connection"));
    debug_assert!(!req.headers().contains_key(TRANSFER_ENCODING));
    debug_assert!(!req.headers().contains_key(TRAILER));

    let (parts, _body) = req.into_parts();
    let method = parts.method;
    head.clear();
    head.reserve(512);
    head.extend_from_slice(method.as_str().as_bytes());
    head.extend_from_slice(b" ");
    append_http1_request_target(head, &method, &parts.uri, &parts.extensions);
    head.extend_from_slice(b" HTTP/1.1\r\n");
    serialize_headers(&parts.headers, head)?;
    head.extend_from_slice(b"\r\n");
    crate::http::codec::header_pool::recycle(parts.headers);
    Ok(method)
}

fn append_http1_request_target(
    head: &mut BytesMut,
    method: &Method,
    uri: &http::Uri,
    extensions: &http::Extensions,
) {
    if let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) {
        let raw_empty_path_options_target = extensions
            .get::<crate::http::protocol::EmptyPathAbsoluteOptions>()
            .is_some()
            && *method == Method::OPTIONS
            && uri.query().is_none()
            && uri
                .path_and_query()
                .is_none_or(|value| value.as_str() == "/");
        head.extend_from_slice(scheme.as_str().as_bytes());
        head.extend_from_slice(b"://");
        head.extend_from_slice(authority.as_str().as_bytes());
        if raw_empty_path_options_target {
            return;
        }
        if let Some(path_and_query) = uri.path_and_query() {
            head.extend_from_slice(path_and_query.as_str().as_bytes());
        } else {
            head.extend_from_slice(b"/");
        }
    } else if let Some(path_and_query) = uri.path_and_query() {
        head.extend_from_slice(path_and_query.as_str().as_bytes());
    } else {
        head.extend_from_slice(b"/");
    }
}

async fn write_content_length_body<S>(
    stream: &mut S,
    body: &mut Body,
    mut remaining: u64,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let chunk_len = chunk.len() as u64;
        if chunk_len > remaining {
            return Err(anyhow!("request body exceeded declared content-length"));
        }
        if !chunk.is_empty() {
            stream.write_all(&chunk).await?;
        }
        remaining -= chunk_len;
    }
    if remaining != 0 {
        return Err(anyhow!(
            "request body ended before declared content-length was satisfied"
        ));
    }
    if body.trailers().await?.is_some() {
        return Err(anyhow!(
            "request trailers require chunked transfer-encoding"
        ));
    }
    Ok(())
}

async fn write_chunked_body<S>(
    stream: &mut S,
    body: &mut Body,
    first_chunk: Option<Bytes>,
    first_trailers: Option<HeaderMap>,
    allow_trailers: bool,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if let Some(chunk) = first_chunk {
        write_chunk(stream, &chunk).await?;
    }
    while let Some(chunk) = body.data().await {
        write_chunk(stream, &chunk?).await?;
    }
    let trailers = match first_trailers {
        Some(trailers) => Some(trailers),
        None => body.trailers().await?,
    };
    stream.write_all(b"0\r\n").await?;
    if let Some(trailers) = trailers {
        if !allow_trailers {
            return Err(anyhow!(
                "request trailers require Trailer metadata before forwarding"
            ));
        }
        qpx_http::protocol::semantics::validate_request_trailers(&trailers)
            .map_err(|err| anyhow!("invalid HTTP/1 request trailers: {err:?}"))?;
        let mut trailer_block = Vec::with_capacity(256);
        serialize_headers(&trailers, &mut trailer_block)?;
        stream.write_all(&trailer_block).await?;
    }
    stream.write_all(b"\r\n").await?;
    Ok(())
}

fn announced_request_trailer_names(trailers: &HeaderMap) -> Option<String> {
    if qpx_http::protocol::semantics::validate_request_trailers(trailers).is_err() {
        return None;
    }
    let mut names = Vec::new();
    for name in trailers.keys() {
        if name == TRAILER
            || name == CONTENT_LENGTH
            || name == TRANSFER_ENCODING
            || name == CONNECTION
        {
            continue;
        }
        names.push(name.as_str().to_string());
    }
    (!names.is_empty()).then(|| names.join(", "))
}

async fn write_chunk<S>(stream: &mut S, chunk: &Bytes) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if chunk.is_empty() {
        return Ok(());
    }
    let mut header = [0_u8; 18];
    let header = chunk_size_header(chunk.len(), &mut header);
    write_vectored_all(
        stream,
        &[header, chunk, b"\r\n"],
        "failed to write HTTP/1 request",
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{classify_bodyless_http1_request, serialize_bodyless_http1_request};
    use bytes::BytesMut;
    use hyper::header::{CONTENT_LENGTH, HeaderValue};
    use hyper::{Method, Request};
    use qpx_http::body::Body;

    #[test]
    fn classifies_and_serializes_empty_request_once() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/asset?encoding=br")
            .header("host", "origin.test")
            .body(Body::empty())
            .expect("request");
        let classified = classify_bodyless_http1_request(request)
            .expect("content-length validation")
            .expect("bodyless request");
        let mut head = BytesMut::new();

        let method = serialize_bodyless_http1_request(classified, &mut head)
            .expect("serialize request head");

        assert_eq!(method, Method::GET);
        assert_eq!(
            head.as_ref(),
            b"GET /asset?encoding=br HTTP/1.1\r\nhost: origin.test\r\n\r\n"
        );
    }

    #[test]
    fn preserves_declared_body_for_streaming_writer() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .header(CONTENT_LENGTH, "1")
            .body(Body::empty())
            .expect("request");

        let classified =
            classify_bodyless_http1_request(request).expect("content-length validation");

        assert!(classified.is_err());
    }

    #[test]
    fn rejects_conflicting_content_length_before_upstream_io() {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .body(Body::empty())
            .expect("request");
        request
            .headers_mut()
            .append(CONTENT_LENGTH, HeaderValue::from_static("0"));
        request
            .headers_mut()
            .append(CONTENT_LENGTH, HeaderValue::from_static("1"));

        let error = match classify_bodyless_http1_request(request) {
            Err(error) => error,
            Ok(_) => panic!("conflicting content-length must fail"),
        };

        assert!(
            error.to_string().contains("conflicting content-length"),
            "{error}"
        );
    }
}
