use crate::http::codec::h2::{
    InflightCounterGuard, h2_response_to_hyper_with_inflight, http_uri_to_http1_uri,
    parse_declared_content_length,
};
use crate::http::protocol::l7::prepare_request_with_headers_in_place;
use crate::upstream::raw_http1::Http1ResponseWithInterim;
use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use hyper::Uri;
use hyper::header::HOST;
use qpx_core::http_message::{OrdinaryHeaderName, Request as OwnerRequest};
use qpx_core::tls::UpstreamCertificateInfo;
use qpx_http::body::Body;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::task::Poll;

pub(super) fn prepare_proxy_h2_request(
    req: OwnerRequest<Body>,
    scheme: &str,
    authority: &str,
    proxy_name: &str,
) -> Result<OwnerRequest<Body>> {
    prepare_h2_request(req, scheme, authority, Some(proxy_name))
}

pub(super) fn prepare_internal_h2_request(
    req: OwnerRequest<Body>,
    scheme: &str,
    authority: &str,
) -> Result<OwnerRequest<Body>> {
    prepare_h2_request(req, scheme, authority, None)
}

fn prepare_h2_request(
    mut req: OwnerRequest<Body>,
    scheme: &str,
    authority: &str,
    proxy_name: Option<&str>,
) -> Result<OwnerRequest<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    if let Some(proxy_name) = proxy_name {
        prepare_request_with_headers_in_place(&mut req, proxy_name, None, false);
    }
    req.headers_mut()
        .remove(&OrdinaryHeaderName::try_from(HOST).expect("host is an ordinary field"));
    *req.version_mut() = http::Version::HTTP_2;
    *req.uri_mut() = Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path.as_str())
        .build()?;
    Ok(req)
}

pub(super) async fn send_h2_request_with_sender(
    req: hyper::Request<Body>,
    mut sender: h2::client::SendRequest<Bytes>,
    upstream_cert: Option<UpstreamCertificateInfo>,
    inflight_streams: Option<Arc<AtomicUsize>>,
) -> Result<Http1ResponseWithInterim> {
    let inflight = InflightCounterGuard::reserve(inflight_streams);
    let (parts, mut body) = req.into_parts();
    let declared_length = parse_declared_content_length(&parts.headers)?;
    let mut request = Http1Request::builder()
        .method(parts.method.as_str())
        .uri(http_uri_to_http1_uri(
            &parts.uri,
            "invalid HTTP/2 upstream URI",
        )?)
        .body(())?;
    *request.headers_mut() = parts.headers;
    // RFC 9110 section 8.6: the value a sender writes is one decimal, so
    // the declaration leaves in the field's canonical form. RFC 9113
    // section 8.1.1 makes a comma list of lengths malformed in HTTP/2, so
    // the field the origin receives is the one the section allows.
    if let Some(length) = declared_length {
        request.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            qpx_core::http_content_length::canonical_content_length_value(length),
        );
    }
    *request.version_mut() = ::http::Version::HTTP_2;

    let (mut response, mut send_stream) = sender.send_request(request, false)?;
    stream_request_body_to_h2(&mut body, &mut send_stream, declared_length).await?;
    let (interim, response) = recv_h2_response_with_interim(&mut response).await?;
    let response = h2_response_to_hyper_with_inflight(response, inflight)?;
    Ok(Http1ResponseWithInterim {
        interim,
        response,
        upstream_cert,
        response_finalized: false,
    })
}

async fn stream_request_body_to_h2(
    body: &mut Body,
    send_stream: &mut h2::SendStream<Bytes>,
    declared_length: Option<u64>,
) -> Result<()> {
    let mut sent_len = 0u64;
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        sent_len = sent_len
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow!("HTTP/2 request body length overflow"))?;
        if let Some(expected) = declared_length
            && sent_len > expected
        {
            send_stream.send_reset(h2::Reason::PROTOCOL_ERROR);
            return Err(anyhow!(
                "HTTP/2 request body exceeded declared content-length"
            ));
        }
        if !chunk.is_empty() {
            send_stream.send_data(chunk, false)?;
        }
    }

    let trailers = body.trailers().await?;
    if let Some(expected) = declared_length
        && sent_len != expected
    {
        send_stream.send_reset(h2::Reason::PROTOCOL_ERROR);
        return Err(anyhow!(
            "HTTP/2 request body ended before declared content-length was satisfied"
        ));
    }
    if let Some(trailers) = trailers {
        qpx_http::protocol::semantics::validate_request_trailers(&trailers)
            .map_err(|err| anyhow!("{}", err))?;
        send_stream.send_trailers(trailers)?;
    } else {
        send_stream.send_data(Bytes::new(), true)?;
    }
    Ok(())
}

async fn recv_h2_response_with_interim(
    response: &mut h2::client::ResponseFuture,
) -> Result<(
    Vec<crate::upstream::raw_http1::InterimResponseHead>,
    Http1Response<h2::RecvStream>,
)> {
    let mut interim = Vec::new();
    loop {
        enum H2ResponseEvent {
            Informational(Http1Response<()>),
            Final(Http1Response<h2::RecvStream>),
        }

        let event = poll_fn(|cx| match Pin::new(&mut *response).poll(cx) {
            Poll::Ready(Ok(response)) => Poll::Ready(Ok(H2ResponseEvent::Final(response))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(anyhow!(err))),
            Poll::Pending => match response.poll_informational(cx) {
                Poll::Ready(Some(Ok(response))) => {
                    Poll::Ready(Ok(H2ResponseEvent::Informational(response)))
                }
                Poll::Ready(Some(Err(err))) => Poll::Ready(Err(anyhow!(err))),
                Poll::Ready(None) | Poll::Pending => Poll::Pending,
            },
        })
        .await?;

        match event {
            H2ResponseEvent::Informational(response) => {
                let status = qpx_http::protocol::semantics::validate_http_status_class(
                    response.status(),
                    "HTTP/2 upstream interim response",
                )?;
                if status == http::StatusCode::SWITCHING_PROTOCOLS {
                    return Err(anyhow!("HTTP/2 upstream must not send 101"));
                }
                let (parts, ()) = response.into_parts();
                interim.push(crate::upstream::raw_http1::InterimResponseHead::new(
                    status,
                    parts.headers,
                ));
            }
            H2ResponseEvent::Final(response) => return Ok((interim, response)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::VIA;

    #[test]
    fn h2_request_preparation_keeps_proxy_headers_out_of_internal_path() -> Result<()> {
        let request = || -> Result<OwnerRequest<Body>> {
            Ok(OwnerRequest::from_http(
                Http1Request::builder()
                    .method("GET")
                    .uri("http://incoming.invalid/path?x=1")
                    .header(HOST, "incoming.invalid")
                    .body(Body::empty())?,
            ))
        };

        let host = OrdinaryHeaderName::try_from(HOST).expect("host is an ordinary field");
        let via = OrdinaryHeaderName::try_from(VIA).expect("via is an ordinary field");
        let proxy = prepare_proxy_h2_request(request()?, "https", "proxy.invalid", "qpx-test")?;
        assert_eq!(proxy.version(), http::Version::HTTP_2);
        assert_eq!(proxy.uri().to_string(), "https://proxy.invalid/path?x=1");
        assert!(!proxy.headers().contains_key(&host));
        assert_eq!(
            proxy
                .headers()
                .get(&via)
                .and_then(|value| value.to_str().ok()),
            Some("1.1 qpx-test")
        );

        let internal = prepare_internal_h2_request(request()?, "https", "internal.invalid")?;
        assert_eq!(internal.version(), http::Version::HTTP_2);
        assert_eq!(
            internal.uri().to_string(),
            "https://internal.invalid/path?x=1"
        );
        assert!(!internal.headers().contains_key(&host));
        assert!(!internal.headers().contains_key(&via));
        Ok(())
    }
}
