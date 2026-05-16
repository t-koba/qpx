use super::*;
use crate::tls::UpstreamCertificateInfo;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

pub(super) fn prepare_proxy_h2_request(
    mut req: Request<Body>,
    scheme: &str,
    authority: &str,
    proxy_name: &str,
) -> Result<Request<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    prepare_request_with_headers_in_place(&mut req, proxy_name, None, false);
    req.headers_mut().remove(HOST);
    *req.version_mut() = http::Version::HTTP_2;
    *req.uri_mut() = Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path.as_str())
        .build()?;
    Ok(req)
}

pub(super) fn prepare_internal_h2_request(
    mut req: Request<Body>,
    scheme: &str,
    authority: &str,
) -> Result<Request<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    req.headers_mut().remove(HOST);
    *req.version_mut() = http::Version::HTTP_2;
    *req.uri_mut() = Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path.as_str())
        .build()?;
    Ok(req)
}

pub(super) async fn send_h2_request_with_sender(
    req: Request<Body>,
    mut sender: h2::client::SendRequest<Bytes>,
    upstream_cert: Option<UpstreamCertificateInfo>,
    inflight_streams: Option<Arc<AtomicUsize>>,
) -> Result<Http1ResponseWithInterim> {
    let inflight = H2InflightReservation::new(inflight_streams);
    let (parts, mut body) = req.into_parts();
    let declared_length = parse_declared_content_length(&parts.headers)?;
    let mut request = Http1Request::builder()
        .method(parts.method.as_str())
        .uri(http_uri_to_http1_uri(&parts.uri)?)
        .body(())?;
    *request.headers_mut() = http_headers_to_h1(&parts.headers)?;
    *request.version_mut() = ::http::Version::HTTP_2;

    let (mut response, mut send_stream) = sender.send_request(request, false)?;
    stream_request_body_to_h2(&mut body, &mut send_stream, declared_length).await?;
    let (interim, response) = recv_h2_response_with_interim(&mut response).await?;
    let response = h2_response_to_hyper_with_inflight(response, inflight.into_counter())?;
    Ok(Http1ResponseWithInterim {
        interim,
        response,
        upstream_cert,
    })
}

struct H2InflightReservation(Option<Arc<AtomicUsize>>);

impl H2InflightReservation {
    fn new(counter: Option<Arc<AtomicUsize>>) -> Self {
        if let Some(counter) = &counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Self(counter)
    }

    fn into_counter(mut self) -> Option<Arc<AtomicUsize>> {
        self.0.take()
    }
}

impl Drop for H2InflightReservation {
    fn drop(&mut self) {
        if let Some(counter) = self.0.take() {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
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
        crate::http::semantics::validate_request_trailers(&trailers)
            .map_err(|err| anyhow!("{}", err))?;
        send_stream.send_trailers(http_headers_to_h1(&trailers)?)?;
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
                if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
                    return Err(anyhow!("HTTP/2 upstream must not send 101"));
                }
                interim.push(crate::upstream::raw_http1::InterimResponseHead {
                    status: hyper::StatusCode::from_u16(response.status().as_u16())?,
                    headers: h1_headers_to_http(response.headers())?,
                });
            }
            H2ResponseEvent::Final(response) => return Ok((interim, response)),
        }
    }
}

fn http_uri_to_http1_uri(uri: &Uri) -> Result<::http::Uri> {
    uri.to_string()
        .parse::<::http::Uri>()
        .or_else(|_| {
            let mut builder = ::http::Uri::builder();
            if let Some(scheme) = uri.scheme_str() {
                builder = builder.scheme(scheme);
            }
            if let Some(authority) = uri.authority() {
                builder = builder.authority(authority.as_str());
            }
            builder
                .path_and_query(
                    uri.path_and_query()
                        .map(|value| value.as_str())
                        .unwrap_or("/"),
                )
                .build()
        })
        .map_err(|err| anyhow!("invalid HTTP/2 upstream URI: {err}"))
}
