use crate::http::codec::h2::{
    InflightCounterGuard, h2_response_to_owner_with_inflight, http_uri_to_http1_uri,
    parse_declared_content_length,
};
use crate::http::protocol::l7::prepare_request_with_headers_in_place;
use crate::upstream::raw_http1::Http1ResponseWithInterim;
use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use qpx_core::http_message::Request as OwnerRequest;
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

pub(super) fn prepare_h2_request(
    mut req: OwnerRequest<Body>,
    scheme: &str,
    authority: &str,
    proxy_name: Option<&str>,
) -> Result<OwnerRequest<Body>> {
    if let Some(proxy_name) = proxy_name {
        prepare_request_with_headers_in_place(&mut req, proxy_name, None, false);
    }
    super::prepare_origin_request_head(req, scheme, authority, http::Version::HTTP_2)
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
    let mut upload = tokio::spawn(async move {
        stream_request_body_to_h2(&mut body, &mut send_stream, declared_length).await
    });
    let mut recv = Box::pin(recv_h2_response_with_interim(&mut response));
    let mut upload_error = None;
    let (interim, response) = poll_fn(|cx| {
        if !upload.is_finished()
            && let Poll::Ready(joined) = Pin::new(&mut upload).poll(cx)
        {
            upload_error = Some(match joined {
                Ok(Ok(())) => return recv.as_mut().poll(cx),
                Ok(Err(err)) => err,
                Err(err) => anyhow!("HTTP/2 request upload task failed: {err}"),
            });
        }
        if let Some(err) = upload_error.take() {
            return Poll::Ready(Err(err));
        }
        recv.as_mut().poll(cx)
    })
    .await?;
    let mut response = h2_response_to_owner_with_inflight(response, inflight)?;
    if !upload.is_finished() {
        // A final response can precede upload EOF. Keep the upload alive with
        // the response body so it is aborted with the exchange, not forgotten.
        response.body_mut().retain_resource(upload);
    }
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

        // h2 documents that informational responses must be polled before the
        // main response: polling the final future first skips (and discards)
        // any 1xx heads already queued on the stream.
        let event = poll_fn(|cx| match response.poll_informational(cx) {
            Poll::Ready(Some(Ok(response))) => {
                Poll::Ready(Ok(H2ResponseEvent::Informational(response)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(anyhow!(err))),
            Poll::Ready(None) | Poll::Pending => match Pin::new(&mut *response).poll(cx) {
                Poll::Ready(Ok(response)) => Poll::Ready(Ok(H2ResponseEvent::Final(response))),
                Poll::Ready(Err(err)) => Poll::Ready(Err(anyhow!(err))),
                Poll::Pending => Poll::Pending,
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
    use hyper::header::{HOST, VIA};
    use qpx_core::http_message::OrdinaryHeaderName;

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

        let internal = prepare_h2_request(request()?, "https", "internal.invalid", None)?;
        assert_eq!(internal.version(), http::Version::HTTP_2);
        assert_eq!(
            internal.uri().to_string(),
            "https://internal.invalid/path?x=1"
        );
        assert!(!internal.headers().contains_key(&host));
        assert!(!internal.headers().contains_key(&via));
        Ok(())
    }

    #[tokio::test]
    async fn recv_h2_response_with_interim_keeps_buffered_early_hints() -> Result<()> {
        async fn drive_to_idle<F>(connection: &mut F)
        where
            F: Future<Output = std::result::Result<(), h2::Error>> + Unpin,
        {
            if let Some(result) = futures_util::future::poll_immediate(&mut *connection).await {
                result.expect("h2 connection stays open");
            }
        }

        let (client_io, server_io) = tokio::io::duplex(4096);
        let (mut client, mut client_connection) = h2::client::handshake(client_io).await?;
        let mut server_connection = h2::server::handshake(server_io).await?;
        drive_to_idle(&mut client_connection).await;

        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://origin.test/preload")
            .body(())
            .expect("request");
        let (mut response_future, _send_stream) = client.send_request(request, true)?;
        drive_to_idle(&mut client_connection).await;

        let (request, mut respond) = server_connection.accept().await.expect("accept request")?;
        assert_eq!(request.method(), ::http::Method::GET);

        let hints = ::http::Response::builder()
            .status(::http::StatusCode::EARLY_HINTS)
            .header(::http::header::LINK, "</app.css>; rel=preload")
            .body(())
            .expect("informational response");
        respond.send_informational(hints)?;
        let final_response = ::http::Response::builder()
            .status(::http::StatusCode::OK)
            .body(())
            .expect("final response");
        respond.send_response(final_response, true)?;

        // Flush both heads and let the client process them before the receive
        // helper runs: the 103 must already be queued behind the final 200.
        for _ in 0..2 {
            poll_fn(|cx| {
                if let Poll::Ready(result) = server_connection.poll_closed(cx) {
                    result.expect("h2 server connection stays open");
                }
                Poll::Ready(())
            })
            .await;
        }
        drive_to_idle(&mut client_connection).await;

        let (interim, response) = recv_h2_response_with_interim(&mut response_future).await?;
        assert_eq!(response.status(), ::http::StatusCode::OK);
        assert_eq!(
            interim.len(),
            1,
            "buffered 103 must survive an already-buffered final response"
        );
        assert_eq!(interim[0].status, ::http::StatusCode::EARLY_HINTS);
        assert_eq!(
            interim[0]
                .headers_for_egress()
                .get(::http::header::LINK)
                .and_then(|value| value.to_str().ok()),
            Some("</app.css>; rel=preload")
        );
        Ok(())
    }

    #[tokio::test]
    async fn final_h2_response_does_not_wait_for_request_upload() -> Result<()> {
        use std::time::Duration;
        use tokio::time::timeout;

        let (client_io, server_io) = tokio::io::duplex(4096);
        let (client, client_connection) = h2::client::handshake(client_io).await?;
        tokio::spawn(async move {
            let _ = client_connection.await;
        });

        let server_task = tokio::spawn(async move {
            let mut server_connection = h2::server::handshake(server_io).await?;
            let (_request, mut respond) =
                server_connection.accept().await.expect("accept request")?;
            let response = ::http::Response::builder()
                .status(::http::StatusCode::FORBIDDEN)
                .body(())
                .expect("final response");
            let mut send_stream = respond.send_response(response, false)?;
            send_stream.send_data(Bytes::from_static(b"denied"), true)?;
            poll_fn(|cx| match server_connection.poll_closed(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(()),
                Poll::Ready(Err(err)) => panic!("server connection failed: {err}"),
                Poll::Pending => Poll::Pending,
            })
            .await;
            Ok::<_, anyhow::Error>(())
        });

        let (upload_sender, body) = Body::channel();
        let request = hyper::Request::builder()
            .method("POST")
            .uri("https://origin.test/upload")
            .body(body)?;
        let exchange = timeout(
            Duration::from_secs(2),
            send_h2_request_with_sender(request, client, None, None),
        )
        .await
        .expect("final response must arrive before upload EOF")?;
        assert_eq!(exchange.response.status(), ::http::StatusCode::FORBIDDEN);
        let bytes = timeout(
            Duration::from_secs(2),
            qpx_http::body::to_bytes(exchange.response.into_head_and_body().1),
        )
        .await
        .expect("response body must be readable before upload EOF")?;
        assert_eq!(bytes.as_ref(), b"denied");

        drop(upload_sender);
        server_task.await??;
        Ok(())
    }
}
