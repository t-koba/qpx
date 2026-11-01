macro_rules! define_upstream_error_response_body {
    ($function:ident, $stream:ty, $to_bytes:expr $(,)?) => {
        fn $function(
            mut upstream: $stream,
            body_read_timeout: ::std::time::Duration,
        ) -> ::qpx_http::body::Body {
            let to_bytes = $to_bytes;
            let (mut sender, body) = ::qpx_http::body::Body::channel_with_capacity(16);
            ::tokio::spawn(async move {
                loop {
                    let next = ::tokio::select! {
                        _ = sender.closed() => return,
                        recv = ::tokio::time::timeout(body_read_timeout, upstream.recv_data()) => recv,
                    };
                    match next {
                        Err(_) => {
                            ::tracing::warn!("extended CONNECT upstream error body timed out");
                            sender.abort();
                            return;
                        }
                        Ok(Ok(Some(chunk))) => {
                            if sender.send_data(to_bytes(chunk)).await.is_err() {
                                return;
                            }
                        }
                        Ok(Ok(None)) => break,
                        Ok(Err(err)) => {
                            ::tracing::warn!(error = ?err, "extended CONNECT upstream error body stream failed");
                            sender.abort();
                            return;
                        }
                    }
                }
                let trailers = ::tokio::select! {
                    _ = sender.closed() => return,
                    recv = ::tokio::time::timeout(body_read_timeout, upstream.recv_trailers()) => recv,
                };
                match trailers {
                    Err(_) => {
                        ::tracing::warn!("extended CONNECT upstream error trailers timed out");
                        sender.abort();
                    }
                    Ok(Ok(Some(trailers))) => {
                        match $crate::http3::codec::h1_headers_to_http(&trailers) {
                            Ok(trailers) => {
                                let _ = sender.send_trailers(trailers).await;
                            }
                            Err(err) => {
                                ::tracing::warn!(error = ?err, "extended CONNECT upstream trailers were invalid");
                            }
                        }
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(err)) => {
                        ::tracing::warn!(error = ?err, "extended CONNECT upstream error trailers failed");
                    }
                }
            });
            body
        }
    };
}

pub(super) use define_upstream_error_response_body;
