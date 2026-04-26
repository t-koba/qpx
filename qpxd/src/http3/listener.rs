use crate::http::body::Body;
use crate::http::body_size::set_observed_request_size;
use crate::http3::codec::{h3_request_to_hyper, sanitize_interim_response_for_h3};
use crate::http3::datagram::{DatagramRegistration, H3DatagramDispatch, H3StreamDatagrams};
use crate::http3::server::{
    read_h3_request_body, send_h3_response, send_h3_static_response, H3ReadBodyError,
    H3ServerRequestStream,
};
use crate::sidecar_control::SidecarControl;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use hyper::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{watch, Semaphore};
use tokio::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub(crate) struct H3Limits {
    pub(crate) max_request_body_bytes: usize,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) max_concurrent_streams_per_connection: usize,
    pub(crate) read_timeout: Duration,
    pub(crate) proxy_name: Arc<str>,
    pub(crate) error_body: Arc<str>,
}

#[derive(Debug, Clone)]
pub(crate) struct H3ConnInfo {
    pub(crate) remote_addr: SocketAddr,
    pub(crate) dst_port: u16,
    pub(crate) tls_sni: Option<Arc<str>>,
    pub(crate) peer_certificates: Option<Arc<Vec<Vec<u8>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum H3ConnectKind {
    Connect,
    ConnectUdp,
    Extended(::h3::ext::Protocol),
}

fn classify_h3_connect_kind(protocol: Option<::h3::ext::Protocol>) -> H3ConnectKind {
    match protocol {
        Some(::h3::ext::Protocol::CONNECT_UDP) => H3ConnectKind::ConnectUdp,
        Some(other) => H3ConnectKind::Extended(other),
        None => H3ConnectKind::Connect,
    }
}

pub(crate) struct H3HttpResponse {
    pub(crate) interim: Vec<::http::Response<()>>,
    pub(crate) response: Response<Body>,
}

fn reject_malformed_h3_request(req_stream: &mut H3ServerRequestStream) {
    let code = ::h3::error::Code::H3_MESSAGE_ERROR;
    req_stream.stop_stream(code);
    req_stream.stop_sending(code);
}

impl H3HttpResponse {
    pub(crate) fn final_only(response: Response<Body>) -> Self {
        Self {
            interim: Vec::new(),
            response,
        }
    }
}

#[async_trait]
pub(crate) trait H3RequestHandler: Clone + Send + Sync + 'static {
    fn limits(&self) -> H3Limits;

    fn enable_extended_connect(&self) -> bool {
        false
    }

    fn enable_datagram(&self) -> bool {
        false
    }

    async fn handle_http(&self, req: Request<Body>, conn: H3ConnInfo) -> Response<Body>;

    async fn handle_http_with_interim(
        &self,
        req: Request<Body>,
        conn: H3ConnInfo,
    ) -> H3HttpResponse {
        H3HttpResponse::final_only(self.handle_http(req, conn).await)
    }

    async fn handle_connect(
        &self,
        req_head: ::http::Request<()>,
        req_stream: H3ServerRequestStream,
        conn: H3ConnInfo,
        kind: H3ConnectKind,
        datagrams: Option<H3StreamDatagrams>,
    ) -> Result<()>;
}

pub(crate) async fn serve_endpoint<H: H3RequestHandler>(
    endpoint: quinn::Endpoint,
    dst_port: u16,
    handler: H,
    label: &str,
    connection_semaphore: Arc<Semaphore>,
    mut shutdown: watch::Receiver<SidecarControl>,
) -> Result<()> {
    info!(label = %label, "HTTP/3 listener starting");
    loop {
        let connecting = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown.borrow().should_stop() {
                    None
                } else {
                    continue;
                }
            }
            connecting = endpoint.accept() => connecting
        };
        if connecting.is_none() {
            break;
        }
        let connecting = connecting.expect("checked connecting");
        let handler = handler.clone();
        let label = label.to_string();
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown.borrow().should_stop() {
                    None
                } else {
                    continue;
                }
            }
            permit = connection_semaphore.clone().acquire_owned() => Some(permit?),
        };
        if permit.is_none() {
            break;
        }
        let permit = permit.expect("checked permit");
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = serve_connection(connecting, dst_port, handler).await {
                warn!(label = %label, error = ?err, "HTTP/3 connection failed");
            }
        });
    }
    Ok(())
}

fn extract_tls_sni(conn: &quinn::Connection) -> Option<Arc<str>> {
    conn.handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hs| hs.server_name.clone())
        .map(Arc::<str>::from)
}

#[cfg(feature = "tls-rustls")]
fn extract_peer_certificates(conn: &quinn::Connection) -> Option<Arc<Vec<Vec<u8>>>> {
    let identity = conn.peer_identity()?;
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    Some(Arc::new(
        certs
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect::<Vec<_>>(),
    ))
}

async fn serve_connection<H: H3RequestHandler>(
    connecting: quinn::Incoming,
    dst_port: u16,
    handler: H,
) -> Result<()> {
    let limits = handler.limits();
    let stream_semaphore = Arc::new(Semaphore::new(
        limits.max_concurrent_streams_per_connection.max(1),
    ));
    let connection = connecting.await?;
    let conn_info = H3ConnInfo {
        remote_addr: connection.remote_address(),
        dst_port,
        tls_sni: extract_tls_sni(&connection),
        #[cfg(feature = "tls-rustls")]
        peer_certificates: extract_peer_certificates(&connection),
    };
    let mut builder = ::h3::server::builder();
    builder
        .enable_extended_connect(handler.enable_extended_connect())
        .enable_datagram(handler.enable_datagram());
    let mut h3_conn = builder
        .build::<_, Bytes>(h3_quinn::Connection::new(connection))
        .await?;

    let datagram_dispatch = if handler.enable_datagram() {
        use h3_datagram::datagram_handler::HandleDatagramsExt as _;

        let dispatch = Arc::new(H3DatagramDispatch::new(64));
        let reader = h3_conn.get_datagram_reader();
        let dispatch_task = dispatch.clone();
        tokio::spawn(async move {
            dispatch_task.run(reader).await;
        });
        Some(dispatch)
    } else {
        None
    };

    while let Some(resolver) = h3_conn.accept().await? {
        let (req_head, req_stream) = resolver.resolve_request().await?;
        let connect_kind = (req_head.method() == ::http::Method::CONNECT)
            .then(|| classify_h3_connect_kind(req_head.extensions().get().cloned()));
        let stream_id = req_stream.id();
        let (datagrams, disabled_datagram_registration) =
            match (datagram_dispatch.as_ref(), connect_kind) {
                (Some(dispatch), Some(H3ConnectKind::ConnectUdp))
                | (
                    Some(dispatch),
                    Some(H3ConnectKind::Extended(::h3::ext::Protocol::WEB_TRANSPORT)),
                ) => {
                    use h3_datagram::datagram_handler::HandleDatagramsExt as _;
                    let sender = h3_conn.get_datagram_sender(stream_id);
                    (
                        Some(dispatch.register_stream(stream_id, sender).await),
                        None,
                    )
                }
                (Some(dispatch), _) => (
                    None,
                    Some(dispatch.register_stream_without_datagrams(stream_id).await),
                ),
                (None, _) => (None, None),
            };
        let permit = match stream_semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        let handler = handler.clone();
        let conn_info = conn_info.clone();
        let limits = limits.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_stream(
                req_head,
                req_stream,
                conn_info,
                handler,
                limits,
                datagrams,
                disabled_datagram_registration,
            )
            .await;
        });
    }
    Ok(())
}

async fn handle_stream<H: H3RequestHandler>(
    req_head: ::http::Request<()>,
    mut req_stream: H3ServerRequestStream,
    conn_info: H3ConnInfo,
    handler: H,
    limits: H3Limits,
    datagrams: Option<H3StreamDatagrams>,
    disabled_datagram_registration: Option<DatagramRegistration>,
) {
    let _disabled_datagram_registration = disabled_datagram_registration;
    let request_method = req_head
        .method()
        .as_str()
        .parse::<http::Method>()
        .unwrap_or(http::Method::GET);

    if let Err(err) = crate::http::semantics::validate_h2_h3_request_headers(
        http::Version::HTTP_3,
        req_head.headers(),
    ) {
        warn!(error = ?err, "malformed HTTP/3 request headers");
        reject_malformed_h3_request(&mut req_stream);
        return;
    }
    let declared_content_length = match parse_content_length(req_head.headers()) {
        Ok(length) => length,
        Err(err) => {
            warn!(error = %err, "invalid HTTP/3 request content-length");
            reject_malformed_h3_request(&mut req_stream);
            return;
        }
    };

    if req_head.method() == ::http::Method::CONNECT {
        let kind =
            classify_h3_connect_kind(req_head.extensions().get::<::h3::ext::Protocol>().copied());
        if let Err(err) = handler
            .handle_connect(req_head, req_stream, conn_info, kind, datagrams)
            .await
        {
            warn!(error = ?err, "HTTP/3 CONNECT handling failed");
        }
        return;
    }

    match parse_expect_continue(req_head.headers()) {
        Ok(true) => {
            let continue_head = match ::http::Response::builder()
                .status(::http::StatusCode::CONTINUE)
                .body(())
            {
                Ok(head) => head,
                Err(err) => {
                    warn!(error = ?err, "failed to build HTTP/3 100-continue response");
                    return;
                }
            };
            let send_result =
                tokio::time::timeout(limits.read_timeout, req_stream.send_response(continue_head))
                    .await;
            if let Err(err) = send_result
                .map_err(|_| anyhow::anyhow!("HTTP/3 100-continue send timed out"))
                .and_then(|result| result.map_err(Into::into))
            {
                warn!(error = ?err, "failed to send HTTP/3 100-continue response");
                return;
            }
        }
        Ok(false) => {}
        Err(_) => {
            let _ = send_h3_static_response(
                &mut req_stream,
                ::http::StatusCode::EXPECTATION_FAILED,
                b"expectation failed",
                &request_method,
                limits.proxy_name.as_ref(),
                limits.max_response_body_bytes,
            )
            .await;
            return;
        }
    }

    let (req_body, req_trailers) = match read_h3_request_body(
        &mut req_stream,
        limits.read_timeout,
        limits.max_request_body_bytes,
    )
    .await
    {
        Ok(parts) => parts,
        Err(H3ReadBodyError::TimedOut) => {
            if let Err(err) = send_h3_static_response(
                &mut req_stream,
                ::http::StatusCode::REQUEST_TIMEOUT,
                b"request read timed out",
                &request_method,
                limits.proxy_name.as_ref(),
                limits.max_response_body_bytes,
            )
            .await
            {
                warn!(error = ?err, "failed to send HTTP/3 request-timeout response");
            }
            return;
        }
        Err(H3ReadBodyError::TooLarge) => {
            if let Err(err) = send_h3_static_response(
                &mut req_stream,
                ::http::StatusCode::PAYLOAD_TOO_LARGE,
                b"request payload too large",
                &request_method,
                limits.proxy_name.as_ref(),
                limits.max_response_body_bytes,
            )
            .await
            {
                warn!(error = ?err, "failed to send HTTP/3 payload-too-large response");
            }
            return;
        }
        Err(H3ReadBodyError::Stream(err)) => {
            warn!(error = ?err, "HTTP/3 request stream failed");
            return;
        }
    };

    let req_body_len = req_body.len();
    if let Some(content_length) = declared_content_length {
        if content_length != req_body_len as u64 {
            warn!(
                expected = content_length,
                actual = req_body_len,
                "HTTP/3 request content-length mismatch"
            );
            reject_malformed_h3_request(&mut req_stream);
            return;
        }
    }
    let mut req = match h3_request_to_hyper(req_head, req_body, req_trailers) {
        Ok(req) => req,
        Err(err) => {
            warn!(error = ?err, "invalid HTTP/3 request");
            reject_malformed_h3_request(&mut req_stream);
            return;
        }
    };
    set_observed_request_size(&mut req, req_body_len as u64);

    let response = handler.handle_http_with_interim(req, conn_info).await;
    for interim in response.interim {
        let interim = match sanitize_interim_response_for_h3(interim) {
            Ok(interim) => interim,
            Err(err) => {
                warn!(error = ?err, "invalid HTTP/3 interim response");
                return;
            }
        };
        if let Err(err) =
            tokio::time::timeout(limits.read_timeout, req_stream.send_response(interim))
                .await
                .map_err(|_| anyhow::anyhow!("HTTP/3 interim response send timed out"))
                .and_then(|result| result.map_err(Into::into))
        {
            warn!(error = ?err, "HTTP/3 interim response stream failed");
            return;
        }
    }
    if let Err(err) = send_h3_response(
        response.response,
        &request_method,
        &mut req_stream,
        limits.max_response_body_bytes,
        limits.read_timeout,
    )
    .await
    {
        warn!(error = ?err, "HTTP/3 response stream failed");
        let _ = send_h3_static_response(
            &mut req_stream,
            ::http::StatusCode::BAD_GATEWAY,
            limits.error_body.as_bytes(),
            &request_method,
            limits.proxy_name.as_ref(),
            limits.max_response_body_bytes,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_h3_connect_kind_rejects_unknown_extended_connect_protocols() {
        assert_eq!(classify_h3_connect_kind(None), H3ConnectKind::Connect);
        assert_eq!(
            classify_h3_connect_kind(Some(::h3::ext::Protocol::CONNECT_UDP)),
            H3ConnectKind::ConnectUdp
        );
        assert_eq!(
            classify_h3_connect_kind(Some(::h3::ext::Protocol::WEB_TRANSPORT)),
            H3ConnectKind::Extended(::h3::ext::Protocol::WEB_TRANSPORT)
        );
    }
}

fn parse_content_length(headers: &http::HeaderMap) -> Result<Option<u64>, String> {
    let mut parsed: Option<u64> = None;
    for value in headers.get_all(http::header::CONTENT_LENGTH).iter() {
        let raw = value
            .to_str()
            .map_err(|err| format!("invalid Content-Length header: {err}"))?
            .trim();
        if raw.is_empty() {
            return Err("empty Content-Length header".to_string());
        }
        for part in raw.split(',') {
            let value = part
                .trim()
                .parse::<u64>()
                .map_err(|err| format!("invalid Content-Length value: {err}"))?;
            match parsed {
                Some(existing) if existing != value => {
                    return Err("conflicting Content-Length values".to_string());
                }
                Some(_) => {}
                None => parsed = Some(value),
            }
        }
    }
    Ok(parsed)
}

#[derive(Debug, Clone, Copy)]
struct InvalidExpectHeader;

fn parse_expect_continue(
    headers: &::http::HeaderMap,
) -> std::result::Result<bool, InvalidExpectHeader> {
    let mut saw_expect = false;
    for value in headers.get_all(::http::header::EXPECT).iter() {
        let raw = value.to_str().map_err(|_| InvalidExpectHeader)?;
        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            saw_expect = true;
            if !token.eq_ignore_ascii_case("100-continue") {
                return Err(InvalidExpectHeader);
            }
        }
    }
    if headers.contains_key(::http::header::EXPECT) && !saw_expect {
        return Err(InvalidExpectHeader);
    }
    Ok(saw_expect)
}
