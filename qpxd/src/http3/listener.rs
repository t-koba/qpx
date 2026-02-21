use crate::http3::codec::h3_request_to_hyper;
use crate::http3::datagram::{H3DatagramDispatch, H3StreamDatagrams};
use crate::http3::server::{
    read_h3_request_body, send_h3_response, send_h3_static_response, H3ReadBodyError,
    H3ServerRequestStream,
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use hyper::{Body, Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub(crate) struct H3Limits {
    pub(crate) max_request_body_bytes: usize,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) read_timeout: Duration,
    pub(crate) proxy_name: Arc<str>,
    pub(crate) error_body: Arc<str>,
}

#[derive(Debug, Clone)]
pub(crate) struct H3ConnInfo {
    pub(crate) remote_addr: SocketAddr,
    pub(crate) dst_port: u16,
    pub(crate) tls_sni: Option<Arc<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum H3ConnectKind {
    Connect,
    ConnectUdp,
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

    async fn handle_connect(
        &self,
        req_head: http1::Request<()>,
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
) -> Result<()> {
    info!(label = %label, "HTTP/3 listener starting");
    while let Some(connecting) = endpoint.accept().await {
        let handler = handler.clone();
        let label = label.to_string();
        let permit = connection_semaphore.clone().acquire_owned().await?;
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

async fn serve_connection<H: H3RequestHandler>(
    connecting: quinn::Incoming,
    dst_port: u16,
    handler: H,
) -> Result<()> {
    let limits = handler.limits();
    let connection = connecting.await?;
    let conn_info = H3ConnInfo {
        remote_addr: connection.remote_address(),
        dst_port,
        tls_sni: extract_tls_sni(&connection),
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
        let datagrams = if req_head.method() == http1::Method::CONNECT
            && req_head
                .extensions()
                .get::<::h3::ext::Protocol>()
                .map(|p| *p == ::h3::ext::Protocol::CONNECT_UDP)
                .unwrap_or(false)
        {
            match datagram_dispatch.as_ref() {
                Some(dispatch) => {
                    use h3_datagram::datagram_handler::HandleDatagramsExt as _;
                    let stream_id = req_stream.id();
                    let sender = h3_conn.get_datagram_sender(stream_id);
                    Some(dispatch.register_stream(stream_id, sender).await)
                }
                None => None,
            }
        } else {
            None
        };
        let handler = handler.clone();
        let conn_info = conn_info.clone();
        let limits = limits.clone();
        tokio::spawn(async move {
            handle_stream(req_head, req_stream, conn_info, handler, limits, datagrams).await;
        });
    }
    Ok(())
}

async fn handle_stream<H: H3RequestHandler>(
    req_head: http1::Request<()>,
    mut req_stream: H3ServerRequestStream,
    conn_info: H3ConnInfo,
    handler: H,
    limits: H3Limits,
    datagrams: Option<H3StreamDatagrams>,
) {
    let request_method = req_head
        .method()
        .as_str()
        .parse::<http::Method>()
        .unwrap_or(http::Method::GET);

    if req_head.method() == http1::Method::CONNECT {
        let is_connect_udp = req_head
            .extensions()
            .get::<::h3::ext::Protocol>()
            .map(|p| *p == ::h3::ext::Protocol::CONNECT_UDP)
            .unwrap_or(false);
        let kind = if is_connect_udp {
            H3ConnectKind::ConnectUdp
        } else {
            H3ConnectKind::Connect
        };
        if let Err(err) = handler
            .handle_connect(req_head, req_stream, conn_info, kind, datagrams)
            .await
        {
            warn!(error = ?err, "HTTP/3 CONNECT handling failed");
        }
        return;
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
                http1::StatusCode::REQUEST_TIMEOUT,
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
                http1::StatusCode::PAYLOAD_TOO_LARGE,
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
    let req = match h3_request_to_hyper(req_head, req_body, req_trailers) {
        Ok(req) => req,
        Err(err) => {
            warn!(error = ?err, "invalid HTTP/3 request");
            if let Err(send_err) = send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::BAD_REQUEST,
                b"bad request",
                &request_method,
                limits.proxy_name.as_ref(),
                limits.max_response_body_bytes,
            )
            .await
            {
                warn!(error = ?send_err, "failed to send HTTP/3 bad-request response");
            }
            return;
        }
    };

    if let Some(content_length) = parse_content_length(req.headers()) {
        if content_length != req_body_len as u64 {
            if let Err(send_err) = send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::BAD_REQUEST,
                b"content-length mismatch",
                &request_method,
                limits.proxy_name.as_ref(),
                limits.max_response_body_bytes,
            )
            .await
            {
                warn!(error = ?send_err, "failed to send HTTP/3 content-length-mismatch response");
            }
            return;
        }
    }

    let response = handler.handle_http(req, conn_info).await;
    if let Err(err) = send_h3_response(
        response,
        &request_method,
        &mut req_stream,
        limits.max_response_body_bytes,
    )
    .await
    {
        warn!(error = ?err, "HTTP/3 response stream failed");
        let _ = send_h3_static_response(
            &mut req_stream,
            http1::StatusCode::BAD_GATEWAY,
            limits.error_body.as_bytes(),
            &request_method,
            limits.proxy_name.as_ref(),
            limits.max_response_body_bytes,
        )
        .await;
    }
}

fn parse_content_length(headers: &http::HeaderMap) -> Option<u64> {
    let mut parsed: Option<u64> = None;
    for value in headers.get_all(http::header::CONTENT_LENGTH).iter() {
        let raw = value.to_str().ok()?.trim();
        if raw.is_empty() {
            return None;
        }
        for part in raw.split(',') {
            let value = part.trim().parse::<u64>().ok()?;
            match parsed {
                Some(existing) if existing != value => return None,
                Some(_) => {}
                None => parsed = Some(value),
            }
        }
    }
    parsed
}
