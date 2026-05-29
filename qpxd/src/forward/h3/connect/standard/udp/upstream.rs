use super::{normalize_h3_upstream_connect_headers, recv_upstream_h3_response_with_interim};
use crate::http3::datagram::{H3DatagramDispatch, H3StreamDatagrams};
use crate::http3::quic::{build_h3_client_config, enforce_h3_connection_trust};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::lookup_host;
use tokio::time::{Duration, timeout};

pub(super) struct UpstreamConnectUdpStream {
    pub(super) interim: Vec<::http::Response<()>>,
    pub(super) _endpoint: quinn::Endpoint,
    pub(super) driver: tokio::task::JoinHandle<()>,
    pub(super) datagram_task: tokio::task::JoinHandle<()>,
    pub(super) datagrams: Option<H3StreamDatagrams>,
    pub(super) req_stream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

pub(super) struct UpstreamConnectUdpParams<'a> {
    pub(super) upstream: &'a str,
    pub(super) target_host: &'a str,
    pub(super) target_port: u16,
    pub(super) proxy_name: &'a str,
    pub(super) verify_upstream: bool,
    pub(super) trust: Option<&'a crate::tls::CompiledUpstreamTlsTrust>,
    pub(super) timeout_dur: Duration,
    pub(super) datagram_channel_capacity: usize,
}

pub(super) async fn open_upstream_connect_udp_stream(
    params: UpstreamConnectUdpParams<'_>,
) -> Result<UpstreamConnectUdpStream> {
    let UpstreamConnectUdpParams {
        upstream,
        target_host,
        target_port,
        proxy_name,
        verify_upstream,
        trust,
        timeout_dur,
        datagram_channel_capacity,
    } = params;
    let (upstream_host, upstream_port, uri) =
        crate::forward::connect::udp_upstream::build_upstream_connect_udp_uri(
            upstream,
            target_host,
            target_port,
        )?;
    let upstream_addr = timeout(
        timeout_dur,
        lookup_host((upstream_host.as_str(), upstream_port)),
    )
    .await??
    .next()
    .ok_or_else(|| anyhow!("failed to resolve CONNECT-UDP upstream proxy"))?;

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(build_h3_client_config(verify_upstream, trust)?);

    let connection = timeout(
        timeout_dur,
        endpoint.connect(upstream_addr, &upstream_host)?,
    )
    .await??;
    enforce_h3_connection_trust(&connection, &upstream_host, trust)?;
    let mut builder = ::h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let h3_build = builder.build::<_, _, Bytes>(h3_quinn::Connection::new(connection));
    let (mut h3_conn, mut sender) = timeout(timeout_dur, h3_build).await??;
    use h3_datagram::datagram_handler::HandleDatagramsExt as _;
    let datagram_dispatch = Arc::new(H3DatagramDispatch::new(datagram_channel_capacity));
    let reader = h3_conn.get_datagram_reader();
    let datagram_task = {
        let dispatch = datagram_dispatch.clone();
        tokio::spawn(async move {
            dispatch.run(reader).await;
        })
    };

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::HeaderName::from_static("capsule-protocol"),
        http::header::HeaderValue::from_static("?1"),
    );
    let normalized_headers = normalize_h3_upstream_connect_headers(&uri, &headers, proxy_name)?;
    let mut request = ::http::Request::builder()
        .method(::http::Method::CONNECT)
        .uri(uri)
        .body(())?;
    request
        .extensions_mut()
        .insert(::h3::ext::Protocol::CONNECT_UDP);
    *request.headers_mut() = normalized_headers;

    let mut req_stream = match timeout(timeout_dur, sender.send_request(request)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(err.into());
        }
        Err(_) => {
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(anyhow!("upstream CONNECT-UDP request timed out"));
        }
    };
    let (interim, response) = match recv_upstream_h3_response_with_interim(
        &mut req_stream,
        timeout_dur,
        "upstream CONNECT-UDP response",
    )
    .await
    {
        Ok(parts) => parts,
        Err(err) => {
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(err);
        }
    };
    if !response.status().is_success() {
        datagram_task.abort();
        let _ = datagram_task.await;
        return Err(anyhow!(
            "upstream CONNECT-UDP failed with status {}",
            response.status()
        ));
    }
    let capsule = response
        .headers()
        .get(::http::header::HeaderName::from_static("capsule-protocol"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    if capsule != Some("?1") {
        datagram_task.abort();
        let _ = datagram_task.await;
        return Err(anyhow!(
            "upstream CONNECT-UDP missing required response header: Capsule-Protocol: ?1"
        ));
    }

    let stream_id = req_stream.id();
    let upstream_datagrams = Some(
        datagram_dispatch
            .register_stream(stream_id, h3_conn.get_datagram_sender(stream_id))
            .await,
    );

    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    Ok(UpstreamConnectUdpStream {
        interim,
        _endpoint: endpoint,
        driver,
        datagram_task,
        datagrams: upstream_datagrams,
        req_stream,
    })
}
