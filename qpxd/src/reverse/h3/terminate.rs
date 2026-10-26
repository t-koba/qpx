use super::super::ReloadableReverse;
#[cfg(test)]
use super::super::{record_reverse_connection_filter_block, reverse_quic_connection_filter_match};
pub(crate) use super::terminate_socket::prepare_reverse_terminate_socket;
pub(crate) use super::terminate_tls::build_reverse_tls_config;
use crate::http3::listener::{
    H3ConnInfo, H3ConnectKind, H3HttpResponse, H3Limits, H3RequestHandler,
};
use crate::http3::quic::build_h3_server_config_from_tls;
use crate::http3::quinn_socket::{QuinnEndpointSocket, build_server_endpoint};
use crate::http3::server::{H3ServerRequestStream, send_h3_static_response};
use crate::reverse::transport::{self, ReverseConnInfo};
use crate::server::control::SidecarControl;
use anyhow::Result;
use async_trait::async_trait;
use hyper::{Request, Response};
use qpx_core::config::ReverseEdgeConfig;
use qpx_http::body::Body;
#[cfg(test)]
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Duration;
use tracing::warn;

pub(crate) async fn run_http3_terminate(
    reverse: ReverseEdgeConfig,
    listen_addr: SocketAddr,
    reverse_rt: ReloadableReverse,
    shutdown: watch::Receiver<SidecarControl>,
    endpoint_socket: QuinnEndpointSocket,
) -> Result<()> {
    let tls_config = build_reverse_tls_config(&reverse)?;
    let max_bidi = reverse_rt
        .runtime
        .state()
        .plan
        .limits
        .h3
        .max_h3_streams_per_connection
        .min(u32::MAX as usize) as u32;
    let server_config = build_h3_server_config_from_tls(tls_config, max_bidi.max(1), 1024)?;
    let endpoint = build_server_endpoint(endpoint_socket, server_config)?;

    let semaphore = reverse_rt.runtime.state().connection_semaphore.clone();
    let handler = ReverseH3Handler {
        reverse: reverse_rt,
    };
    crate::http3::listener::serve_endpoint(
        endpoint,
        listen_addr.port(),
        handler,
        "reverse-terminate",
        semaphore,
        shutdown,
    )
    .await
}

#[cfg(test)]
fn filter_quic_recv_batch(
    reverse: &ReloadableReverse,
    local_port: u16,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [quinn::udp::RecvMeta],
    count: usize,
) -> usize {
    let mut kept = 0usize;
    for idx in 0..count {
        let current = meta[idx];
        let (kept_len, kept_segments) = if kept == idx {
            filter_quic_buffer_in_place(reverse, local_port, current, &mut bufs[idx])
        } else {
            let (before, after) = bufs.split_at_mut(idx);
            let src = &mut after[0];
            let (kept_len, kept_segments) =
                filter_quic_buffer_in_place(reverse, local_port, current, src);
            if kept_len > 0 {
                let dst = &mut before[kept];
                dst[..kept_len].copy_from_slice(&src[..kept_len]);
            }
            (kept_len, kept_segments)
        };
        if kept_len == 0 {
            continue;
        }
        meta[kept] = current;
        meta[kept].len = kept_len;
        meta[kept].stride = if kept_segments <= 1 {
            kept_len
        } else {
            current.stride.max(1)
        };
        kept += 1;
    }
    kept
}

#[cfg(test)]
fn filter_quic_buffer_in_place(
    reverse: &ReloadableReverse,
    local_port: u16,
    meta: quinn::udp::RecvMeta,
    buf: &mut IoSliceMut<'_>,
) -> (usize, usize) {
    let total_len = meta.len.min(buf.len());
    let mut read_offset = 0usize;
    let mut write_offset = 0usize;
    let mut kept_segments = 0usize;
    while read_offset < total_len {
        let packet_len = if meta.stride == 0 {
            total_len - read_offset
        } else {
            meta.stride.min(total_len - read_offset)
        };
        let packet_end = read_offset + packet_len;
        let blocked = reverse_quic_connection_filter_match(
            reverse,
            meta.addr,
            local_port,
            &buf[read_offset..packet_end],
        );
        if let Some((stage, matched_rule, sni)) = blocked {
            record_reverse_connection_filter_block(
                reverse,
                meta.addr,
                local_port,
                stage,
                matched_rule.as_str(),
                sni.as_deref(),
            );
        } else {
            if write_offset != read_offset {
                buf.copy_within(read_offset..packet_end, write_offset);
            }
            write_offset += packet_len;
            kept_segments += 1;
        }
        read_offset = packet_end;
    }
    (write_offset, kept_segments)
}

#[derive(Clone)]
struct ReverseH3Handler {
    reverse: ReloadableReverse,
}

#[async_trait]
impl H3RequestHandler for ReverseH3Handler {
    fn limits(&self) -> H3Limits {
        let state = self.reverse.runtime.state();
        let limits = state.plan.limits;
        let streaming = state
            .plan
            .reverse_edge(self.reverse.name.as_ref())
            .map(|edge| edge.streaming)
            .unwrap_or_else(|| crate::runtime::ResolvedStreamingLimits::from(limits));
        let mut connection_streaming = streaming;
        connection_streaming.max_request_body_bytes =
            super::streaming::max_reverse_h3_request_body_bytes(&self.reverse, streaming);
        H3Limits {
            listener_name: Arc::<str>::from(self.reverse.name.as_ref()),
            max_concurrent_streams_per_connection: limits.h3.max_h3_streams_per_connection,
            datagram_channel_capacity: limits.h3.datagram_channel_capacity,
            streaming: connection_streaming,
            request_body_drain: crate::http3::server::H3RequestBodyDrainControl {
                config: limits.h3.request_body_drain,
                semaphore: state.h3_request_body_drain_semaphore.clone(),
            },
            read_timeout: Duration::from_millis(limits.timeouts.h3_read_timeout_ms),
            proxy_name: Arc::<str>::from(state.plan.identity.proxy_name.as_ref()),
            error_body: Arc::<str>::from(state.messages.reverse_error.as_str()),
        }
    }

    fn request_streaming_limits(
        &self,
        req_head: &::http::Request<()>,
        conn: &H3ConnInfo,
        fallback: crate::runtime::ResolvedStreamingLimits,
    ) -> crate::runtime::ResolvedStreamingLimits {
        super::streaming::request_streaming_limits_for_head(
            &self.reverse,
            req_head,
            super::streaming::ReverseH3RequestPeer {
                remote_addr: conn.remote_addr,
                dst_port: conn.dst_port,
                tls_sni: conn.tls_sni.as_deref(),
                peer_certificates: conn
                    .peer_certificates
                    .as_deref()
                    .map(|certs| certs.as_slice()),
            },
            fallback,
        )
    }

    async fn handle_http(&self, req: Request<Body>, conn: H3ConnInfo) -> Response<Body> {
        let reverse_conn = ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
            conn.peer_certificates.clone(),
        );
        match transport::handle_request(req, self.reverse.clone(), reverse_conn).await {
            Ok(resp) => resp,
            Err(impossible) => match impossible {},
        }
    }

    async fn handle_http_with_interim(
        &self,
        req: Request<Body>,
        conn: H3ConnInfo,
    ) -> H3HttpResponse {
        let reverse_conn = ReverseConnInfo::terminated(
            conn.remote_addr,
            conn.dst_port,
            conn.tls_sni.clone(),
            conn.peer_certificates.clone(),
        );
        match transport::handle_request_with_interim(req, self.reverse.clone(), reverse_conn).await
        {
            Ok((interim, response)) => H3HttpResponse {
                interim: interim
                    .into_iter()
                    .filter(|head| {
                        qpx_http::protocol::semantics::validate_http_status_class(
                            head.status,
                            "HTTP/3 interim response",
                        )
                        .is_ok()
                    })
                    .collect(),
                response,
            },
            Err(impossible) => match impossible {},
        }
    }

    async fn handle_connect(
        &self,
        _req_head: ::http::Request<()>,
        mut req_stream: H3ServerRequestStream,
        _conn: H3ConnInfo,
        _kind: H3ConnectKind,
        _datagrams: Option<crate::http3::datagram::H3StreamDatagrams>,
    ) -> Result<()> {
        let state = self.reverse.runtime.state();
        let proxy_name = state.plan.identity.proxy_name.as_ref();
        if let Err(err) = send_h3_static_response(
            &mut req_stream,
            ::http::StatusCode::METHOD_NOT_ALLOWED,
            state.messages.reverse_error.as_bytes(),
            &http::Method::CONNECT,
            proxy_name,
            state.plan.limits.body.max_h3_response_body_bytes,
        )
        .await
        {
            warn!(error = ?err, "failed to send reverse HTTP/3 CONNECT rejection response");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
