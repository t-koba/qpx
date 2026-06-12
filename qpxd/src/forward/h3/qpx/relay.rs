use crate::http3::capsule::{
    CapsuleBuffer, decode_quic_varint, encode_datagram_capsule_context_header,
    encode_datagram_capsule_header,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use qpx_core::config::ConnectUdpConfig;
use tokio::net::UdpSocket;
use tokio::time::{Duration, sleep, timeout};
use tracing::warn;

pub(super) async fn relay_qpx_extended_connect_stream(
    downstream: qpx_h3::RequestStream,
    mut downstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    upstream: qpx_h3::RequestStream,
    mut upstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    idle_timeout: Duration,
) -> Result<()> {
    let (downstream_send, downstream_recv) = downstream.split();
    let (upstream_send, upstream_recv) = upstream.split();
    let activity = crate::tunnel::TunnelActivity::new();
    let stream_relay = crate::tunnel::relay_tunnel(
        downstream_recv,
        downstream_send,
        upstream_recv,
        upstream_send,
        crate::tunnel::TunnelPolicy::h3(Some(idle_timeout), "qpx_extended_connect", "unknown")
            .with_activity(activity.clone()),
    );
    let datagram_relay = async {
        let mut upstream_datagram_scratch = BytesMut::new();
        let mut downstream_datagram_scratch = BytesMut::new();
        loop {
            tokio::select! {
                down_payload = async {
                    if let Some(datagrams) = downstream_datagrams.as_mut() {
                        datagrams.receiver.recv().await
                    } else {
                        std::future::pending::<Option<Bytes>>().await
                    }
                } => {
                    let Some(payload) = down_payload else {
                        break;
                    };
                    if let Some(datagrams) = upstream_datagrams.as_mut()
                        && let Err(err) = datagrams
                            .sender
                            .send_unprefixed_datagram_with_scratch(payload, &mut upstream_datagram_scratch)
                    {
                        warn!(error = ?err, "forward HTTP/3 qpx-h3 upstream datagram send failed");
                    }
                    activity.touch();
                }
                up_payload = async {
                    if let Some(datagrams) = upstream_datagrams.as_mut() {
                        datagrams.receiver.recv().await
                    } else {
                        std::future::pending::<Option<Bytes>>().await
                    }
                } => {
                    let Some(payload) = up_payload else {
                        break;
                    };
                    if let Some(datagrams) = downstream_datagrams.as_mut()
                        && let Err(err) = datagrams
                            .sender
                            .send_unprefixed_datagram_with_scratch(payload, &mut downstream_datagram_scratch)
                    {
                        warn!(error = ?err, "forward HTTP/3 qpx-h3 downstream datagram send failed");
                    }
                    activity.touch();
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = stream_relay => {
            let _stats = result?;
        }
        result = datagram_relay => {
            result?;
        }
    }
    Ok(())
}

pub(super) async fn relay_qpx_connect_udp_stream(
    req_stream: qpx_h3::RequestStream,
    udp: UdpSocket,
    connect_udp_cfg: ConnectUdpConfig,
    mut datagrams: Option<qpx_h3::StreamDatagrams>,
    rate_limit_ctx: RateLimitContext,
    request_limits: AppliedRateLimits,
) -> Result<()> {
    let (mut req_send, mut req_recv) = req_stream.split();
    let idle_timeout = Duration::from_secs(connect_udp_cfg.idle_timeout_secs.max(1));
    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let mut capsule_buf = CapsuleBuffer::new();
    let datagram_prefix = datagrams
        .as_ref()
        .map(|datagrams| datagrams.sender.datagram_prefix());
    let datagram_prefix_len = datagram_prefix.as_ref().map_or(0, Bytes::len);
    let mut udp_buf = BytesMut::with_capacity(65_536 + datagram_prefix_len + 1);
    if let Some(prefix) = datagram_prefix.as_ref() {
        udp_buf.extend_from_slice(prefix.as_ref());
    }
    udp_buf.extend_from_slice(&[0]); // CONNECT-UDP context id = 0

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                break;
            }
            recv = req_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        capsule_buf.push(chunk, connect_udp_cfg.max_capsule_buffer_bytes)?;
                        while let Some((capsule_type, payload)) = capsule_buf.take_next()? {
                            if capsule_type != 0 {
                                continue;
                            }
                            let (context_id, offset) = match decode_quic_varint(payload.as_ref()) {
                                Some(v) => v,
                                None => continue,
                            };
                            if context_id != 0 || offset > payload.len() {
                                continue;
                            }
                            apply_connect_udp_bandwidth_controls(
                                &rate_limit_ctx,
                                &request_limits,
                                payload.len().saturating_sub(offset),
                            )
                            .await?;
                            udp.send(&payload[offset..]).await?;
                        }
                        idle_deadline
                            .as_mut()
                            .reset(crate::runtime::tokio_deadline_after(idle_timeout));
                    }
                    None => break,
                }
            }
            payload = async {
                if let Some(datagrams) = datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = payload else {
                    break;
                };
                let (context_id, offset) = match decode_quic_varint(payload.as_ref()) {
                    Some(v) => v,
                    None => continue,
                };
                if context_id != 0 || offset > payload.len() {
                    continue;
                }
                apply_connect_udp_bandwidth_controls(
                    &rate_limit_ctx,
                    &request_limits,
                    payload.len().saturating_sub(offset),
                )
                .await?;
                udp.send(&payload[offset..]).await?;
                idle_deadline
                    .as_mut()
                    .reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
            recv = udp.recv_buf(&mut udp_buf) => {
                let read_len = recv?;
                if read_len == 0 {
                    udp_buf.truncate(1);
                    continue;
                }
                let datagram_payload = udp_buf.split_to(datagram_prefix_len + read_len + 1).freeze();
                let payload_len = datagram_payload
                    .len()
                    .saturating_sub(datagram_prefix_len + 1);
                let stream_payload = datagram_payload.slice(datagram_prefix_len + 1..);
                if udp_buf.capacity() < 65_536 + datagram_prefix_len + 1 {
                    udp_buf.reserve(65_536 + datagram_prefix_len + 1 - udp_buf.capacity());
                }
                if let Some(prefix) = datagram_prefix.as_ref() {
                    udp_buf.extend_from_slice(prefix.as_ref());
                }
                udp_buf.extend_from_slice(&[0]);
                apply_connect_udp_bandwidth_controls(&rate_limit_ctx, &request_limits, payload_len).await?;
                let mut sent = false;
                if let Some(datagrams) = datagrams.as_mut()
                    && datagrams
                        .sender
                        .send_prefixed_datagram(datagram_payload, payload_len)
                        .is_ok()
                {
                    sent = true;
                }
                if !sent {
                    let header = encode_datagram_capsule_context_header(payload_len)?;
                    timeout(idle_timeout, req_send.send_data(header))
                        .await
                        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP capsule send timed out"))??;
                    timeout(
                        idle_timeout,
                        req_send.send_data(stream_payload),
                    )
                    .await
                    .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP capsule payload send timed out"))??;
                }
                idle_deadline
                    .as_mut()
                    .reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
        }
    }

    timeout(idle_timeout, req_send.finish())
        .await
        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP finish timed out"))??;
    Ok(())
}

pub(super) async fn relay_qpx_connect_udp_stream_chained(
    downstream: qpx_h3::RequestStream,
    mut downstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    upstream: qpx_h3::RequestStream,
    mut upstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    connect_udp_cfg: ConnectUdpConfig,
    rate_limit_ctx: RateLimitContext,
    request_limits: AppliedRateLimits,
) -> Result<()> {
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();
    let idle_timeout = Duration::from_secs(connect_udp_cfg.idle_timeout_secs.max(1));
    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);
    let mut upstream_datagram_scratch = BytesMut::new();
    let mut downstream_datagram_scratch = BytesMut::new();

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                break;
            }
            recv = downstream_recv.recv_data() => {
                match recv? {
                    Some(bytes) => {
                        apply_connect_udp_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            bytes.len(),
                        )
                        .await?;
                        timeout(idle_timeout, upstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP upstream DATA send timed out"))??;
                        idle_deadline
                            .as_mut()
                            .reset(crate::runtime::tokio_deadline_after(idle_timeout));
                    }
                    None => break,
                }
            }
            recv = upstream_recv.recv_data() => {
                match recv? {
                    Some(bytes) => {
                        apply_connect_udp_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            bytes.len(),
                        )
                        .await?;
                        timeout(idle_timeout, downstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP downstream DATA send timed out"))??;
                        idle_deadline
                            .as_mut()
                            .reset(crate::runtime::tokio_deadline_after(idle_timeout));
                    }
                    None => break,
                }
            }
            down_payload = async {
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = down_payload else {
                    break;
                };
                let fallback = payload.clone();
                apply_connect_udp_bandwidth_controls(
                    &rate_limit_ctx,
                    &request_limits,
                    fallback.len(),
                )
                .await?;
                let mut sent = false;
                if let Some(datagrams) = upstream_datagrams.as_mut()
                    && datagrams
                        .sender
                        .send_unprefixed_datagram_with_scratch(payload, &mut upstream_datagram_scratch)
                        .is_ok()
                {
                    sent = true;
                }
                if !sent {
                    let header = encode_datagram_capsule_header(fallback.len())?;
                    timeout(idle_timeout, upstream_send.send_data(header))
                        .await
                        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP upstream capsule send timed out"))??;
                    timeout(idle_timeout, upstream_send.send_data(fallback))
                        .await
                        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP upstream capsule payload send timed out"))??;
                }
                idle_deadline
                    .as_mut()
                    .reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
            up_payload = async {
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = up_payload else {
                    break;
                };
                let fallback = payload.clone();
                apply_connect_udp_bandwidth_controls(
                    &rate_limit_ctx,
                    &request_limits,
                    fallback.len(),
                )
                .await?;
                let mut sent = false;
                if let Some(datagrams) = downstream_datagrams.as_mut()
                    && datagrams
                        .sender
                        .send_unprefixed_datagram_with_scratch(payload, &mut downstream_datagram_scratch)
                        .is_ok()
                {
                    sent = true;
                }
                if !sent {
                    let header = encode_datagram_capsule_header(fallback.len())?;
                    timeout(idle_timeout, downstream_send.send_data(header))
                        .await
                        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP downstream capsule send timed out"))??;
                    timeout(idle_timeout, downstream_send.send_data(fallback))
                        .await
                        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP downstream capsule payload send timed out"))??;
                }
                idle_deadline
                    .as_mut()
                    .reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
        }
    }

    let _ = timeout(idle_timeout, upstream_send.finish()).await;
    let _ = timeout(idle_timeout, downstream_send.finish()).await;
    Ok(())
}

async fn apply_connect_udp_bandwidth_controls(
    ctx: &RateLimitContext,
    limits: &AppliedRateLimits,
    bytes: usize,
) -> Result<()> {
    let delay = limits
        .reserve_bytes(ctx, bytes as u64)
        .map_err(|_| anyhow!("CONNECT-UDP bandwidth quota exceeded"))?;
    if !delay.is_zero() {
        sleep(delay).await;
    }
    Ok(())
}
