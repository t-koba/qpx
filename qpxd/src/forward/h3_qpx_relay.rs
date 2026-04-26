use crate::http3::capsule::{
    append_capsule_chunk, decode_quic_varint, encode_datagram_capsule,
    encode_datagram_capsule_value, take_next_capsule,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};
use qpx_core::config::ConnectUdpConfig;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout, Duration, Instant};
use tracing::warn;

pub(super) async fn relay_qpx_extended_connect_stream(
    downstream: qpx_h3::RequestStream,
    mut downstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    upstream: qpx_h3::RequestStream,
    mut upstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    idle_timeout: Duration,
) -> Result<()> {
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();
    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);
    let mut downstream_eof = false;
    let mut upstream_eof = false;

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                return Err(anyhow!("forward HTTP/3 qpx-h3 extended CONNECT tunnel idle timeout"));
            }
            recv = downstream_recv.recv_data(), if !downstream_eof => {
                match recv? {
                    Some(chunk) => {
                        timeout(idle_timeout, upstream_send.send_data(chunk))
                            .await
                            .map_err(|_| anyhow!("qpx-h3 upstream DATA send timed out"))??;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => {
                        downstream_eof = true;
                        timeout(idle_timeout, upstream_send.finish())
                            .await
                            .map_err(|_| anyhow!("qpx-h3 upstream finish timed out"))??;
                        if upstream_eof {
                            break;
                        }
                    }
                }
            }
            recv = upstream_recv.recv_data(), if !upstream_eof => {
                match recv? {
                    Some(chunk) => {
                        timeout(idle_timeout, downstream_send.send_data(chunk))
                            .await
                            .map_err(|_| anyhow!("qpx-h3 downstream DATA send timed out"))??;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => {
                        upstream_eof = true;
                        timeout(idle_timeout, downstream_send.finish())
                            .await
                            .map_err(|_| anyhow!("qpx-h3 downstream finish timed out"))??;
                        if downstream_eof {
                            break;
                        }
                    }
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
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    if let Err(err) = datagrams.sender.send_datagram(payload) {
                        warn!(error = ?err, "forward HTTP/3 qpx-h3 upstream datagram send failed");
                    }
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
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
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    if let Err(err) = datagrams.sender.send_datagram(payload) {
                        warn!(error = ?err, "forward HTTP/3 qpx-h3 downstream datagram send failed");
                    }
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
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

    let mut capsule_buf = BytesMut::new();
    let mut udp_buf = [0u8; 65_535];

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                break;
            }
            recv = req_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        append_capsule_chunk(
                            &mut capsule_buf,
                            &bytes,
                            connect_udp_cfg.max_capsule_buffer_bytes,
                        )?;
                        while let Some((capsule_type, payload)) = take_next_capsule(&mut capsule_buf)? {
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
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
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
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
            recv = udp.recv(&mut udp_buf) => {
                let n = recv?;
                if n == 0 {
                    continue;
                }
                apply_connect_udp_bandwidth_controls(&rate_limit_ctx, &request_limits, n).await?;
                let mut sent = false;
                if let Some(datagrams) = datagrams.as_mut() {
                    let mut value = Vec::with_capacity(1 + n);
                    value.push(0);
                    value.extend_from_slice(&udp_buf[..n]);
                    if datagrams.sender.send_datagram(Bytes::from(value)).is_ok() {
                        sent = true;
                    }
                }
                if !sent {
                    let capsule = encode_datagram_capsule(&udp_buf[..n])?;
                    timeout(idle_timeout, req_send.send_data(capsule))
                        .await
                        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP capsule send timed out"))??;
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
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

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                break;
            }
            recv = downstream_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        apply_connect_udp_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            bytes.len(),
                        )
                        .await?;
                        timeout(idle_timeout, upstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP upstream DATA send timed out"))??;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => break,
                }
            }
            recv = upstream_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        apply_connect_udp_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            bytes.len(),
                        )
                        .await?;
                        timeout(idle_timeout, downstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP downstream DATA send timed out"))??;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
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
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    if datagrams.sender.send_datagram(payload).is_ok() {
                        sent = true;
                    }
                }
                if !sent {
                    let capsule = encode_datagram_capsule_value(fallback.as_ref())?;
                    timeout(idle_timeout, upstream_send.send_data(capsule))
                        .await
                        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP upstream capsule send timed out"))??;
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
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
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    if datagrams.sender.send_datagram(payload).is_ok() {
                        sent = true;
                    }
                }
                if !sent {
                    let capsule = encode_datagram_capsule_value(fallback.as_ref())?;
                    timeout(idle_timeout, downstream_send.send_data(capsule))
                        .await
                        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP downstream capsule send timed out"))??;
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
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
