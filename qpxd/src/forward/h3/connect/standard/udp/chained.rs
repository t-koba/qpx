use crate::http3::datagram::H3StreamDatagrams;
use crate::http3::h3_buf_to_bytes;
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use qpx_core::config::ConnectUdpConfig;
use tokio::time::{Duration, sleep, timeout};

use crate::http3::capsule::encode_datagram_capsule_header;

pub(super) async fn relay_h3_connect_udp_stream_chained(
    downstream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut downstream_datagrams: Option<H3StreamDatagrams>,
    upstream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut upstream_datagrams: Option<H3StreamDatagrams>,
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
                        let bytes = h3_buf_to_bytes(chunk);
                        apply_connect_udp_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            bytes.len(),
                        )
                        .await?;
                        timeout(idle_timeout, upstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("CONNECT-UDP upstream DATA send timed out"))??;
                        reset_idle_deadline(idle_deadline.as_mut(), idle_timeout);
                    }
                    None => break,
                }
            }
            recv = upstream_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let bytes = h3_buf_to_bytes(chunk);
                        apply_connect_udp_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            bytes.len(),
                        )
                        .await?;
                        timeout(idle_timeout, downstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("CONNECT-UDP downstream DATA send timed out"))??;
                        reset_idle_deadline(idle_deadline.as_mut(), idle_timeout);
                    }
                    None => break,
                }
            }
            down_payload = recv_datagram(&mut downstream_datagrams) => {
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
                    && datagrams.sender.send_datagram(payload).is_ok() {
                        sent = true;
                    }
                if !sent {
                    let header = encode_datagram_capsule_header(fallback.len())?;
                    timeout(idle_timeout, upstream_send.send_data(header))
                        .await
                        .map_err(|_| anyhow!("CONNECT-UDP upstream capsule send timed out"))??;
                    timeout(idle_timeout, upstream_send.send_data(fallback))
                        .await
                        .map_err(|_| anyhow!("CONNECT-UDP upstream capsule payload send timed out"))??;
                }
                reset_idle_deadline(idle_deadline.as_mut(), idle_timeout);
            }
            up_payload = recv_datagram(&mut upstream_datagrams) => {
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
                    && datagrams.sender.send_datagram(payload).is_ok() {
                        sent = true;
                    }
                if !sent {
                    let header = encode_datagram_capsule_header(fallback.len())?;
                    timeout(idle_timeout, downstream_send.send_data(header))
                        .await
                        .map_err(|_| anyhow!("CONNECT-UDP downstream capsule send timed out"))??;
                    timeout(idle_timeout, downstream_send.send_data(fallback))
                        .await
                        .map_err(|_| anyhow!("CONNECT-UDP downstream capsule payload send timed out"))??;
                }
                reset_idle_deadline(idle_deadline.as_mut(), idle_timeout);
            }
        }
    }

    let _ = timeout(idle_timeout, upstream_send.finish()).await;
    let _ = timeout(idle_timeout, downstream_send.finish()).await;
    Ok(())
}

pub(super) async fn apply_connect_udp_bandwidth_controls(
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

async fn recv_datagram(datagrams: &mut Option<H3StreamDatagrams>) -> Option<Bytes> {
    if let Some(datagrams) = datagrams.as_mut() {
        datagrams.receiver.recv().await
    } else {
        std::future::pending::<Option<Bytes>>().await
    }
}

fn reset_idle_deadline(deadline: std::pin::Pin<&mut tokio::time::Sleep>, idle_timeout: Duration) {
    deadline.reset(crate::runtime::tokio_deadline_after(idle_timeout));
}
