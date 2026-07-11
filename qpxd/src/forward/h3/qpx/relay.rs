use crate::http3::capsule::{
    CapsuleBuffer, decode_quic_varint, encode_capsule_header,
    encode_datagram_capsule_context_header, encode_datagram_capsule_header,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use qpx_core::config::ConnectUdpConfig;
use qpx_http::connect_ip::{
    ADDRESS_ASSIGN_CAPSULE, ADDRESS_REQUEST_CAPSULE, ConnectIpPacketPolicy,
    ROUTE_ADVERTISEMENT_CAPSULE, decode_ip_prefix_records, decode_ip_routes,
};
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

pub(super) struct ChainedConnectIpRelay {
    pub downstream: qpx_h3::RequestStream,
    pub downstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    pub upstream: qpx_h3::RequestStream,
    pub upstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    pub downstream_policy: ConnectIpPacketPolicy,
    pub upstream_policy: ConnectIpPacketPolicy,
    pub max_capsule_buffer_bytes: usize,
    pub idle_timeout: Duration,
}

pub(super) async fn relay_qpx_connect_ip_stream_chained(
    input: ChainedConnectIpRelay,
) -> Result<()> {
    let ChainedConnectIpRelay {
        downstream,
        mut downstream_datagrams,
        upstream,
        mut upstream_datagrams,
        downstream_policy,
        upstream_policy,
        max_capsule_buffer_bytes,
        idle_timeout,
    } = input;
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();
    let mut downstream_capsules = CapsuleBuffer::new();
    let mut upstream_capsules = CapsuleBuffer::new();
    let mut downstream_scratch = BytesMut::new();
    let mut upstream_scratch = BytesMut::new();
    let deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            chunk = downstream_recv.recv_data() => {
                let Some(chunk) = chunk? else { break };
                downstream_capsules.push(chunk, max_capsule_buffer_bytes)?;
                while let Some((capsule_type, payload)) = downstream_capsules.take_next()? {
                    validate_connect_ip_capsule(capsule_type, &payload, &downstream_policy)?;
                    upstream_send.send_data(encode_capsule_header(capsule_type, payload.len())?).await?;
                    if !payload.is_empty() {
                        upstream_send.send_data(payload).await?;
                    }
                }
                deadline.as_mut().reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
            chunk = upstream_recv.recv_data() => {
                let Some(chunk) = chunk? else { break };
                upstream_capsules.push(chunk, max_capsule_buffer_bytes)?;
                while let Some((capsule_type, payload)) = upstream_capsules.take_next()? {
                    validate_connect_ip_capsule(capsule_type, &payload, &upstream_policy)?;
                    downstream_send.send_data(encode_capsule_header(capsule_type, payload.len())?).await?;
                    if !payload.is_empty() {
                        downstream_send.send_data(payload).await?;
                    }
                }
                deadline.as_mut().reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
            payload = async {
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = payload else { break };
                validate_connect_ip_datagram(&payload, &downstream_policy)?;
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    datagrams.sender.send_unprefixed_datagram_with_scratch(payload, &mut upstream_scratch)?;
                } else {
                    let header = encode_datagram_capsule_header(payload.len())?;
                    upstream_send.send_data(header).await?;
                    upstream_send.send_data(payload).await?;
                }
                deadline.as_mut().reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
            payload = async {
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = payload else { break };
                validate_connect_ip_datagram(&payload, &upstream_policy)?;
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    datagrams.sender.send_unprefixed_datagram_with_scratch(payload, &mut downstream_scratch)?;
                } else {
                    let header = encode_datagram_capsule_header(payload.len())?;
                    downstream_send.send_data(header).await?;
                    downstream_send.send_data(payload).await?;
                }
                deadline.as_mut().reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
        }
    }
    let _ = upstream_send.finish().await;
    let _ = downstream_send.finish().await;
    Ok(())
}

pub(super) async fn relay_qpx_connect_ip_device(
    req_stream: qpx_h3::RequestStream,
    mut datagrams: Option<qpx_h3::StreamDatagrams>,
    device: crate::connect_ip::SystemIpDevice,
    downstream_policy: ConnectIpPacketPolicy,
    upstream_policy: ConnectIpPacketPolicy,
    max_capsule_buffer_bytes: usize,
    idle_timeout: Duration,
) -> Result<()> {
    let (mut req_send, mut req_recv) = req_stream.split();
    let (mut device_reader, mut device_writer) = device.split();
    let mut capsules = CapsuleBuffer::new();
    let mut datagram_scratch = BytesMut::new();
    let mut packet = vec![0u8; 65_535];
    let deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            chunk = req_recv.recv_data() => {
                let Some(chunk) = chunk? else { break };
                capsules.push(chunk, max_capsule_buffer_bytes)?;
                while let Some((capsule_type, payload)) = capsules.take_next()? {
                    validate_connect_ip_capsule(capsule_type, &payload, &downstream_policy)?;
                    if capsule_type == 0 {
                        let (_, offset) = decode_quic_varint(&payload)
                            .ok_or_else(|| anyhow!("CONNECT-IP capsule context is invalid"))?;
                        device_writer.send_packet(&payload[offset..]).await?;
                    } else if capsule_type == ADDRESS_REQUEST_CAPSULE {
                        let assignments = decode_ip_prefix_records(&payload, true)?;
                        let payload = qpx_http::connect_ip::encode_ip_prefix_records(&assignments)?;
                        req_send
                            .send_data(encode_capsule_header(
                                ADDRESS_ASSIGN_CAPSULE,
                                payload.len(),
                            )?)
                            .await?;
                        req_send.send_data(Bytes::from(payload)).await?;
                    }
                }
                deadline.as_mut().reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
            payload = async {
                if let Some(datagrams) = datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = payload else { break };
                validate_connect_ip_datagram(&payload, &downstream_policy)?;
                let (_, offset) = decode_quic_varint(&payload)
                    .ok_or_else(|| anyhow!("CONNECT-IP datagram context is invalid"))?;
                device_writer.send_packet(&payload[offset..]).await?;
                deadline.as_mut().reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
            read = device_reader.recv_packet(&mut packet) => {
                let read = read?;
                if read == 0 {
                    break;
                }
                upstream_policy.validate(&packet[..read])?;
                let mut payload = BytesMut::with_capacity(read + 1);
                payload.extend_from_slice(&[0]);
                payload.extend_from_slice(&packet[..read]);
                let payload = payload.freeze();
                let mut sent = false;
                if let Some(datagrams) = datagrams.as_mut()
                    && datagrams
                        .sender
                        .send_unprefixed_datagram_with_scratch(payload.clone(), &mut datagram_scratch)
                        .is_ok()
                {
                    sent = true;
                }
                if !sent {
                    req_send.send_data(encode_datagram_capsule_header(payload.len())?).await?;
                    req_send.send_data(payload).await?;
                }
                deadline.as_mut().reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
        }
    }
    let _ = req_send.finish().await;
    Ok(())
}

fn validate_connect_ip_datagram(payload: &[u8], policy: &ConnectIpPacketPolicy) -> Result<()> {
    let (context_id, offset) = decode_quic_varint(payload)
        .ok_or_else(|| anyhow!("CONNECT-IP datagram has an invalid context ID"))?;
    if context_id != 0 || offset >= payload.len() {
        return Err(anyhow!("CONNECT-IP datagram context must be zero"));
    }
    policy.validate(&payload[offset..])?;
    Ok(())
}

fn validate_connect_ip_capsule(
    capsule_type: u64,
    payload: &[u8],
    policy: &ConnectIpPacketPolicy,
) -> Result<()> {
    match capsule_type {
        0 => validate_connect_ip_datagram(payload, policy),
        ADDRESS_ASSIGN_CAPSULE | ADDRESS_REQUEST_CAPSULE => {
            let records =
                decode_ip_prefix_records(payload, capsule_type == ADDRESS_REQUEST_CAPSULE)?;
            if records
                .iter()
                .any(|record| !policy.allows_source_prefix(record.address, record.prefix_len))
            {
                return Err(anyhow!(
                    "CONNECT-IP address assignment is outside the source CIDR policy"
                ));
            }
            Ok(())
        }
        ROUTE_ADVERTISEMENT_CAPSULE => {
            let routes = decode_ip_routes(payload)?;
            if routes
                .iter()
                .any(|route| !policy.allows_destination_range(route.start, route.end))
            {
                return Err(anyhow!(
                    "CONNECT-IP route advertisement is outside the destination CIDR policy"
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
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

#[cfg(test)]
mod connect_ip_tests {
    use super::*;
    use qpx_http::connect_ip::{
        IpPrefixRecord, IpRouteRecord, encode_ip_prefix_records, encode_ip_routes,
    };

    fn policy() -> ConnectIpPacketPolicy {
        ConnectIpPacketPolicy::new(
            vec!["192.0.2.0/24".parse().unwrap()],
            vec!["198.51.100.0/24".parse().unwrap()],
            1280,
        )
        .unwrap()
    }

    #[test]
    fn connect_ip_relay_validates_datagram_packet_policy() {
        let mut payload = vec![0, 0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0];
        payload.extend_from_slice(&[192, 0, 2, 1, 198, 51, 100, 2]);
        assert!(validate_connect_ip_datagram(&payload, &policy()).is_ok());
        payload[18] = 113;
        assert!(validate_connect_ip_datagram(&payload, &policy()).is_err());
    }

    #[test]
    fn connect_ip_relay_bounds_assignment_and_route_capsules() {
        let assignment = encode_ip_prefix_records(&[IpPrefixRecord {
            request_id: 1,
            address: "192.0.2.0".parse().unwrap(),
            prefix_len: 24,
        }])
        .unwrap();
        assert!(
            validate_connect_ip_capsule(ADDRESS_ASSIGN_CAPSULE, &assignment, &policy()).is_ok()
        );
        let oversized_assignment = encode_ip_prefix_records(&[IpPrefixRecord {
            request_id: 2,
            address: "192.0.2.0".parse().unwrap(),
            prefix_len: 23,
        }])
        .unwrap();
        assert!(
            validate_connect_ip_capsule(ADDRESS_ASSIGN_CAPSULE, &oversized_assignment, &policy())
                .is_err()
        );
        let route = encode_ip_routes(&[IpRouteRecord {
            start: "198.51.100.1".parse().unwrap(),
            end: "198.51.100.254".parse().unwrap(),
            protocol: 0,
        }])
        .unwrap();
        assert!(
            validate_connect_ip_capsule(ROUTE_ADVERTISEMENT_CAPSULE, &route, &policy()).is_ok()
        );
        let denied = encode_ip_routes(&[IpRouteRecord {
            start: "203.0.113.1".parse().unwrap(),
            end: "203.0.113.2".parse().unwrap(),
            protocol: 0,
        }])
        .unwrap();
        assert!(
            validate_connect_ip_capsule(ROUTE_ADVERTISEMENT_CAPSULE, &denied, &policy()).is_err()
        );
        let crossing = encode_ip_routes(&[IpRouteRecord {
            start: "198.51.100.254".parse().unwrap(),
            end: "198.51.101.1".parse().unwrap(),
            protocol: 0,
        }])
        .unwrap();
        assert!(
            validate_connect_ip_capsule(ROUTE_ADVERTISEMENT_CAPSULE, &crossing, &policy()).is_err()
        );
    }
}
