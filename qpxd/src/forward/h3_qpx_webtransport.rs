use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinSet;
use tokio::time::{Duration, Instant};

struct WebTransportActivity {
    last_activity: Mutex<Instant>,
    notify: Notify,
}

impl WebTransportActivity {
    fn new() -> Self {
        Self {
            last_activity: Mutex::new(Instant::now()),
            notify: Notify::new(),
        }
    }

    async fn touch(&self) {
        *self.last_activity.lock().await = Instant::now();
        self.notify.notify_waiters();
    }

    async fn wait_for_idle(&self, idle_timeout: Duration) {
        loop {
            let deadline = {
                let last = *self.last_activity.lock().await;
                last + idle_timeout
            };
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    let last = *self.last_activity.lock().await;
                    if Instant::now().duration_since(last) >= idle_timeout {
                        return;
                    }
                }
                _ = self.notify.notified() => {}
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum WebTransportDirection {
    Downstream,
    Upstream,
}

impl WebTransportDirection {
    fn opposite(self) -> Self {
        match self {
            Self::Downstream => Self::Upstream,
            Self::Upstream => Self::Downstream,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct WebTransportFlowLimits {
    pub(super) bidi: AppliedRateLimits,
    pub(super) bidi_downstream: AppliedRateLimits,
    pub(super) bidi_upstream: AppliedRateLimits,
    pub(super) uni: AppliedRateLimits,
    pub(super) uni_downstream: AppliedRateLimits,
    pub(super) uni_upstream: AppliedRateLimits,
    pub(super) datagram: AppliedRateLimits,
    pub(super) datagram_downstream: AppliedRateLimits,
    pub(super) datagram_upstream: AppliedRateLimits,
}

impl WebTransportFlowLimits {
    fn bidi_limits(&self, direction: WebTransportDirection) -> [&AppliedRateLimits; 2] {
        match direction {
            WebTransportDirection::Downstream => [&self.bidi, &self.bidi_downstream],
            WebTransportDirection::Upstream => [&self.bidi, &self.bidi_upstream],
        }
    }

    fn uni_limits(&self, direction: WebTransportDirection) -> [&AppliedRateLimits; 2] {
        match direction {
            WebTransportDirection::Downstream => [&self.uni, &self.uni_downstream],
            WebTransportDirection::Upstream => [&self.uni, &self.uni_upstream],
        }
    }

    fn datagram_limits(&self, direction: WebTransportDirection) -> [&AppliedRateLimits; 2] {
        match direction {
            WebTransportDirection::Downstream => [&self.datagram, &self.datagram_downstream],
            WebTransportDirection::Upstream => [&self.datagram, &self.datagram_upstream],
        }
    }
}

#[derive(Clone)]
struct WebTransportRelayShared {
    activity: Arc<WebTransportActivity>,
    idle_timeout: Duration,
    rate_limit_ctx: RateLimitContext,
    request_limits: AppliedRateLimits,
    flow_limits: WebTransportFlowLimits,
}

async fn relay_bidi_pair(
    left: qpx_h3::BidiStream,
    right: qpx_h3::BidiStream,
    shared: WebTransportRelayShared,
    left_to_right_direction: WebTransportDirection,
) -> Result<()> {
    let WebTransportRelayShared {
        activity,
        idle_timeout,
        rate_limit_ctx,
        request_limits,
        flow_limits,
    } = shared;
    let (mut left_send, mut left_recv) = left.split();
    let (mut right_send, mut right_recv) = right.split();
    let mut left_eof = false;
    let mut right_eof = false;

    loop {
        tokio::select! {
            recv = left_recv.recv_chunk(), if !left_eof => {
                match recv? {
                    Some(chunk) => {
                        let directional_limits = flow_limits.bidi_limits(left_to_right_direction);
                        apply_webtransport_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            &directional_limits,
                            chunk.len(),
                        )
                        .await?;
                        tokio::time::timeout(idle_timeout, right_send.send_chunk(chunk))
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 WebTransport stream send timeout"))??;
                        activity.touch().await;
                    }
                    None => {
                        left_eof = true;
                        tokio::time::timeout(idle_timeout, right_send.finish())
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 WebTransport stream finish timeout"))??;
                        if right_eof {
                            break;
                        }
                    }
                }
            }
            recv = right_recv.recv_chunk(), if !right_eof => {
                match recv? {
                    Some(chunk) => {
                        let directional_limits =
                            flow_limits.bidi_limits(left_to_right_direction.opposite());
                        apply_webtransport_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            &directional_limits,
                            chunk.len(),
                        )
                        .await?;
                        tokio::time::timeout(idle_timeout, left_send.send_chunk(chunk))
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 WebTransport stream send timeout"))??;
                        activity.touch().await;
                    }
                    None => {
                        right_eof = true;
                        tokio::time::timeout(idle_timeout, left_send.finish())
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 WebTransport stream finish timeout"))??;
                        if left_eof {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn relay_uni_stream(
    mut recv: qpx_h3::UniRecvStream,
    mut send: qpx_h3::UniSendStream,
    shared: WebTransportRelayShared,
    direction: WebTransportDirection,
) -> Result<()> {
    let WebTransportRelayShared {
        activity,
        idle_timeout,
        rate_limit_ctx,
        request_limits,
        flow_limits,
    } = shared;
    while let Some(chunk) = recv.recv_chunk().await? {
        let directional_limits = flow_limits.uni_limits(direction);
        apply_webtransport_bandwidth_controls(
            &rate_limit_ctx,
            &request_limits,
            &directional_limits,
            chunk.len(),
        )
        .await?;
        tokio::time::timeout(idle_timeout, send.send_chunk(chunk))
            .await
            .map_err(|_| anyhow!("forward HTTP/3 WebTransport stream send timeout"))??;
        activity.touch().await;
    }
    tokio::time::timeout(idle_timeout, send.finish())
        .await
        .map_err(|_| anyhow!("forward HTTP/3 WebTransport stream finish timeout"))??;
    Ok(())
}

struct WebTransportRequestRelayContext {
    downstream: qpx_h3::RequestStream,
    downstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    upstream: qpx_h3::RequestStream,
    upstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    activity: Arc<WebTransportActivity>,
    idle_timeout: Duration,
    rate_limit_ctx: RateLimitContext,
    request_limits: AppliedRateLimits,
    flow_limits: WebTransportFlowLimits,
}

async fn relay_request_stream(ctx: WebTransportRequestRelayContext) -> Result<()> {
    let WebTransportRequestRelayContext {
        downstream,
        mut downstream_datagrams,
        upstream,
        mut upstream_datagrams,
        activity,
        idle_timeout,
        rate_limit_ctx,
        request_limits,
        flow_limits,
    } = ctx;
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();
    let mut downstream_eof = false;
    let mut upstream_eof = false;

    loop {
        tokio::select! {
            recv = downstream_recv.recv_data(), if !downstream_eof => {
                match recv? {
                    Some(chunk) => {
                        let empty_limits: [&AppliedRateLimits; 0] = [];
                        apply_webtransport_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            &empty_limits,
                            chunk.len(),
                        )
                        .await?;
                        tokio::time::timeout(idle_timeout, upstream_send.send_data(chunk))
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 WebTransport request send timeout"))??;
                        activity.touch().await;
                    }
                    None => {
                        downstream_eof = true;
                        tokio::time::timeout(idle_timeout, upstream_send.finish())
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 WebTransport request finish timeout"))??;
                        if upstream_eof {
                            break;
                        }
                    }
                }
            }
            recv = upstream_recv.recv_data(), if !upstream_eof => {
                match recv? {
                    Some(chunk) => {
                        let empty_limits: [&AppliedRateLimits; 0] = [];
                        apply_webtransport_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            &empty_limits,
                            chunk.len(),
                        )
                        .await?;
                        tokio::time::timeout(idle_timeout, downstream_send.send_data(chunk))
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 WebTransport request send timeout"))??;
                        activity.touch().await;
                    }
                    None => {
                        upstream_eof = true;
                        tokio::time::timeout(idle_timeout, downstream_send.finish())
                            .await
                            .map_err(|_| anyhow!("forward HTTP/3 WebTransport request finish timeout"))??;
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
                    let directional_limits =
                        flow_limits.datagram_limits(WebTransportDirection::Downstream);
                    apply_webtransport_bandwidth_controls(
                        &rate_limit_ctx,
                        &request_limits,
                        &directional_limits,
                        payload.len(),
                    )
                    .await?;
                    datagrams.sender.send_datagram(payload)?;
                    activity.touch().await;
                }
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
                    let directional_limits =
                        flow_limits.datagram_limits(WebTransportDirection::Upstream);
                    apply_webtransport_bandwidth_controls(
                        &rate_limit_ctx,
                        &request_limits,
                        &directional_limits,
                        payload.len(),
                    )
                    .await?;
                    datagrams.sender.send_datagram(payload)?;
                    activity.touch().await;
                }
            }
        }
    }

    Ok(())
}

enum WebTransportSessionEvent {
    DownstreamBidi(qpx_h3::BidiStream),
    DownstreamUni(qpx_h3::UniRecvStream),
    UpstreamBidi(qpx_h3::BidiStream),
    UpstreamUni(qpx_h3::UniRecvStream),
    RelayDone(Result<()>),
    RequestDone(Result<()>),
    Idle,
}

pub(super) struct QpxWebTransportRelayContext {
    pub(super) downstream_request: qpx_h3::RequestStream,
    pub(super) downstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    pub(super) downstream_opener: qpx_h3::OpenStreams,
    pub(super) downstream_bidi_streams: mpsc::UnboundedReceiver<qpx_h3::BidiStream>,
    pub(super) downstream_uni_streams: mpsc::UnboundedReceiver<qpx_h3::UniRecvStream>,
    pub(super) upstream_request: qpx_h3::RequestStream,
    pub(super) upstream_datagrams: Option<qpx_h3::StreamDatagrams>,
    pub(super) upstream_opener: qpx_h3::OpenStreams,
    pub(super) upstream_bidi_streams: mpsc::UnboundedReceiver<qpx_h3::BidiStream>,
    pub(super) upstream_uni_streams: mpsc::UnboundedReceiver<qpx_h3::UniRecvStream>,
    pub(super) session_id: u64,
    pub(super) idle_timeout: Duration,
    pub(super) rate_limit_ctx: RateLimitContext,
    pub(super) request_limits: AppliedRateLimits,
    pub(super) flow_limits: WebTransportFlowLimits,
}

pub(super) async fn relay_qpx_webtransport_session(ctx: QpxWebTransportRelayContext) -> Result<()> {
    let QpxWebTransportRelayContext {
        downstream_request,
        downstream_datagrams,
        mut downstream_opener,
        mut downstream_bidi_streams,
        mut downstream_uni_streams,
        upstream_request,
        upstream_datagrams,
        mut upstream_opener,
        mut upstream_bidi_streams,
        mut upstream_uni_streams,
        session_id,
        idle_timeout,
        rate_limit_ctx,
        request_limits,
        flow_limits,
    } = ctx;

    let activity = Arc::new(WebTransportActivity::new());
    let shared = WebTransportRelayShared {
        activity: activity.clone(),
        idle_timeout,
        rate_limit_ctx: rate_limit_ctx.clone(),
        request_limits: request_limits.clone(),
        flow_limits: flow_limits.clone(),
    };
    let mut request_task = tokio::spawn(relay_request_stream(WebTransportRequestRelayContext {
        downstream: downstream_request,
        downstream_datagrams,
        upstream: upstream_request,
        upstream_datagrams,
        activity: activity.clone(),
        idle_timeout,
        rate_limit_ctx: rate_limit_ctx.clone(),
        request_limits: request_limits.clone(),
        flow_limits: flow_limits.clone(),
    }));
    let mut idle_task = tokio::spawn({
        let activity = activity.clone();
        async move {
            activity.wait_for_idle(idle_timeout).await;
        }
    });
    let mut relays = JoinSet::new();

    loop {
        let event = tokio::select! {
            maybe = downstream_bidi_streams.recv() => match maybe {
                Some(stream) => WebTransportSessionEvent::DownstreamBidi(stream),
                None => WebTransportSessionEvent::RequestDone(Ok(())),
            },
            maybe = downstream_uni_streams.recv() => match maybe {
                Some(stream) => WebTransportSessionEvent::DownstreamUni(stream),
                None => WebTransportSessionEvent::RequestDone(Ok(())),
            },
            maybe = upstream_bidi_streams.recv() => match maybe {
                Some(stream) => WebTransportSessionEvent::UpstreamBidi(stream),
                None => WebTransportSessionEvent::RequestDone(Ok(())),
            },
            maybe = upstream_uni_streams.recv() => match maybe {
                Some(stream) => WebTransportSessionEvent::UpstreamUni(stream),
                None => WebTransportSessionEvent::RequestDone(Ok(())),
            },
            joined = relays.join_next(), if !relays.is_empty() => {
                match joined {
                    Some(Ok(res)) => WebTransportSessionEvent::RelayDone(res),
                    Some(Err(err)) => WebTransportSessionEvent::RelayDone(Err(anyhow!(err))),
                    None => WebTransportSessionEvent::RequestDone(Ok(())),
                }
            }
            joined = &mut request_task => {
                match joined {
                    Ok(res) => WebTransportSessionEvent::RequestDone(res),
                    Err(err) => WebTransportSessionEvent::RequestDone(Err(anyhow!(err))),
                }
            }
            _ = &mut idle_task => WebTransportSessionEvent::Idle,
        };

        match event {
            WebTransportSessionEvent::DownstreamBidi(stream) => {
                let upstream =
                    downstream_to_upstream_bidi(&mut upstream_opener, session_id).await?;
                relays.spawn(relay_bidi_pair(
                    stream,
                    upstream,
                    shared.clone(),
                    WebTransportDirection::Downstream,
                ));
            }
            WebTransportSessionEvent::DownstreamUni(stream) => {
                let upstream = upstream_opener.open_webtransport_uni(session_id).await?;
                relays.spawn(relay_uni_stream(
                    stream,
                    upstream,
                    shared.clone(),
                    WebTransportDirection::Downstream,
                ));
            }
            WebTransportSessionEvent::UpstreamBidi(stream) => {
                let downstream =
                    downstream_to_upstream_bidi(&mut downstream_opener, session_id).await?;
                relays.spawn(relay_bidi_pair(
                    stream,
                    downstream,
                    shared.clone(),
                    WebTransportDirection::Upstream,
                ));
            }
            WebTransportSessionEvent::UpstreamUni(stream) => {
                let downstream = downstream_opener.open_webtransport_uni(session_id).await?;
                relays.spawn(relay_uni_stream(
                    stream,
                    downstream,
                    shared.clone(),
                    WebTransportDirection::Upstream,
                ));
            }
            WebTransportSessionEvent::RelayDone(res) => {
                res?;
            }
            WebTransportSessionEvent::RequestDone(res) => {
                relays.abort_all();
                let _ = idle_task.await;
                res?;
                break;
            }
            WebTransportSessionEvent::Idle => {
                relays.abort_all();
                request_task.abort();
                return Err(anyhow!("forward HTTP/3 WebTransport tunnel idle timeout"));
            }
        }
    }

    Ok(())
}

async fn downstream_to_upstream_bidi(
    opener: &mut qpx_h3::OpenStreams,
    session_id: u64,
) -> Result<qpx_h3::BidiStream> {
    opener.open_webtransport_bidi(session_id).await
}

async fn apply_webtransport_bandwidth_controls(
    ctx: &RateLimitContext,
    session_limits: &AppliedRateLimits,
    flow_limits: &[&AppliedRateLimits],
    bytes: usize,
) -> Result<()> {
    let mut delay = session_limits
        .reserve_bytes(ctx, bytes as u64)
        .map_err(|_| anyhow!("WebTransport bandwidth quota exceeded"))?;
    for limits in flow_limits {
        delay = delay.max(
            limits
                .reserve_bytes(ctx, bytes as u64)
                .map_err(|_| anyhow!("WebTransport bandwidth quota exceeded"))?,
        );
    }
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    Ok(())
}
