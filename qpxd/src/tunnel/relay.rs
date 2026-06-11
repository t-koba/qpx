use crate::exporter::ExportSession;
use crate::tunnel::{TunnelHalf, TunnelHalfWrite};
use crate::upstream::io_copy::BandwidthThrottle;
use anyhow::Result;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{Duration, Instant, sleep, timeout};

const TUNNEL_DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct TunnelActivity {
    base: Arc<Instant>,
    last_activity_nanos: Arc<AtomicU64>,
}

impl TunnelActivity {
    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub(crate) fn new() -> Self {
        Self {
            base: Arc::new(Instant::now()),
            last_activity_nanos: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn touch(&self) {
        self.last_activity_nanos.store(
            duration_as_nanos_u64(self.base.elapsed()),
            Ordering::Relaxed,
        );
    }

    pub(crate) async fn wait_for_idle(&self, idle_timeout: Duration) {
        if idle_timeout.is_zero() {
            return;
        }
        let idle_timeout_nanos = duration_as_nanos_u64(idle_timeout);
        loop {
            let last = self.last_activity_nanos.load(Ordering::Relaxed);
            let deadline_offset = last.saturating_add(idle_timeout_nanos);
            let deadline = (*self.base) + Duration::from_nanos(deadline_offset);
            tokio::time::sleep_until(deadline).await;
            let now = duration_as_nanos_u64(self.base.elapsed());
            let last = self.last_activity_nanos.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= idle_timeout_nanos {
                return;
            }
        }
    }
}

fn duration_as_nanos_u64(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

pub(crate) struct TunnelPolicy {
    pub(crate) idle_timeout: Option<Duration>,
    pub(crate) max_bytes_client_to_server: Option<u64>,
    pub(crate) max_bytes_server_to_client: Option<u64>,
    pub(crate) throttle: Option<BandwidthThrottle>,
    pub(crate) export: Option<ExportSession>,
    pub(crate) transport: &'static str,
    pub(crate) listener: Arc<str>,
    pub(crate) activity: Option<TunnelActivity>,
    metrics: super::metrics::TunnelMetricHandles,
    io_timeout: Duration,
}

impl TunnelPolicy {
    pub(crate) fn new(
        idle_timeout: Option<Duration>,
        throttle: Option<BandwidthThrottle>,
        export: Option<ExportSession>,
        transport: &'static str,
        listener: Arc<str>,
    ) -> Self {
        let metrics = super::metrics::TunnelMetricHandles::new(transport, listener.as_ref());
        Self {
            idle_timeout,
            max_bytes_client_to_server: None,
            max_bytes_server_to_client: None,
            throttle,
            export,
            transport,
            listener,
            activity: None,
            metrics,
            io_timeout: idle_timeout.unwrap_or(TUNNEL_DEFAULT_IO_TIMEOUT),
        }
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub(crate) fn with_activity(mut self, activity: TunnelActivity) -> Self {
        self.activity = Some(activity);
        self
    }
}

#[derive(Debug)]
pub(crate) struct TunnelStats {
    pub(crate) bytes_client_to_server: u64,
    pub(crate) bytes_server_to_client: u64,
    pub(crate) duration: Duration,
    pub(crate) close_reason: TunnelCloseReason,
}

#[derive(Debug)]
pub(crate) enum TunnelCloseReason {
    Complete,
    ClientEof,
    ServerEof,
    IdleTimeout,
    ByteLimitExceeded,
}

impl TunnelCloseReason {
    pub(super) fn as_label(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ClientEof => "client_eof",
            Self::ServerEof => "server_eof",
            Self::IdleTimeout => "idle_timeout",
            Self::ByteLimitExceeded => "byte_limit_exceeded",
        }
    }
}

pub(crate) async fn relay_tunnel<CR, CW, SR, SW>(
    mut client_read: CR,
    mut client_write: CW,
    mut server_read: SR,
    mut server_write: SW,
    policy: TunnelPolicy,
) -> Result<TunnelStats>
where
    CR: TunnelHalf,
    CW: TunnelHalfWrite,
    SR: TunnelHalf,
    SW: TunnelHalfWrite,
{
    let started = Instant::now();
    super::metrics::emit_tunnel_active(&policy, 1.0);
    let _active_guard = TunnelActiveGuard { policy: &policy };
    let activity = policy.activity.clone();
    if let Some(activity) = activity.as_ref() {
        activity.touch();
    }
    let local_idle_deadline = policy
        .idle_timeout
        .filter(|_| activity.is_none())
        .map(tokio::time::sleep);
    tokio::pin!(local_idle_deadline);

    let mut bytes_client_to_server = 0u64;
    let mut bytes_server_to_client = 0u64;
    let mut client_eof = false;
    let mut server_eof = false;
    let mut first_eof = None;
    let close_reason = loop {
        if client_eof && server_eof {
            break first_eof.take().unwrap_or(TunnelCloseReason::Complete);
        }

        tokio::select! {
                _ = wait_for_policy_idle(policy.idle_timeout, activity.as_ref(), &mut local_idle_deadline) => {
                shutdown_quietly(&mut client_write, policy.io_timeout).await;
                shutdown_quietly(&mut server_write, policy.io_timeout).await;
                break TunnelCloseReason::IdleTimeout;
            }
            recv = client_read.recv(), if !client_eof => {
                match recv? {
                    Some(chunk) => {
                        let next = match relay_chunk(
                            &mut server_write,
                            chunk,
                            &policy,
                            true,
                            bytes_client_to_server,
                            policy.max_bytes_client_to_server,
                        )
                        .await {
                            Ok(next) => next,
                            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                                shutdown_quietly(&mut client_write, policy.io_timeout).await;
                                shutdown_quietly(&mut server_write, policy.io_timeout).await;
                                break TunnelCloseReason::ByteLimitExceeded;
                            }
                            Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                                shutdown_quietly(&mut client_write, policy.io_timeout).await;
                                shutdown_quietly(&mut server_write, policy.io_timeout).await;
                                break TunnelCloseReason::IdleTimeout;
                            }
                            Err(err) => return Err(err.into()),
                        };
                        bytes_client_to_server = next;
                        touch_or_reset_idle(activity.as_ref(), &mut local_idle_deadline, policy.idle_timeout).await;
                    }
                    None => {
                        client_eof = true;
                        first_eof.get_or_insert(TunnelCloseReason::ClientEof);
                        shutdown_quietly(&mut server_write, policy.io_timeout).await;
                    }
                }
            }
            recv = server_read.recv(), if !server_eof => {
                match recv? {
                    Some(chunk) => {
                        let next = match relay_chunk(
                            &mut client_write,
                            chunk,
                            &policy,
                            false,
                            bytes_server_to_client,
                            policy.max_bytes_server_to_client,
                        )
                        .await {
                            Ok(next) => next,
                            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                                shutdown_quietly(&mut client_write, policy.io_timeout).await;
                                shutdown_quietly(&mut server_write, policy.io_timeout).await;
                                break TunnelCloseReason::ByteLimitExceeded;
                            }
                            Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                                shutdown_quietly(&mut client_write, policy.io_timeout).await;
                                shutdown_quietly(&mut server_write, policy.io_timeout).await;
                                break TunnelCloseReason::IdleTimeout;
                            }
                            Err(err) => return Err(err.into()),
                        };
                        bytes_server_to_client = next;
                        touch_or_reset_idle(activity.as_ref(), &mut local_idle_deadline, policy.idle_timeout).await;
                    }
                    None => {
                        server_eof = true;
                        first_eof.get_or_insert(TunnelCloseReason::ServerEof);
                        shutdown_quietly(&mut client_write, policy.io_timeout).await;
                    }
                }
            }
        }
    };

    let stats = TunnelStats {
        bytes_client_to_server,
        bytes_server_to_client,
        duration: started.elapsed(),
        close_reason,
    };
    super::metrics::emit_tunnel_metrics(&policy, &stats);
    Ok(stats)
}

struct TunnelActiveGuard<'a> {
    policy: &'a TunnelPolicy,
}

impl Drop for TunnelActiveGuard<'_> {
    fn drop(&mut self) {
        super::metrics::emit_tunnel_active(self.policy, -1.0);
    }
}

async fn relay_chunk<W>(
    writer: &mut W,
    chunk: bytes::Bytes,
    policy: &TunnelPolicy,
    client_to_server: bool,
    current_total: u64,
    max_bytes: Option<u64>,
) -> io::Result<u64>
where
    W: TunnelHalfWrite,
{
    let next = current_total.saturating_add(chunk.len() as u64);
    if let Some(max_bytes) = max_bytes
        && next > max_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "tunnel byte limit exceeded",
        ));
    }
    if let Some(throttle) = policy.throttle.as_ref() {
        let delay = throttle.reserve_delay(chunk.len())?;
        if !delay.is_zero() {
            policy
                .metrics
                .record_backpressure(client_to_server, delay.as_secs_f64());
            sleep(delay).await;
        }
    }
    timeout(policy.io_timeout, writer.send(chunk.clone()))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tunnel write timed out"))??;
    if let Some(session) = &policy.export {
        session.emit_encrypted_pair(client_to_server, chunk.as_ref());
    }
    Ok(next)
}

async fn shutdown_quietly<W>(writer: &mut W, io_timeout: Duration)
where
    W: TunnelHalfWrite,
{
    let _ = timeout(io_timeout, writer.shutdown()).await;
}

async fn touch_or_reset_idle(
    activity: Option<&TunnelActivity>,
    local_idle_deadline: &mut std::pin::Pin<&mut Option<tokio::time::Sleep>>,
    idle_timeout: Option<Duration>,
) {
    if let Some(activity) = activity {
        activity.touch();
    } else if let (Some(deadline), Some(idle_timeout)) =
        (local_idle_deadline.as_mut().as_pin_mut(), idle_timeout)
    {
        deadline.reset(crate::runtime::tokio_deadline_after(idle_timeout));
    }
}

async fn wait_for_policy_idle(
    idle_timeout: Option<Duration>,
    activity: Option<&TunnelActivity>,
    local_idle_deadline: &mut std::pin::Pin<&mut Option<tokio::time::Sleep>>,
) {
    match (idle_timeout, activity) {
        (Some(timeout), Some(activity)) => activity.wait_for_idle(timeout).await,
        (Some(_), None) => {
            if let Some(deadline) = local_idle_deadline.as_mut().as_pin_mut() {
                deadline.await;
            } else {
                std::future::pending::<()>().await;
            }
        }
        (None, _) => std::future::pending::<()>().await,
    }
}
