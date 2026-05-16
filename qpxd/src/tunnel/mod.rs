mod relay;
pub(crate) mod stream;

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) use relay::TunnelActivity;
pub(crate) use relay::{TunnelPolicy, TunnelStats, relay_tunnel};
pub(crate) use stream::{TunnelHalf, TunnelHalfWrite};

use crate::exporter::ExportSession;
use crate::io_copy::BandwidthThrottle;
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Duration;

impl TunnelPolicy {
    pub(crate) fn tcp(
        idle_timeout: Option<Duration>,
        throttle: Option<BandwidthThrottle>,
        export: Option<ExportSession>,
    ) -> Self {
        Self::new(
            idle_timeout,
            throttle,
            export,
            "tcp",
            Arc::<str>::from("unknown"),
        )
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub(crate) fn h3(
        idle_timeout: Option<Duration>,
        transport: &'static str,
        listener: impl Into<Arc<str>>,
    ) -> Self {
        Self::new(idle_timeout, None, None, transport, listener.into())
    }
}

pub(crate) async fn relay_tcp_tunnel<A, B>(a: A, b: B, policy: TunnelPolicy) -> Result<TunnelStats>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (a_reader, a_writer) = tokio::io::split(a);
    let (b_reader, b_writer) = tokio::io::split(b);
    relay_tunnel(a_reader, a_writer, b_reader, b_writer, policy).await
}
