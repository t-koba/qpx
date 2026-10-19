pub(super) mod parse;

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
mod standard;

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(in crate::forward::h3) use standard::{handle_h3_connect, handle_h3_extended_connect};

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(in crate::forward::h3) mod udp {
    pub(in crate::forward::h3) use super::standard::udp::handle_h3_connect_udp;
}

#[cfg(feature = "http3")]
pub(super) async fn apply_connect_udp_bandwidth_controls(
    ctx: &crate::rate_limit::RateLimitContext,
    limits: &crate::rate_limit::AppliedRateLimits,
    bytes: usize,
) -> anyhow::Result<()> {
    let delay = limits
        .reserve_bytes(ctx, bytes as u64)
        .map_err(|_| anyhow::anyhow!("CONNECT-UDP bandwidth quota exceeded"))?;
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    Ok(())
}
