use crate::rate_limit::{QuotaLimiter, RateLimitContext, RateLimiter};
use std::sync::Arc;
use tokio::time::Duration;

#[derive(Clone)]
pub struct BandwidthThrottle {
    context: RateLimitContext,
    limiters: Arc<Vec<Arc<RateLimiter>>>,
    quotas: Arc<Vec<Arc<QuotaLimiter>>>,
}

impl BandwidthThrottle {
    pub fn with_context(
        context: RateLimitContext,
        limiters: Vec<Arc<RateLimiter>>,
        quotas: Vec<Arc<QuotaLimiter>>,
    ) -> Option<Self> {
        if limiters.is_empty() && quotas.is_empty() {
            return None;
        }
        Some(Self {
            context,
            limiters: Arc::new(limiters),
            quotas: Arc::new(quotas),
        })
    }

    pub(crate) fn reserve_delay(&self, bytes: usize) -> std::io::Result<Duration> {
        for quota in self.quotas.iter() {
            if !quota.try_take_bytes_with_context(&self.context, bytes as u64) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "bandwidth quota exceeded",
                ));
            }
        }
        let mut delay = Duration::ZERO;
        for limiter in self.limiters.iter() {
            delay = delay.max(limiter.reserve_delay_with_context(&self.context, bytes as u64));
        }
        Ok(delay)
    }
}
