use crate::rate_limit::{QuotaLimiter, RateLimitContext, RateLimiter};
use smallvec::SmallVec;
use std::sync::Arc;
use tokio::time::Duration;

#[derive(Clone)]
pub struct BandwidthThrottle {
    context: RateLimitContext,
    limiters: Arc<SmallVec<[Arc<RateLimiter>; 2]>>,
    quotas: Arc<SmallVec<[Arc<QuotaLimiter>; 2]>>,
}

impl BandwidthThrottle {
    pub fn with_context(
        context: RateLimitContext,
        limiters: SmallVec<[Arc<RateLimiter>; 2]>,
        quotas: SmallVec<[Arc<QuotaLimiter>; 2]>,
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
