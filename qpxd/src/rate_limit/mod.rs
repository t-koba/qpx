mod bucket;
mod concurrency;
mod key;
mod plan;
mod quota;

use std::num::NonZeroUsize;

fn nonzero_capacity(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value.max(1)) {
        Some(capacity) => capacity,
        None => unreachable!("usize::max(1) is always non-zero"),
    }
}

pub(crate) use bucket::RateLimiter;
pub(crate) use key::RateLimitContext;
pub(crate) use plan::{
    AppliedRateLimits, CompiledRateLimitPlan, ConcurrencyAcquire, ConcurrencyPermits, RateLimitSet,
    RateLimiters, RequestLimitAcquire, TransportScope, admit_request,
};
pub(crate) use quota::QuotaLimiter;

#[cfg(test)]
mod tests;
