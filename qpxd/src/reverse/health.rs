use anyhow::Result;
use qpx_core::config::HealthCheckConfig;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::time::Duration;

#[derive(Debug, Clone)]
pub(super) struct HealthCheckRuntime {
    pub(super) interval: Duration,
    pub(super) timeout: Duration,
    pub(super) fail_threshold: u32,
    pub(super) cooldown: Duration,
}

impl HealthCheckRuntime {
    pub(super) fn from_config(config: Option<&HealthCheckConfig>) -> Self {
        if let Some(cfg) = config {
            return Self {
                interval: Duration::from_millis(cfg.interval_ms),
                timeout: Duration::from_millis(cfg.timeout_ms),
                fail_threshold: cfg.fail_threshold.max(1),
                cooldown: Duration::from_millis(cfg.cooldown_ms),
            };
        }
        Self {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(1),
            fail_threshold: 3,
            cooldown: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub(super) struct UpstreamEndpoint {
    pub(super) target: String,
    failures: AtomicU32,
    unhealthy_until_ms: AtomicU64,
    pub(super) inflight: AtomicUsize,
}

impl UpstreamEndpoint {
    pub(super) fn new(target: String) -> Self {
        Self {
            target,
            failures: AtomicU32::new(0),
            unhealthy_until_ms: AtomicU64::new(0),
            inflight: AtomicUsize::new(0),
        }
    }

    pub(super) fn is_healthy(&self, now_ms: u64) -> bool {
        self.unhealthy_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    pub(super) fn mark_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.unhealthy_until_ms.store(0, Ordering::Relaxed);
    }

    pub(super) fn mark_failure(&self, policy: &HealthCheckRuntime) {
        let fails = self
            .failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if fails >= policy.fail_threshold {
            let until = now_millis().saturating_add(policy.cooldown.as_millis() as u64);
            self.unhealthy_until_ms.store(until, Ordering::Relaxed);
        }
    }
}

pub(super) async fn probe_upstream(raw: &str) -> Result<()> {
    let default_port = if raw.starts_with("http://") { 80 } else { 443 };
    let addr = crate::upstream::origin::parse_upstream_addr(raw, default_port)?;
    let _ = TcpStream::connect(addr).await?;
    Ok(())
}

pub(super) fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as u64
}
