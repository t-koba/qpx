use anyhow::{Result, anyhow};

use crate::config::types::{RateLimitConfig, RateLimitQuotaConfig};

use super::{Validate, validate_optional};

impl Validate for RateLimitConfig {
    fn validate(&self, context: &str) -> Result<()> {
        validate_rate_limit_fields(self, context)
    }
}

pub(crate) fn validate_rate_limit_config(
    rate: Option<&RateLimitConfig>,
    context: &str,
) -> Result<()> {
    validate_optional(rate, context)
}

fn validate_rate_limit_fields(rate: &RateLimitConfig, context: &str) -> Result<()> {
    let key = rate.key.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err(anyhow!("{context} rate_limit.key must not be empty"));
    }
    if !matches!(
        key.as_str(),
        "global" | "src_ip" | "user" | "group" | "tenant" | "device" | "route" | "upstream"
    ) {
        return Err(anyhow!(
            "{context} rate_limit.key must be one of: global, src_ip, user, group, tenant, device, route, upstream"
        ));
    }

    if rate.apply_to.is_empty() {
        return Err(anyhow!("{context} rate_limit.apply_to must not be empty"));
    }

    if let Some(requests) = rate.requests.as_ref() {
        if matches!(requests.rps, Some(0)) {
            return Err(anyhow!("{context} rate_limit.requests.rps must be >= 1"));
        }
        if matches!(requests.burst, Some(0)) {
            return Err(anyhow!("{context} rate_limit.requests.burst must be >= 1"));
        }
        if requests.burst.is_some() && requests.rps.is_none() {
            return Err(anyhow!(
                "{context} rate_limit.requests.burst requires rate_limit.requests.rps"
            ));
        }
        validate_rate_limit_quota_config(
            requests.quota.as_ref(),
            &format!("{context} rate_limit.requests.quota"),
        )?;
    }

    if let Some(traffic) = rate.traffic.as_ref() {
        if matches!(traffic.bytes_per_sec, Some(0)) {
            return Err(anyhow!(
                "{context} rate_limit.traffic.bytes_per_sec must be >= 1"
            ));
        }
        if matches!(traffic.burst_bytes, Some(0)) {
            return Err(anyhow!(
                "{context} rate_limit.traffic.burst_bytes must be >= 1"
            ));
        }
        if traffic.burst_bytes.is_some() && traffic.bytes_per_sec.is_none() {
            return Err(anyhow!(
                "{context} rate_limit.traffic.burst_bytes requires rate_limit.traffic.bytes_per_sec"
            ));
        }
        validate_rate_limit_quota_config(
            traffic.quota_bytes.as_ref(),
            &format!("{context} rate_limit.traffic.quota_bytes"),
        )?;
    }

    if let Some(sessions) = rate.sessions.as_ref() {
        if matches!(sessions.max_concurrency, Some(0)) {
            return Err(anyhow!(
                "{context} rate_limit.sessions.max_concurrency must be >= 1"
            ));
        }
        validate_rate_limit_quota_config(
            sessions.quota_sessions.as_ref(),
            &format!("{context} rate_limit.sessions.quota_sessions"),
        )?;
    }

    if rate.enabled && rate.requests.is_none() && rate.traffic.is_none() && rate.sessions.is_none()
    {
        return Err(anyhow!(
            "{context} rate_limit.enabled requires at least one of rate_limit.requests, rate_limit.traffic, or rate_limit.sessions"
        ));
    }
    Ok(())
}

fn validate_rate_limit_quota_config(
    quota: Option<&RateLimitQuotaConfig>,
    context: &str,
) -> Result<()> {
    let Some(quota) = quota else {
        return Ok(());
    };
    if quota.interval_secs == 0 {
        return Err(anyhow!("{context}.interval_secs must be >= 1"));
    }
    if matches!(quota.amount, Some(0)) {
        return Err(anyhow!("{context}.amount must be >= 1"));
    }
    if quota.amount.is_none() {
        return Err(anyhow!("{context}.amount must be set"));
    }
    Ok(())
}
