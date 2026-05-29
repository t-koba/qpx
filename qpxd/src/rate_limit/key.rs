// Extracted from rate_limit.rs; public surface is re-exported by mod.rs.
use crate::policy_context::ResolvedIdentity;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

pub(super) const DEFAULT_MAX_ENTRIES: usize = 65_536;
pub(super) const DEFAULT_ENTRY_TTL: Duration = Duration::from_secs(600);
pub(super) const SRC_IP_SHARDS: usize = 64;
const MISSING_USER: &str = "__missing_user__";
const MISSING_GROUP: &str = "__missing_group__";
const MISSING_TENANT: &str = "__missing_tenant__";
const MISSING_DEVICE: &str = "__missing_device__";
const MISSING_ROUTE: &str = "__missing_route__";
const MISSING_UPSTREAM: &str = "__missing_upstream__";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyKind {
    Global,
    SrcIp,
    User,
    Group,
    Tenant,
    Device,
    Route,
    Upstream,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum LimiterKey {
    Global,
    Ip(IpAddr),
    Text(Arc<str>),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RateLimitContext {
    pub(crate) src_ip: Option<IpAddr>,
    pub(crate) user: Option<String>,
    pub(crate) groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) groups_key: Option<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) tenant: Option<String>,
    pub(crate) route: Option<String>,
    pub(crate) upstream: Option<String>,
}

impl RateLimitContext {
    pub(crate) fn from_identity(
        src_ip: IpAddr,
        identity: &ResolvedIdentity,
        route: Option<&str>,
        upstream: Option<&str>,
    ) -> Self {
        Self {
            src_ip: Some(src_ip),
            user: identity.user.clone(),
            groups: identity.groups.clone(),
            groups_key: normalized_groups_key(identity.groups.as_slice()),
            device_id: identity.device_id.clone(),
            tenant: identity.tenant.clone(),
            route: route.map(str::to_string),
            upstream: upstream.map(str::to_string),
        }
    }
}

pub(super) fn max_entries_for_key_kind(key_kind: KeyKind) -> usize {
    match key_kind {
        KeyKind::Global => 1,
        _ => DEFAULT_MAX_ENTRIES,
    }
}

pub(super) fn shard_count_for_key_kind(key_kind: KeyKind) -> usize {
    match key_kind {
        KeyKind::Global => 1,
        _ => SRC_IP_SHARDS,
    }
    .max(1)
}

pub(super) fn make_limiter_key(key_kind: KeyKind, ctx: &RateLimitContext) -> LimiterKey {
    match key_kind {
        KeyKind::Global => LimiterKey::Global,
        KeyKind::SrcIp => LimiterKey::Ip(ctx.src_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
        KeyKind::User => LimiterKey::Text(text_key(ctx.user.as_deref(), MISSING_USER)),
        KeyKind::Group => {
            let normalized;
            let groups = if let Some(groups) = ctx.groups_key.as_deref() {
                Some(groups)
            } else {
                normalized = normalized_groups_key(ctx.groups.as_slice());
                normalized.as_deref()
            };
            LimiterKey::Text(text_key(groups, MISSING_GROUP))
        }
        KeyKind::Tenant => LimiterKey::Text(text_key(ctx.tenant.as_deref(), MISSING_TENANT)),
        KeyKind::Device => LimiterKey::Text(text_key(ctx.device_id.as_deref(), MISSING_DEVICE)),
        KeyKind::Route => LimiterKey::Text(text_key(ctx.route.as_deref(), MISSING_ROUTE)),
        KeyKind::Upstream => LimiterKey::Text(text_key(ctx.upstream.as_deref(), MISSING_UPSTREAM)),
    }
}

pub(super) fn shard_for_key(key: &LimiterKey, shard_mask: usize) -> usize {
    if shard_mask == 0 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) & shard_mask
}

pub(super) fn normalized_groups_key(groups: &[String]) -> Option<String> {
    if groups.is_empty() {
        return None;
    }
    let mut groups = groups
        .iter()
        .map(|group| group.trim())
        .filter(|group| !group.is_empty())
        .collect::<Vec<_>>();
    if groups.is_empty() {
        return None;
    }
    groups.sort_unstable();
    groups.dedup();
    Some(groups.join(","))
}

pub(super) fn text_key(value: Option<&str>, missing: &str) -> Arc<str> {
    Arc::<str>::from(
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(missing),
    )
}
