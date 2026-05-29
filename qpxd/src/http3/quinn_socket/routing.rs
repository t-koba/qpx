mod parse;
mod shared;
mod state;

pub(crate) use parse::is_quic_long_header;
pub(super) use shared::SharedRouteState;
#[cfg(test)]
pub(crate) use state::RouteState;

use std::time::Duration;

pub(super) const ROUTE_STATE_MAX_ADDRS: usize = 4096;
pub(super) const ROUTE_STATE_MAX_CIDS: usize = 8192;
const ROUTE_STATE_TTL: Duration = Duration::from_secs(600);
const ROUTE_STATE_QUEUE_COMPACTION_FACTOR: usize = 2;
const ROUTE_STATE_SHARDS: usize = 32;
