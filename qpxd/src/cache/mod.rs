mod backend_http;
mod backend_redis;
mod directives;
mod freshness;
mod hash;
mod vary;

mod backends;
mod entry;
mod invalidate;
mod key;
mod lookup_ops;
mod store;
mod types;
mod util;

pub use backends::build_backends;
pub use invalidate::{maybe_invalidate, purge_cache_key};
pub use lookup_ops::{
    attach_revalidation_headers, build_only_if_cached_miss_response, lookup,
    maybe_build_stale_if_error_response,
};
pub use store::{maybe_store, revalidate_not_modified, CacheStoreTiming};
pub(crate) use types::{
    begin_request_collapse, try_begin_background_revalidation, RequestCollapseJoin,
};
pub use types::{CacheBackend, CacheRequestKey, LookupOutcome, RevalidationState};

#[cfg(test)]
mod tests;
