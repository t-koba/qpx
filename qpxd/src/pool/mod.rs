//! Orthogonal, reusable connection-pool building blocks.
//!
//! These primitives are deliberately small and composable rather than a single
//! `Pool<T>` trait: pooled connections have fundamentally different lifecycles
//! (HTTP/1 exclusive checkout vs HTTP/2 / HTTP/3 multiplexed sharing), so each
//! pool keeps its connection-specific logic and only shares the cross-cutting
//! coordination concerns implemented here.

#[cfg(feature = "http3")]
mod evict;
mod registry;
#[cfg(feature = "http3")]
mod single_flight;

#[cfg(feature = "http3")]
pub(crate) use evict::evict_oldest_if_full;
pub(crate) use registry::{PoolLimits, PoolRegistry};
#[cfg(feature = "http3")]
pub(crate) use single_flight::{FlightRole, SingleFlight};
