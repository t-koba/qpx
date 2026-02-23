pub mod auth;
pub mod config;
pub mod envsubst;
pub mod exporter;
pub mod ipc;
pub mod matchers;
pub mod middleware;
pub mod observability;
pub mod prefilter;
pub mod rules;
pub mod shm_ring;

#[cfg(all(feature = "tls-rustls", feature = "tls-native"))]
compile_error!("qpx-core: features tls-rustls and tls-native are mutually exclusive");

pub mod tls;
