pub mod config;
pub mod envsubst;
pub mod exporter;
#[cfg(feature = "ipc-support")]
pub mod ipc;
pub mod matchers;
pub mod prefilter;
pub mod rules;
#[cfg(feature = "ipc-support")]
pub mod shm_ring;

#[cfg(all(feature = "tls-rustls", feature = "tls-native"))]
compile_error!("qpx-core: features tls-rustls and tls-native are mutually exclusive");

pub mod tls;
pub mod uri_template;
