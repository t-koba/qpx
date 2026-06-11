//! Daemon-local HTTP body helpers. The body core (`Body`, `Sender`,
//! `BodyError`, `to_bytes`, `tee`, `metrics`) lives in the shared `qpx-http`
//! crate and is imported directly from there. The `observation` and `size`
//! submodules stay in `qpxd` because they depend on `http::policy` /
//! `http::rpc`.

pub mod observation;
pub mod size;
