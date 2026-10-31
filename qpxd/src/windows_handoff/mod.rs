#[cfg(windows)]
mod imp;
#[cfg(not(windows))]
mod unsupported;

#[cfg(windows)]
pub(crate) use imp::*;

#[cfg(windows)]
use self::imp as platform;
#[cfg(not(windows))]
use self::unsupported as platform;

pub(crate) fn handoff_dir(config: &qpx_core::config::Config) -> std::path::PathBuf {
    config
        .state_dir
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(platform::default_handoff_root)
        .join("upgrade")
}
