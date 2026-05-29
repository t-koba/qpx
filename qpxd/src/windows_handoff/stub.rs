use qpx_core::config::Config;
use std::path::PathBuf;

pub(crate) fn handoff_dir(config: &Config) -> PathBuf {
    config
        .state_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(default_handoff_root)
        .join("upgrade")
}

fn default_handoff_root() -> PathBuf {
    std::env::temp_dir().join("qpx-upgrade")
}
