use std::path::PathBuf;

pub(crate) fn default_handoff_root() -> PathBuf {
    std::env::temp_dir().join("qpx-upgrade")
}
