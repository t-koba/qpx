use super::*;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, path::PathBuf};

fn unique_tmp_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut dir = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.push(format!(
        "qpx-config-test-{}-{}-{}",
        std::process::id(),
        nanos,
        seq
    ));
    dir
}

fn write_config(path: &PathBuf, input: &str) -> std::io::Result<()> {
    fs::write(path, input)
}

mod capture_tests;
mod http_module_tests;
mod load_merge_tests;
mod observability_tests;
mod reverse_tests;
mod runtime_resolution_tests;
mod schema_tests;
mod streaming_limits_tests;
mod validation_tests;
