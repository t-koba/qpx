//! Regression tests for the shared spool guard's cleanup-failure reporting.
//!
//! The guard removes its spool file when it is released. A removal that fails
//! is reported through `qpx_body_spool_cleanup_errors_total`, labelled with the
//! reason of the site that owns the spool, so a spool that cannot be removed is
//! visible instead of silent. These tests pin that reporting in both
//! directions: a failed removal is counted with the site's reason, and a
//! successful removal is not counted at all.

use super::SpoolFile;
use metrics::{
    Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The counter the guard reports a failed removal through.
const CLEANUP_ERROR_COUNTER: &str = "qpx_body_spool_cleanup_errors_total";

/// The reason of the site under test, so a report under a wrong or shared
/// label is caught.
const REASON: &str = "spool_cleanup_test";

/// The identity of a counter: its name and its labels.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CounterKey {
    name: String,
    labels: Vec<(String, String)>,
}

impl CounterKey {
    fn label(&self, key: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

/// A recorder that keeps the counters it is handed, so a test can observe them.
///
/// The local recorder is thread-local, so a test observes only the counters
/// that its own thread recorded.
#[derive(Clone, Default)]
struct RecordingRecorder {
    counters: Arc<Mutex<BTreeMap<CounterKey, u64>>>,
}

impl RecordingRecorder {
    /// The counters recorded under `name`.
    fn counters_named(&self, name: &str) -> Vec<(CounterKey, u64)> {
        let counters = self
            .counters
            .lock()
            .expect("the recorder lock is not poisoned");
        counters
            .iter()
            .filter(|(key, _)| key.name == name)
            .map(|(key, value)| (key.clone(), *value))
            .collect()
    }
}

/// The counter handle the recorder hands out, which records its increments.
struct RecordingCounter {
    key: CounterKey,
    counters: Arc<Mutex<BTreeMap<CounterKey, u64>>>,
}

impl CounterFn for RecordingCounter {
    fn increment(&self, value: u64) {
        let mut counters = self
            .counters
            .lock()
            .expect("the recorder lock is not poisoned");
        *counters.entry(self.key.clone()).or_insert(0) += value;
    }

    fn absolute(&self, value: u64) {
        let mut counters = self
            .counters
            .lock()
            .expect("the recorder lock is not poisoned");
        counters.insert(self.key.clone(), value);
    }
}

impl Recorder for RecordingRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let counter_key = CounterKey {
            name: key.name().to_owned(),
            labels: key
                .labels()
                .map(|label| (label.key().to_owned(), label.value().to_owned()))
                .collect(),
        };
        Counter::from_arc(Arc::new(RecordingCounter {
            key: counter_key,
            counters: Arc::clone(&self.counters),
        }))
    }

    fn register_gauge(&self, _key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }

    fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

/// A temporary directory that is removed when it is released.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            label
        );
        let path = std::env::temp_dir().join(format!("qpx-http-spool-{unique}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the temporary directory");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A spool path whose removal fails on every platform.
///
/// `remove_file` on a path that is a non-empty directory fails with `EISDIR`
/// on Unix and with an access-denied error on Windows. The failure is a real
/// error and never "not found", which the guard deliberately ignores.
fn undeletable_spool_path(directory: &Path) -> PathBuf {
    let path = directory.join("spool.bin");
    std::fs::create_dir(&path).expect("create the spool directory");
    std::fs::write(path.join("occupied"), b"occupied").expect("write the spool payload");
    let probe = std::fs::remove_file(&path).expect_err("removing a directory must fail");
    assert_ne!(
        probe.kind(),
        std::io::ErrorKind::NotFound,
        "the removal must fail for a real reason, not because the path is gone"
    );
    path
}

/// A failed removal is reported with the reason of the site that owns the spool.
#[test]
fn failed_spool_removal_is_reported_with_the_site_reason() {
    let recorder = RecordingRecorder::default();
    let directory = TempDir::new("failure");
    let payload = directory.join("payload");
    std::fs::write(&payload, b"spooled body").expect("write the spool payload");
    let handle = std::fs::File::open(&payload).expect("open the spool payload");
    let path = undeletable_spool_path(&directory.path);

    metrics::with_local_recorder(&recorder, || {
        let guard = SpoolFile::new(handle, path.clone(), REASON);
        assert_eq!(guard.path(), path.as_path());
        drop(guard);
    });

    let reported = recorder.counters_named(CLEANUP_ERROR_COUNTER);
    assert_eq!(
        reported.len(),
        1,
        "exactly one cleanup failure is reported, got {reported:?}"
    );
    let (key, value) = &reported[0];
    assert_eq!(*value, 1, "the cleanup failure is counted once");
    assert_eq!(key.label("reason"), Some(REASON));
}

/// A removal that succeeds is not reported.
#[test]
fn successful_spool_removal_is_not_reported() {
    let recorder = RecordingRecorder::default();
    let directory = TempDir::new("success");
    let path = directory.join("spool.bin");
    std::fs::write(&path, b"spooled body").expect("write the spool file");
    let handle = std::fs::File::open(&path).expect("open the spool file");

    metrics::with_local_recorder(&recorder, || {
        let guard = SpoolFile::new(handle, path.clone(), REASON);
        drop(guard);
    });

    assert!(!path.exists(), "the spool file is removed");
    assert!(
        recorder.counters_named(CLEANUP_ERROR_COUNTER).is_empty(),
        "a removed spool file reports no cleanup failure"
    );
}

/// A spool file that is already gone is not a cleanup failure.
#[test]
fn missing_spool_file_is_not_reported() {
    let recorder = RecordingRecorder::default();
    let directory = TempDir::new("missing");
    let payload = directory.join("payload");
    std::fs::write(&payload, b"spooled body").expect("write the spool payload");
    let handle = std::fs::File::open(&payload).expect("open the spool payload");
    let path = directory.join("spool.bin");

    metrics::with_local_recorder(&recorder, || {
        let guard = SpoolFile::new(handle, path.clone(), REASON);
        drop(guard);
    });

    assert!(
        recorder.counters_named(CLEANUP_ERROR_COUNTER).is_empty(),
        "an already removed spool file reports no cleanup failure"
    );
}
