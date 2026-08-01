use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError};
use parking_lot::Mutex;
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, LogOutputConfig, OtelConfig, SystemLogConfig,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::time::Duration;
use tracing_subscriber::EnvFilter;

mod security;

use security::{ensure_private_log_dir, reject_symlink_path};

use super::tracing_support::{OtelGuard, build_otel_layer};
use crate::ObservabilityResult;

const DIRECT_ACCESS_BUFFER_BYTES: usize = 64 * 1024;
const DIRECT_ACCESS_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
const DIRECT_ACCESS_BUFFER_SHARDS: usize = 16;
const DIRECT_ACCESS_QUEUE_CHUNKS: usize = 256;
const DIRECT_ACCESS_RECYCLE_CAPACITY: usize = DIRECT_ACCESS_BUFFER_SHARDS;
const DIRECT_ACCESS_BUSY_WRITES_PER_INTERVAL: usize = 4096;
const DIRECT_ACCESS_THREAD_STACK_BYTES: usize = 256 * 1024;
static NEXT_DIRECT_ACCESS_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static DIRECT_ACCESS_SHARD: usize =
        NEXT_DIRECT_ACCESS_SHARD.fetch_add(1, Ordering::Relaxed) % DIRECT_ACCESS_BUFFER_SHARDS;
}

#[derive(Debug)]
struct DirectCombinedAccessWriter {
    sender: Sender<DirectAccessMessage>,
    recycled: Receiver<Vec<u8>>,
    states: Box<[CachePaddedDirectAccessBuffer]>,
    dropped_chunks: AtomicUsize,
}

#[repr(align(128))]
#[derive(Debug)]
struct CachePaddedDirectAccessBuffer(Mutex<DirectCombinedAccessBuffer>);

#[derive(Debug)]
struct DirectCombinedAccessBuffer {
    bytes: Vec<u8>,
    writes: usize,
}

#[derive(Debug)]
enum DirectAccessMessage {
    Data(Vec<u8>),
    Shutdown,
}

impl DirectCombinedAccessWriter {
    fn new<W>(mut sink: W) -> Result<(Arc<Self>, DirectCombinedAccessGuard)>
    where
        W: Write + Send + 'static,
    {
        let (sender, receiver) = crossbeam_channel::bounded(DIRECT_ACCESS_QUEUE_CHUNKS);
        let (recycled_sender, recycled) =
            crossbeam_channel::bounded(DIRECT_ACCESS_RECYCLE_CAPACITY);
        let writer = Arc::new(Self {
            sender,
            recycled,
            states: (0..DIRECT_ACCESS_BUFFER_SHARDS)
                .map(|_| {
                    CachePaddedDirectAccessBuffer(Mutex::new(DirectCombinedAccessBuffer {
                        bytes: Vec::new(),
                        writes: 0,
                    }))
                })
                .collect(),
            dropped_chunks: AtomicUsize::new(0),
        });
        let thread_writer = writer.clone();
        let sink_thread = std::thread::Builder::new()
            .name("qpx-access-writer".to_string())
            .stack_size(DIRECT_ACCESS_THREAD_STACK_BYTES)
            .spawn(move || {
                let mut previous_writes = [0; DIRECT_ACCESS_BUFFER_SHARDS];
                let mut next_flush = std::time::Instant::now() + DIRECT_ACCESS_FLUSH_INTERVAL;
                loop {
                    let wait = next_flush.saturating_duration_since(std::time::Instant::now());
                    match receiver.recv_timeout(wait) {
                        Ok(DirectAccessMessage::Data(mut bytes)) => {
                            if let Err(error) = sink.write_all(&bytes) {
                                eprintln!("access log writer failed: {error}");
                            }
                            bytes.clear();
                            let _ = recycled_sender.try_send(bytes);
                        }
                        Ok(DirectAccessMessage::Shutdown) => {
                            if let Err(error) = sink.flush() {
                                eprintln!("access log flush failed: {error}");
                            }
                            break;
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    let now = std::time::Instant::now();
                    if now >= next_flush {
                        thread_writer.try_flush(&mut previous_writes);
                        next_flush = now + DIRECT_ACCESS_FLUSH_INTERVAL;
                    }
                }
            })
            .context("failed to start direct access-log writer thread")?;
        let guard = DirectCombinedAccessGuard::new(writer.clone(), sink_thread);
        Ok((writer, guard))
    }

    fn write(&self, write_line: impl FnOnce(&mut Vec<u8>)) {
        DIRECT_ACCESS_SHARD.with(|shard| {
            let mut state = self.states[*shard].0.lock();
            write_line(&mut state.bytes);
            state.writes = state.writes.wrapping_add(1);
            if state.bytes.len() >= DIRECT_ACCESS_BUFFER_BYTES {
                self.flush_locked(&mut state);
            }
        });
    }

    fn flush(&self) {
        for state in &self.states {
            let mut state = state.0.lock();
            self.flush_locked(&mut state);
        }
    }

    fn try_flush(&self, previous_writes: &mut [usize; DIRECT_ACCESS_BUFFER_SHARDS]) {
        for (index, state) in self.states.iter().enumerate() {
            if let Some(mut state) = state.0.try_lock() {
                let writes = state.writes;
                let interval_writes = writes.wrapping_sub(previous_writes[index]);
                previous_writes[index] = writes;
                if interval_writes >= DIRECT_ACCESS_BUSY_WRITES_PER_INTERVAL {
                    continue;
                }
                self.flush_locked(&mut state);
            }
        }
    }

    fn flush_locked(&self, state: &mut DirectCombinedAccessBuffer) {
        if state.bytes.is_empty() {
            return;
        }
        let replacement = self
            .recycled
            .try_recv()
            .unwrap_or_else(|_| Vec::with_capacity(DIRECT_ACCESS_BUFFER_BYTES));
        let bytes = std::mem::replace(&mut state.bytes, replacement);
        match self.sender.try_send(DirectAccessMessage::Data(bytes)) {
            Ok(()) => {}
            Err(TrySendError::Full(DirectAccessMessage::Data(mut bytes))) => {
                if self.dropped_chunks.fetch_add(1, Ordering::Relaxed) == 0 {
                    eprintln!("access log queue full; dropping buffered records");
                }
                bytes.clear();
                state.bytes = bytes;
            }
            Err(TrySendError::Disconnected(DirectAccessMessage::Data(mut bytes))) => {
                eprintln!("access log writer channel disconnected");
                bytes.clear();
                state.bytes = bytes;
            }
            Err(TrySendError::Full(DirectAccessMessage::Shutdown))
            | Err(TrySendError::Disconnected(DirectAccessMessage::Shutdown)) => {
                unreachable!("request threads never send shutdown messages")
            }
        }
    }
}

#[derive(Debug)]
struct DirectCombinedAccessGuard {
    writer: Arc<DirectCombinedAccessWriter>,
    sink_thread: Option<std::thread::JoinHandle<()>>,
}

impl DirectCombinedAccessGuard {
    fn new(
        writer: Arc<DirectCombinedAccessWriter>,
        sink_thread: std::thread::JoinHandle<()>,
    ) -> Self {
        Self {
            writer,
            sink_thread: Some(sink_thread),
        }
    }
}

impl Drop for DirectCombinedAccessGuard {
    fn drop(&mut self) {
        self.writer.flush();
        if self
            .writer
            .sender
            .send(DirectAccessMessage::Shutdown)
            .is_err()
        {
            eprintln!("access log writer channel disconnected during shutdown");
        }
        if let Some(thread) = self.sink_thread.take()
            && thread.join().is_err()
        {
            eprintln!("access log writer thread panicked");
        }
    }
}

static DIRECT_COMBINED_ACCESS_WRITER: OnceLock<Arc<DirectCombinedAccessWriter>> = OnceLock::new();

pub(super) fn write_direct_combined_access_log(write_line: impl FnOnce(&mut Vec<u8>)) -> bool {
    let Some(writer) = DIRECT_COMBINED_ACCESS_WRITER.get() else {
        return false;
    };
    writer.write(write_line);
    true
}

pub(super) fn direct_combined_access_log_enabled() -> bool {
    DIRECT_COMBINED_ACCESS_WRITER.get().is_some()
}

/// Guards that keep non-blocking logging workers alive.
#[derive(Debug)]
pub struct LogGuards {
    _direct_access: Option<DirectCombinedAccessGuard>,
    _access: Option<tracing_appender::non_blocking::WorkerGuard>,
    _audit: Option<tracing_appender::non_blocking::WorkerGuard>,
    _otel: Option<OtelGuard>,
}

/// Initializes system, access, audit, and optional OpenTelemetry logging.
pub fn init_logging(
    system: &SystemLogConfig,
    access: &AccessLogConfig,
    audit: &AuditLogConfig,
    otel: Option<&OtelConfig>,
) -> ObservabilityResult<LogGuards> {
    init_logging_inner(system, access, audit, otel).map_err(Into::into)
}

fn init_logging_inner(
    system: &SystemLogConfig,
    access: &AccessLogConfig,
    audit: &AuditLogConfig,
    otel: Option<&OtelConfig>,
) -> Result<LogGuards> {
    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::Directive;
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let mut system_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(system.level.clone()));
    system_filter = system_filter
        .add_directive("access_log=off".parse::<Directive>()?)
        .add_directive("audit_log=off".parse::<Directive>()?);
    super::set_request_spans_enabled(request_spans_are_consumed(
        system.format.as_str(),
        otel.is_some_and(|config| config.enabled),
    ));

    let system_layer = if system.format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_file(false)
            .with_line_number(false)
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .with_filter(system_filter)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_file(false)
            .with_line_number(false)
            .pretty()
            .with_filter(system_filter)
            .boxed()
    };

    let (access_layer, access_guard, direct_access_writer, direct_access_guard) =
        if access.output.enabled && access.output.format.eq_ignore_ascii_case("combined") {
            let (sink, cleanup) = build_log_sink(&access.output, "access_log")?;
            if let Some(cleanup) = cleanup {
                spawn_rotation_cleanup(cleanup);
            }
            let (writer, guard) = DirectCombinedAccessWriter::new(sink)?;
            (None, None, Some(writer), Some(guard))
        } else if access.output.enabled {
            let (writer, guard, cleanup) =
                build_non_blocking_writer(&access.output, "access_log", true)?;
            if let Some(cleanup) = cleanup {
                spawn_rotation_cleanup(cleanup);
            }
            let filter = Targets::new().with_target("access_log", LevelFilter::INFO);
            let layer = if access.output.format.eq_ignore_ascii_case("json") {
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .with_file(false)
                    .with_line_number(false)
                    .with_writer(writer)
                    .json()
                    .with_current_span(false)
                    .with_span_list(false)
                    .with_filter(filter)
                    .boxed()
            } else {
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .with_file(false)
                    .with_line_number(false)
                    .with_writer(writer)
                    .compact()
                    .with_filter(filter)
                    .boxed()
            };
            (Some(layer), Some(guard), None, None)
        } else {
            (None, None, None, None)
        };

    let (audit_layer, audit_guard) = if audit.output.enabled {
        let (writer, guard, cleanup) =
            build_non_blocking_writer(&audit.output, "audit_log", false)?;
        if let Some(cleanup) = cleanup {
            spawn_rotation_cleanup(cleanup);
        }
        let filter = Targets::new().with_target("audit_log", LevelFilter::INFO);
        let layer = if audit.output.format.eq_ignore_ascii_case("json") {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .json()
                .with_current_span(false)
                .with_span_list(false)
                .with_filter(filter)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .compact()
                .with_filter(filter)
                .boxed()
        };
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    let (otel_layer, otel_guard) = match otel {
        Some(cfg) if cfg.enabled => {
            let (layer, guard) = build_otel_layer(cfg)?;
            (Some(layer), Some(guard))
        }
        _ => (None, None),
    };

    let mut combined = vec![system_layer];
    combined.extend(access_layer);
    combined.extend(audit_layer);
    combined.extend(otel_layer);

    tracing_subscriber::registry().with(combined).try_init()?;
    if let Some(writer) = direct_access_writer {
        DIRECT_COMBINED_ACCESS_WRITER
            .set(writer)
            .map_err(|_| anyhow::anyhow!("direct access-log writer was already initialized"))?;
    }

    Ok(LogGuards {
        _direct_access: direct_access_guard,
        _access: access_guard,
        _audit: audit_guard,
        _otel: otel_guard,
    })
}

fn request_spans_are_consumed(system_format: &str, otel_enabled: bool) -> bool {
    !system_format.eq_ignore_ascii_case("json") || otel_enabled
}

fn expand_tilde_path(input: &str) -> PathBuf {
    if let Some(stripped) = input.strip_prefix("~/")
        && let Some(home) = dirs_next::home_dir()
    {
        return home.join(stripped);
    }
    PathBuf::from(input)
}

struct RotationCleanup {
    dir: PathBuf,
    base_name: String,
    rotation: String,
    keep: usize,
}

fn build_log_sink(
    output: &LogOutputConfig,
    label: &'static str,
) -> Result<(Box<dyn Write + Send>, Option<RotationCleanup>)> {
    use tracing_appender::rolling;

    let rotation = output.rotation.trim().to_ascii_lowercase();
    let Some(path) = output.path.as_deref() else {
        return Ok((Box::new(std::io::stdout()), None));
    };
    let path = expand_tilde_path(path.trim());
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    ensure_private_log_dir(&dir)
        .with_context(|| format!("{label}: failed to prepare log directory {}", dir.display()))?;
    reject_symlink_path(&path)
        .with_context(|| format!("{label}: invalid log path {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("{label}: log path must include a valid file name"))?
        .to_string();
    let appender = match rotation.as_str() {
        "hourly" => rolling::hourly(&dir, file_name.as_str()),
        "daily" => rolling::daily(&dir, file_name.as_str()),
        _ => rolling::never(&dir, file_name.as_str()),
    };
    let cleanup = if rotation != "never" {
        Some(RotationCleanup {
            dir,
            base_name: file_name,
            rotation,
            keep: output.rotation_count,
        })
    } else {
        None
    };
    if let Some(cleanup) = cleanup.as_ref() {
        cleanup_old_logs(cleanup);
    }
    Ok((Box::new(appender), cleanup))
}

fn build_non_blocking_writer(
    output: &LogOutputConfig,
    label: &'static str,
    lossy: bool,
) -> Result<(
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
    Option<RotationCleanup>,
)> {
    use tracing_appender::non_blocking::NonBlockingBuilder;
    let (sink, cleanup) = build_log_sink(output, label)?;
    let (writer, guard) = NonBlockingBuilder::default().lossy(lossy).finish(sink);
    Ok((writer, guard, cleanup))
}

fn spawn_rotation_cleanup(cleanup: RotationCleanup) {
    let interval = if cleanup.rotation.eq_ignore_ascii_case("hourly") {
        Duration::from_secs(3600)
    } else {
        Duration::from_secs(86400)
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let cleanup = RotationCleanup {
                    dir: cleanup.dir.clone(),
                    base_name: cleanup.base_name.clone(),
                    rotation: cleanup.rotation.clone(),
                    keep: cleanup.keep,
                };
                let _ = tokio::task::spawn_blocking(move || cleanup_old_logs(&cleanup)).await;
            }
        });
    }
}

fn cleanup_old_logs(cleanup: &RotationCleanup) {
    if cleanup.keep == 0 {
        return;
    }
    let prefix = format!("{}.", cleanup.base_name);
    let mut entries = match std::fs::read_dir(&cleanup.dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
            .filter(|name| name.starts_with(prefix.as_str()))
            .collect::<Vec<_>>(),
        Err(err) => {
            tracing::warn!(
                error = ?err,
                dir = %cleanup.dir.display(),
                "log cleanup failed"
            );
            return;
        }
    };
    if entries.len() <= cleanup.keep {
        return;
    }
    entries.sort();
    let remove_count = entries.len().saturating_sub(cleanup.keep);
    for name in entries.into_iter().take(remove_count) {
        let path = cleanup.dir.join(&name);
        if let Err(err) = std::fs::remove_file(&path) {
            tracing::warn!(
                error = ?err,
                file = %path.display(),
                "failed to remove old log file"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DIRECT_ACCESS_FLUSH_INTERVAL, DirectCombinedAccessWriter, request_spans_are_consumed,
    };
    use std::io::Write as _;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::layer::{Layer as _, SubscriberExt as _};

    #[test]
    fn request_spans_follow_configured_consumers() {
        assert!(!request_spans_are_consumed("json", false));
        assert!(request_spans_are_consumed("json", true));
        assert!(request_spans_are_consumed("pretty", false));
        assert!(request_spans_are_consumed("compact", false));
    }

    #[test]
    fn absent_optional_layers_do_not_enable_filtered_callsites() {
        let system = tracing_subscriber::fmt::layer()
            .with_writer(std::io::sink)
            .with_filter(LevelFilter::WARN);
        let system = system.boxed();
        let active_layers = vec![system];
        let subscriber = tracing_subscriber::registry().with(active_layers);

        tracing::subscriber::with_default(subscriber, || {
            assert!(!tracing::enabled!(
                target: "qpx_optional_layer_filter_test",
                tracing::Level::TRACE
            ));
            assert!(tracing::enabled!(
                target: "qpx_optional_layer_filter_test",
                tracing::Level::WARN
            ));
        });
    }

    #[derive(Clone, Debug)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("shared sink lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn direct_access_writer_delivers_owned_buffers_before_shutdown() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let (writer, guard) =
            DirectCombinedAccessWriter::new(SharedSink(output.clone())).expect("writer");
        assert!(writer.recycled.is_empty());
        assert!(
            writer
                .states
                .iter()
                .all(|state| state.0.lock().bytes.capacity() == 0)
        );
        writer.write(|bytes| bytes.extend_from_slice(b"first\n"));
        writer.write(|bytes| bytes.write_all(b"second\n").expect("buffer write"));
        drop(guard);

        let output = output.lock().expect("shared sink lock");
        assert_eq!(output.as_slice(), b"first\nsecond\n");
    }

    #[test]
    fn direct_access_writer_flushes_partial_buffers_on_interval() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let (writer, guard) =
            DirectCombinedAccessWriter::new(SharedSink(output.clone())).expect("writer");
        writer.write(|bytes| bytes.extend_from_slice(b"periodic\n"));

        let deadline = std::time::Instant::now() + DIRECT_ACCESS_FLUSH_INTERVAL * 4;
        loop {
            if output.lock().expect("shared sink lock").as_slice() == b"periodic\n" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "partial access-log buffer was not flushed on schedule"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        drop(guard);
    }
}
