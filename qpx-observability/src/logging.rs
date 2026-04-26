use anyhow::{anyhow, Context, Result};
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, LogOutputConfig, OtelConfig, SystemLogConfig,
};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::time::Duration;
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;

use super::tracing_support::{build_otel_layer, OtelGuard};

#[derive(Debug)]
pub struct LogGuards {
    _access: Option<tracing_appender::non_blocking::WorkerGuard>,
    _audit: Option<tracing_appender::non_blocking::WorkerGuard>,
    _otel: Option<OtelGuard>,
}

#[derive(Debug, Clone, Copy, Default)]
struct AccessLogCombinedFormat {
    timer: tracing_subscriber::fmt::time::SystemTime,
}

struct AccessLogCombinedFields {
    remote: Option<String>,
    method: Option<String>,
    uri: Option<String>,
    version: Option<String>,
    status: Option<u64>,
    bytes_out: Option<u64>,
    referer: Option<String>,
    user_agent: Option<String>,
    latency_ms: Option<f64>,
}

impl tracing::field::Visit for AccessLogCombinedFields {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if field.name() == "latency_ms" {
            self.latency_ms = Some(value);
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "status" => self.status = Some(value),
            "bytes_out" => self.bytes_out = Some(value),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "referer" => self.referer = Some(value.to_string()),
            "user_agent" => self.user_agent = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "remote" => self.remote = Some(format!("{value:?}")),
            "method" => self.method = Some(format!("{value:?}")),
            "uri" => self.uri = Some(format!("{value:?}")),
            "version" => self.version = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

impl AccessLogCombinedFormat {
    fn write_quoted(
        writer: &mut tracing_subscriber::fmt::format::Writer<'_>,
        value: &str,
    ) -> std::fmt::Result {
        writer.write_char('"')?;
        for ch in value.chars() {
            match ch {
                '\\' => writer.write_str("\\\\")?,
                '"' => writer.write_str("\\\"")?,
                _ => writer.write_char(ch)?,
            }
        }
        writer.write_char('"')
    }
}

impl<S, N> tracing_subscriber::fmt::format::FormatEvent<S, N> for AccessLogCombinedFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> tracing_subscriber::fmt::format::FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut fields = AccessLogCombinedFields {
            remote: None,
            method: None,
            uri: None,
            version: None,
            status: None,
            bytes_out: None,
            referer: None,
            user_agent: None,
            latency_ms: None,
        };
        event.record(&mut fields);

        if let Some(remote) = fields.remote.as_deref() {
            writer.write_str(remote)?;
        } else {
            writer.write_str("-")?;
        }

        writer.write_str(" - - [")?;
        self.timer.format_time(&mut writer)?;
        writer.write_str("] \"")?;

        if let Some(method) = fields.method.as_deref() {
            writer.write_str(method)?;
        } else {
            writer.write_str("-")?;
        }
        writer.write_char(' ')?;
        if let Some(uri) = fields.uri.as_deref() {
            writer.write_str(uri)?;
        } else {
            writer.write_str("-")?;
        }
        writer.write_char(' ')?;
        if let Some(version) = fields.version.as_deref() {
            writer.write_str(version)?;
        } else {
            writer.write_str("-")?;
        }
        writer.write_str("\" ")?;

        write!(writer, "{} ", fields.status.unwrap_or(0))?;
        write!(writer, "{} ", fields.bytes_out.unwrap_or(0))?;

        let referer = fields.referer.as_deref().unwrap_or("");
        let referer = if referer.is_empty() { "-" } else { referer };
        Self::write_quoted(&mut writer, referer)?;
        writer.write_char(' ')?;

        let user_agent = fields.user_agent.as_deref().unwrap_or("");
        let user_agent = if user_agent.is_empty() {
            "-"
        } else {
            user_agent
        };
        Self::write_quoted(&mut writer, user_agent)?;

        if let Some(latency_ms) = fields.latency_ms {
            write!(writer, " latency_ms={latency_ms:.3}")?;
        }

        writer.write_char('\n')
    }
}

pub fn init_logging(
    system: &SystemLogConfig,
    access: &AccessLogConfig,
    audit: &AuditLogConfig,
    otel: Option<&OtelConfig>,
) -> Result<LogGuards> {
    use tracing_subscriber::filter::Directive;
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;

    let mut system_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(system.level.clone()));
    system_filter = system_filter
        .add_directive("access_log=off".parse::<Directive>()?)
        .add_directive("audit_log=off".parse::<Directive>()?);

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

    let (access_layer, access_guard) = if access.output.enabled {
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
        } else if access.output.format.eq_ignore_ascii_case("combined") {
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_file(false)
                .with_line_number(false)
                .with_writer(writer)
                .event_format(AccessLogCombinedFormat::default())
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
        (layer, Some(guard))
    } else {
        (tracing_subscriber::layer::Identity::new().boxed(), None)
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
        (layer, Some(guard))
    } else {
        (tracing_subscriber::layer::Identity::new().boxed(), None)
    };

    let (otel_layer, otel_guard) = match otel {
        Some(cfg) if cfg.enabled => {
            let (layer, guard) = build_otel_layer(cfg)?;
            (layer, Some(guard))
        }
        _ => (tracing_subscriber::layer::Identity::new().boxed(), None),
    };

    let combined = system_layer
        .and_then(access_layer)
        .and_then(audit_layer)
        .and_then(otel_layer)
        .boxed();

    tracing_subscriber::registry().with(combined).try_init()?;

    Ok(LogGuards {
        _access: access_guard,
        _audit: audit_guard,
        _otel: otel_guard,
    })
}

fn expand_tilde_path(input: &str) -> PathBuf {
    if let Some(stripped) = input.strip_prefix("~/") {
        if let Some(home) = dirs_next::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(input)
}

struct RotationCleanup {
    dir: PathBuf,
    base_name: String,
    rotation: String,
    keep: usize,
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
    use tracing_appender::rolling;

    let rotation = output.rotation.trim().to_ascii_lowercase();

    if let Some(path) = output.path.as_deref() {
        let path = expand_tilde_path(path.trim());
        let dir = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        ensure_private_log_dir(&dir).with_context(|| {
            format!("{label}: failed to prepare log directory {}", dir.display())
        })?;
        reject_symlink_path(&path)
            .with_context(|| format!("{label}: invalid log path {}", path.display()))?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("{label}: log path must include a valid file name"))?
            .to_string();

        let appender = match rotation.as_str() {
            "hourly" => rolling::hourly(&dir, file_name.as_str()),
            "daily" => rolling::daily(&dir, file_name.as_str()),
            _ => rolling::never(&dir, file_name.as_str()),
        };
        let (writer, guard) = NonBlockingBuilder::default().lossy(lossy).finish(appender);

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
        return Ok((writer, guard, cleanup));
    }

    let (writer, guard) = NonBlockingBuilder::default()
        .lossy(lossy)
        .finish(std::io::stdout());
    Ok((writer, guard, None))
}

fn ensure_private_log_dir(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(anyhow!(
                        "refusing to use symlinked log path component {}",
                        current.display()
                    ));
                }
                if !meta.is_dir() {
                    return Err(anyhow!(
                        "log path component is not a directory: {}",
                        current.display()
                    ));
                }
                reject_untrusted_log_ancestor(&current, &meta)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                set_private_directory_permissions(&current)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(unix)]
fn reject_untrusted_log_ancestor(path: &Path, meta: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = meta.mode();
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let sticky_bit = u32::from(libc::S_ISVTX);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let sticky_bit = libc::S_ISVTX;
    let sticky = mode & sticky_bit != 0;
    let euid = unsafe { libc::geteuid() };

    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing log ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if sticky && mode & 0o022 != 0 && meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing sticky writable log ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow!(
            "refusing attacker-writable log ancestor directory {}",
            path.display()
        ));
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing group-writable log ancestor directory not owned by current user: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_untrusted_log_ancestor(_path: &Path, _meta: &fs::Metadata) -> Result<()> {
    Ok(())
}

fn reject_symlink_path(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(anyhow!(
                "refusing to write logs through symlink path {}",
                path.display()
            ));
        }
    }
    Ok(())
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
