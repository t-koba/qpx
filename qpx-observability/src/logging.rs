use anyhow::{Context, Result};
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, LogOutputConfig, OtelConfig, SystemLogConfig,
};
use std::path::{Path, PathBuf};
use tokio::time::Duration;
use tracing_subscriber::EnvFilter;

mod format;
mod security;

use format::AccessLogCombinedFormat;
use security::{ensure_private_log_dir, reject_symlink_path};

use super::tracing_support::{OtelGuard, build_otel_layer};

#[derive(Debug)]
pub struct LogGuards {
    _access: Option<tracing_appender::non_blocking::WorkerGuard>,
    _audit: Option<tracing_appender::non_blocking::WorkerGuard>,
    _otel: Option<OtelGuard>,
}

pub fn init_logging(
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
