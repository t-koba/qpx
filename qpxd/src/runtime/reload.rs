use anyhow::{anyhow, Result};
use qpx_core::config::{Config, ListenerConfig, ReverseConfig, RuntimeConfig, XdpConfig};

pub fn ensure_hot_reload_compatible(old: &Config, new: &Config) -> Result<()> {
    if old.state_dir != new.state_dir {
        return Err(anyhow!("state_dir changed; restart required"));
    }
    if old.system_log != new.system_log {
        return Err(anyhow!("system_log changed; restart required"));
    }
    if old.access_log != new.access_log {
        return Err(anyhow!("access_log changed; restart required"));
    }
    if old.audit_log != new.audit_log {
        return Err(anyhow!("audit_log changed; restart required"));
    }
    if old.acme != new.acme {
        return Err(anyhow!("acme changed; restart required"));
    }
    if old.otel != new.otel {
        return Err(anyhow!("otel changed; restart required"));
    }
    if old.metrics != new.metrics {
        return Err(anyhow!("metrics listener config changed; restart required"));
    }
    if old.identity.metrics_prefix != new.identity.metrics_prefix {
        return Err(anyhow!("identity.metrics_prefix changed; restart required"));
    }
    if runtime_process_signature(&old.runtime) != runtime_process_signature(&new.runtime) {
        return Err(anyhow!("runtime startup tuning changed; restart required"));
    }

    Ok(())
}

pub fn requires_server_restart(old: &Config, new: &Config) -> bool {
    if runtime_server_signature(&old.runtime) != runtime_server_signature(&new.runtime) {
        return true;
    }

    if old.listeners.len() != new.listeners.len() {
        return true;
    }
    for (old_listener, new_listener) in old.listeners.iter().zip(new.listeners.iter()) {
        if old_listener.name != new_listener.name
            || old_listener.listen != new_listener.listen
            || listener_mode_tag(old_listener) != listener_mode_tag(new_listener)
            || listener_http3_signature(old_listener) != listener_http3_signature(new_listener)
            || listener_xdp_signature(old_listener) != listener_xdp_signature(new_listener)
        {
            return true;
        }
    }

    if old.reverse.len() != new.reverse.len() {
        return true;
    }
    for (old_reverse, new_reverse) in old.reverse.iter().zip(new.reverse.iter()) {
        if old_reverse.name != new_reverse.name || old_reverse.listen != new_reverse.listen {
            return true;
        }
        if reverse_startup_signature(old_reverse) != reverse_startup_signature(new_reverse) {
            return true;
        }
    }

    false
}

fn runtime_process_signature(runtime: &RuntimeConfig) -> (Option<usize>, Option<usize>) {
    (runtime.worker_threads, runtime.max_blocking_threads)
}

fn runtime_server_signature(runtime: &RuntimeConfig) -> (Option<usize>, bool, i32) {
    (
        runtime.acceptor_tasks_per_listener,
        runtime.reuse_port,
        runtime.tcp_backlog,
    )
}

fn listener_mode_tag(listener: &ListenerConfig) -> &'static str {
    match listener.mode {
        qpx_core::config::ListenerMode::Forward => "forward",
        qpx_core::config::ListenerMode::Transparent => "transparent",
    }
}

type XdpSignature = (bool, String, bool, Vec<String>);
type ReverseHttp3Signature = (String, Vec<String>, usize, u64, u64, usize, u32);
type ReverseStartupSignature = (
    bool,
    XdpSignature,
    Option<ReverseHttp3Signature>,
    Option<qpx_core::config::ReverseTlsConfig>,
);

fn listener_http3_signature(
    listener: &ListenerConfig,
) -> (
    bool,
    Option<String>,
    Option<qpx_core::config::ConnectUdpConfig>,
) {
    match listener.http3.as_ref() {
        Some(cfg) => (cfg.enabled, cfg.listen.clone(), cfg.connect_udp.clone()),
        None => (false, None, None),
    }
}

fn listener_xdp_signature(listener: &ListenerConfig) -> XdpSignature {
    xdp_signature(listener.xdp.as_ref())
}

fn reverse_startup_signature(reverse: &ReverseConfig) -> ReverseStartupSignature {
    let tls_enabled = reverse.tls.is_some();
    let xdp = xdp_signature(reverse.xdp.as_ref());
    let http3 = reverse_http3_signature(reverse);
    let h3_terminate_uses_tls = http3
        .as_ref()
        .map(|(_, passthrough_upstreams, ..)| passthrough_upstreams.is_empty())
        .unwrap_or(false);
    let h3_tls = if h3_terminate_uses_tls {
        reverse.tls.clone()
    } else {
        None
    };
    (tls_enabled, xdp, http3, h3_tls)
}

fn reverse_http3_signature(reverse: &ReverseConfig) -> Option<ReverseHttp3Signature> {
    let cfg = reverse.http3.as_ref()?;
    if !cfg.enabled {
        return None;
    }
    let listen = cfg.listen.clone().unwrap_or_else(|| reverse.listen.clone());
    Some((
        listen,
        cfg.passthrough_upstreams.clone(),
        cfg.passthrough_max_sessions,
        cfg.passthrough_idle_timeout_secs,
        cfg.passthrough_max_new_sessions_per_sec,
        cfg.passthrough_min_client_bytes,
        cfg.passthrough_max_amplification,
    ))
}

fn xdp_signature(xdp: Option<&XdpConfig>) -> XdpSignature {
    match xdp {
        Some(xdp) => (
            xdp.enabled,
            xdp.metadata_mode.clone(),
            xdp.require_metadata,
            xdp.trusted_peers.clone(),
        ),
        None => (false, String::new(), false, Vec::new()),
    }
}
