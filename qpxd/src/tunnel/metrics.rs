use super::relay::{TunnelCloseReason, TunnelPolicy, TunnelStats};
use metrics::{Histogram, counter, gauge, histogram};

#[derive(Clone)]
pub(super) struct TunnelMetricHandles {
    backpressure_tunnel_client_to_server: Histogram,
    backpressure_tunnel_server_to_client: Histogram,
    backpressure_stream_client_to_server: Histogram,
    backpressure_stream_server_to_client: Histogram,
}

impl TunnelMetricHandles {
    pub(super) fn new(transport: &'static str, listener: &str) -> Self {
        Self {
            backpressure_tunnel_client_to_server: backpressure(
                transport,
                listener,
                "qpx_tunnel_backpressure_seconds_total",
                "client_to_server",
            ),
            backpressure_tunnel_server_to_client: backpressure(
                transport,
                listener,
                "qpx_tunnel_backpressure_seconds_total",
                "server_to_client",
            ),
            backpressure_stream_client_to_server: backpressure(
                transport,
                listener,
                "qpx_stream_backpressure_seconds_total",
                "client_to_server",
            ),
            backpressure_stream_server_to_client: backpressure(
                transport,
                listener,
                "qpx_stream_backpressure_seconds_total",
                "server_to_client",
            ),
        }
    }

    pub(super) fn record_backpressure(&self, client_to_server: bool, seconds: f64) {
        if client_to_server {
            self.backpressure_tunnel_client_to_server.record(seconds);
            self.backpressure_stream_client_to_server.record(seconds);
        } else {
            self.backpressure_tunnel_server_to_client.record(seconds);
            self.backpressure_stream_server_to_client.record(seconds);
        }
    }
}

pub(super) fn emit_tunnel_metrics(policy: &TunnelPolicy, stats: &TunnelStats) {
    let reason = stats.close_reason.as_label();
    bytes(policy, "client_to_server", stats.bytes_client_to_server);
    bytes(policy, "server_to_client", stats.bytes_server_to_client);
    histogram!("qpx_tunnel_duration_seconds", "protocol" => policy.transport, "transport" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown", "close_reason" => reason).record(stats.duration.as_secs_f64());
    histogram!("qpx_stream_duration_seconds", "protocol" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown").record(stats.duration.as_secs_f64());
    counter!("qpx_tunnel_close_total", "protocol" => policy.transport, "transport" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown", "close_reason" => reason).increment(1);
    let reset = matches!(
        stats.close_reason,
        TunnelCloseReason::IdleTimeout | TunnelCloseReason::ByteLimitExceeded
    ) as u64;
    counter!("qpx_tunnel_resets_total", "protocol" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown", "reason" => reason).increment(reset);
    counter!("qpx_stream_resets_total", "protocol" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown", "reason" => reason).increment(reset);
    if matches!(stats.close_reason, TunnelCloseReason::IdleTimeout) {
        counter!("qpx_tunnel_idle_timeouts_total", "protocol" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown").increment(1);
        counter!("qpx_stream_idle_timeouts_total", "protocol" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown").increment(1);
        counter!("qpx_tunnel_low_speed_timeouts_total", "protocol" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown").increment(1);
    }
}

pub(super) fn emit_tunnel_active(policy: &TunnelPolicy, delta: f64) {
    gauge!("qpx_tunnel_active", "protocol" => policy.transport, "transport" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown").increment(delta);
    gauge!("qpx_streams_active", "protocol" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown", "direction" => "bidirectional").increment(delta);
}

fn backpressure(
    transport: &'static str,
    listener: &str,
    metric: &'static str,
    direction: &'static str,
) -> Histogram {
    histogram!(metric, "protocol" => transport, "listener" => listener.to_string(), "route" => "unknown", "direction" => direction)
}

fn bytes(policy: &TunnelPolicy, direction: &'static str, bytes: u64) {
    counter!("qpx_tunnel_bytes_total", "direction" => direction, "protocol" => policy.transport, "transport" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown").increment(bytes);
    counter!("qpx_stream_bytes_total", "direction" => direction, "protocol" => policy.transport, "listener" => policy.listener.to_string(), "route" => "unknown").increment(bytes);
}
