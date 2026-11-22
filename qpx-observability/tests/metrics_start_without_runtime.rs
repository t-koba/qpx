use qpx_core::config::MetricsConfig;
use qpx_observability::{metrics_enabled, start_metrics};

#[test]
fn failed_start_without_runtime_has_no_global_side_effects() {
    let config = MetricsConfig {
        listen: "127.0.0.1:0".to_string(),
        path: "/metrics".to_string(),
        allow: Vec::new(),
        max_concurrent_connections: 1,
    };
    let _error = start_metrics(&config, None).expect_err("no Tokio runtime is active");
    assert!(
        !metrics_enabled(),
        "a failed start must not report metrics as enabled"
    );
}
