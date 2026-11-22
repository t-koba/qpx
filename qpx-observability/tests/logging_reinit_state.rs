use qpx_core::config::{AccessLogConfig, AuditLogConfig, SystemLogConfig};
use qpx_observability::{init_logging, request_spans_enabled};

#[test]
fn rejected_logging_reinit_does_not_change_request_span_state() {
    let pretty = SystemLogConfig {
        level: "info".to_string(),
        format: "pretty".to_string(),
    };
    let json = SystemLogConfig {
        level: "info".to_string(),
        format: "json".to_string(),
    };
    let access = AccessLogConfig::default();
    let audit = AuditLogConfig::default();

    let guards = init_logging(&pretty, &access, &audit, None).expect("first init");
    assert!(request_spans_enabled());

    let _error = init_logging(&json, &access, &audit, None).expect_err("subscriber already set");
    assert!(
        request_spans_enabled(),
        "a rejected reinit must not misreport the active subscriber"
    );

    drop(guards);
}
