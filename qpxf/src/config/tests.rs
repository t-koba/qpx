use super::*;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
#[test]
fn default_listen_uses_private_user_scoped_socket_path() {
    let listen = default_listen();
    assert!(listen.starts_with("unix://"));
    assert!(listen.ends_with("/qpxf.sock"));
    assert!(!listen.contains("unix:///tmp/qpxf.sock"));
}

fn minimal_config(listen: String) -> QpxfConfig {
    QpxfConfig {
        listen,
        workers: 1,
        max_connections: 1,
        max_requests_per_connection: 1,
        allow_insecure_tcp: false,
        max_params_bytes: 1024,
        max_stdin_bytes: 1024,
        input_idle_timeout_ms: 1000,
        conn_idle_timeout_ms: 1000,
        handlers: Vec::new(),
    }
}

#[test]
fn validate_rejects_tcp_without_explicit_opt_in() {
    let err = minimal_config("127.0.0.1:9000".to_string())
        .validate()
        .expect_err("tcp should require explicit opt-in");
    assert!(err.to_string().contains("allow_insecure_tcp=true"));
}

#[cfg(unix)]
#[test]
fn validate_accepts_unix_socket_default() {
    let cfg = minimal_config(default_listen());
    cfg.validate().expect("unix socket should be accepted");
}

#[test]
fn validate_rejects_cgi_zero_timeout_and_byte_limits() {
    fn cgi_config() -> QpxfConfig {
        let mut cfg = minimal_config("unix:///tmp/qpxf-test.sock".to_string());
        cfg.handlers.push(HandlerConfig {
            r#match: MatchConfig {
                path_prefix: Some("/cgi-bin".to_string()),
                path_regex: None,
                host: None,
            },
            backend: BackendConfig::Cgi(CgiBackendConfig {
                root: PathBuf::from("/tmp"),
                timeout_ms: 1000,
                env_passthrough: Vec::new(),
                max_stdout_bytes: 1024,
                max_stderr_bytes: 1024,
            }),
        });
        cfg
    }

    let mut cfg = cgi_config();
    let BackendConfig::Cgi(cgi) = &mut cfg.handlers[0].backend else {
        panic!("expected cgi backend");
    };
    cgi.timeout_ms = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = cgi_config();
    let BackendConfig::Cgi(cgi) = &mut cfg.handlers[0].backend else {
        panic!("expected cgi backend");
    };
    cgi.max_stdout_bytes = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = cgi_config();
    let BackendConfig::Cgi(cgi) = &mut cfg.handlers[0].backend else {
        panic!("expected cgi backend");
    };
    cgi.max_stderr_bytes = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = cgi_config();
    let BackendConfig::Cgi(cgi) = &mut cfg.handlers[0].backend else {
        panic!("expected cgi backend");
    };
    cgi.env_passthrough.push("REQUEST_METHOD".to_string());
    let err = cfg
        .validate()
        .expect_err("reserved CGI variable passthrough should fail");
    assert!(err.to_string().contains("CGI reserved variable"));
}

#[cfg(unix)]
#[test]
fn load_config_expands_env_variables() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("qpxf-config-{unique}.yaml"));
    fs::write(
        &path,
        "listen: \"unix://${QPXF_TEST_RUNTIME_DIR:-/tmp/qpxf-runtime}/qpxf.sock\"\nhandlers: []\n",
    )
    .expect("write config");
    let cfg = load_config(&path).expect("config");
    let _ = fs::remove_file(&path);
    assert_eq!(cfg.listen, "unix:///tmp/qpxf-runtime/qpxf.sock");
}
