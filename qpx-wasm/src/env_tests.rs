//! Inspect actual Preview 1 environ_get output, including duplicate keys.
use super::tests::{temp_file, test_config};
use super::*;

// Write the guest's entire NUL-separated environment byte buffer to stdout.
const ENV_GUEST: &[u8] = br#"(module
    (import "wasi_snapshot_preview1" "environ_sizes_get"
        (func $sizes (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "environ_get"
        (func $env (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write"
        (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 2)
    (func (export "_start")
        (drop (call $sizes (i32.const 0) (i32.const 4)))
        (drop (call $env (i32.const 32) (i32.const 8192)))
        (i32.store (i32.const 8) (i32.const 8192))
        (i32.store (i32.const 12) (i32.load (i32.const 4)))
        (drop (call $write (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 16)))))"#;

fn request(length: usize, http_headers: RequestHeaders) -> WasmRequest {
    WasmRequest {
        script_name: "/app".into(),
        path_info: "/path".into(),
        query_string: "q=1".into(),
        request_method: "POST".into(),
        content_type: "text/plain".into(),
        content_length: length,
        server_protocol: "HTTP/1.1".into(),
        server_name: "localhost".into(),
        server_port: 80,
        remote_addr: Some("127.0.0.1".into()),
        remote_port: Some(1234),
        http_headers,
        identity_env: HashMap::new(),
    }
}

async fn visible_env(executor: &WasmExecutor, req: WasmRequest) -> Vec<(String, String)> {
    let mut execution = executor.start(req).await.unwrap();
    drop(execution.stdin);
    let mut out = Vec::new();
    while let Some(chunk) = execution.stdout.recv().await {
        out.extend_from_slice(&chunk);
    }
    execution.done.await.unwrap().unwrap();
    std::str::from_utf8(&out)
        .unwrap()
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let (k, v) = s.split_once('=').unwrap();
            (k.to_owned(), v.to_owned())
        })
        .collect()
}

fn values<'a>(env: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    env.iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .collect()
}

#[tokio::test]
async fn wasi_visible_filtering_duplicates_uncapped_fields_and_lengths() {
    let module = temp_file("environ.wat", ENV_GUEST);
    let mut config = test_config(module.clone(), true);
    config.max_stdout_bytes = 64 * 1024;
    let executor = WasmExecutor::new(config).unwrap();
    for length in [None, Some(0), Some(5)] {
        let mut pairs: Vec<(String, String)> = [
            ("X-Dup", "first"),
            ("x-dup", "second"),
            ("Cookie", "a=1"),
            ("COOKIE", "b=2"),
            ("Content-Length", "99"),
            ("Content-Type", "wire-type"),
            ("Connection", "X-Secret"),
            ("CONNECTION", "x-other"),
            ("X-Secret", "hidden"),
            ("X-Other", "hidden"),
            ("Keep-Alive", "hidden"),
            ("Proxy", "hidden"),
            ("Proxy-Connection", "hidden"),
            ("Proxy-Authenticate", "hidden"),
            ("Proxy-Authorization", "hidden"),
            ("Proxy-Authentication-Info", "hidden"),
            ("TE", "hidden"),
            ("Trailer", "hidden"),
            ("Trailers", "hidden"),
            ("Transfer-Encoding", "hidden"),
            ("Upgrade", "hidden"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        pairs.extend((0..120).map(|n| (format!("x-field-{n}"), n.to_string())));
        // Match the qpxf adapter: absent and explicit zero both map to Wasm length 0.
        let req = request(length.unwrap_or(0), RequestHeaders::from_http_pairs(pairs));
        let env = visible_env(&executor, req).await;
        assert_eq!(values(&env, "HTTP_X_DUP"), ["first, second"]);
        assert_eq!(values(&env, "HTTP_COOKIE"), ["a=1; b=2"]);
        assert_eq!(values(&env, "HTTP_CONTENT_LENGTH"), ["99"]);
        assert_eq!(values(&env, "HTTP_CONTENT_TYPE"), ["wire-type"]);
        assert_eq!(values(&env, "CONTENT_TYPE"), ["text/plain"]);
        let expected = length.filter(|n| *n > 0).map(|n| n.to_string());
        assert_eq!(
            values(&env, "CONTENT_LENGTH"),
            expected.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(
            env.iter().filter(|(k, _)| k.starts_with("HTTP_")).count(),
            124
        );
        for n in 0..120 {
            assert_eq!(values(&env, &format!("HTTP_X_FIELD_{n}")), [n.to_string()]);
        }
    }
    drop(executor);
    std::fs::remove_dir_all(module.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn wasi_visible_collisions_and_extra_env_precedence_remain_ordered() {
    let module = temp_file("collision-environ.wat", ENV_GUEST);
    let mut config = test_config(module.clone(), true);
    config.max_stdout_bytes = 64 * 1024;
    config.env = HashMap::from([
        ("REQUEST_METHOD".into(), "forbidden-method".into()),
        ("HTTP_X_A".into(), "forbidden-header".into()),
        ("CONTENT_LENGTH".into(), "forbidden-length".into()),
        ("CONTENT_TYPE".into(), "forbidden-type".into()),
        ("REMOTE_USER".into(), "forbidden-user".into()),
        ("APP_ENV".into(), "extra".into()),
    ]);
    let executor = WasmExecutor::new(config).unwrap();
    let fields: HashMap<String, String> = HashMap::from([
        ("x-a".into(), "dash".into()),
        ("x_a".into(), "underscore".into()),
    ]);
    let mut expected_collision = vec!["identity-header".to_owned()];
    expected_collision.extend(fields.values().cloned());
    let mut req = request(5, RequestHeaders::from_http_fields(fields));
    req.identity_env = HashMap::from([
        ("HTTP_X_A".into(), "identity-header".into()),
        ("CONTENT_LENGTH".into(), "identity-length".into()),
        ("CONTENT_TYPE".into(), "identity-type".into()),
        ("REQUEST_METHOD".into(), "identity-method".into()),
        ("REMOTE_USER".into(), "verified-user".into()),
        ("APP_ENV".into(), "identity-app".into()),
    ]);
    let env = visible_env(&executor, req).await;
    assert_eq!(values(&env, "HTTP_X_A"), expected_collision);
    assert_eq!(values(&env, "CONTENT_LENGTH"), ["5", "identity-length"]);
    assert_eq!(
        values(&env, "CONTENT_TYPE"),
        ["text/plain", "identity-type"]
    );
    assert_eq!(values(&env, "REQUEST_METHOD"), ["POST", "identity-method"]);
    assert_eq!(values(&env, "REMOTE_USER"), ["verified-user"]);
    assert_eq!(values(&env, "APP_ENV"), ["identity-app", "extra"]);
    drop(executor);
    std::fs::remove_dir_all(module.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn wasi_visible_connection_filter_handles_mixed_case_field_names() {
    let module = temp_file("mixed-case-connection.wat", ENV_GUEST);
    let executor = WasmExecutor::new(test_config(module.clone(), true)).unwrap();
    let fields = HashMap::from([
        ("Connection".into(), "X-Secret".into()),
        ("connection".into(), "X-Other".into()),
        ("X-Secret".into(), "hidden".into()),
        ("x-other".into(), "hidden".into()),
        ("X-Visible".into(), "visible".into()),
    ]);
    let env = visible_env(
        &executor,
        request(0, RequestHeaders::from_http_fields(fields)),
    )
    .await;
    assert!(values(&env, "HTTP_X_SECRET").is_empty());
    assert!(values(&env, "HTTP_X_OTHER").is_empty());
    assert_eq!(values(&env, "HTTP_X_VISIBLE"), ["visible"]);
    drop(executor);
    std::fs::remove_dir_all(module.parent().unwrap()).unwrap();
}

#[test]
fn wasm_request_debug_does_not_reveal_header_fields() {
    let req = request(
        0,
        RequestHeaders::from_http_pairs(vec![(
            "private-field-marker".into(),
            "private-value-marker".into(),
        )]),
    );
    let debug = format!("{req:?}");
    assert!(!debug.contains("private-field-marker"));
    assert!(!debug.contains("private-value-marker"));
}
