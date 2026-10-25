//! Public API coverage: custom executors get final environments, never raw fields.
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use qpxf::executor::{CgiRequest, Execution, Executor, RequestHeaders};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

fn request() -> CgiRequest {
    CgiRequest {
        script_name: "/app".into(),
        path_info: "/path".into(),
        query_string: "q=1".into(),
        request_method: "POST".into(),
        content_type: "text/plain".into(),
        content_length: 0,
        declared_content_length: None,
        server_protocol: "HTTP/1.1".into(),
        server_name: "localhost".into(),
        server_port: 80,
        remote_addr: Some("127.0.0.1".into()),
        remote_port: Some(1234),
        http_headers: RequestHeaders::default(),
        matched_prefix: None,
        identity_env: HashMap::new(),
    }
}

fn joined_headers() -> RequestHeaders {
    RequestHeaders::from_http_pairs(
        [
            ("X-Dup", "first"),
            ("x-dup", "second"),
            ("Cookie", "a=1"),
            ("COOKIE", "b=2"),
            ("Content-Length", "99"),
            ("Content-Type", "wrong"),
            ("Connection", "x-secret"),
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
        .collect(),
    )
}

#[test]
fn cgi_and_persistent_join_filter_and_preserve_length_policy() {
    for length in [None, Some(0), Some(5)] {
        let mut req = request();
        req.http_headers = joined_headers();
        req.declared_content_length = length;
        req.content_length = length.unwrap_or(0);
        let cgi = req.cgi_environment().into_variables();
        let persistent = req.persistent_environment(length).into_variables();
        let http: HashMap<_, _> = cgi.iter().filter(|(k, _)| k.starts_with("HTTP_")).collect();
        assert_eq!(http.len(), 2);
        assert_eq!(cgi["HTTP_X_DUP"], "first, second");
        assert_eq!(cgi["HTTP_COOKIE"], "a=1; b=2");
        assert_eq!(cgi["CONTENT_TYPE"], "text/plain");
        assert_eq!(
            cgi.get("CONTENT_LENGTH"),
            length.filter(|n| *n > 0).map(|n| n.to_string()).as_ref()
        );
        let persistent_http: HashMap<_, _> = persistent
            .iter()
            .filter(|(k, _)| k.starts_with("HTTP_"))
            .map(|(k, v)| (k, v))
            .collect();
        assert_eq!(persistent_http, http);
        assert_eq!(
            persistent
                .iter()
                .find(|(k, _)| k == "CONTENT_LENGTH")
                .map(|(_, v)| v),
            length.map(|n| n.to_string()).as_ref()
        );
    }
}

#[test]
fn cgi_and_persistent_keep_distinct_cap_selection_in_original_hash_iteration() {
    let mut fields: HashMap<String, String> = (0..160)
        .map(|n| (format!("x-{n}"), n.to_string()))
        .collect();
    fields.insert(
        "connection".into(),
        (0..40)
            .map(|n| format!("x-{n}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    fields.insert("content-length".into(), "99".into());
    let admitted = |k: &&String| {
        !matches!(k.as_str(), "connection" | "content-length")
            && !k
                .strip_prefix("x-")
                .unwrap()
                .parse::<usize>()
                .is_ok_and(|n| n < 40)
    };
    let project = |(k, v): (&String, &String)| {
        (
            format!("HTTP_{}", k.to_uppercase().replace('-', "_")),
            v.clone(),
        )
    };
    // Compute from this map before moving it; no fixed hash order or selected subset.
    let cgi_expected: HashMap<_, _> = fields
        .iter()
        .filter(|(k, _)| admitted(k))
        .take(100)
        .map(project)
        .collect();
    let persistent_expected: Vec<_> = fields
        .iter()
        .take(100)
        .filter(|(k, _)| admitted(k))
        .map(project)
        .collect();
    let mut req = request();
    req.http_headers = RequestHeaders::from_http_fields(fields);
    let cgi: HashMap<_, _> = req
        .cgi_environment()
        .into_variables()
        .into_iter()
        .filter(|(k, _)| k.starts_with("HTTP_"))
        .collect();
    let persistent: Vec<_> = req
        .persistent_environment(None)
        .into_variables()
        .into_iter()
        .filter(|(k, _)| k.starts_with("HTTP_"))
        .collect();
    assert_eq!(cgi.len(), 100);
    assert_eq!(cgi, cgi_expected);
    assert_eq!(persistent, persistent_expected);
}

#[test]
fn projection_collisions_and_identity_precedence_are_not_unified() {
    let fields = HashMap::from([
        ("x-a".into(), "dash".into()),
        ("x_a".into(), "underscore".into()),
    ]);
    let projected: Vec<_> = fields.values().cloned().collect();
    let mut req = request();
    req.http_headers = RequestHeaders::from_http_fields(fields);
    req.declared_content_length = Some(5);
    req.identity_env = HashMap::from([
        ("HTTP_X_A".into(), "identity-header".into()),
        ("CONTENT_LENGTH".into(), "identity-length".into()),
        ("CONTENT_TYPE".into(), "identity-type".into()),
        ("REQUEST_METHOD".into(), "identity-method".into()),
        ("PATH".into(), "identity-path".into()),
    ]);
    let cgi = req.cgi_environment().into_variables();
    assert_eq!(&cgi["HTTP_X_A"], projected.last().unwrap());
    assert_eq!(cgi["CONTENT_LENGTH"], "5");
    assert_eq!(cgi["CONTENT_TYPE"], "text/plain");
    assert_eq!(cgi["REQUEST_METHOD"], "identity-method");
    assert_eq!(cgi["PATH"], "identity-path");
    let persistent = req.persistent_environment(Some(5)).into_variables();
    let values = |name: &str| {
        persistent
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
    };
    let mut expected = vec!["identity-header"];
    expected.extend(projected.iter().map(String::as_str));
    assert_eq!(values("HTTP_X_A"), expected);
    assert_eq!(values("CONTENT_LENGTH"), ["5", "identity-length"]);
    assert_eq!(values("CONTENT_TYPE"), ["text/plain", "identity-type"]);
    assert_eq!(values("REQUEST_METHOD"), ["POST", "identity-method"]);
}

#[test]
fn mixed_case_connection_fields_filter_nominated_headers() {
    let fields = HashMap::from([
        ("Connection".into(), "X-Secret".into()),
        ("connection".into(), "X-Other".into()),
        ("X-Secret".into(), "hidden".into()),
        ("x-other".into(), "hidden".into()),
        ("X-Visible".into(), "visible".into()),
    ]);
    let mut req = request();
    req.http_headers = RequestHeaders::from_http_fields(fields);

    let cgi = req.cgi_environment().into_variables();
    assert!(!cgi.contains_key("HTTP_X_SECRET"));
    assert!(!cgi.contains_key("HTTP_X_OTHER"));
    assert_eq!(cgi["HTTP_X_VISIBLE"], "visible");

    let persistent = req.persistent_environment(None).into_variables();
    assert!(!persistent.iter().any(|(name, _)| name == "HTTP_X_SECRET"));
    assert!(!persistent.iter().any(|(name, _)| name == "HTTP_X_OTHER"));
    assert!(
        persistent
            .iter()
            .any(|(name, value)| name == "HTTP_X_VISIBLE" && value == "visible")
    );
}

#[test]
fn debug_never_exposes_raw_header_names_or_values() {
    let mut req = request();
    req.http_headers = RequestHeaders::from_http_pairs(vec![(
        "x-private-marker".into(),
        "private-value-marker".into(),
    )]);
    let debug = format!("{req:?}");
    assert!(!debug.contains("x-private-marker"));
    assert!(!debug.contains("private-value-marker"));
}

struct CustomExecutor;
#[async_trait]
impl Executor for CustomExecutor {
    async fn start(&self, req: CgiRequest) -> Result<Execution> {
        // No built-ins-only privilege: this external crate consumes a final artifact.
        let env = req.cgi_environment().into_variables();
        let (stdin, mut input) = mpsc::channel::<Bytes>(1);
        let (output, stdout) = mpsc::channel(1);
        let (_errors, stderr) = mpsc::channel(1);
        let (abort, mut aborted) = oneshot::channel();
        let done = tokio::spawn(async move {
            output
                .send(Bytes::from(format!(
                    "{}|{}|{}",
                    env["HTTP_X_DUP"], env["HTTP_COOKIE"], env["REQUEST_METHOD"]
                )))
                .await?;
            loop {
                tokio::select! {
                    _ = &mut aborted => break,
                    chunk = input.recv() => match chunk {
                        Some(chunk) => output.send(chunk).await?,
                        None => break,
                    }
                }
            }
            Ok(())
        });
        Ok(Execution {
            max_stdout_bytes: 1024,
            stdin,
            stdout,
            stderr,
            abort,
            done,
        })
    }
}

#[tokio::test]
async fn public_custom_executor_consumes_final_environment_and_streams_body() {
    let mut req = request();
    req.http_headers = joined_headers();
    let mut exec = CustomExecutor.start(req).await.unwrap();
    exec.stdin.send(Bytes::from_static(b"body")).await.unwrap();
    drop(exec.stdin);
    assert_eq!(
        exec.stdout.recv().await.unwrap(),
        "first, second|a=1; b=2|POST"
    );
    assert_eq!(exec.stdout.recv().await.unwrap(), "body");
    assert!(exec.stdout.recv().await.is_none());
    exec.done.await.unwrap().unwrap();
}
