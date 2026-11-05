use crate::upstream::pool::ConnectionPool;
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use qpx_core::config::ActionConfig;
use qpx_core::http_message::Response as OwnerResponse;
use qpx_http::body::Body;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Trims only HTTP optional whitespace (SP and HTAB).
pub(crate) fn trim_http_ows(value: &str) -> &str {
    let (start, end) = http_ows_bounds(value.as_bytes());
    &value[start..end]
}

/// Counts the bytes left after trimming HTTP optional whitespace.
#[cfg(test)]
pub(crate) fn trim_http_ows_len(value: &[u8]) -> usize {
    let (start, end) = http_ows_bounds(value);
    end - start
}

fn http_ows_bounds(value: &[u8]) -> (usize, usize) {
    let start = value
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);
    (start, end)
}

pub(crate) fn blocked_response(message: &str) -> qpx_core::http_message::Response<Body> {
    forbidden_response(message)
}

pub(crate) fn forbidden_response(message: &str) -> qpx_core::http_message::Response<Body> {
    let mut response = qpx_core::http_message::Response::new(Body::from(message.to_owned()));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response
}

pub(crate) fn bad_request_response(message: impl Into<String>) -> OwnerResponse<Body> {
    let mut response = OwnerResponse::new(Body::from(message.into()));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

pub(crate) fn connect_established_response() -> OwnerResponse<Body> {
    let mut response = OwnerResponse::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    qpx_http::protocol::semantics::strip_message_body_headers(response.headers_mut());
    response
}

pub(crate) fn too_many_requests_response(retry_after: Option<Duration>) -> OwnerResponse<Body> {
    let mut response = OwnerResponse::new(Body::from("too many requests"));
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    if let Ok(name) = http::header::CONTENT_TYPE.try_into() {
        response.headers_mut().insert(
            name,
            http::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    }
    if let Some(retry_after) = retry_after {
        let secs = retry_after.as_secs().max(1);
        if let (Ok(name), Ok(value)) = (
            http::header::RETRY_AFTER.try_into(),
            http::HeaderValue::from_str(&secs.to_string()),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

pub(crate) fn http_version_label(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2",
        http::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/1.1",
    }
}

pub(crate) fn shared_http_client() -> &'static Client<HttpConnector, Body> {
    static CLIENT: OnceLock<Client<HttpConnector, Body>> = OnceLock::new();
    CLIENT.get_or_init(|| Client::builder(TokioExecutor::new()).build(HttpConnector::new()))
}

pub(crate) async fn request_with_shared_client(
    mut req: http::Request<Body>,
) -> Result<Response<Body>, hyper_util::client::legacy::Error> {
    qpx_core::http_content_length::canonicalize_content_length(req.headers_mut());
    Ok(shared_http_client().request(req).await?.map(Body::from))
}

pub(crate) fn resolve_named_upstream(
    action: &ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener_upstream_proxy: Option<&str>,
) -> Result<Option<crate::upstream::pool::ResolvedUpstreamProxy>> {
    if matches!(action.kind, qpx_core::config::ActionKind::Direct) {
        return Ok(None);
    }

    if let Some(upstream_name) = action.upstream.as_deref().or(listener_upstream_proxy) {
        if upstream_name.contains("://") {
            return Ok(Some(crate::upstream::pool::ResolvedUpstreamProxy::direct(
                upstream_name,
            )?));
        }
        // Keep validation and runtime behavior aligned: bare "host:port" (and "[::1]:port")
        // is treated as a direct upstream proxy endpoint.
        if (upstream_name.contains(':') || upstream_name.starts_with('['))
            && upstream_name.parse::<http::uri::Authority>().is_ok()
        {
            let direct = if upstream_name.contains('@') {
                format!("http://{}", upstream_name)
            } else {
                upstream_name.to_string()
            };
            return Ok(Some(crate::upstream::pool::ResolvedUpstreamProxy::direct(
                direct.as_str(),
            )?));
        }
        if let Some(cluster) = state.resources.upstream_proxies.get(upstream_name) {
            return Ok(Some(cluster.acquire_connection(())?));
        }
        return Err(anyhow!(
            "unknown upstream reference: {} (define it in top-level upstreams[])",
            upstream_name
        ));
    }

    match action.kind {
        qpx_core::config::ActionKind::Proxy | qpx_core::config::ActionKind::Tunnel => Err(anyhow!(
            "{:?} action requires an upstream reference (set action.upstream or forward_edges[].upstream_proxy)",
            action.kind
        )),
        // Inspect can be direct (e.g. transparent/forward MITM); upstream proxy chaining remains optional.
        qpx_core::config::ActionKind::Inspect => Ok(None),
        qpx_core::config::ActionKind::Direct
        | qpx_core::config::ActionKind::Block
        | qpx_core::config::ActionKind::Respond => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use crate::http::protocol::common::*;

    #[tokio::test]
    async fn connect_established_owner_preserves_finalized_output() {
        use crate::http::protocol::l7::{
            finalize_response_with_headers, finalize_response_with_headers_in_place,
        };
        use qpx_core::http_message::OrdinaryHeaderName;

        let control = qpx_core::rules::CompiledHeaderControl::compile(
            &serde_yaml::from_str(
                "response_set: {date: 'Tue, 01 Jan 2030 00:00:00 GMT', content-length: '7', transfer-encoding: chunked, trailer: x-end, connection: x-hop, x-hop: removed, capsule-protocol: '?0'}",
            )
            .expect("header config"),
        )
        .expect("header control");
        for version in [
            http::Version::HTTP_10,
            http::Version::HTTP_11,
            http::Version::HTTP_2,
            http::Version::HTTP_3,
        ] {
            for capsule in [false, true] {
                for header_control in [None, Some(&control)] {
                    let mut owner: OwnerResponse<Body> = connect_established_response();
                    assert_eq!(owner.status(), StatusCode::OK);
                    assert_eq!(owner.version(), http::Version::HTTP_11);
                    assert_eq!(owner.headers().declared_content_length(), Ok(None));
                    // Former construction path, retained only as the parity oracle.
                    let mut expected = Response::new(Body::empty());
                    qpx_http::protocol::semantics::strip_message_body_headers(
                        expected.headers_mut(),
                    );
                    if capsule {
                        owner.headers_mut().insert(
                            OrdinaryHeaderName::try_from("capsule-protocol").unwrap(),
                            http::HeaderValue::from_static("?1"),
                        );
                        expected
                            .headers_mut()
                            .insert("capsule-protocol", http::HeaderValue::from_static("?1"));
                    }
                    let expected = finalize_response_with_headers(
                        &http::Method::CONNECT,
                        version,
                        "edge",
                        expected,
                        header_control,
                        false,
                    );
                    finalize_response_with_headers_in_place(
                        &http::Method::CONNECT,
                        version,
                        "edge",
                        &mut owner,
                        header_control,
                        false,
                    );
                    let mut actual = owner.into_http_for_codec().expect("valid CONNECT framing");
                    let mut expected = expected;
                    assert_eq!(actual.status(), expected.status());
                    assert_eq!(actual.version(), expected.version());
                    // With no configured Date, finalization may cross a second boundary.
                    assert!(actual.headers_mut().remove("date").is_some());
                    assert!(expected.headers_mut().remove("date").is_some());
                    assert_eq!(actual.headers(), expected.headers());
                    for name in ["content-length", "transfer-encoding", "trailer", "x-hop"] {
                        assert!(!actual.headers().contains_key(name));
                    }
                    assert!(
                        qpx_http::body::to_bytes(actual.into_body())
                            .await
                            .unwrap()
                            .is_empty()
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn blocked_owner_preserves_text_response_and_finalization_output() {
        use crate::http::protocol::l7::{
            finalize_response_with_headers, finalize_response_with_headers_in_place,
        };
        use http_body_util::BodyExt;
        use qpx_core::http_message::Response as OwnerResponse;

        let control = qpx_core::rules::CompiledHeaderControl::compile(
            &serde_yaml::from_str(
                "response_set:\n  date: 'Tue, 01 Jan 2030 00:00:00 GMT'\n  connection: x-hop\n  x-hop: removed\nresponse_add:\n  set-cookie: 'a=1'\n",
            )
            .expect("header config"),
        )
        .expect("header control");
        for message in ["", "blocked: café\r\n"] {
            let initial: OwnerResponse<Body> = blocked_response(message);
            assert_eq!(initial.status(), StatusCode::FORBIDDEN);
            assert_eq!(initial.version(), http::Version::HTTP_11);
            assert_eq!(initial.headers().declared_content_length(), Ok(None));
            let initial = initial
                .into_http_for_codec()
                .expect("valid initial framing");
            assert!(initial.headers().is_empty());
            let body = initial.into_body().collect().await.expect("body");
            assert_eq!(body.to_bytes(), message.as_bytes());
            for method in [http::Method::GET, http::Method::HEAD, http::Method::CONNECT] {
                for version in [
                    http::Version::HTTP_10,
                    http::Version::HTTP_11,
                    http::Version::HTTP_2,
                    http::Version::HTTP_3,
                ] {
                    let mut owner = blocked_response(message);
                    // This is the former builder and finalization path.
                    let expected = finalize_response_with_headers(
                        &method,
                        version,
                        "edge",
                        http::Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(message.to_owned()))
                            .expect("baseline response"),
                        Some(&control),
                        false,
                    );
                    finalize_response_with_headers_in_place(
                        &method,
                        version,
                        "edge",
                        &mut owner,
                        Some(&control),
                        false,
                    );
                    let actual = owner.into_http_for_codec().expect("valid final framing");
                    assert_eq!(actual.status(), expected.status());
                    assert_eq!(actual.version(), expected.version());
                    assert_eq!(actual.headers(), expected.headers());
                    assert!(!actual.headers().contains_key("x-hop"));
                    let actual_body = actual.into_body().collect().await.expect("actual body");
                    let expected_body =
                        expected.into_body().collect().await.expect("expected body");
                    assert_eq!(actual_body.to_bytes(), expected_body.to_bytes());
                }
            }
        }
    }

    #[test]
    fn trim_http_ows_removes_only_ascii_space_and_tab() {
        assert_eq!(trim_http_ows(" \tvalue\t "), "value");
        assert_eq!(trim_http_ows("\t "), "");
        assert_eq!(
            trim_http_ows("\u{00a0}value\u{00a0}"),
            "\u{00a0}value\u{00a0}"
        );
    }

    #[test]
    fn trim_http_ows_len_counts_the_same_bytes_without_requiring_utf8() {
        assert_eq!(trim_http_ows_len(b" \tvalue\t "), 5);
        assert_eq!(trim_http_ows_len(b" \t "), 0);
        assert_eq!(trim_http_ows_len(b"\x80value\x80"), 7);
    }
    use crate::runtime::Runtime;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config,
        IdentityConfig, IngressEdgeConfig, IngressEdgeMode, MessagesConfig, RuntimeConfig,
        SystemLogConfig,
    };

    fn base_runtime() -> Runtime {
        let config = Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            telemetry: qpx_core::config::TelemetryConfig {
                system_log: SystemLogConfig::default(),
                access_log: AccessLogConfig::default(),
                audit_log: AuditLogConfig::default(),
                metrics: None,
                otel: None,
                exporter: None,
            },
            security: qpx_core::config::SecurityConfig {
                auth: AuthConfig::default(),
                identity_sources: Vec::new(),
                decisions: qpx_core::config::DecisionConfig {
                    services: Vec::new(),
                },
                destination: Default::default(),
                named_sets: Vec::new(),
                upstream_trust_profiles: Vec::new(),
            },
            http: qpx_core::config::HttpGlobalConfig::default(),
            traffic: qpx_core::config::TrafficConfig::default(),
            acme: None,
            edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
                name: "forward".to_string(),
                mode: IngressEdgeMode::Forward,
                listen: "127.0.0.1:0".to_string(),
                default_action: ActionConfig {
                    kind: ActionKind::Direct,
                    upstream: None,
                    local_response: None,
                },
                original_dst: None,
                tls_inspection: None,
                rules: Vec::new(),
                connection_filter: Vec::new(),
                streaming: None,
                grpc: None,
                sse: None,
                streaming_requirement: None,
                upstream_proxy: None,
                http3: None,
                ftp: Default::default(),
                xdp: None,
                cache: None,
                capture: None,
                rate_limit: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                http_modules: Vec::new(),
            })],
            upstreams: Vec::new(),
            caches: Vec::new(),
        };
        Runtime::new(config).expect("runtime")
    }

    #[test]
    fn resolve_named_upstream_accepts_bare_authority() {
        let runtime = base_runtime();
        let state = runtime.state();
        let action = ActionConfig {
            kind: ActionKind::Proxy,
            upstream: Some("127.0.0.1:3128".to_string()),
            local_response: None,
        };
        let resolved = resolve_named_upstream(&action, &state, None).expect("resolve");
        assert_eq!(
            resolved.as_ref().map(|upstream| upstream.label()),
            Some("127.0.0.1:3128")
        );
    }

    #[tokio::test]
    async fn shared_client_emits_one_canonical_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::time::{Duration, timeout};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let authority = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut captured = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let count = timeout(Duration::from_secs(5), stream.read(&mut chunk))
                    .await
                    .expect("request head timeout")
                    .expect("read request");
                assert_ne!(count, 0, "client closed before completing the request head");
                captured.extend_from_slice(&chunk[..count]);
                assert!(captured.len() <= 8192, "request head exceeded its bound");
                if captured.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .expect("write response");
            captured
        });

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://{authority}/canonical-length"))
            .header(http::header::CONTENT_LENGTH, "0, 0")
            .body(qpx_http::body::Body::empty())
            .expect("request");
        let response = request_with_shared_client(request)
            .await
            .expect("shared-client request");
        assert_eq!(response.status(), http::StatusCode::OK);
        let captured = timeout(Duration::from_secs(5), server)
            .await
            .expect("capture timeout")
            .expect("capture task");
        let captured = String::from_utf8(captured).expect("request is text");
        let content_length_lines: Vec<_> = captured
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("content-length:"))
            .collect();
        assert_eq!(content_length_lines, ["content-length: 0"]);
    }

    #[test]
    fn resolve_named_upstream_accepts_bare_authority_from_listener() {
        let runtime = base_runtime();
        let state = runtime.state();
        let action = ActionConfig {
            kind: ActionKind::Proxy,
            upstream: None,
            local_response: None,
        };
        let resolved =
            resolve_named_upstream(&action, &state, Some("127.0.0.1:3128")).expect("resolve");
        assert_eq!(
            resolved.as_ref().map(|upstream| upstream.label()),
            Some("127.0.0.1:3128")
        );
    }
}
