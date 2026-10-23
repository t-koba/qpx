use crate::upstream::pool::ConnectionPool;
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use qpx_core::config::ActionConfig;
use qpx_http::body::Body;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Trims only HTTP optional whitespace (SP and HTAB).
pub(super) fn trim_http_ows(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t'))
}

pub(crate) fn blocked_response(message: &str) -> Response<Body> {
    text_response(StatusCode::FORBIDDEN, message.to_owned())
}

pub(crate) fn forbidden_response(message: &str) -> Response<Body> {
    text_response(StatusCode::FORBIDDEN, message.to_owned())
}

pub(crate) fn bad_request_response(message: impl Into<String>) -> Response<Body> {
    text_response(StatusCode::BAD_REQUEST, message.into())
}

fn text_response(status: StatusCode, message: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(message))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

pub(crate) fn connect_established_response() -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()));
    qpx_http::protocol::semantics::strip_message_body_headers(response.headers_mut());
    response
}

pub(crate) fn too_many_requests_response(retry_after: Option<Duration>) -> Response<Body> {
    let mut builder = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    if let Some(retry_after) = retry_after {
        let secs = retry_after.as_secs().max(1);
        builder = builder.header(http::header::RETRY_AFTER, secs.to_string());
    }
    builder
        .body(Body::from("too many requests"))
        .unwrap_or_else(|_| Response::new(Body::empty()))
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

    #[test]
    fn trim_http_ows_removes_only_ascii_space_and_tab() {
        assert_eq!(trim_http_ows(" \tvalue\t "), "value");
        assert_eq!(trim_http_ows("\t "), "");
        assert_eq!(
            trim_http_ows("\u{00a0}value\u{00a0}"),
            "\u{00a0}value\u{00a0}"
        );
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
