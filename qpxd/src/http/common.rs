use anyhow::{anyhow, Result};
use hyper::client::HttpConnector;
use hyper::{Body, Response, StatusCode};
use qpx_core::config::ActionConfig;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub fn blocked_response(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(message.to_owned()))
        .expect("static response")
}

pub fn forbidden_response(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(message.to_owned()))
        .expect("static response")
}

pub fn bad_request_response(message: impl Into<String>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(message.into()))
        .expect("static response")
}

pub fn connect_established_response() -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("static response");
    crate::http::semantics::strip_message_body_headers(response.headers_mut());
    response
}

pub fn too_many_requests_response(retry_after: Option<Duration>) -> Response<Body> {
    let mut builder = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    if let Some(retry_after) = retry_after {
        let secs = retry_after.as_secs().max(1);
        builder = builder.header(http::header::RETRY_AFTER, secs.to_string());
    }
    builder
        .body(Body::from("too many requests"))
        .expect("static response")
}

pub fn shared_http_client() -> &'static hyper::Client<HttpConnector, Body> {
    static CLIENT: OnceLock<hyper::Client<HttpConnector, Body>> = OnceLock::new();
    CLIENT.get_or_init(hyper::Client::new)
}

pub fn resolve_named_upstream(
    action: &ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener_upstream_proxy: Option<&str>,
) -> Result<Option<String>> {
    if matches!(action.kind, qpx_core::config::ActionKind::Direct) {
        return Ok(None);
    }

    if let Some(upstream_name) = action.upstream.as_deref().or(listener_upstream_proxy) {
        if upstream_name.contains("://") {
            return Ok(Some(upstream_name.to_string()));
        }
        // Keep validation and runtime behavior aligned: bare "host:port" (and "[::1]:port")
        // is treated as a direct upstream proxy endpoint.
        if (upstream_name.contains(':') || upstream_name.starts_with('['))
            && upstream_name.parse::<http::uri::Authority>().is_ok()
        {
            // Preserve userinfo semantics by converting to a URL form, so downstream parsing can
            // produce Proxy-Authorization (parse_upstream_proxy_endpoint).
            if upstream_name.contains('@') {
                return Ok(Some(format!("http://{}", upstream_name)));
            }
            return Ok(Some(upstream_name.to_string()));
        }
        if let Some(url) = state.upstreams.get(upstream_name) {
            return Ok(Some(url.clone()));
        }
        return Err(anyhow!(
            "unknown upstream reference: {} (define it in top-level upstreams[])",
            upstream_name
        ));
    }

    match action.kind {
        qpx_core::config::ActionKind::Proxy | qpx_core::config::ActionKind::Tunnel => Err(anyhow!(
            "{:?} action requires an upstream reference (set action.upstream or listeners[].upstream_proxy)",
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
    use super::*;
    use crate::runtime::Runtime;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig, Config,
        IdentityConfig, ListenerConfig, ListenerMode, MessagesConfig, RuntimeConfig,
        SystemLogConfig,
    };

    fn base_runtime() -> Runtime {
        let config = Config {
            version: 1,
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: AuthConfig::default(),
            listeners: vec![ListenerConfig {
                name: "forward".to_string(),
                mode: ListenerMode::Forward,
                listen: "127.0.0.1:0".to_string(),
                default_action: ActionConfig {
                    kind: ActionKind::Direct,
                    upstream: None,
                    local_response: None,
                },
                tls_inspection: None,
                rules: Vec::new(),
                upstream_proxy: None,
                http3: None,
                ftp: Default::default(),
                xdp: None,
                cache: None,
                rate_limit: None,
            }],
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: CacheConfig::default(),
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
        assert_eq!(resolved.as_deref(), Some("127.0.0.1:3128"));
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
        assert_eq!(resolved.as_deref(), Some("127.0.0.1:3128"));
    }
}
