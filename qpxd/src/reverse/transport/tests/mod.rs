use super::super::router::{CompiledPathRewrite, CompiledRegexPathRewrite, ReverseRouter};
use super::path_rewrite::apply_path_rewrite;
use super::response_rules::{ResponseRuleInput, apply_response_rules};
use super::*;
use crate::destination::DestinationMetadata;
use crate::http::policy::response_policy::ListenerResponsePolicyDecision;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::runtime::Runtime;
use crate::test_util::{decode_gzip, spawn_static_http_server};
use http::{Method, header::CONTENT_LENGTH};
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, AuthConfig, CertificateMatchConfig, Config,
    DecisionServiceCapabilityConfig, DecisionServiceConfig, DecisionServiceContractConfig,
    DecisionServiceDriver, DecisionServiceMappingRuleConfig, DecisionServiceMappingTargetDocument,
    DecisionServiceSchemasConfig, DestinationDimensionMatchConfig, DestinationMatchConfig,
    HeaderControl, HttpPolicyConfig, HttpResponseCacheEffectsConfig, HttpResponseEffectsConfig,
    HttpResponseRuleConfig, IdentityConfig, LocalResponseConfig, MatchConfig, MessagesConfig,
    NamedSetConfig, NamedSetKind, PolicyContextConfig, RateLimitConfig, RateLimitProfileConfig,
    ReverseEdgeConfig, ReverseRouteConfig, RpcMatchConfig, RuntimeConfig, StreamingConfig,
    StreamingRequirement, SystemLogConfig, UnknownLengthExactSizePolicy, UpstreamConfig,
};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::rules::CompiledHeaderControl;
use qpx_core::tls::UpstreamCertificateInfo;
use qpx_http::body::to_bytes;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use rcgen::generate_simple_self_signed;
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc as StdArc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn materialized_webdav_file_region_keeps_verified_snapshot() {
    use std::io::Write as _;

    let mut file = tempfile::tempfile().expect("temporary WebDAV file");
    file.write_all(b"changed!").expect("write WebDAV file");
    let region = qpx_webdav::ResourceFileRegion {
        file: StdArc::new(file),
        offset: 0,
        len: 8,
    };
    let body = super::dispatch::apply_webdav_file_region(
        Body::from("snapshot").mark_trailers_sanitized(),
        8,
        region,
    )
    .expect("apply WebDAV file region");

    assert!(!body.has_file_region());
    assert_eq!(to_bytes(body).await.expect("WebDAV body"), "snapshot");
}

#[tokio::test]
async fn empty_webdav_file_region_materializes_portable_body() {
    use std::io::Write as _;

    let mut file = tempfile::tempfile().expect("temporary WebDAV file");
    file.write_all(b"payload").expect("write WebDAV file");
    let region = qpx_webdav::ResourceFileRegion {
        file: StdArc::new(file),
        offset: 0,
        len: 7,
    };
    let body = super::dispatch::apply_webdav_file_region(
        Body::empty().mark_trailers_sanitized(),
        0,
        region,
    )
    .expect("apply WebDAV file region");

    assert!(!body.has_file_region());
    assert_eq!(to_bytes(body).await.expect("WebDAV body"), "payload");
}

fn test_decision_service_config(name: &str, endpoint: String) -> DecisionServiceConfig {
    DecisionServiceConfig {
        name: name.to_string(),
        endpoint,
        timeout_ms: 1_000,
        max_response_bytes: 1024 * 1024,
        contract: DecisionServiceContractConfig {
            driver: DecisionServiceDriver::SchemaMappedHttp,
            profile_id: "test".to_string(),
            contract_id: None,
            schemas: DecisionServiceSchemasConfig::default(),
        },
        schema_resolution: Default::default(),
        request_mapping: Vec::new(),
        response_mapping: vec![
            DecisionServiceMappingRuleConfig {
                target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
                target: "/decision".to_string(),
                source: Some("$.decision_response.decision".to_string()),
                literal: None,
                value_map: Default::default(),
                optional: false,
            },
            DecisionServiceMappingRuleConfig {
                target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
                target: "/rate_limit_profile".to_string(),
                source: Some("$.decision_response.rate_limit_profile".to_string()),
                literal: None,
                value_map: Default::default(),
                optional: true,
            },
        ],
        pep_signal: Default::default(),
        capability: DecisionServiceCapabilityConfig {
            effects: vec!["allow".to_string(), "rate_limit_profile".to_string()],
            ..Default::default()
        },
        policy_composition: Default::default(),
        auth: Default::default(),
        cache: Default::default(),
        signal_extensions: serde_json::Value::Object(Default::default()),
    }
}

fn make_req(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("test request")
}

fn compile_headers(name: &str, value: &str) -> Arc<CompiledHeaderControl> {
    let mut response_set = HashMap::new();
    response_set.insert(name.to_string(), value.to_string());
    Arc::new(
        CompiledHeaderControl::compile(&HeaderControl {
            request_set: HashMap::new(),
            request_add: HashMap::new(),
            request_remove: Vec::new(),
            request_regex_replace: Vec::new(),
            response_set,
            response_add: HashMap::new(),
            response_remove: Vec::new(),
            response_regex_replace: Vec::new(),
        })
        .expect("compile headers"),
    )
}

fn make_base_request_fields(
    method: &str,
    authority: &str,
    path: &str,
    query: Option<&str>,
) -> BaseRequestFields {
    let request_uri = match query {
        Some(query) => format!("https://{authority}{path}?{query}"),
        None => format!("https://{authority}{path}"),
    };
    let request = Request::builder()
        .method(method)
        .uri(request_uri)
        .body(())
        .expect("request");
    crate::http::protocol::base_fields::extract_base_request_fields(
        &request,
        crate::http::protocol::base_fields::BaseRequestContext::default(),
    )
}

async fn spawn_decision_service_server(response_body: String, accepts: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind authz");
    let addr = listener.local_addr().expect("authz addr");
    tokio::spawn(async move {
        for _ in 0..accepts {
            let (mut stream, _) = listener.accept().await.expect("authz accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("authz read");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("authz write");
        }
    });
    addr
}

fn build_router(response_rules: Vec<HttpResponseRuleConfig>) -> ReverseRouter {
    let registry = crate::http::modules::default_http_module_registry();
    ReverseRouter::new(
        ReverseEdgeConfig {
            name: "test".to_string(),
            listen: "127.0.0.1:0".to_string(),
            tls: None,
            http3: None,
            xdp: None,
            enforce_sni_host_match: false,
            sni_host_exceptions: Vec::new(),
            policy_context: None,
            destination_resolution: None,
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            routes: vec![ReverseRouteConfig {
                name: Some("test".to_string()),
                r#match: MatchConfig::default(),
                target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
                    upstreams: vec!["upstream".to_string()],
                    lb: "round_robin".to_string(),
                },
                mirrors: Vec::new(),
                headers: None,
                timeout_ms: None,
                health_check: None,
                cache: None,
                capture: None,
                rate_limit: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                affinity: None,
                policy_context: None,
                http: Some(HttpPolicyConfig {
                    response_rules,
                    forwarded: None,
                    api_metadata: None,
                    hsts: None,
                    require_precondition: false,
                    capport: false,
                }),
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
                streaming: None,
                grpc: None,
                sse: None,
                streaming_requirement: Some(StreamingRequirement::Preferred),
            }],
            tls_passthrough_routes: Vec::new(),
        },
        &[UpstreamConfig {
            name: "upstream".to_string(),
            url: "http://127.0.0.1:8080".to_string(),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        registry.as_ref(),
    )
    .expect("router")
}

#[test]
fn single_featureless_route_enables_plain_http_dispatch() {
    let router = build_router(Vec::new());

    assert!(router.single_plain_http_route().is_some());
}

mod authz_interim_tests;
mod interim_tests;
mod module_tests;
mod path_rewrite_tests;
mod response_policy_context_tests;
mod response_policy_rpc_tests;
mod route_selection_tests;
