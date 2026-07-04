use super::*;
use crate::runtime::Runtime;
use crate::test_util::{decode_gzip, spawn_static_http_server};
use http::StatusCode;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config,
    DecisionServiceCapabilityConfig, DecisionServiceConfig, DecisionServiceContractConfig,
    DecisionServiceDriver, DecisionServiceMappingRuleConfig, DecisionServiceMappingTargetDocument,
    DecisionServiceSchemasConfig, HttpModuleConfig, HttpPolicyConfig, HttpResponseEffectsConfig,
    HttpResponseRuleConfig, IdentityConfig, IngressEdgeConfig, IngressEdgeMode,
    LocalResponseConfig, MatchConfig, MessagesConfig, PolicyContextConfig, RpcMatchConfig,
    RuleConfig, RuntimeConfig, StreamingRequirement, SystemLogConfig, UnknownLengthExactSizePolicy,
};
use qpx_http::body::to_bytes;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod authz;
mod core;
mod modules;
mod response_rules;

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
                optional: false,
            },
            DecisionServiceMappingRuleConfig {
                target_document: DecisionServiceMappingTargetDocument::EnforceableEffect,
                target: "/rate_limit_profile".to_string(),
                source: Some("$.decision_response.rate_limit_profile".to_string()),
                literal: None,
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
