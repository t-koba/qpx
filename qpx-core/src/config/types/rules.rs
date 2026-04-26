use super::super::defaults::*;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuleConfig {
    pub name: String,
    #[serde(default)]
    pub r#match: Option<MatchConfig>,
    #[serde(default)]
    pub auth: Option<RuleAuthConfig>,
    #[serde(default)]
    pub action: Option<ActionConfig>,
    #[serde(default)]
    pub headers: Option<HeaderControl>,
    #[serde(default)]
    pub rate_limit: Option<super::RateLimitConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuleAuthConfig {
    #[serde(default)]
    pub require: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct HeaderControl {
    #[serde(default)]
    pub request_set: HashMap<String, String>,
    #[serde(default)]
    pub request_add: HashMap<String, String>,
    #[serde(default)]
    pub request_remove: Vec<String>,
    #[serde(default)]
    pub request_regex_replace: Vec<RegexReplace>,
    #[serde(default)]
    pub response_set: HashMap<String, String>,
    #[serde(default)]
    pub response_add: HashMap<String, String>,
    #[serde(default)]
    pub response_remove: Vec<String>,
    #[serde(default)]
    pub response_regex_replace: Vec<RegexReplace>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RegexReplace {
    pub header: String,
    pub pattern: String,
    pub replace: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct MatchConfig {
    #[serde(default)]
    pub src_ip: Vec<String>,
    #[serde(default)]
    pub dst_port: Vec<u16>,
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(default)]
    pub sni: Vec<String>,
    #[serde(default)]
    pub method: Vec<String>,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub query: Vec<String>,
    #[serde(default)]
    pub authority: Vec<String>,
    #[serde(default)]
    pub scheme: Vec<String>,
    #[serde(default)]
    pub http_version: Vec<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub tls_version: Vec<String>,
    #[serde(default)]
    pub destination: Option<DestinationMatchConfig>,
    #[serde(default)]
    pub request_size: Vec<String>,
    #[serde(default)]
    pub response_status: Vec<String>,
    #[serde(default)]
    pub response_size: Vec<String>,
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
    #[serde(default)]
    pub identity: Option<IdentityMatchConfig>,
    #[serde(default)]
    pub tls_fingerprint: Option<TlsFingerprintMatchConfig>,
    #[serde(default)]
    pub client_cert: Option<CertificateMatchConfig>,
    #[serde(default)]
    pub upstream_cert: Option<CertificateMatchConfig>,
    #[serde(default)]
    pub rpc: Option<RpcMatchConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DestinationMatchConfig {
    #[serde(default)]
    pub category: Option<DestinationDimensionMatchConfig>,
    #[serde(default)]
    pub reputation: Option<DestinationDimensionMatchConfig>,
    #[serde(default)]
    pub application: Option<DestinationDimensionMatchConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DestinationDimensionMatchConfig {
    #[serde(default)]
    pub value: Vec<String>,
    #[serde(default)]
    pub source: Vec<String>,
    #[serde(default)]
    pub confidence: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RpcMatchConfig {
    #[serde(default)]
    pub protocol: Vec<String>,
    #[serde(default)]
    pub service: Vec<String>,
    #[serde(default)]
    pub method: Vec<String>,
    #[serde(default)]
    pub streaming: Vec<String>,
    #[serde(default)]
    pub status: Vec<String>,
    #[serde(default)]
    pub message_size: Vec<String>,
    #[serde(default)]
    pub message: Vec<String>,
    #[serde(default)]
    pub trailers: Vec<HeaderMatch>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsFingerprintMatchConfig {
    #[serde(default)]
    pub ja3: Vec<String>,
    #[serde(default)]
    pub ja4: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertificateMatchConfig {
    #[serde(default)]
    pub present: Option<bool>,
    #[serde(default)]
    pub subject: Vec<String>,
    #[serde(default)]
    pub issuer: Vec<String>,
    #[serde(default)]
    pub san_dns: Vec<String>,
    #[serde(default)]
    pub san_uri: Vec<String>,
    #[serde(default)]
    pub fingerprint_sha256: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityMatchConfig {
    #[serde(default)]
    pub user: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub device_id: Vec<String>,
    #[serde(default)]
    pub posture: Vec<String>,
    #[serde(default)]
    pub tenant: Vec<String>,
    #[serde(default)]
    pub auth_strength: Vec<String>,
    #[serde(default)]
    pub idp: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HeaderMatch {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionConfig {
    #[serde(rename = "type")]
    pub kind: ActionKind,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub local_response: Option<LocalResponseConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    Inspect,
    Tunnel,
    Block,
    Direct,
    Proxy,
    Respond,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct LocalResponseConfig {
    #[serde(default = "default_local_response_status")]
    pub status: u16,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub rpc: Option<RpcLocalResponseConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RpcLocalResponseConfig {
    pub protocol: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub http_status: Option<u16>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub trailers: HashMap<String, String>,
}
