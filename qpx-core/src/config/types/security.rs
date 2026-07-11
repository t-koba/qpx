use super::super::defaults::*;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyContextConfig {
    #[serde(default)]
    pub identity_sources: Vec<String>,
    #[serde(default)]
    pub decision_service: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedSetConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: NamedSetKind,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamedSetKind {
    Cidr,
    Domain,
    Regex,
    Category,
    Reputation,
    String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySourceConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: IdentitySourceKind,
    #[serde(default)]
    pub from: IdentitySourceFromConfig,
    #[serde(default)]
    pub headers: Option<IdentitySourceHeadersConfig>,
    #[serde(default)]
    pub map: Option<MtlsIdentityMapConfig>,
    #[serde(default)]
    pub assertion: Option<SignedAssertionConfig>,
    #[serde(default)]
    pub bearer: Option<BearerIdentityConfig>,
    #[serde(default)]
    pub strip_from_untrusted: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySourceKind {
    Bearer,
    TrustedHeaders,
    MtlsSubject,
    SignedAssertion,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BearerIdentityConfig {
    #[serde(default)]
    pub header: Option<String>,
    pub source: BearerIdentitySourceConfig,
    #[serde(default)]
    pub claims: AssertionClaimsMapConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum BearerIdentitySourceConfig {
    Jwt {
        issuer: String,
        audience: String,
        #[serde(default)]
        algorithms: Vec<String>,
        #[serde(default)]
        jwks_url: Option<String>,
        #[serde(default)]
        public_key_env: Option<String>,
        #[serde(default = "default_bearer_clock_skew_seconds")]
        clock_skew_seconds: u64,
    },
    Introspection {
        endpoint: String,
        client_id: String,
        client_secret_env: String,
        #[serde(default = "default_introspection_positive_cache_seconds")]
        positive_cache_seconds: u64,
        #[serde(default = "default_introspection_negative_cache_seconds")]
        negative_cache_seconds: u64,
    },
}

fn default_bearer_clock_skew_seconds() -> u64 {
    60
}

fn default_introspection_positive_cache_seconds() -> u64 {
    60
}

fn default_introspection_negative_cache_seconds() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySourceFromConfig {
    #[serde(default)]
    pub trusted_peers: Vec<String>,
    #[serde(default)]
    pub client_ca: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySourceHeadersConfig {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub groups: Option<String>,
    #[serde(default)]
    pub roles: Option<String>,
    #[serde(default)]
    pub entitlements: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub posture: Option<String>,
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub auth_strength: Option<String>,
    #[serde(default)]
    pub idp: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MtlsIdentityMapConfig {
    #[serde(default)]
    pub user_from_san_uri_prefix: Option<String>,
    #[serde(default)]
    pub user_from_subject_cn: bool,
    #[serde(default)]
    pub auth_strength: Option<String>,
    #[serde(default)]
    pub idp: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAssertionConfig {
    pub header: String,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub secret_env: Option<String>,
    #[serde(default)]
    pub public_key_env: Option<String>,
    #[serde(default)]
    pub claims: AssertionClaimsMapConfig,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssertionClaimsMapConfig {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub groups: Option<String>,
    #[serde(default)]
    pub roles: Option<String>,
    #[serde(default)]
    pub entitlements: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub posture: Option<String>,
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub auth_strength: Option<String>,
    #[serde(default)]
    pub idp: Option<String>,
    #[serde(default)]
    pub user_from_sub: bool,
    #[serde(default)]
    pub groups_separator: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceConfig {
    pub name: String,
    pub endpoint: String,
    #[serde(default = "default_decision_service_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_decision_service_max_response_bytes")]
    pub max_response_bytes: usize,
    pub contract: DecisionServiceContractConfig,
    #[serde(default)]
    pub schema_resolution: DecisionServiceSchemaResolutionConfig,
    #[serde(default)]
    pub request_mapping: Vec<DecisionServiceMappingRuleConfig>,
    #[serde(default)]
    pub response_mapping: Vec<DecisionServiceMappingRuleConfig>,
    #[serde(default)]
    pub pep_signal: DecisionServicePepSignalConfig,
    #[serde(default)]
    pub capability: DecisionServiceCapabilityConfig,
    #[serde(default)]
    pub policy_composition: DecisionServicePolicyCompositionConfig,
    #[serde(default)]
    pub auth: DecisionServiceAuthConfig,
    #[serde(default)]
    pub cache: DecisionServiceCacheConfig,
    #[serde(default)]
    pub signal_extensions: Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceContractConfig {
    pub driver: DecisionServiceDriver,
    pub profile_id: String,
    #[serde(default)]
    pub contract_id: Option<String>,
    pub schemas: DecisionServiceSchemasConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionServiceDriver {
    Authzen,
    SchemaMappedHttp,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceSchemasConfig {
    #[serde(default)]
    pub qpx: DecisionServiceQpxSchemasConfig,
    #[serde(default)]
    pub remote: DecisionServiceRemoteSchemasConfig,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceQpxSchemasConfig {
    #[serde(default)]
    pub pep_signal: Option<DecisionServiceSchemaRefConfig>,
    #[serde(default)]
    pub effect_capability: Option<DecisionServiceSchemaRefConfig>,
    #[serde(default)]
    pub enforceable_effect: Option<DecisionServiceSchemaRefConfig>,
    #[serde(default)]
    pub local_response: Option<DecisionServiceSchemaRefConfig>,
    #[serde(default)]
    pub audit_event: Option<DecisionServiceSchemaRefConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceRemoteSchemasConfig {
    #[serde(default)]
    pub decision_request: Option<DecisionServiceSchemaRefConfig>,
    #[serde(default)]
    pub decision_response: Option<DecisionServiceSchemaRefConfig>,
    #[serde(default)]
    pub auth_context: Option<DecisionServiceSchemaRefConfig>,
    #[serde(default)]
    pub audit_context: Option<DecisionServiceSchemaRefConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceSchemaRefConfig {
    pub id: String,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceSchemaResolutionConfig {
    #[serde(default)]
    pub local_bundle: Option<String>,
    #[serde(default)]
    pub trusted_registries: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceMappingRuleConfig {
    pub target_document: DecisionServiceMappingTargetDocument,
    pub target: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub literal: Option<Value>,
    #[serde(default)]
    pub value_map: std::collections::BTreeMap<String, Value>,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DecisionServiceMappingTargetDocument {
    DecisionRequest,
    EnforceableEffect,
    AuthAssertions,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServicePepSignalConfig {
    #[serde(default)]
    pub selected_headers: Vec<String>,
    #[serde(default)]
    pub sensitive_headers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceCapabilityConfig {
    #[serde(default)]
    pub modes: Vec<String>,
    #[serde(default)]
    pub phases: Vec<String>,
    #[serde(default)]
    pub effects: Vec<String>,
    #[serde(default)]
    pub authority: DecisionServiceAuthorityConfig,
    #[serde(default)]
    pub constraints: DecisionServiceConstraintsConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceAuthorityConfig {
    #[serde(default = "default_true")]
    pub can_allow: bool,
    #[serde(default)]
    pub can_deny: bool,
    #[serde(default)]
    pub can_override_route: bool,
    #[serde(default)]
    pub can_weaken_local_policy: bool,
}

impl Default for DecisionServiceAuthorityConfig {
    fn default() -> Self {
        Self {
            can_allow: true,
            can_deny: false,
            can_override_route: false,
            can_weaken_local_policy: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceConstraintsConfig {
    #[serde(default)]
    pub allowed_request_headers_to_add: Vec<String>,
    #[serde(default)]
    pub allowed_response_headers_to_add: Vec<String>,
    #[serde(default)]
    pub override_upstreams: Vec<String>,
    #[serde(default)]
    pub max_timeout_override_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServicePolicyCompositionConfig {
    #[serde(default)]
    pub external_allow_can_override_local_deny: bool,
    #[serde(default = "default_true")]
    pub external_deny_can_stop_local_allow: bool,
}

impl Default for DecisionServicePolicyCompositionConfig {
    fn default() -> Self {
        Self {
            external_allow_can_override_local_deny: false,
            external_deny_can_stop_local_allow: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceAuthConfig {
    #[serde(default)]
    pub bearer_token_env: Option<String>,
    #[serde(default)]
    pub oauth2_client_credentials: Option<OAuth2ClientCredentialsConfig>,
    #[serde(default)]
    pub mtls: Option<DecisionServiceMtlsConfig>,
    #[serde(default)]
    pub http_message_signatures: Option<DecisionServiceHttpMessageSignaturesConfig>,
    #[serde(default)]
    pub expected_auth_context: Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OAuth2ClientCredentialsConfig {
    pub token_endpoint: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub private_key_env: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub client_auth_method: OAuth2ClientAuthMethod,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2ClientAuthMethod {
    #[default]
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
    TlsClientAuth,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceMtlsConfig {
    #[serde(default)]
    pub upstream_trust_profile: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceHttpMessageSignaturesConfig {
    pub key_id: String,
    pub algorithm: DecisionServiceSignatureAlgorithm,
    #[serde(default)]
    pub secret_env: Option<String>,
    #[serde(default)]
    pub private_key_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionServiceSignatureAlgorithm {
    HmacSha256,
    Ed25519,
    EcdsaP256Sha256,
    RsaPssSha256,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionServiceCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub max_entries: Option<usize>,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct AuthConfig {
    #[serde(default)]
    pub users: Vec<LocalUser>,
    #[serde(default)]
    pub ldap: Option<LdapConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LocalUser {
    pub username: String,
    pub password: Option<String>,
    pub ha1: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    pub bind_password_env: String,
    pub user_base_dn: String,
    pub group_base_dn: String,
    #[serde(default = "default_ldap_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_ldap_require_starttls")]
    pub require_starttls: bool,
    #[serde(default = "default_user_filter")]
    pub user_filter: String,
    #[serde(default = "default_group_filter")]
    pub group_filter: String,
    #[serde(default = "default_group_attr")]
    pub group_attr: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTlsTrustConfig {
    #[serde(default)]
    pub pin_sha256: Vec<String>,
    #[serde(default)]
    pub issuer: Vec<String>,
    #[serde(default)]
    pub san_dns: Vec<String>,
    #[serde(default)]
    pub san_uri: Vec<String>,
    #[serde(default)]
    pub client_cert: Option<String>,
    #[serde(default)]
    pub client_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTlsTrustProfileConfig {
    pub name: String,
    #[serde(flatten)]
    pub trust: UpstreamTlsTrustConfig,
}
