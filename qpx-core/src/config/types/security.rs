use super::super::defaults::*;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyContextConfig {
    #[serde(default)]
    pub identity_sources: Vec<String>,
    #[serde(default)]
    pub ext_authz: Option<String>,
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
    pub strip_from_untrusted: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySourceKind {
    TrustedHeaders,
    MtlsSubject,
    SignedAssertion,
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

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtAuthzKind {
    #[default]
    Http,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtAuthzOnError {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtAuthzSendConfig {
    #[serde(default)]
    pub request: bool,
    #[serde(default)]
    pub identity: bool,
    #[serde(default)]
    pub selected_headers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtAuthzConfig {
    pub name: String,
    #[serde(default)]
    pub kind: ExtAuthzKind,
    pub endpoint: String,
    #[serde(default = "default_ext_authz_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_ext_authz_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default)]
    pub send: ExtAuthzSendConfig,
    #[serde(default)]
    pub on_error: ExtAuthzOnError,
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
