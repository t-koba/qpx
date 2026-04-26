use super::super::defaults::*;
use super::{HeaderControl, LocalResponseConfig, MatchConfig};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HttpModuleConfig {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub order: Option<i16>,
    #[serde(flatten)]
    pub settings: BTreeMap<String, Value>,
}

impl HttpModuleConfig {
    pub fn parse_settings<T>(&self) -> Result<T, serde_yaml::Error>
    where
        T: DeserializeOwned,
    {
        let mut mapping = Mapping::new();
        for (key, value) in &self.settings {
            mapping.insert(Value::String(key.clone()), value.clone());
        }
        serde_yaml::from_value(Value::Mapping(mapping))
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseCompressionModuleConfig {
    #[serde(default = "default_http_compression_min_body_bytes")]
    pub min_body_bytes: usize,
    #[serde(default = "default_http_compression_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default)]
    pub content_types: Vec<String>,
    #[serde(default = "default_http_compression_enable_gzip")]
    pub gzip: bool,
    #[serde(default = "default_http_compression_enable_brotli")]
    pub brotli: bool,
    #[serde(default = "default_http_compression_enable_zstd")]
    pub zstd: bool,
    #[serde(default = "default_http_compression_gzip_level")]
    pub gzip_level: u32,
    #[serde(default = "default_http_compression_brotli_level")]
    pub brotli_level: u32,
    #[serde(default = "default_http_compression_zstd_level")]
    pub zstd_level: i32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubrequestPhase {
    RequestHeaders,
    ResponseHeaders,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubrequestResponseMode {
    Ignore,
    ReturnOnError,
    ReturnAlways,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeaderCaptureConfig {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SubrequestModuleConfig {
    pub name: String,
    pub phase: SubrequestPhase,
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub pass_headers: Vec<String>,
    #[serde(default)]
    pub request_headers: HashMap<String, String>,
    #[serde(default)]
    pub copy_response_headers_to_request: Vec<HeaderCaptureConfig>,
    #[serde(default)]
    pub copy_response_headers_to_response: Vec<HeaderCaptureConfig>,
    #[serde(default)]
    pub response_mode: Option<SubrequestResponseMode>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CachePurgeModuleConfig {
    #[serde(default = "default_http_cache_purge_methods")]
    pub methods: Vec<String>,
    #[serde(default = "default_http_cache_purge_response_status")]
    pub response_status: u16,
    #[serde(default)]
    pub response_body: String,
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct HttpPolicyConfig {
    #[serde(default)]
    pub response_rules: Vec<HttpResponseRuleConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseRuleConfig {
    pub name: String,
    #[serde(default)]
    pub r#match: Option<MatchConfig>,
    #[serde(default)]
    pub effects: HttpResponseEffectsConfig,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseEffectsConfig {
    #[serde(default)]
    pub local_response: Option<LocalResponseConfig>,
    #[serde(default)]
    pub headers: Option<HeaderControl>,
    #[serde(default)]
    pub cache: Option<HttpResponseCacheEffectsConfig>,
    #[serde(default)]
    pub retry: Option<HttpResponseRetryEffectsConfig>,
    #[serde(default)]
    pub mirror: Option<HttpResponseMirrorEffectsConfig>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseCacheEffectsConfig {
    #[serde(default)]
    pub bypass: bool,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseRetryEffectsConfig {
    #[serde(default)]
    pub suppress: bool,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseMirrorEffectsConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub upstreams: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpGuardProfileConfig {
    pub name: String,
    #[serde(default)]
    pub normalize: HttpGuardNormalizeConfig,
    #[serde(default)]
    pub protocol_safety: HttpGuardProtocolSafetyConfig,
    #[serde(default)]
    pub limits: HttpGuardLimitsConfig,
    #[serde(default)]
    pub json: HttpGuardJsonConfig,
    #[serde(default)]
    pub multipart: HttpGuardMultipartConfig,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpGuardNormalizeConfig {
    #[serde(default)]
    pub path: bool,
    #[serde(default)]
    pub query: bool,
    #[serde(default)]
    pub headers: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpGuardProtocolSafetyConfig {
    #[serde(default = "default_http_guard_enable_smuggling_checks")]
    pub smuggling: bool,
    #[serde(default = "default_http_guard_enable_invalid_framing_checks")]
    pub invalid_framing: bool,
}

impl Default for HttpGuardProtocolSafetyConfig {
    fn default() -> Self {
        Self {
            smuggling: default_http_guard_enable_smuggling_checks(),
            invalid_framing: default_http_guard_enable_invalid_framing_checks(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpGuardLimitsConfig {
    #[serde(default)]
    pub header_count: Option<usize>,
    #[serde(default)]
    pub header_bytes: Option<usize>,
    #[serde(default)]
    pub path_bytes: Option<usize>,
    #[serde(default)]
    pub query_pairs: Option<usize>,
    #[serde(default)]
    pub query_key_bytes: Option<usize>,
    #[serde(default)]
    pub query_value_bytes: Option<usize>,
    #[serde(default)]
    pub body_bytes: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpGuardJsonConfig {
    #[serde(default)]
    pub max_depth: Option<usize>,
    #[serde(default)]
    pub max_fields: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpGuardMultipartConfig {
    #[serde(default)]
    pub max_parts: Option<usize>,
    #[serde(default)]
    pub max_name_bytes: Option<usize>,
    #[serde(default)]
    pub max_filename_bytes: Option<usize>,
}
