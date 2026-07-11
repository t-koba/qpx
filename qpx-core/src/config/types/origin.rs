use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OriginConfig {
    #[serde(default)]
    pub webdav: Vec<WebDavOriginConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebDavOriginConfig {
    pub name: String,
    pub root: String,
    pub metadata: String,
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_max_multistatus_entries")]
    pub max_multistatus_entries: usize,
    #[serde(default = "default_max_lock_timeout_seconds")]
    pub max_lock_timeout_seconds: u64,
}

fn default_max_depth() -> usize {
    32
}

fn default_max_multistatus_entries() -> usize {
    10_000
}

fn default_max_lock_timeout_seconds() -> u64 {
    86_400
}
