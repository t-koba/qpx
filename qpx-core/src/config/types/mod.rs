mod cache;
mod canonical;
mod core;
mod http;
mod listener;
mod observability;
mod policy;
mod reverse;
mod rules;
mod security;
mod upstream;

pub use self::cache::*;
pub use self::canonical::*;
pub use self::core::*;
pub use self::http::*;
pub use self::listener::*;
pub use self::observability::*;
pub use self::policy::*;
pub use self::reverse::*;
pub use self::rules::*;
pub use self::security::*;
pub use self::upstream::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub state_dir: Option<String>,
    pub identity: IdentityConfig,
    pub messages: MessagesConfig,
    pub runtime: RuntimeConfig,
    pub telemetry: TelemetryConfig,
    pub security: SecurityConfig,
    pub http: HttpGlobalConfig,
    pub traffic: TrafficConfig,
    pub acme: Option<AcmeConfig>,
    pub edges: Vec<EdgeConfig>,
    pub upstreams: Vec<UpstreamConfig>,
    pub caches: Vec<CacheBackendConfig>,
}

impl Config {
    pub fn ingress_edges(&self) -> impl Iterator<Item = &IngressEdgeConfig> {
        self.edges.iter().filter_map(EdgeConfig::as_ingress)
    }

    pub fn ingress_edge_configs(&self) -> Vec<&IngressEdgeConfig> {
        self.ingress_edges().collect()
    }

    pub fn ingress_edges_mut(&mut self) -> impl Iterator<Item = &mut IngressEdgeConfig> {
        self.edges.iter_mut().filter_map(EdgeConfig::as_ingress_mut)
    }

    pub fn reverse_edges(&self) -> impl Iterator<Item = &ReverseEdgeConfig> {
        self.edges.iter().filter_map(EdgeConfig::as_reverse)
    }

    pub fn reverse_edge_configs(&self) -> Vec<&ReverseEdgeConfig> {
        self.reverse_edges().collect()
    }

    pub fn reverse_edges_mut(&mut self) -> impl Iterator<Item = &mut ReverseEdgeConfig> {
        self.edges.iter_mut().filter_map(EdgeConfig::as_reverse_mut)
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeConfig {
    Forward(IngressEdgeConfig),
    Reverse(ReverseEdgeConfig),
    Transparent(IngressEdgeConfig),
}

impl EdgeConfig {
    pub fn as_ingress(&self) -> Option<&IngressEdgeConfig> {
        match self {
            Self::Forward(edge) | Self::Transparent(edge) => Some(edge),
            Self::Reverse(_) => None,
        }
    }

    pub fn as_ingress_mut(&mut self) -> Option<&mut IngressEdgeConfig> {
        match self {
            Self::Forward(edge) | Self::Transparent(edge) => Some(edge),
            Self::Reverse(_) => None,
        }
    }

    pub fn as_reverse(&self) -> Option<&ReverseEdgeConfig> {
        match self {
            Self::Reverse(edge) => Some(edge),
            Self::Forward(_) | Self::Transparent(_) => None,
        }
    }

    pub fn as_reverse_mut(&mut self) -> Option<&mut ReverseEdgeConfig> {
        match self {
            Self::Reverse(edge) => Some(edge),
            Self::Forward(_) | Self::Transparent(_) => None,
        }
    }
}
