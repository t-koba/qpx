use super::{
    AccessLogConfig, AcmeConfig, AuditLogConfig, AuthConfig, CacheBackendConfig, CachePolicyConfig,
    CapturePolicyConfig, DestinationResolutionConfig, DestinationResolutionOverrideConfig,
    EdgeConfig, ExporterConfig, ExtAuthzConfig, FtpConfig, HeaderControl, HealthCheckConfig,
    Http3IngressEdgeConfig, HttpGuardProfileConfig, HttpModuleConfig, HttpPolicyConfig,
    IdentityConfig, IdentitySourceConfig, IngressEdgeConfig, IngressEdgeMode, IpcBodyLimitConfig,
    IpcMode, IpcUpstreamConfig, LocalResponseConfig, MatchConfig, MessagesConfig, NamedSetConfig,
    OriginalDstConfig, RateLimitConfig, RateLimitProfileConfig, ResilienceConfig,
    ReverseAffinityConfig, ReverseEdgeConfig, ReverseHttp3Config, ReverseRouteBackendConfig,
    ReverseRouteConfig, ReverseRouteMirrorConfig, ReverseRouteTargetConfig, ReverseTlsConfig,
    ReverseTlsPassthroughRouteConfig, RuleConfig, TlsInspectionConfig, TlsPassthroughMatchConfig,
    UpstreamConfig, UpstreamTlsTrustConfig, UpstreamTlsTrustProfileConfig, XdpConfig,
};
use super::{Config, RuntimeConfig};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Deserializer};
use serde_json::json;
use std::collections::HashMap;

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(default)]
            state_dir: Option<String>,
            #[serde(default)]
            identity: IdentityConfig,
            #[serde(default)]
            messages: MessagesConfig,
            #[serde(default)]
            runtime: RuntimeConfig,
            #[serde(default)]
            telemetry: TelemetryConfig,
            #[serde(default)]
            security: SecurityConfig,
            #[serde(default)]
            http: HttpGlobalConfig,
            #[serde(default)]
            traffic: TrafficConfig,
            #[serde(default)]
            upstreams: Vec<UpstreamConfig>,
            #[serde(default)]
            caches: Vec<CacheBackendConfig>,
            #[serde(default)]
            acme: Option<AcmeConfig>,
            #[serde(default)]
            edges: Vec<EdgeInputConfig>,
        }

        let fields = Fields::deserialize(deserializer)?;
        let mut edges = Vec::new();
        let module_chains = build_module_chain_registry(&fields.http.module_chains)
            .map_err(serde::de::Error::custom)?;
        for edge in fields.edges {
            match edge {
                EdgeInputConfig::Forward(edge) => {
                    edges.push(EdgeConfig::Forward(
                        edge.load(&module_chains)
                            .map_err(serde::de::Error::custom)?,
                    ));
                }
                EdgeInputConfig::Transparent(edge) => {
                    edges.push(EdgeConfig::Transparent(
                        edge.load(&module_chains)
                            .map_err(serde::de::Error::custom)?,
                    ));
                }
                EdgeInputConfig::Reverse(edge) => {
                    edges.push(EdgeConfig::Reverse(
                        edge.load(&module_chains)
                            .map_err(serde::de::Error::custom)?,
                    ));
                }
            }
        }

        Ok(Config {
            state_dir: fields.state_dir,
            identity: fields.identity,
            messages: fields.messages,
            runtime: fields.runtime,
            telemetry: fields.telemetry,
            security: fields.security,
            http: fields.http,
            traffic: fields.traffic,
            acme: fields.acme,
            edges,
            upstreams: fields.upstreams,
            caches: fields.caches,
        })
    }
}

pub fn canonical_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "qpxd canonical configuration",
        "type": "object",
        "required": ["edges"],
        "additionalProperties": false,
        "$defs": {
            "capturePolicy": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "encrypted": {"type": "boolean", "default": false},
                    "plaintext": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "enabled": {"type": "boolean", "default": false},
                            "headers": {"type": "boolean", "default": false},
                            "body": {"type": "boolean", "default": false},
                            "sample_percent": {"type": "integer", "minimum": 0, "maximum": 100},
                            "max_body_bytes": {"type": "integer", "minimum": 1},
                            "redact": {"$ref": "#/$defs/captureRedaction"}
                        }
                    }
                }
            },
            "captureRedaction": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "headers": {"type": "array", "items": {"type": "string"}},
                    "query_keys": {"type": "array", "items": {"type": "string"}},
                    "json_paths": {"type": "array", "items": {"type": "string"}}
                }
            },
            "routeTarget": {
                "oneOf": [
                    {"type": "object", "required": ["type", "upstreams"], "additionalProperties": false, "properties": {"type": {"const": "upstream"}, "upstreams": {"type": "array", "items": {"type": "string"}}, "lb": {"type": "string"}}},
                    {"type": "object", "required": ["type", "backends"], "additionalProperties": false, "properties": {"type": {"const": "weighted"}, "backends": {"type": "array", "items": {"type": "object"}}}},
                    {"type": "object", "required": ["type", "endpoint"], "additionalProperties": false, "properties": {"type": {"const": "ipc"}, "endpoint": {"type": "string"}, "mode": {"enum": ["shm", "tcp"]}, "timeout_ms": {"type": "integer", "minimum": 1}, "body": {"$ref": "#/$defs/ipcBodyLimit"}}},
                    {"type": "object", "required": ["type", "response"], "additionalProperties": false, "properties": {"type": {"const": "local_response"}, "response": {"type": "object"}}},
                    {"type": "object", "required": ["type", "upstreams"], "additionalProperties": false, "properties": {"type": {"const": "tls_passthrough"}, "upstreams": {"type": "array", "items": {"type": "string"}}, "lb": {"type": "string"}}}
                ]
            },
            "ipcBodyLimit": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "max_request_bytes": {"type": "integer", "minimum": 1},
                    "max_response_bytes": {"type": "integer", "minimum": 1}
                }
            },
            "originalDst": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "source": {"enum": ["linux_so_original_dst"], "default": "linux_so_original_dst"}
                }
            },
            "httpModule": {
                "type": "object",
                "required": ["type"],
                "additionalProperties": false,
                "properties": {
                    "type": {"type": "string"},
                    "id": {"type": "string"},
                    "order": {"type": "integer"},
                    "settings": true
                }
            },
            "httpPolicy": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "response_rules": {"type": "array", "items": {"type": "object"}}
                }
            },
            "commonEdgeFields": {
                "type": "object",
                "properties": {
                    "tls_inspection": {"type": "object"},
                    "connection_filter": {"type": "array", "items": {"type": "object"}},
                    "rules": {"type": "array", "items": {"type": "object"}},
                    "http3": {"type": "object"},
                    "ftp": {"type": "object"},
                    "xdp": {"type": "object"},
                    "cache": {"type": "object"},
                    "capture": {"$ref": "#/$defs/capturePolicy"},
                    "rate_limit": {"type": "object"},
                    "policy_context": {"type": "object"},
                    "destination_resolution": {"type": "object"},
                    "http": {"$ref": "#/$defs/httpPolicy"},
                    "http_guard_profile": {"type": "string"},
                    "modules": {"type": "array", "items": {"type": "string"}},
                    "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}
                }
            }
        },
        "properties": {
            "state_dir": {"type": "string"},
            "identity": {"type": "object"},
            "messages": {"type": "object"},
            "runtime": {"type": "object"},
            "telemetry": {"type": "object"},
            "security": {"type": "object"},
            "http": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "guard_profiles": {"type": "array", "items": {"type": "object"}},
                    "module_chains": {"type": "array", "items": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}, "modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}}}}
                }
            },
            "traffic": {"type": "object"},
            "upstreams": {"type": "array"},
            "caches": {"type": "array"},
            "acme": {"type": "object"},
            "edges": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {"allOf": [{"$ref": "#/$defs/commonEdgeFields"}, {"type": "object", "required": ["kind", "name", "listen", "default_action"], "additionalProperties": false, "properties": {"kind": {"const": "forward"}, "name": {"type": "string"}, "listen": {"type": "string"}, "default_action": {"type": "object"}, "upstream_proxy": {"type": "string"}, "tls_inspection": {"type": "object"}, "connection_filter": {"type": "array", "items": {"type": "object"}}, "rules": {"type": "array", "items": {"type": "object"}}, "http3": {"type": "object"}, "ftp": {"type": "object"}, "xdp": {"type": "object"}, "cache": {"type": "object"}, "capture": {"$ref": "#/$defs/capturePolicy"}, "rate_limit": {"type": "object"}, "policy_context": {"type": "object"}, "destination_resolution": {"type": "object"}, "http": {"$ref": "#/$defs/httpPolicy"}, "http_guard_profile": {"type": "string"}, "modules": {"type": "array", "items": {"type": "string"}}, "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}}}]},
                        {"type": "object", "required": ["kind", "name", "listen"], "additionalProperties": false, "properties": {"kind": {"const": "reverse"}, "name": {"type": "string"}, "listen": {"type": "string"}, "tls": {"type": "object"}, "http3": {"type": "object"}, "xdp": {"type": "object"}, "enforce_sni_host_match": {"type": "boolean"}, "sni_host_exceptions": {"type": "array", "items": {"type": "string"}}, "policy_context": {"type": "object"}, "destination_resolution": {"type": "object"}, "connection_filter": {"type": "array", "items": {"type": "object"}}, "routes": {"type": "array", "items": {"type": "object", "required": ["match", "target"], "additionalProperties": false, "properties": {"name": {"type": "string"}, "match": {"type": "object"}, "target": {"$ref": "#/$defs/routeTarget"}, "mirrors": {"type": "array", "items": {"type": "object"}}, "headers": {"type": "object"}, "timeout_ms": {"type": "integer", "minimum": 1}, "health_check": {"type": "object"}, "resilience": {"type": "object"}, "cache": {"type": "object"}, "capture": {"$ref": "#/$defs/capturePolicy"}, "rate_limit": {"type": "object"}, "path_rewrite": {"type": "object"}, "upstream_trust_profile": {"type": "string"}, "upstream_trust": {"type": "object"}, "lifecycle": {"type": "object"}, "affinity": {"type": "object"}, "policy_context": {"type": "object"}, "destination_resolution": {"type": "object"}, "http": {"$ref": "#/$defs/httpPolicy"}, "http_guard_profile": {"type": "string"}, "modules": {"type": "array", "items": {"type": "string"}}, "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}}}}, "tls_passthrough_routes": {"type": "array", "items": {"type": "object"}}}},
                        {"allOf": [{"$ref": "#/$defs/commonEdgeFields"}, {"type": "object", "required": ["kind", "name", "listen", "default_action"], "additionalProperties": false, "properties": {"kind": {"const": "transparent"}, "name": {"type": "string"}, "listen": {"type": "string"}, "default_action": {"type": "object"}, "original_dst": {"$ref": "#/$defs/originalDst"}, "tls_inspection": {"type": "object"}, "connection_filter": {"type": "array", "items": {"type": "object"}}, "rules": {"type": "array", "items": {"type": "object"}}, "http3": {"type": "object"}, "ftp": {"type": "object"}, "xdp": {"type": "object"}, "cache": {"type": "object"}, "capture": {"$ref": "#/$defs/capturePolicy"}, "rate_limit": {"type": "object"}, "policy_context": {"type": "object"}, "destination_resolution": {"type": "object"}, "http": {"$ref": "#/$defs/httpPolicy"}, "http_guard_profile": {"type": "string"}, "modules": {"type": "array", "items": {"type": "string"}}, "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}}}]}
                    ]
                }
            }
        }
    })
}

type ModuleChainRegistry = HashMap<String, Vec<HttpModuleConfig>>;

fn build_module_chain_registry(chains: &[HttpModuleChainConfig]) -> Result<ModuleChainRegistry> {
    let mut registry = HashMap::new();
    for chain in chains {
        if chain.name.trim().is_empty() {
            return Err(anyhow!("http.module_chains[].name must not be empty"));
        }
        if registry
            .insert(chain.name.clone(), chain.modules.clone())
            .is_some()
        {
            return Err(anyhow!("duplicate http.module_chains name: {}", chain.name));
        }
    }
    Ok(registry)
}

fn expand_module_refs(
    refs: &[String],
    inline: Vec<HttpModuleConfig>,
    chains: &ModuleChainRegistry,
    context: &str,
) -> Result<Vec<HttpModuleConfig>> {
    let mut modules = Vec::new();
    for name in refs {
        let chain = chains.get(name).ok_or_else(|| {
            anyhow!("{context} references unknown http.module_chains entry: {name}")
        })?;
        modules.extend(chain.iter().cloned());
    }
    modules.extend(inline);
    Ok(modules)
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub system_log: super::SystemLogConfig,
    #[serde(default)]
    pub access_log: AccessLogConfig,
    #[serde(default)]
    pub audit_log: AuditLogConfig,
    #[serde(default)]
    pub metrics: Option<super::MetricsConfig>,
    #[serde(default)]
    pub otel: Option<super::OtelConfig>,
    #[serde(default)]
    pub exporter: Option<ExporterConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub identity_sources: Vec<IdentitySourceConfig>,
    #[serde(default)]
    pub decisions: DecisionConfig,
    #[serde(default)]
    pub destination: DestinationResolutionConfig,
    #[serde(default)]
    pub named_sets: Vec<NamedSetConfig>,
    #[serde(default)]
    pub upstream_trust_profiles: Vec<UpstreamTlsTrustProfileConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionConfig {
    #[serde(default)]
    pub ext_authz: Vec<ExtAuthzConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpGlobalConfig {
    #[serde(default)]
    pub guard_profiles: Vec<HttpGuardProfileConfig>,
    #[serde(default)]
    pub module_chains: Vec<HttpModuleChainConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpModuleChainConfig {
    pub name: String,
    #[serde(default)]
    pub modules: Vec<HttpModuleConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrafficConfig {
    #[serde(default)]
    pub rate_limit_profiles: Vec<RateLimitProfileConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EdgeInputConfig {
    Forward(ForwardEdgeInputConfig),
    Reverse(ReverseEdgeInputConfig),
    Transparent(TransparentEdgeInputConfig),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ForwardEdgeInputConfig {
    pub name: String,
    pub listen: String,
    pub default_action: super::ActionConfig,
    #[serde(default)]
    pub tls_inspection: Option<TlsInspectionConfig>,
    #[serde(default)]
    pub connection_filter: Vec<RuleConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub upstream_proxy: Option<String>,
    #[serde(default)]
    pub http3: Option<Http3IngressEdgeConfig>,
    #[serde(default)]
    pub ftp: FtpConfig,
    #[serde(default)]
    pub xdp: Option<XdpConfig>,
    #[serde(default)]
    pub cache: Option<CachePolicyConfig>,
    #[serde(default)]
    pub capture: Option<CapturePolicyConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub policy_context: Option<super::PolicyContextConfig>,
    #[serde(default)]
    pub destination_resolution: Option<DestinationResolutionOverrideConfig>,
    #[serde(default)]
    pub http: Option<HttpPolicyConfig>,
    #[serde(default)]
    pub http_guard_profile: Option<String>,
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub http_modules: Vec<HttpModuleConfig>,
}

impl ForwardEdgeInputConfig {
    fn load(self, chains: &ModuleChainRegistry) -> Result<IngressEdgeConfig> {
        let context = format!("edge {}", self.name);
        let http_modules =
            expand_module_refs(&self.modules, self.http_modules, chains, context.as_str())?;
        Ok(IngressEdgeConfig {
            name: self.name,
            mode: IngressEdgeMode::Forward,
            listen: self.listen,
            default_action: self.default_action,
            original_dst: None,
            tls_inspection: self.tls_inspection,
            rules: self.rules,
            connection_filter: self.connection_filter,
            upstream_proxy: self.upstream_proxy,
            http3: self.http3,
            ftp: self.ftp,
            xdp: self.xdp,
            cache: self.cache,
            capture: self.capture,
            rate_limit: self.rate_limit,
            policy_context: self.policy_context,
            destination_resolution: self.destination_resolution,
            http: self.http,
            http_guard_profile: self.http_guard_profile,
            http_modules,
        })
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TransparentEdgeInputConfig {
    pub name: String,
    pub listen: String,
    pub default_action: super::ActionConfig,
    #[serde(default)]
    pub original_dst: Option<OriginalDstConfig>,
    #[serde(default)]
    pub connection_filter: Vec<RuleConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub tls_inspection: Option<TlsInspectionConfig>,
    #[serde(default)]
    pub http3: Option<Http3IngressEdgeConfig>,
    #[serde(default)]
    pub ftp: FtpConfig,
    #[serde(default)]
    pub xdp: Option<XdpConfig>,
    #[serde(default)]
    pub cache: Option<CachePolicyConfig>,
    #[serde(default)]
    pub capture: Option<CapturePolicyConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub policy_context: Option<super::PolicyContextConfig>,
    #[serde(default)]
    pub destination_resolution: Option<DestinationResolutionOverrideConfig>,
    #[serde(default)]
    pub http: Option<HttpPolicyConfig>,
    #[serde(default)]
    pub http_guard_profile: Option<String>,
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub http_modules: Vec<HttpModuleConfig>,
}

impl TransparentEdgeInputConfig {
    fn load(self, chains: &ModuleChainRegistry) -> Result<IngressEdgeConfig> {
        let context = format!("edge {}", self.name);
        let http_modules =
            expand_module_refs(&self.modules, self.http_modules, chains, context.as_str())?;
        Ok(IngressEdgeConfig {
            name: self.name,
            mode: IngressEdgeMode::Transparent,
            listen: self.listen,
            default_action: self.default_action,
            original_dst: self.original_dst,
            tls_inspection: self.tls_inspection,
            rules: self.rules,
            connection_filter: self.connection_filter,
            upstream_proxy: None,
            http3: self.http3,
            ftp: self.ftp,
            xdp: self.xdp,
            cache: self.cache,
            capture: self.capture,
            rate_limit: self.rate_limit,
            policy_context: self.policy_context,
            destination_resolution: self.destination_resolution,
            http: self.http,
            http_guard_profile: self.http_guard_profile,
            http_modules,
        })
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReverseEdgeInputConfig {
    pub name: String,
    pub listen: String,
    #[serde(default)]
    pub tls: Option<ReverseTlsConfig>,
    #[serde(default)]
    pub http3: Option<ReverseHttp3Config>,
    #[serde(default)]
    pub xdp: Option<XdpConfig>,
    #[serde(default = "super::super::defaults::default_reverse_enforce_sni_host_match")]
    pub enforce_sni_host_match: bool,
    #[serde(default)]
    pub sni_host_exceptions: Vec<String>,
    #[serde(default)]
    pub policy_context: Option<super::PolicyContextConfig>,
    #[serde(default)]
    pub destination_resolution: Option<DestinationResolutionOverrideConfig>,
    #[serde(default)]
    pub connection_filter: Vec<RuleConfig>,
    #[serde(default)]
    pub routes: Vec<ReverseRouteInputConfig>,
    #[serde(default)]
    pub tls_passthrough_routes: Vec<ReverseTlsPassthroughRouteConfig>,
}

impl ReverseEdgeInputConfig {
    fn load(self, chains: &ModuleChainRegistry) -> Result<ReverseEdgeConfig> {
        let mut routes = Vec::new();
        let mut tls_passthrough_routes = self.tls_passthrough_routes;
        for route in self.routes {
            match route.into_route_or_passthrough(chains, self.name.as_str())? {
                LoadedReverseRoute::Http(route) => routes.push(*route),
                LoadedReverseRoute::TlsPassthrough(route) => tls_passthrough_routes.push(*route),
            }
        }
        Ok(ReverseEdgeConfig {
            name: self.name,
            listen: self.listen,
            tls: self.tls,
            http3: self.http3,
            xdp: self.xdp,
            enforce_sni_host_match: self.enforce_sni_host_match,
            sni_host_exceptions: self.sni_host_exceptions,
            policy_context: self.policy_context,
            destination_resolution: self.destination_resolution,
            connection_filter: self.connection_filter,
            routes,
            tls_passthrough_routes,
        })
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReverseRouteInputConfig {
    #[serde(default)]
    pub name: Option<String>,
    pub r#match: MatchConfig,
    pub target: RouteTargetConfig,
    #[serde(default)]
    pub mirrors: Vec<ReverseRouteMirrorConfig>,
    #[serde(default)]
    pub headers: Option<HeaderControl>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub resilience: Option<ResilienceConfig>,
    #[serde(default)]
    pub cache: Option<CachePolicyConfig>,
    #[serde(default)]
    pub capture: Option<CapturePolicyConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub path_rewrite: Option<super::PathRewriteConfig>,
    #[serde(default)]
    pub upstream_trust_profile: Option<String>,
    #[serde(default)]
    pub upstream_trust: Option<UpstreamTlsTrustConfig>,
    #[serde(default)]
    pub lifecycle: Option<super::EndpointLifecycleConfig>,
    #[serde(default)]
    pub affinity: Option<ReverseAffinityConfig>,
    #[serde(default)]
    pub policy_context: Option<super::PolicyContextConfig>,
    #[serde(default)]
    pub destination_resolution: Option<DestinationResolutionOverrideConfig>,
    #[serde(default)]
    pub http: Option<HttpPolicyConfig>,
    #[serde(default)]
    pub http_guard_profile: Option<String>,
    #[serde(default)]
    pub modules: Vec<String>,
    #[serde(default)]
    pub http_modules: Vec<HttpModuleConfig>,
}

impl ReverseRouteInputConfig {
    fn into_route_or_passthrough(
        self,
        chains: &ModuleChainRegistry,
        edge_name: &str,
    ) -> Result<LoadedReverseRoute> {
        let route_context = self
            .name
            .as_deref()
            .map(|name| format!("edge {edge_name} route {name}"))
            .unwrap_or_else(|| format!("edge {edge_name} route <unnamed>"));
        match self.target {
            RouteTargetConfig::TlsPassthrough { upstreams, lb } => Ok(
                LoadedReverseRoute::TlsPassthrough(Box::new(ReverseTlsPassthroughRouteConfig {
                    r#match: TlsPassthroughMatchConfig {
                        src_ip: self.r#match.src_ip,
                        dst_port: self.r#match.dst_port,
                        sni: self.r#match.sni,
                    },
                    upstreams,
                    lb,
                    timeout_ms: self.timeout_ms,
                    health_check: self.health_check,
                    resilience: self.resilience,
                    lifecycle: self.lifecycle,
                    affinity: self.affinity,
                })),
            ),
            target => {
                let http_modules = expand_module_refs(
                    &self.modules,
                    self.http_modules,
                    chains,
                    route_context.as_str(),
                )?;
                let mut route = ReverseRouteConfig {
                    name: self.name,
                    r#match: self.r#match,
                    target: ReverseRouteTargetConfig::LocalResponse {
                        response: Box::new(LocalResponseConfig {
                            status: 500,
                            body: String::new(),
                            content_type: None,
                            headers: Default::default(),
                            rpc: None,
                        }),
                    },
                    mirrors: self.mirrors,
                    headers: self.headers,
                    timeout_ms: self.timeout_ms,
                    health_check: self.health_check,
                    resilience: self.resilience,
                    cache: self.cache,
                    capture: self.capture,
                    rate_limit: self.rate_limit,
                    path_rewrite: self.path_rewrite,
                    upstream_trust_profile: self.upstream_trust_profile,
                    upstream_trust: self.upstream_trust,
                    lifecycle: self.lifecycle,
                    affinity: self.affinity,
                    policy_context: self.policy_context,
                    destination_resolution: self.destination_resolution,
                    http: self.http,
                    http_guard_profile: self.http_guard_profile,
                    http_modules,
                };
                match target {
                    RouteTargetConfig::Upstream { upstreams, lb } => {
                        route.target = ReverseRouteTargetConfig::Upstream { upstreams, lb };
                    }
                    RouteTargetConfig::Weighted { backends } => {
                        route.target = ReverseRouteTargetConfig::Weighted {
                            backends,
                            lb: super::super::defaults::default_lb(),
                        };
                    }
                    RouteTargetConfig::Ipc {
                        endpoint,
                        mode,
                        timeout_ms,
                        body,
                    } => {
                        route.target = ReverseRouteTargetConfig::Ipc {
                            config: IpcUpstreamConfig {
                                mode,
                                address: endpoint,
                                timeout_ms,
                                body,
                            },
                        };
                    }
                    RouteTargetConfig::LocalResponse { response } => {
                        route.target = ReverseRouteTargetConfig::LocalResponse { response };
                    }
                    RouteTargetConfig::TlsPassthrough { .. } => unreachable!(),
                }
                Ok(LoadedReverseRoute::Http(Box::new(route)))
            }
        }
    }
}

enum LoadedReverseRoute {
    Http(Box<ReverseRouteConfig>),
    TlsPassthrough(Box<ReverseTlsPassthroughRouteConfig>),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RouteTargetConfig {
    Upstream {
        upstreams: Vec<String>,
        #[serde(default = "super::super::defaults::default_lb")]
        lb: String,
    },
    Weighted {
        backends: Vec<ReverseRouteBackendConfig>,
    },
    Ipc {
        endpoint: String,
        #[serde(default)]
        mode: IpcMode,
        #[serde(default = "super::super::defaults::default_ipc_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        body: IpcBodyLimitConfig,
    },
    LocalResponse {
        response: Box<LocalResponseConfig>,
    },
    TlsPassthrough {
        upstreams: Vec<String>,
        #[serde(default = "super::super::defaults::default_lb")]
        lb: String,
    },
}
