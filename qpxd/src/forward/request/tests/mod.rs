use super::*;
use crate::runtime::Runtime;
use crate::test_util::{decode_gzip, spawn_static_http_server};
use http::StatusCode;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config, ExtAuthzConfig,
    ExtAuthzSendConfig, HttpModuleConfig, HttpPolicyConfig, HttpResponseEffectsConfig,
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
