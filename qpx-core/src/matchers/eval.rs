use crate::prefilter::is_ascii_uppercase_token;
use crate::rules::RuleMatchContext;

use super::CompiledMatch;
use super::headers::{fast_headers_match, regex_headers_match};
use super::identity::match_optional_text;
use super::numeric::match_optional_numeric;

impl CompiledMatch {
    pub fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        if !self.src_ip.is_empty() {
            let Some(ip) = ctx.src_ip else {
                return false;
            };
            if !self.src_ip.iter().any(|cidr| cidr.contains(&ip)) {
                return false;
            }
        }

        if !self.dst_port.is_empty() {
            let Some(port) = ctx.dst_port else {
                return false;
            };
            if !self.dst_port.contains(&port) {
                return false;
            }
        }

        if let Some(host_matcher) = &self.host {
            let host = match ctx.host {
                Some(host) => host,
                None => return false,
            };
            if !host_matcher.matches(host) {
                return false;
            }
        }

        if let Some(sni_matcher) = &self.sni {
            let sni = match ctx.sni {
                Some(sni) => sni,
                None => return false,
            };
            if !sni_matcher.matches(sni) {
                return false;
            }
        }

        if !self.method.is_empty() {
            let method = match ctx.method {
                Some(method) => method,
                None => return false,
            };
            if !self.method.contains(method) {
                if is_ascii_uppercase_token(method) {
                    return false;
                }
                let upper = method.to_ascii_uppercase();
                if !self.method.contains(upper.as_str()) {
                    return false;
                }
            }
        }

        if let Some(path_matcher) = &self.path {
            let path = match ctx.path {
                Some(path) => path,
                None => return false,
            };
            if !path_matcher.matches(path) {
                return false;
            }
        }

        if !match_optional_text(&self.query, ctx.query)
            || !match_optional_text(&self.authority, ctx.authority)
            || !match_optional_text(&self.scheme, ctx.scheme)
            || !match_optional_text(&self.http_version, ctx.http_version)
            || !match_optional_text(&self.alpn, ctx.alpn)
            || !match_optional_text(&self.tls_version, ctx.tls_version)
            || !match_optional_numeric(&self.request_size, ctx.request_size)
            || !match_optional_numeric(&self.response_status, ctx.response_status.map(u64::from))
            || !match_optional_numeric(&self.response_size, ctx.response_size)
        {
            return false;
        }

        if let Some(destination) = &self.destination
            && !destination.matches(ctx)
        {
            return false;
        }

        if !fast_headers_match(&self.headers_fast, ctx.headers)
            || !regex_headers_match(&self.headers_regex, ctx.headers)
        {
            return false;
        }

        if let Some(identity) = &self.identity
            && !identity.matches(ctx)
        {
            return false;
        }

        if let Some(fingerprint) = &self.tls_fingerprint
            && !fingerprint.matches(ctx)
        {
            return false;
        }

        if let Some(cert) = &self.client_cert
            && !cert.matches(
                ctx.client_cert_present,
                ctx.client_cert_subject,
                ctx.client_cert_issuer,
                ctx.client_cert_san_dns,
                ctx.client_cert_san_uri,
                ctx.client_cert_fingerprint_sha256,
            )
        {
            return false;
        }

        if let Some(cert) = &self.upstream_cert
            && !cert.matches(
                ctx.upstream_cert_present,
                ctx.upstream_cert_subject,
                ctx.upstream_cert_issuer,
                ctx.upstream_cert_san_dns,
                ctx.upstream_cert_san_uri,
                ctx.upstream_cert_fingerprint_sha256,
            )
        {
            return false;
        }

        if let Some(rpc) = &self.rpc
            && !rpc.matches(ctx)
        {
            return false;
        }

        true
    }

    pub fn requires_request_size(&self) -> bool {
        self.request_size.is_some()
            || self
                .rpc
                .as_ref()
                .map(|rpc| rpc.requires_request_body_observation())
                .unwrap_or(false)
    }

    pub fn requires_request_body_observation(&self) -> bool {
        self.rpc
            .as_ref()
            .map(|rpc| rpc.requires_request_body_observation())
            .unwrap_or(false)
    }

    pub fn requires_request_rpc_context(&self) -> bool {
        self.rpc.is_some()
    }

    pub fn requires_response_size(&self) -> bool {
        self.response_size.is_some()
            || self
                .rpc
                .as_ref()
                .map(|rpc| rpc.requires_response_body_observation())
                .unwrap_or(false)
    }

    pub fn requires_response_body_observation(&self) -> bool {
        self.rpc
            .as_ref()
            .map(|rpc| rpc.requires_response_body_observation())
            .unwrap_or(false)
    }

    pub fn requires_response_context(&self) -> bool {
        self.response_status.is_some()
            || self.response_size.is_some()
            || self
                .rpc
                .as_ref()
                .map(|rpc| rpc.requires_response_context())
                .unwrap_or(false)
    }

    pub fn requires_response_rpc_context(&self) -> bool {
        self.rpc
            .as_ref()
            .map(|rpc| rpc.requires_any_response_rule_rpc_context())
            .unwrap_or(false)
    }

    pub fn requires_response_rpc_observation(&self) -> bool {
        self.rpc
            .as_ref()
            .map(|rpc| rpc.requires_response_observation())
            .unwrap_or(false)
    }

    pub fn requires_response_request_rpc_context(&self) -> bool {
        self.rpc
            .as_ref()
            .map(|rpc| rpc.requires_request_context_for_response_rule())
            .unwrap_or(false)
    }

    pub fn requires_response_request_body_observation(&self) -> bool {
        self.rpc
            .as_ref()
            .map(|rpc| rpc.requires_request_body_observation_for_response_rule())
            .unwrap_or(false)
    }
}
