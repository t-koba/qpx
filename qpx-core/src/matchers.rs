use crate::config::{
    CertificateMatchConfig, HeaderMatch, IdentityMatchConfig, MatchConfig, RpcMatchConfig,
    TlsFingerprintMatchConfig, TlsPassthroughMatchConfig,
};
use crate::prefilter::{
    compile_text_patterns, dedup_uppercase_arc, is_ascii_uppercase_token, StringInterner,
    TextPatternMatcher,
};
use crate::rules::RuleMatchContext;
use anyhow::{anyhow, Result};
use cidr::IpCidr;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CompiledMatch {
    src_ip: Vec<IpCidr>,
    dst_port: HashSet<u16>,
    host: Option<TextPatternMatcher>,
    sni: Option<TextPatternMatcher>,
    method: HashSet<Arc<str>>,
    path: Option<TextPatternMatcher>,
    query: Option<TextPatternMatcher>,
    authority: Option<TextPatternMatcher>,
    scheme: Option<TextPatternMatcher>,
    http_version: Option<TextPatternMatcher>,
    alpn: Option<TextPatternMatcher>,
    tls_version: Option<TextPatternMatcher>,
    destination_category: Option<TextPatternMatcher>,
    destination_category_source: Option<TextPatternMatcher>,
    destination_category_confidence: Option<CompiledNumericMatcher>,
    destination_reputation: Option<TextPatternMatcher>,
    destination_reputation_source: Option<TextPatternMatcher>,
    destination_reputation_confidence: Option<CompiledNumericMatcher>,
    destination_application: Option<TextPatternMatcher>,
    destination_application_source: Option<TextPatternMatcher>,
    destination_application_confidence: Option<CompiledNumericMatcher>,
    request_size: Option<CompiledNumericMatcher>,
    response_status: Option<CompiledNumericMatcher>,
    response_size: Option<CompiledNumericMatcher>,
    headers_fast: Vec<HeaderMatcherFast>,
    headers_regex: Vec<HeaderMatcherRegex>,
    identity: Option<CompiledIdentityMatch>,
    tls_fingerprint: Option<CompiledTlsFingerprintMatch>,
    client_cert: Option<CompiledCertificateMatch>,
    upstream_cert: Option<CompiledCertificateMatch>,
    rpc: Option<CompiledRpcMatch>,
}

#[derive(Debug, Clone)]
struct HeaderMatcherFast {
    name: Arc<str>,
    mode: HeaderFastMode,
}

#[derive(Debug, Clone)]
enum HeaderFastMode {
    Present,
    Exact(Arc<str>),
}

#[derive(Debug, Clone)]
struct HeaderMatcherRegex {
    name: Arc<str>,
    regex: Regex,
}

#[derive(Debug, Clone)]
struct CompiledIdentityMatch {
    user: Option<TextPatternMatcher>,
    groups: Option<TextPatternMatcher>,
    device_id: Option<TextPatternMatcher>,
    posture: Option<TextPatternMatcher>,
    tenant: Option<TextPatternMatcher>,
    auth_strength: Option<TextPatternMatcher>,
    idp: Option<TextPatternMatcher>,
}

#[derive(Debug, Clone)]
struct CompiledTlsFingerprintMatch {
    ja3: Option<TextPatternMatcher>,
    ja4: Option<TextPatternMatcher>,
}

#[derive(Debug, Clone)]
struct CompiledCertificateMatch {
    present: Option<bool>,
    subject: Option<TextPatternMatcher>,
    issuer: Option<TextPatternMatcher>,
    san_dns: Option<TextPatternMatcher>,
    san_uri: Option<TextPatternMatcher>,
    fingerprint_sha256: Option<TextPatternMatcher>,
}

#[derive(Debug, Clone)]
struct CompiledRpcMatch {
    protocol: Option<TextPatternMatcher>,
    service: Option<TextPatternMatcher>,
    method: Option<TextPatternMatcher>,
    streaming: Option<TextPatternMatcher>,
    status: Option<TextPatternMatcher>,
    message_size: Option<CompiledNumericMatcher>,
    message: Option<TextPatternMatcher>,
    trailers_fast: Vec<HeaderMatcherFast>,
    trailers_regex: Vec<HeaderMatcherRegex>,
}

#[derive(Debug, Clone)]
struct CompiledNumericMatcher {
    ranges: Vec<NumericRange>,
}

#[derive(Debug, Clone)]
struct NumericRange {
    min: Option<u64>,
    max: Option<u64>,
}

impl CompiledMatch {
    pub fn compile(
        config: &MatchConfig,
        interner: &mut StringInterner,
    ) -> Result<(Self, crate::prefilter::MatchPrefilterHint)> {
        let src_cidrs = parse_cidrs(&config.src_ip)?;
        let dst_ports = dedup_u16(&config.dst_port);
        let method_values = dedup_uppercase_arc(&config.method, interner);

        let (host, host_hint) = compile_text_patterns(&config.host, true, true, interner)?;
        let (sni, sni_hint) = compile_text_patterns(&config.sni, true, true, interner)?;
        let (path, path_hint) = compile_text_patterns(&config.path, false, false, interner)?;
        let (query, _) = compile_text_patterns(&config.query, false, false, interner)?;
        let (authority, _) = compile_text_patterns(&config.authority, true, true, interner)?;
        let (scheme, _) = compile_text_patterns(&config.scheme, true, false, interner)?;
        let (http_version, _) = compile_text_patterns(&config.http_version, true, false, interner)?;
        let (alpn, _) = compile_text_patterns(&config.alpn, true, false, interner)?;
        let (tls_version, _) = compile_text_patterns(&config.tls_version, true, false, interner)?;
        let destination_match = config.destination.as_ref();
        let category_match =
            destination_match.and_then(|destination| destination.category.as_ref());
        let reputation_match =
            destination_match.and_then(|destination| destination.reputation.as_ref());
        let application_match =
            destination_match.and_then(|destination| destination.application.as_ref());
        let (destination_category, _) = compile_text_patterns(
            category_match
                .map(|dimension| dimension.value.as_slice())
                .unwrap_or(&[]),
            true,
            false,
            interner,
        )?;
        let (destination_category_source, _) = compile_text_patterns(
            category_match
                .map(|dimension| dimension.source.as_slice())
                .unwrap_or(&[]),
            true,
            false,
            interner,
        )?;
        let destination_category_confidence = compile_numeric_matchers(
            category_match
                .map(|dimension| dimension.confidence.as_slice())
                .unwrap_or(&[]),
        )?;
        let (destination_reputation, _) = compile_text_patterns(
            reputation_match
                .map(|dimension| dimension.value.as_slice())
                .unwrap_or(&[]),
            true,
            false,
            interner,
        )?;
        let (destination_reputation_source, _) = compile_text_patterns(
            reputation_match
                .map(|dimension| dimension.source.as_slice())
                .unwrap_or(&[]),
            true,
            false,
            interner,
        )?;
        let destination_reputation_confidence = compile_numeric_matchers(
            reputation_match
                .map(|dimension| dimension.confidence.as_slice())
                .unwrap_or(&[]),
        )?;
        let (destination_application, _) = compile_text_patterns(
            application_match
                .map(|dimension| dimension.value.as_slice())
                .unwrap_or(&[]),
            true,
            false,
            interner,
        )?;
        let (destination_application_source, _) = compile_text_patterns(
            application_match
                .map(|dimension| dimension.source.as_slice())
                .unwrap_or(&[]),
            true,
            false,
            interner,
        )?;
        let destination_application_confidence = compile_numeric_matchers(
            application_match
                .map(|dimension| dimension.confidence.as_slice())
                .unwrap_or(&[]),
        )?;
        let request_size = compile_numeric_matchers(&config.request_size)?;
        let response_status = compile_numeric_matchers(&config.response_status)?;
        let response_size = compile_numeric_matchers(&config.response_size)?;
        let (headers_fast, headers_regex) = build_header_matchers(&config.headers, interner)?;
        let identity = config
            .identity
            .as_ref()
            .map(|identity| CompiledIdentityMatch::compile(identity, interner))
            .transpose()?;
        let tls_fingerprint = config
            .tls_fingerprint
            .as_ref()
            .map(|raw| CompiledTlsFingerprintMatch::compile(raw, interner))
            .transpose()?;
        let client_cert = config
            .client_cert
            .as_ref()
            .map(|raw| CompiledCertificateMatch::compile(raw, interner))
            .transpose()?;
        let upstream_cert = config
            .upstream_cert
            .as_ref()
            .map(|raw| CompiledCertificateMatch::compile(raw, interner))
            .transpose()?;
        let rpc = config
            .rpc
            .as_ref()
            .map(|raw| CompiledRpcMatch::compile(raw, interner))
            .transpose()?;

        let mut dst_port = HashSet::new();
        dst_port.extend(dst_ports.iter().copied());
        let method: HashSet<Arc<str>> = method_values.iter().cloned().collect();

        Ok((
            Self {
                src_ip: src_cidrs.clone(),
                dst_port,
                host,
                sni,
                method,
                path,
                query,
                authority,
                scheme,
                http_version,
                alpn,
                tls_version,
                destination_category,
                destination_category_source,
                destination_category_confidence,
                destination_reputation,
                destination_reputation_source,
                destination_reputation_confidence,
                destination_application,
                destination_application_source,
                destination_application_confidence,
                request_size,
                response_status,
                response_size,
                headers_fast,
                headers_regex,
                identity,
                tls_fingerprint,
                client_cert,
                upstream_cert,
                rpc,
            },
            crate::prefilter::MatchPrefilterHint {
                method_values,
                dst_ports,
                src_cidrs,
                host: host_hint,
                sni: sni_hint,
                path: path_hint,
            },
        ))
    }

    pub fn compile_tls_passthrough(
        config: &TlsPassthroughMatchConfig,
        interner: &mut StringInterner,
    ) -> Result<(Self, crate::prefilter::MatchPrefilterHint)> {
        let src_cidrs = parse_cidrs(&config.src_ip)?;
        let dst_ports = dedup_u16(&config.dst_port);
        let (sni, sni_hint) = compile_text_patterns(&config.sni, true, true, interner)?;

        let mut dst_port = HashSet::new();
        dst_port.extend(dst_ports.iter().copied());
        Ok((
            Self {
                src_ip: src_cidrs.clone(),
                dst_port,
                host: None,
                sni,
                method: HashSet::new(),
                path: None,
                query: None,
                authority: None,
                scheme: None,
                http_version: None,
                alpn: None,
                tls_version: None,
                destination_category: None,
                destination_category_source: None,
                destination_category_confidence: None,
                destination_reputation: None,
                destination_reputation_source: None,
                destination_reputation_confidence: None,
                destination_application: None,
                destination_application_source: None,
                destination_application_confidence: None,
                request_size: None,
                response_status: None,
                response_size: None,
                headers_fast: Vec::new(),
                headers_regex: Vec::new(),
                identity: None,
                tls_fingerprint: None,
                client_cert: None,
                upstream_cert: None,
                rpc: None,
            },
            crate::prefilter::MatchPrefilterHint {
                method_values: Vec::new(),
                dst_ports,
                src_cidrs,
                host: crate::prefilter::TextPrefilterHint {
                    any: true,
                    ..Default::default()
                },
                sni: sni_hint,
                path: crate::prefilter::TextPrefilterHint {
                    any: true,
                    ..Default::default()
                },
            },
        ))
    }

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
                Some(m) => m,
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

        if !match_optional_text(&self.query, ctx.query) {
            return false;
        }
        if !match_optional_text(&self.authority, ctx.authority) {
            return false;
        }
        if !match_optional_text(&self.scheme, ctx.scheme) {
            return false;
        }
        if !match_optional_text(&self.http_version, ctx.http_version) {
            return false;
        }
        if !match_optional_text(&self.alpn, ctx.alpn) {
            return false;
        }
        if !match_optional_text(&self.tls_version, ctx.tls_version) {
            return false;
        }
        if !match_optional_text(&self.destination_category, ctx.destination_category) {
            return false;
        }
        if !match_optional_text(
            &self.destination_category_source,
            ctx.destination_category_source,
        ) {
            return false;
        }
        if !match_optional_numeric(
            &self.destination_category_confidence,
            ctx.destination_category_confidence,
        ) {
            return false;
        }
        if !match_optional_text(&self.destination_reputation, ctx.destination_reputation) {
            return false;
        }
        if !match_optional_text(
            &self.destination_reputation_source,
            ctx.destination_reputation_source,
        ) {
            return false;
        }
        if !match_optional_numeric(
            &self.destination_reputation_confidence,
            ctx.destination_reputation_confidence,
        ) {
            return false;
        }
        if !match_optional_text(&self.destination_application, ctx.destination_application) {
            return false;
        }
        if !match_optional_text(
            &self.destination_application_source,
            ctx.destination_application_source,
        ) {
            return false;
        }
        if !match_optional_numeric(
            &self.destination_application_confidence,
            ctx.destination_application_confidence,
        ) {
            return false;
        }
        if !match_optional_numeric(&self.request_size, ctx.request_size) {
            return false;
        }
        if !match_optional_numeric(&self.response_status, ctx.response_status.map(|v| v as u64)) {
            return false;
        }
        if !match_optional_numeric(&self.response_size, ctx.response_size) {
            return false;
        }

        if !self.headers_fast.is_empty() {
            let headers = match ctx.headers {
                Some(h) => h,
                None => return false,
            };
            for matcher in &self.headers_fast {
                let mut matched = false;
                for value in headers.get_all(matcher.name.as_ref()).iter() {
                    let Ok(v) = value.to_str() else {
                        continue;
                    };
                    match &matcher.mode {
                        HeaderFastMode::Present => {
                            matched = true;
                            break;
                        }
                        HeaderFastMode::Exact(expected) => {
                            if v == expected.as_ref() {
                                matched = true;
                                break;
                            }
                        }
                    }
                }
                if !matched {
                    return false;
                }
            }
        }

        if !self.headers_regex.is_empty() {
            let headers = match ctx.headers {
                Some(h) => h,
                None => return false,
            };
            for matcher in &self.headers_regex {
                let mut matched = false;
                for value in headers.get_all(matcher.name.as_ref()).iter() {
                    let Ok(v) = value.to_str() else {
                        continue;
                    };
                    if matcher.regex.is_match(v) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    return false;
                }
            }
        }

        if let Some(identity) = &self.identity {
            if !identity.matches(ctx) {
                return false;
            }
        }

        if let Some(fingerprint) = &self.tls_fingerprint {
            if !fingerprint.matches(ctx) {
                return false;
            }
        }

        if let Some(cert) = &self.client_cert {
            if !cert.matches(
                ctx.client_cert_present,
                ctx.client_cert_subject,
                ctx.client_cert_issuer,
                ctx.client_cert_san_dns,
                ctx.client_cert_san_uri,
                ctx.client_cert_fingerprint_sha256,
            ) {
                return false;
            }
        }

        if let Some(cert) = &self.upstream_cert {
            if !cert.matches(
                ctx.upstream_cert_present,
                ctx.upstream_cert_subject,
                ctx.upstream_cert_issuer,
                ctx.upstream_cert_san_dns,
                ctx.upstream_cert_san_uri,
                ctx.upstream_cert_fingerprint_sha256,
            ) {
                return false;
            }
        }

        if let Some(rpc) = &self.rpc {
            if !rpc.matches(ctx) {
                return false;
            }
        }

        true
    }

    pub fn requires_request_size(&self) -> bool {
        self.request_size.is_some()
            || self
                .rpc
                .as_ref()
                .map(CompiledRpcMatch::requires_request_body_observation)
                .unwrap_or(false)
    }

    pub fn requires_request_body_observation(&self) -> bool {
        self.rpc
            .as_ref()
            .map(CompiledRpcMatch::requires_request_body_observation)
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
                .map(CompiledRpcMatch::requires_response_body_observation)
                .unwrap_or(false)
    }

    pub fn requires_response_body_observation(&self) -> bool {
        self.rpc
            .as_ref()
            .map(CompiledRpcMatch::requires_response_body_observation)
            .unwrap_or(false)
    }

    pub fn requires_response_context(&self) -> bool {
        self.response_status.is_some()
            || self.response_size.is_some()
            || self
                .rpc
                .as_ref()
                .map(CompiledRpcMatch::requires_response_context)
                .unwrap_or(false)
    }

    pub fn requires_response_rpc_context(&self) -> bool {
        self.rpc
            .as_ref()
            .map(CompiledRpcMatch::requires_any_response_rule_rpc_context)
            .unwrap_or(false)
    }

    pub fn requires_response_rpc_observation(&self) -> bool {
        self.rpc
            .as_ref()
            .map(CompiledRpcMatch::requires_response_observation)
            .unwrap_or(false)
    }

    pub fn requires_response_request_rpc_context(&self) -> bool {
        self.rpc
            .as_ref()
            .map(CompiledRpcMatch::requires_request_context_for_response_rule)
            .unwrap_or(false)
    }

    pub fn requires_response_request_body_observation(&self) -> bool {
        self.rpc
            .as_ref()
            .map(CompiledRpcMatch::requires_request_body_observation_for_response_rule)
            .unwrap_or(false)
    }
}

impl CompiledRpcMatch {
    fn compile(config: &RpcMatchConfig, interner: &mut StringInterner) -> Result<Self> {
        let (protocol, _) = compile_text_patterns(&config.protocol, true, false, interner)?;
        let (service, _) = compile_text_patterns(&config.service, true, false, interner)?;
        let (method, _) = compile_text_patterns(&config.method, true, false, interner)?;
        let (streaming, _) = compile_text_patterns(&config.streaming, true, false, interner)?;
        let (status, _) = compile_text_patterns(&config.status, true, false, interner)?;
        let message_size = compile_numeric_matchers(&config.message_size)?;
        let (message, _) = compile_text_patterns(&config.message, false, false, interner)?;
        let (trailers_fast, trailers_regex) = build_header_matchers(&config.trailers, interner)?;
        Ok(Self {
            protocol,
            service,
            method,
            streaming,
            status,
            message_size,
            message,
            trailers_fast,
            trailers_regex,
        })
    }

    fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        if !match_optional_text(&self.protocol, ctx.rpc_protocol) {
            return false;
        }
        if !match_optional_text(&self.service, ctx.rpc_service) {
            return false;
        }
        if !match_optional_text(&self.method, ctx.rpc_method) {
            return false;
        }
        if !match_optional_text(&self.streaming, ctx.rpc_streaming) {
            return false;
        }
        if !match_optional_text(&self.status, ctx.rpc_status) {
            return false;
        }
        if !match_optional_numeric(&self.message_size, ctx.rpc_message_size) {
            return false;
        }
        if !match_optional_text(&self.message, ctx.rpc_message) {
            return false;
        }
        if !self.trailers_fast.is_empty() {
            let trailers = match ctx.rpc_trailers {
                Some(value) => value,
                None => return false,
            };
            for matcher in &self.trailers_fast {
                let mut matched = false;
                for value in trailers.get_all(matcher.name.as_ref()).iter() {
                    let Ok(v) = value.to_str() else {
                        continue;
                    };
                    match &matcher.mode {
                        HeaderFastMode::Present => {
                            matched = true;
                            break;
                        }
                        HeaderFastMode::Exact(expected) => {
                            if v == expected.as_ref() {
                                matched = true;
                                break;
                            }
                        }
                    }
                }
                if !matched {
                    return false;
                }
            }
        }
        if !self.trailers_regex.is_empty() {
            let trailers = match ctx.rpc_trailers {
                Some(value) => value,
                None => return false,
            };
            for matcher in &self.trailers_regex {
                let mut matched = false;
                for value in trailers.get_all(matcher.name.as_ref()).iter() {
                    let Ok(v) = value.to_str() else {
                        continue;
                    };
                    if matcher.regex.is_match(v) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    return false;
                }
            }
        }
        true
    }

    fn requires_request_body_observation(&self) -> bool {
        self.message_size.is_some() || self.streaming.is_some()
    }

    fn requires_response_body_observation(&self) -> bool {
        self.message_size.is_some()
            || self.message.is_some()
            || !self.trailers_fast.is_empty()
            || !self.trailers_regex.is_empty()
            || self.status.is_some()
            || self.streaming.is_some()
    }

    fn requires_response_observation(&self) -> bool {
        self.status.is_some()
            || self.message_size.is_some()
            || self.message.is_some()
            || !self.trailers_fast.is_empty()
            || !self.trailers_regex.is_empty()
            || self.streaming.is_some()
    }

    fn requires_response_context(&self) -> bool {
        self.requires_any_response_rule_rpc_context()
    }

    fn requires_request_context_for_response_rule(&self) -> bool {
        self.protocol.is_some()
            || self.service.is_some()
            || self.method.is_some()
            || self.streaming.is_some()
    }

    fn requires_request_body_observation_for_response_rule(&self) -> bool {
        self.streaming.is_some()
    }

    fn requires_any_response_rule_rpc_context(&self) -> bool {
        self.requires_request_context_for_response_rule() || self.requires_response_observation()
    }
}

impl CompiledIdentityMatch {
    fn compile(config: &IdentityMatchConfig, interner: &mut StringInterner) -> Result<Self> {
        Ok(Self {
            user: compile_identity_patterns(&config.user, interner)?,
            groups: compile_identity_patterns(&config.groups, interner)?,
            device_id: compile_identity_patterns(&config.device_id, interner)?,
            posture: compile_identity_patterns(&config.posture, interner)?,
            tenant: compile_identity_patterns(&config.tenant, interner)?,
            auth_strength: compile_identity_patterns(&config.auth_strength, interner)?,
            idp: compile_identity_patterns(&config.idp, interner)?,
        })
    }

    fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        if !match_optional_identity(&self.user, ctx.user) {
            return false;
        }
        if !match_any_identity(&self.groups, ctx.user_groups) {
            return false;
        }
        if !match_optional_identity(&self.device_id, ctx.device_id) {
            return false;
        }
        if !match_any_identity(&self.posture, ctx.posture) {
            return false;
        }
        if !match_optional_identity(&self.tenant, ctx.tenant) {
            return false;
        }
        if !match_optional_identity(&self.auth_strength, ctx.auth_strength) {
            return false;
        }
        if !match_optional_identity(&self.idp, ctx.idp) {
            return false;
        }
        true
    }
}

impl CompiledTlsFingerprintMatch {
    fn compile(config: &TlsFingerprintMatchConfig, interner: &mut StringInterner) -> Result<Self> {
        Ok(Self {
            ja3: compile_identity_patterns(&config.ja3, interner)?,
            ja4: compile_identity_patterns(&config.ja4, interner)?,
        })
    }

    fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        match_optional_text(&self.ja3, ctx.ja3) && match_optional_text(&self.ja4, ctx.ja4)
    }
}

impl CompiledCertificateMatch {
    fn compile(config: &CertificateMatchConfig, interner: &mut StringInterner) -> Result<Self> {
        Ok(Self {
            present: config.present,
            subject: compile_identity_patterns(&config.subject, interner)?,
            issuer: compile_identity_patterns(&config.issuer, interner)?,
            san_dns: compile_identity_patterns(&config.san_dns, interner)?,
            san_uri: compile_identity_patterns(&config.san_uri, interner)?,
            fingerprint_sha256: compile_identity_patterns(&config.fingerprint_sha256, interner)?,
        })
    }

    fn matches(
        &self,
        present: Option<bool>,
        subject: Option<&str>,
        issuer: Option<&str>,
        san_dns: &[String],
        san_uri: &[String],
        fingerprint_sha256: Option<&str>,
    ) -> bool {
        if let Some(expected) = self.present {
            if present != Some(expected) {
                return false;
            }
        }
        if !match_optional_text(&self.subject, subject) {
            return false;
        }
        if !match_optional_text(&self.issuer, issuer) {
            return false;
        }
        if !match_any_text(&self.san_dns, san_dns) {
            return false;
        }
        if !match_any_text(&self.san_uri, san_uri) {
            return false;
        }
        if !match_optional_text(&self.fingerprint_sha256, fingerprint_sha256) {
            return false;
        }
        true
    }
}

impl CompiledNumericMatcher {
    fn matches(&self, value: u64) -> bool {
        self.ranges.iter().any(|range| {
            range.min.map(|min| value >= min).unwrap_or(true)
                && range.max.map(|max| value <= max).unwrap_or(true)
        })
    }
}

fn build_header_matchers(
    items: &[HeaderMatch],
    interner: &mut StringInterner,
) -> Result<(Vec<HeaderMatcherFast>, Vec<HeaderMatcherRegex>)> {
    let mut fast = Vec::new();
    let mut regex = Vec::new();

    for item in items {
        let name = interner.intern_lower(&item.name);
        if let Some(pattern) = &item.regex {
            regex.push(HeaderMatcherRegex {
                name,
                regex: Regex::new(pattern)
                    .map_err(|e| anyhow!("invalid header regex {}: {}", pattern, e))?,
            });
            continue;
        }

        let mode = if let Some(value) = &item.value {
            HeaderFastMode::Exact(interner.intern(value))
        } else {
            HeaderFastMode::Present
        };
        fast.push(HeaderMatcherFast { name, mode });
    }

    Ok((fast, regex))
}

fn parse_cidrs(items: &[String]) -> Result<Vec<IpCidr>> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let cidr: IpCidr = item
            .parse()
            .map_err(|_| anyhow!("invalid CIDR: {}", item))?;
        out.push(cidr);
    }
    Ok(out)
}

fn compile_identity_patterns(
    items: &[String],
    interner: &mut StringInterner,
) -> Result<Option<TextPatternMatcher>> {
    let (matcher, _) = compile_text_patterns(items, false, false, interner)?;
    Ok(matcher)
}

fn compile_numeric_matchers(items: &[String]) -> Result<Option<CompiledNumericMatcher>> {
    if items.is_empty() {
        return Ok(None);
    }
    let mut ranges = Vec::with_capacity(items.len());
    for item in items {
        ranges.push(parse_numeric_range(item)?);
    }
    Ok(Some(CompiledNumericMatcher { ranges }))
}

fn parse_numeric_range(raw: &str) -> Result<NumericRange> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("empty numeric matcher"));
    }
    if let Some(rest) = raw.strip_prefix(">=") {
        return Ok(NumericRange {
            min: Some(parse_numeric_value(rest)?),
            max: None,
        });
    }
    if let Some(rest) = raw.strip_prefix('>') {
        let value = parse_numeric_value(rest)?;
        return Ok(NumericRange {
            min: Some(value.saturating_add(1)),
            max: None,
        });
    }
    if let Some(rest) = raw.strip_prefix("<=") {
        return Ok(NumericRange {
            min: None,
            max: Some(parse_numeric_value(rest)?),
        });
    }
    if let Some(rest) = raw.strip_prefix('<') {
        let value = parse_numeric_value(rest)?;
        return Ok(NumericRange {
            min: None,
            max: Some(value.saturating_sub(1)),
        });
    }
    if let Some((start, end)) = raw.split_once('-') {
        let start = parse_numeric_value(start)?;
        let end = parse_numeric_value(end)?;
        if start > end {
            return Err(anyhow!("numeric range start must be <= end"));
        }
        return Ok(NumericRange {
            min: Some(start),
            max: Some(end),
        });
    }
    let value = parse_numeric_value(raw)?;
    Ok(NumericRange {
        min: Some(value),
        max: Some(value),
    })
}

fn parse_numeric_value(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    let (digits, scale) = match raw.chars().last().unwrap_or_default() {
        'k' | 'K' => (&raw[..raw.len() - 1], 1024u64),
        'm' | 'M' => (&raw[..raw.len() - 1], 1024u64 * 1024),
        'g' | 'G' => (&raw[..raw.len() - 1], 1024u64 * 1024 * 1024),
        _ => (raw, 1u64),
    };
    let value = digits
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("invalid numeric matcher"))?;
    value
        .checked_mul(scale)
        .ok_or_else(|| anyhow!("numeric matcher overflow"))
}

fn match_optional_identity(matcher: &Option<TextPatternMatcher>, value: Option<&str>) -> bool {
    match matcher {
        Some(matcher) => value.map(|value| matcher.matches(value)).unwrap_or(false),
        None => true,
    }
}

fn match_any_identity(matcher: &Option<TextPatternMatcher>, values: &[String]) -> bool {
    match matcher {
        Some(matcher) => values.iter().any(|value| matcher.matches(value)),
        None => true,
    }
}

fn match_optional_text(matcher: &Option<TextPatternMatcher>, value: Option<&str>) -> bool {
    match matcher {
        Some(matcher) => value.map(|value| matcher.matches(value)).unwrap_or(false),
        None => true,
    }
}

fn match_any_text(matcher: &Option<TextPatternMatcher>, values: &[String]) -> bool {
    match matcher {
        Some(matcher) => values.iter().any(|value| matcher.matches(value)),
        None => true,
    }
}

fn match_optional_numeric(matcher: &Option<CompiledNumericMatcher>, value: Option<u64>) -> bool {
    match matcher {
        Some(matcher) => value.map(|value| matcher.matches(value)).unwrap_or(false),
        None => true,
    }
}

fn dedup_u16(items: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(items.len());
    let mut seen = HashSet::new();
    for item in items {
        if seen.insert(*item) {
            out.push(*item);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DestinationDimensionMatchConfig, DestinationMatchConfig, HeaderMatch, MatchConfig,
        RpcMatchConfig,
    };
    use http::HeaderMap;
    use http::HeaderValue;

    #[test]
    fn compiled_match_method_is_case_insensitive() {
        let cfg = MatchConfig {
            method: vec!["get".to_string()],
            ..Default::default()
        };
        let mut interner = StringInterner::default();
        let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
        let ctx = RuleMatchContext {
            src_ip: None,
            dst_port: None,
            host: None,
            sni: None,
            method: Some("GET"),
            path: None,
            headers: None,
            user: None,
            user_groups: &[],
            device_id: None,
            posture: &[],
            tenant: None,
            auth_strength: None,
            idp: None,
            ..Default::default()
        };
        assert!(compiled.matches(&ctx));
    }

    #[test]
    fn compiled_match_path_requires_path() {
        let cfg = MatchConfig {
            path: vec!["/foo".to_string()],
            ..Default::default()
        };
        let mut interner = StringInterner::default();
        let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
        let ctx = RuleMatchContext {
            src_ip: None,
            dst_port: None,
            host: None,
            sni: None,
            method: None,
            path: None,
            headers: None,
            user: None,
            user_groups: &[],
            device_id: None,
            posture: &[],
            tenant: None,
            auth_strength: None,
            idp: None,
            ..Default::default()
        };
        assert!(!compiled.matches(&ctx));
    }

    #[test]
    fn compiled_match_supports_destination_source_and_confidence() {
        let cfg = MatchConfig {
            destination: Some(DestinationMatchConfig {
                category: Some(DestinationDimensionMatchConfig {
                    value: vec!["ai".to_string()],
                    source: vec!["host".to_string()],
                    confidence: vec![">=90".to_string()],
                }),
                reputation: None,
                application: Some(DestinationDimensionMatchConfig {
                    value: vec!["https".to_string()],
                    source: vec!["heuristic".to_string()],
                    confidence: vec!["40".to_string()],
                }),
            }),
            ..Default::default()
        };
        let mut interner = StringInterner::default();
        let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
        let ctx = RuleMatchContext {
            destination_category: Some("ai"),
            destination_category_source: Some("host"),
            destination_category_confidence: Some(100),
            destination_application: Some("https"),
            destination_application_source: Some("heuristic"),
            destination_application_confidence: Some(40),
            ..Default::default()
        };
        assert!(compiled.matches(&ctx));
    }

    #[test]
    fn compiled_match_supports_rpc_request_fields() {
        let cfg = MatchConfig {
            rpc: Some(RpcMatchConfig {
                protocol: vec!["grpc".to_string()],
                service: vec!["demo.Echo".to_string()],
                method: vec!["Say".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut interner = StringInterner::default();
        let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
        let ctx = RuleMatchContext {
            rpc_protocol: Some("grpc"),
            rpc_service: Some("demo.Echo"),
            rpc_method: Some("Say"),
            ..Default::default()
        };
        assert!(compiled.matches(&ctx));
    }

    #[test]
    fn compiled_match_supports_rpc_response_trailers() {
        let cfg = MatchConfig {
            rpc: Some(RpcMatchConfig {
                status: vec!["14".to_string()],
                trailers: vec![HeaderMatch {
                    name: "grpc-message".to_string(),
                    value: Some("unavailable".to_string()),
                    regex: None,
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut interner = StringInterner::default();
        let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-message", HeaderValue::from_static("unavailable"));
        let ctx = RuleMatchContext {
            rpc_status: Some("14"),
            rpc_trailers: Some(&trailers),
            ..Default::default()
        };
        assert!(compiled.matches(&ctx));
        assert!(compiled.requires_response_context());
        assert!(compiled.requires_response_size());
    }

    #[test]
    fn response_rpc_streaming_requires_request_body_observation() {
        let cfg = MatchConfig {
            rpc: Some(RpcMatchConfig {
                streaming: vec!["client".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut interner = StringInterner::default();
        let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
        assert!(compiled.requires_response_request_rpc_context());
        assert!(compiled.requires_response_request_body_observation());
        assert!(compiled.requires_response_rpc_context());
        assert!(compiled.requires_response_rpc_observation());
    }
}
