use crate::config::{MatchConfig, TlsPassthroughMatchConfig};
use crate::prefilter::{
    MatchPrefilterHint, StringInterner, TextPrefilterHint, compile_text_patterns,
    dedup_uppercase_arc,
};
use anyhow::anyhow;
use cidr::IpCidr;
use std::collections::HashSet;
use std::sync::Arc;

use super::destination::CompiledDestinationMatch;
use super::headers::build_header_matchers;
use super::identity::{
    CompiledCertificateMatch, CompiledIdentityMatch, CompiledTlsFingerprintMatch,
};
use super::numeric::compile_numeric_matchers;
use super::rpc::CompiledRpcMatch;
use super::{CompiledMatch, Result};

impl CompiledMatch {
    pub fn compile(
        config: &MatchConfig,
        interner: &mut StringInterner,
    ) -> Result<(Self, MatchPrefilterHint)> {
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
        let destination = CompiledDestinationMatch::compile(config.destination.as_ref(), interner)?;
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

        Ok((
            Self {
                src_ip: src_cidrs.clone(),
                dst_port: dst_ports.iter().copied().collect(),
                host,
                sni,
                method: method_values.iter().cloned().collect::<HashSet<Arc<str>>>(),
                path,
                query,
                authority,
                scheme,
                http_version,
                alpn,
                tls_version,
                destination,
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
            MatchPrefilterHint {
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
    ) -> Result<(Self, MatchPrefilterHint)> {
        let src_cidrs = parse_cidrs(&config.src_ip)?;
        let dst_ports = dedup_u16(&config.dst_port);
        let (sni, sni_hint) = compile_text_patterns(&config.sni, true, true, interner)?;

        Ok((
            Self {
                src_ip: src_cidrs.clone(),
                dst_port: dst_ports.iter().copied().collect(),
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
                destination: None,
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
            MatchPrefilterHint {
                method_values: Vec::new(),
                dst_ports,
                src_cidrs,
                host: TextPrefilterHint {
                    any: true,
                    ..Default::default()
                },
                sni: sni_hint,
                path: TextPrefilterHint {
                    any: true,
                    ..Default::default()
                },
            },
        ))
    }
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
