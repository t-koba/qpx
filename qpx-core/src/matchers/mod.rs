//! Compiled rule matchers and prefilter hints.

#![allow(missing_docs)]

mod compile;
mod destination;
mod eval;
mod headers;
mod identity;
mod numeric;
mod rpc;
mod trace;

#[cfg(test)]
mod tests;

use crate::prefilter::TextPatternMatcher;
use cidr::IpCidr;
use destination::CompiledDestinationMatch;
use headers::{HeaderMatcherFast, HeaderMatcherRegex};
use identity::{CompiledCertificateMatch, CompiledIdentityMatch, CompiledTlsFingerprintMatch};
use numeric::CompiledNumericMatcher;
use rpc::CompiledRpcMatch;
use std::collections::HashSet;
use std::sync::Arc;

pub use trace::{MatchMode, MatchReason, MatchTrace};

type Result<T> = std::result::Result<T, MatchCompileError>;

#[derive(Debug, thiserror::Error)]
pub enum MatchCompileError {
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

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
    destination: Option<CompiledDestinationMatch>,
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
