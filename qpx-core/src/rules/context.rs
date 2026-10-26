use std::net::IpAddr;

use crate::http_content_length::{HeaderDiagnostic, HeaderPredicate, HeaderView};
use crate::http_message::OwnedHeaderView;

// A closed union, not an owner-to-raw conversion. Dispatch retains the owner's
// redacted trace semantics throughout matching and diagnostics.
#[derive(Clone, Copy)]
pub(crate) enum PolicyHeaderView<'a> {
    Raw(HeaderView<'a>),
    Owned(OwnedHeaderView<'a>),
}

impl PolicyHeaderView<'_> {
    pub(crate) fn matches(self, name: &str, predicate: HeaderPredicate<'_>) -> bool {
        match self {
            Self::Raw(view) => view.matches(name, predicate),
            Self::Owned(view) => view.matches(name, predicate),
        }
    }

    pub(crate) fn trace(self, name: &str, predicate: HeaderPredicate<'_>) -> HeaderDiagnostic {
        match self {
            Self::Raw(view) => view.trace(name, predicate),
            Self::Owned(view) => view.trace(name, predicate),
        }
    }
}

/// Rule inputs with transitional raw views and owner-backed views.
///
/// Use the owner slots for in-domain messages. They take precedence over the
/// corresponding raw slots so diagnostics never fall back to an unredacted view.
/// No conversion to a raw `HeaderView` is needed or provided.
///
/// ```
/// use qpx_core::http_message::Headers;
/// use qpx_core::rules::RuleMatchContext;
/// let mut headers = Headers::new();
/// headers.set_content_length(5);
/// let context = RuleMatchContext {
///     owned_headers: Some(headers.view()),
///     ..Default::default()
/// };
/// assert!(context.owned_headers.is_some());
/// ```
/// ```compile_fail,E0308
/// use qpx_core::http_message::Headers;
/// use qpx_core::http_content_length::HeaderView;
/// use qpx_core::rules::RuleMatchContext;
/// let headers = Headers::new();
/// let context = RuleMatchContext {
///     owned_headers: Some(headers.view()),
///     ..Default::default()
/// };
/// let raw: HeaderView<'_> = context.owned_headers.unwrap();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleMatchContext<'a> {
    pub src_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub host: Option<&'a str>,
    pub sni: Option<&'a str>,
    pub method: Option<&'a str>,
    pub path: Option<&'a str>,
    pub query: Option<&'a str>,
    pub authority: Option<&'a str>,
    pub scheme: Option<&'a str>,
    pub http_version: Option<&'a str>,
    pub alpn: Option<&'a str>,
    pub tls_version: Option<&'a str>,
    pub destination_category: Option<&'a str>,
    pub destination_category_source: Option<&'a str>,
    pub destination_category_confidence: Option<u64>,
    pub destination_reputation: Option<&'a str>,
    pub destination_reputation_source: Option<&'a str>,
    pub destination_reputation_confidence: Option<u64>,
    pub destination_application: Option<&'a str>,
    pub destination_application_source: Option<&'a str>,
    pub destination_application_confidence: Option<u64>,
    pub ja3: Option<&'a str>,
    pub ja4: Option<&'a str>,
    pub request_size: Option<u64>,
    pub response_status: Option<u16>,
    pub response_size: Option<u64>,
    pub client_cert_present: Option<bool>,
    pub client_cert_subject: Option<&'a str>,
    pub client_cert_issuer: Option<&'a str>,
    pub client_cert_san_dns: &'a [String],
    pub client_cert_san_uri: &'a [String],
    pub client_cert_fingerprint_sha256: Option<&'a str>,
    pub upstream_cert_present: Option<bool>,
    pub upstream_cert_subject: Option<&'a str>,
    pub upstream_cert_issuer: Option<&'a str>,
    pub upstream_cert_san_dns: &'a [String],
    pub upstream_cert_san_uri: &'a [String],
    pub upstream_cert_fingerprint_sha256: Option<&'a str>,
    pub rpc_protocol: Option<&'a str>,
    pub rpc_service: Option<&'a str>,
    pub rpc_method: Option<&'a str>,
    pub rpc_streaming: Option<&'a str>,
    pub rpc_status: Option<&'a str>,
    pub rpc_message_size: Option<u64>,
    pub rpc_message: Option<&'a str>,
    /// Transitional raw trailers; ignored when `owned_rpc_trailers` is present.
    pub rpc_trailers: Option<HeaderView<'a>>,
    /// Transitional raw headers; ignored when `owned_headers` is present.
    pub headers: Option<HeaderView<'a>>,
    /// Owner-backed trailers, preferred over the transitional raw view.
    pub owned_rpc_trailers: Option<OwnedHeaderView<'a>>,
    /// Owner-backed headers, preferred over the transitional raw view.
    /// Content-Length predicate results are unchanged; trace actual is redacted.
    pub owned_headers: Option<OwnedHeaderView<'a>>,
    pub user: Option<&'a str>,
    pub user_groups: &'a [String],
    pub device_id: Option<&'a str>,
    pub posture: &'a [String],
    pub tenant: Option<&'a str>,
    pub auth_strength: Option<&'a str>,
    pub idp: Option<&'a str>,
}

impl<'a> RuleMatchContext<'a> {
    pub(crate) fn header_view(&self) -> Option<PolicyHeaderView<'a>> {
        self.owned_headers
            .map(PolicyHeaderView::Owned)
            .or_else(|| self.headers.map(PolicyHeaderView::Raw))
    }

    pub(crate) fn trailer_view(&self) -> Option<PolicyHeaderView<'a>> {
        self.owned_rpc_trailers
            .map(PolicyHeaderView::Owned)
            .or_else(|| self.rpc_trailers.map(PolicyHeaderView::Raw))
    }
}
