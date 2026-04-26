use super::ReverseConnInfo;
use crate::destination::{DestinationInputs, DestinationMetadata};
use crate::runtime::RuntimeState;
use crate::tls::UpstreamCertificateInfo;

use qpx_core::config::{DestinationMinConfidenceConfig, DestinationResolutionOverrideConfig};

pub(super) fn classify_reverse_destination(
    state: &RuntimeState,
    conn: &ReverseConnInfo,
    host: &str,
    upstream_cert: Option<&UpstreamCertificateInfo>,
    resolution_override: Option<&DestinationResolutionOverrideConfig>,
) -> DestinationMetadata {
    state.classify_destination(
        &DestinationInputs {
            host: (!host.is_empty()).then_some(host),
            ip: host.parse().ok(),
            sni: conn.tls_sni.as_deref(),
            scheme: Some(if conn.tls_terminated { "https" } else { "http" }),
            port: Some(conn.dst_port),
            alpn: None,
            ja3: None,
            ja4: None,
            cert_subject: upstream_cert.and_then(|cert| cert.subject.as_deref()),
            cert_issuer: upstream_cert.and_then(|cert| cert.issuer.as_deref()),
            cert_san_dns: upstream_cert
                .map(|cert| cert.san_dns.as_slice())
                .unwrap_or(&[]),
            cert_san_uri: upstream_cert
                .map(|cert| cert.san_uri.as_slice())
                .unwrap_or(&[]),
            cert_fingerprint_sha256: upstream_cert
                .and_then(|cert| cert.fingerprint_sha256.as_deref()),
        },
        resolution_override,
    )
}

pub(super) fn merge_destination_resolution_override(
    base: Option<&DestinationResolutionOverrideConfig>,
    route: Option<&DestinationResolutionOverrideConfig>,
) -> Option<DestinationResolutionOverrideConfig> {
    match (base, route) {
        (None, None) => None,
        (Some(base), None) => Some(base.clone()),
        (None, Some(route)) => Some(route.clone()),
        (Some(base), Some(route)) => Some(DestinationResolutionOverrideConfig {
            precedence: route.precedence.clone().or_else(|| base.precedence.clone()),
            conflict_mode: route.conflict_mode.or(base.conflict_mode),
            merge_mode: route.merge_mode.or(base.merge_mode),
            min_confidence: match (&base.min_confidence, &route.min_confidence) {
                (None, None) => None,
                (Some(base), None) => Some(base.clone()),
                (None, Some(route)) => Some(route.clone()),
                (Some(base), Some(route)) => Some(DestinationMinConfidenceConfig {
                    category: route.category.or(base.category),
                    reputation: route.reputation.or(base.reputation),
                    application: route.application.or(base.application),
                }),
            },
        }),
    }
}
