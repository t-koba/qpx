mod compile;
mod patterns;
mod resolve;

pub(crate) use compile::DestinationClassifier;
pub(crate) use resolve::CompiledDestinationResolutionPolicy;

use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub(crate) struct DestinationMetadata {
    pub(crate) category: Option<String>,
    pub(crate) category_source: Option<String>,
    pub(crate) category_confidence: Option<u8>,
    pub(crate) reputation: Option<String>,
    pub(crate) reputation_source: Option<String>,
    pub(crate) reputation_confidence: Option<u8>,
    pub(crate) application: Option<String>,
    pub(crate) application_source: Option<String>,
    pub(crate) application_confidence: Option<u8>,
    pub(crate) category_trace: Option<String>,
    pub(crate) reputation_trace: Option<String>,
    pub(crate) application_trace: Option<String>,
}

impl DestinationMetadata {
    pub(crate) fn decision_trace(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(trace) = self.category_trace.as_deref() {
            parts.push(trace.to_string());
        }
        if let Some(trace) = self.reputation_trace.as_deref() {
            parts.push(trace.to_string());
        }
        if let Some(trace) = self.application_trace.as_deref() {
            parts.push(trace.to_string());
        }
        (!parts.is_empty()).then(|| parts.join(" | "))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DestinationInputs<'a> {
    pub(crate) host: Option<&'a str>,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) scheme: Option<&'a str>,
    pub(crate) port: Option<u16>,
    pub(crate) alpn: Option<&'a str>,
    pub(crate) ja3: Option<&'a str>,
    pub(crate) ja4: Option<&'a str>,
    pub(crate) cert_subject: Option<&'a str>,
    pub(crate) cert_issuer: Option<&'a str>,
    pub(crate) cert_san_dns: &'a [String],
    pub(crate) cert_san_uri: &'a [String],
    pub(crate) cert_fingerprint_sha256: Option<&'a str>,
}

#[cfg(test)]
mod tests;
