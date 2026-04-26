#[cfg(any(feature = "tls-rustls", feature = "tls-native", test))]
use crate::tls::cert_info::UpstreamCertificateInfo;
#[cfg(any(feature = "tls-rustls", feature = "tls-native", test))]
use anyhow::anyhow;
use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};
use qpx_core::config::UpstreamTlsTrustConfig;
use regex::Regex;
use std::collections::HashSet;
#[cfg(feature = "tls-rustls")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct CompiledUpstreamTlsTrust {
    pin_sha256: HashSet<String>,
    issuer: PatternSet,
    san_dns: PatternSet,
    san_uri: PatternSet,
    client_auth: Option<UpstreamTlsClientAuth>,
}

#[derive(Debug, Clone)]
pub(crate) struct UpstreamTlsClientAuth {
    cert: PathBuf,
    key: PathBuf,
}

#[derive(Debug, Clone, Default)]
struct PatternSet {
    exact: HashSet<String>,
    suffix: Vec<String>,
    glob: Option<GlobSet>,
    regex: Vec<Regex>,
}

impl CompiledUpstreamTlsTrust {
    pub(crate) fn from_config(raw: Option<&UpstreamTlsTrustConfig>) -> Result<Option<Arc<Self>>> {
        let Some(raw) = raw else {
            return Ok(None);
        };
        let compiled = Self {
            pin_sha256: raw
                .pin_sha256
                .iter()
                .map(|pin| pin.trim().to_ascii_lowercase())
                .filter(|pin| !pin.is_empty())
                .collect(),
            issuer: PatternSet::compile_text(raw.issuer.as_slice())?,
            san_dns: PatternSet::compile_domain(raw.san_dns.as_slice())?,
            san_uri: PatternSet::compile_text(raw.san_uri.as_slice())?,
            client_auth: match (raw.client_cert.as_deref(), raw.client_key.as_deref()) {
                (Some(cert), Some(key)) => Some(UpstreamTlsClientAuth {
                    cert: PathBuf::from(cert),
                    key: PathBuf::from(key),
                }),
                _ => None,
            },
        };
        if compiled.is_empty() {
            return Ok(None);
        }
        Ok(Some(Arc::new(compiled)))
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(crate) fn client_auth(&self) -> Option<&UpstreamTlsClientAuth> {
        self.client_auth.as_ref()
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native", test))]
    pub(crate) fn validate_certificate(
        &self,
        peer_name: &str,
        cert: &UpstreamCertificateInfo,
    ) -> Result<()> {
        if !self.requires_certificate_validation() {
            return Ok(());
        }
        if !cert.present {
            return Err(anyhow!(
                "upstream TLS trust policy requires a peer certificate for {}",
                peer_name
            ));
        }
        if !self.pin_sha256.is_empty() {
            let fingerprint = cert
                .fingerprint_sha256
                .as_deref()
                .map(|value| value.trim().to_ascii_lowercase())
                .ok_or_else(|| {
                    anyhow!(
                        "upstream TLS trust pinning requires a fingerprint for {}",
                        peer_name
                    )
                })?;
            if !self.pin_sha256.contains(fingerprint.as_str()) {
                return Err(anyhow!("upstream TLS trust pin mismatch for {}", peer_name));
            }
        }
        if !self.issuer.is_empty() {
            let issuer = cert
                .issuer
                .as_deref()
                .ok_or_else(|| anyhow!("upstream TLS trust issuer missing for {}", peer_name))?;
            if !self.issuer.matches_text(issuer) {
                return Err(anyhow!(
                    "upstream TLS trust issuer mismatch for {}",
                    peer_name
                ));
            }
        }
        if !self.san_dns.is_empty()
            && !cert
                .san_dns
                .iter()
                .any(|value| self.san_dns.matches_domain(value))
        {
            return Err(anyhow!(
                "upstream TLS trust SAN DNS mismatch for {}",
                peer_name
            ));
        }
        if !self.san_uri.is_empty()
            && !cert
                .san_uri
                .iter()
                .any(|value| self.san_uri.matches_text(value))
        {
            return Err(anyhow!(
                "upstream TLS trust SAN URI mismatch for {}",
                peer_name
            ));
        }
        Ok(())
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native", test))]
    fn requires_certificate_validation(&self) -> bool {
        !self.pin_sha256.is_empty()
            || !self.issuer.is_empty()
            || !self.san_dns.is_empty()
            || !self.san_uri.is_empty()
    }

    fn is_empty(&self) -> bool {
        self.pin_sha256.is_empty()
            && self.issuer.is_empty()
            && self.san_dns.is_empty()
            && self.san_uri.is_empty()
            && self
                .client_auth
                .as_ref()
                .map(UpstreamTlsClientAuth::has_empty_paths)
                .unwrap_or(true)
    }
}

impl UpstreamTlsClientAuth {
    fn has_empty_paths(&self) -> bool {
        self.cert.as_os_str().is_empty() && self.key.as_os_str().is_empty()
    }

    #[cfg(feature = "tls-native")]
    pub(crate) fn is_configured(&self) -> bool {
        !self.cert.as_os_str().is_empty() && !self.key.as_os_str().is_empty()
    }

    #[cfg(feature = "tls-rustls")]
    pub(crate) fn cert_path(&self) -> &Path {
        self.cert.as_path()
    }

    #[cfg(feature = "tls-rustls")]
    pub(crate) fn key_path(&self) -> &Path {
        self.key.as_path()
    }
}

impl PatternSet {
    fn compile_text(values: &[String]) -> Result<Self> {
        let mut exact = HashSet::new();
        let mut glob_values = Vec::new();
        let mut regex = Vec::new();
        for value in values {
            let Some(normalized) = normalize_text(value.as_str()) else {
                continue;
            };
            if let Some(pattern) = extract_regex_pattern(normalized.as_str()) {
                regex.push(Regex::new(pattern)?);
            } else if is_exact_pattern(normalized.as_str()) {
                exact.insert(normalized);
            } else {
                glob_values.push(normalized);
            }
        }
        Ok(Self {
            exact,
            suffix: Vec::new(),
            glob: build_globset(&glob_values)?,
            regex,
        })
    }

    fn compile_domain(values: &[String]) -> Result<Self> {
        let mut exact = HashSet::new();
        let mut suffix = Vec::new();
        let mut glob_values = Vec::new();
        let mut regex = Vec::new();
        for value in values {
            let Some(normalized) = normalize_domain(value.as_str()) else {
                continue;
            };
            if let Some(rest) = normalized.strip_prefix("*.") {
                if !rest.is_empty() && is_exact_pattern(rest) {
                    suffix.push(rest.to_string());
                    continue;
                }
            }
            if let Some(pattern) = extract_regex_pattern(normalized.as_str()) {
                regex.push(Regex::new(pattern)?);
            } else if is_exact_pattern(normalized.as_str()) {
                exact.insert(normalized);
            } else {
                glob_values.push(normalized);
            }
        }
        Ok(Self {
            exact,
            suffix,
            glob: build_globset(&glob_values)?,
            regex,
        })
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native", test))]
    fn matches_text(&self, value: &str) -> bool {
        let Some(normalized) = normalize_text(value) else {
            return false;
        };
        if self.exact.contains(normalized.as_str()) {
            return true;
        }
        if self
            .glob
            .as_ref()
            .map(|glob| glob.is_match(normalized.as_str()))
            .unwrap_or(false)
        {
            return true;
        }
        self.regex
            .iter()
            .any(|pattern| pattern.is_match(normalized.as_str()))
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native", test))]
    fn matches_domain(&self, value: &str) -> bool {
        let Some(normalized) = normalize_domain(value) else {
            return false;
        };
        if self.exact.contains(normalized.as_str()) {
            return true;
        }
        if self
            .suffix
            .iter()
            .any(|suffix| host_matches_suffix(normalized.as_str(), suffix.as_str()))
        {
            return true;
        }
        if self
            .glob
            .as_ref()
            .map(|glob| glob.is_match(normalized.as_str()))
            .unwrap_or(false)
        {
            return true;
        }
        self.regex
            .iter()
            .any(|pattern| pattern.is_match(normalized.as_str()))
    }

    fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffix.is_empty()
            && self.glob.is_none()
            && self.regex.is_empty()
    }
}

fn normalize_text(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

fn normalize_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.');
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

fn extract_regex_pattern(item: &str) -> Option<&str> {
    item.strip_prefix("re:")
        .or_else(|| item.strip_prefix("regex:"))
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
}

fn is_exact_pattern(item: &str) -> bool {
    !item.contains('*')
        && !item.contains('?')
        && !item.contains('[')
        && !item.contains(']')
        && !item.contains('{')
        && !item.contains('}')
}

#[cfg(any(feature = "tls-rustls", feature = "tls-native", test))]
fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host.len() <= suffix.len() || !host.ends_with(suffix) {
        return false;
    }
    let boundary = host.len() - suffix.len();
    host.as_bytes().get(boundary.wrapping_sub(1)).copied() == Some(b'.')
}

fn build_globset(items: &[String]) -> Result<Option<GlobSet>> {
    if items.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for item in items {
        builder.add(Glob::new(item)?);
    }
    Ok(Some(builder.build()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_trust_matches_pin_and_dns() {
        let trust = CompiledUpstreamTlsTrust::from_config(Some(&UpstreamTlsTrustConfig {
            pin_sha256: vec![
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ],
            issuer: Vec::new(),
            san_dns: vec!["*.example.com".into()],
            san_uri: Vec::new(),
            client_cert: None,
            client_key: None,
        }))
        .expect("compile trust")
        .expect("trust present");
        let cert = UpstreamCertificateInfo {
            present: true,
            subject: None,
            issuer: None,
            san_dns: vec!["api.example.com".into()],
            san_uri: Vec::new(),
            fingerprint_sha256: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
        };
        trust
            .validate_certificate("api.example.com", &cert)
            .expect("trust should accept matching cert");
    }

    #[test]
    fn compiled_trust_rejects_mismatch() {
        let trust = CompiledUpstreamTlsTrust::from_config(Some(&UpstreamTlsTrustConfig {
            pin_sha256: Vec::new(),
            issuer: vec!["CN=Expected".into()],
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            client_cert: None,
            client_key: None,
        }))
        .expect("compile trust")
        .expect("trust present");
        let cert = UpstreamCertificateInfo {
            present: true,
            subject: None,
            issuer: Some("CN=Other".into()),
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            fingerprint_sha256: None,
        };
        assert!(trust.validate_certificate("example.com", &cert).is_err());
    }
}
