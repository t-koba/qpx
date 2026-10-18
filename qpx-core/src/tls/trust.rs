use super::{TlsResult, UpstreamCertificateInfo};
use crate::config::UpstreamTlsTrustConfig;
use anyhow::anyhow;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use std::collections::HashSet;
#[cfg(feature = "tls-rustls")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

/// Compiled upstream TLS trust policy.
#[derive(Debug, Clone)]
pub struct CompiledUpstreamTlsTrust {
    pin_sha256: HashSet<String>,
    issuer: PatternSet,
    san_dns: PatternSet,
    san_uri: PatternSet,
    client_auth: Option<UpstreamTlsClientAuth>,
}

/// Upstream mTLS client certificate/key paths.
#[derive(Debug, Clone)]
pub struct UpstreamTlsClientAuth {
    cert: PathBuf,
    key: PathBuf,
}

#[derive(Debug, Clone, Default)]
struct PatternSet {
    exact: HashSet<String>,
    suffix: Vec<String>,
    glob_patterns: Vec<String>,
    glob: Option<GlobSet>,
    regex: Vec<Regex>,
}

impl CompiledUpstreamTlsTrust {
    /// Compile an upstream TLS trust config into matcher state.
    pub fn from_config(raw: Option<&UpstreamTlsTrustConfig>) -> TlsResult<Option<Arc<Self>>> {
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

    /// Return configured upstream client certificate/key paths.
    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub fn client_auth(&self) -> Option<&UpstreamTlsClientAuth> {
        self.client_auth.as_ref()
    }

    /// Validate parsed certificate metadata against this trust policy.
    pub fn validate_certificate(
        &self,
        peer_name: &str,
        cert: &UpstreamCertificateInfo,
    ) -> TlsResult<()> {
        if !self.requires_certificate_validation() {
            return Ok(());
        }
        if !cert.present {
            return Err(anyhow!(
                "upstream TLS trust policy requires a peer certificate for {}",
                peer_name
            )
            .into());
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
                return Err(anyhow!("upstream TLS trust pin mismatch for {}", peer_name).into());
            }
        }
        if !self.issuer.is_empty() {
            let issuer = cert
                .issuer
                .as_deref()
                .ok_or_else(|| anyhow!("upstream TLS trust issuer missing for {}", peer_name))?;
            if !self.issuer.matches_text(issuer) {
                return Err(anyhow!("upstream TLS trust issuer mismatch for {}", peer_name).into());
            }
        }
        if !self.san_dns.is_empty()
            && !cert
                .san_dns
                .iter()
                .any(|value| self.san_dns.matches_domain(value))
        {
            return Err(anyhow!("upstream TLS trust SAN DNS mismatch for {}", peer_name).into());
        }
        if !self.san_uri.is_empty()
            && !cert
                .san_uri
                .iter()
                .any(|value| self.san_uri.matches_text(value))
        {
            return Err(anyhow!("upstream TLS trust SAN URI mismatch for {}", peer_name).into());
        }
        Ok(())
    }

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

    /// Stable key used to separate connection pools by trust policy.
    ///
    /// Version 1 uses byte-length-prefixed fields in fixed order: pins, issuer,
    /// SAN DNS, SAN URI, then an explicit client-auth presence flag and both paths.
    /// Pattern categories and lists are independently framed, so delimiters in
    /// configured values cannot change field or alternative boundaries.
    pub fn pool_key(&self) -> String {
        let mut key = String::from("upstream-tls-v1:");
        for field in [
            sorted_list_key(self.pin_sha256.iter().map(String::as_str)),
            self.issuer.pool_key(),
            self.san_dns.pool_key(),
            self.san_uri.pool_key(),
        ] {
            push_key_field(&mut key, &field);
        }
        match &self.client_auth {
            None => key.push('0'),
            Some(auth) => {
                key.push('1');
                for path in [&auth.cert, &auth.key] {
                    // Preserve path bytes rather than using a lossy UTF-8 conversion.
                    let encoded = hex_encode(path.as_os_str().as_encoded_bytes());
                    push_key_field(&mut key, &encoded);
                }
            }
        }
        key
    }
}

impl UpstreamTlsClientAuth {
    fn has_empty_paths(&self) -> bool {
        self.cert.as_os_str().is_empty() && self.key.as_os_str().is_empty()
    }

    /// Whether both certificate and key paths are configured.
    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
    pub fn is_configured(&self) -> bool {
        !self.cert.as_os_str().is_empty() && !self.key.as_os_str().is_empty()
    }

    /// Client certificate path.
    #[cfg(feature = "tls-rustls")]
    pub fn cert_path(&self) -> &Path {
        self.cert.as_path()
    }

    /// Client private key path.
    #[cfg(feature = "tls-rustls")]
    pub fn key_path(&self) -> &Path {
        self.key.as_path()
    }
}

impl PatternSet {
    fn compile_text(values: &[String]) -> TlsResult<Self> {
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
            glob_patterns: glob_values.clone(),
            glob: build_globset(&glob_values)?,
            regex,
        })
    }

    fn compile_domain(values: &[String]) -> TlsResult<Self> {
        let mut exact = HashSet::new();
        let mut suffix = Vec::new();
        let mut glob_values = Vec::new();
        let mut regex = Vec::new();
        for value in values {
            let Some(normalized) = normalize_domain(value.as_str()) else {
                continue;
            };
            if let Some(rest) = normalized.strip_prefix("*.")
                && !rest.is_empty()
                && is_exact_pattern(rest)
            {
                suffix.push(rest.to_string());
                continue;
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
            glob_patterns: glob_values.clone(),
            glob: build_globset(&glob_values)?,
            regex,
        })
    }

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
            && self.glob_patterns.is_empty()
            && self.glob.is_none()
            && self.regex.is_empty()
    }

    fn pool_key(&self) -> String {
        let mut key = String::new();
        // Fixed category order: exact, suffix, glob, regex.
        for category in [
            sorted_list_key(self.exact.iter().map(String::as_str)),
            sorted_list_key(self.suffix.iter().map(String::as_str)),
            sorted_list_key(self.glob_patterns.iter().map(String::as_str)),
            sorted_list_key(self.regex.iter().map(Regex::as_str)),
        ] {
            push_key_field(&mut key, &category);
        }
        key
    }
}

fn push_decimal(key: &mut String, mut value: usize) {
    let mut digits = [0u8; std::mem::size_of::<usize>() * 3];
    let mut len = 0;
    loop {
        digits[len] = b'0' + (value % 10) as u8;
        len += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for digit in digits[..len].iter().rev() {
        key.push(char::from(*digit));
    }
}

fn push_key_field(key: &mut String, value: &str) {
    push_decimal(key, value.len());
    key.push(':');
    key.push_str(value);
}

fn sorted_list_key<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    let mut key = String::new();
    push_decimal(&mut key, values.len());
    key.push(':');
    for value in values {
        push_key_field(&mut key, value);
    }
    key
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::new();
    for &byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
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

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host.len() <= suffix.len() || !host.ends_with(suffix) {
        return false;
    }
    let boundary = host.len() - suffix.len();
    host.as_bytes().get(boundary.wrapping_sub(1)).copied() == Some(b'.')
}

fn build_globset(items: &[String]) -> TlsResult<Option<GlobSet>> {
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

    fn compile(raw: &UpstreamTlsTrustConfig) -> Arc<CompiledUpstreamTlsTrust> {
        CompiledUpstreamTlsTrust::from_config(Some(raw))
            .expect("compile trust")
            .expect("trust present")
    }

    #[test]
    fn pool_key_distinguishes_uri_alternatives_with_different_validation() {
        let combined = compile(&UpstreamTlsTrustConfig {
            san_uri: vec!["spiffe://a,spiffe://b".into()],
            ..Default::default()
        });
        let alternatives = compile(&UpstreamTlsTrustConfig {
            san_uri: vec!["spiffe://a".into(), "spiffe://b".into()],
            ..Default::default()
        });
        let cert = UpstreamCertificateInfo {
            present: true,
            san_uri: vec!["spiffe://a".into()],
            ..Default::default()
        };
        assert!(combined.validate_certificate("example.com", &cert).is_err());
        assert!(
            alternatives
                .validate_certificate("example.com", &cert)
                .is_ok()
        );
        assert_ne!(combined.pool_key(), alternatives.pool_key());
    }

    #[test]
    fn pool_key_distinguishes_pattern_list_and_category_boundaries() {
        for (combined, alternatives) in [
            (vec!["a,b"], vec!["a", "b"]),
            (vec!["*.a,*.b"], vec!["*.a", "*.b"]),
            (vec!["a*,b*"], vec!["a*", "b*"]),
            (vec!["re:a,re:b"], vec!["re:a", "re:b"]),
            (vec!["a;suffix=b"], vec!["a", "*.b;suffix="]),
        ] {
            let combined = PatternSet::compile_domain(
                &combined.into_iter().map(str::to_owned).collect::<Vec<_>>(),
            )
            .unwrap();
            let alternatives = PatternSet::compile_domain(
                &alternatives
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert_ne!(combined.pool_key(), alternatives.pool_key());
        }
        let combined = compile(&UpstreamTlsTrustConfig {
            pin_sha256: vec!["a,b".into()],
            ..Default::default()
        });
        let alternatives = compile(&UpstreamTlsTrustConfig {
            pin_sha256: vec!["a".into(), "b".into()],
            ..Default::default()
        });
        assert_ne!(combined.pool_key(), alternatives.pool_key());
    }

    #[test]
    fn pool_key_distinguishes_top_level_and_client_path_boundaries() {
        let first = compile(&UpstreamTlsTrustConfig {
            san_uri: vec!["spiffe://a".into()],
            client_cert: Some("cert|client_key=extra".into()),
            client_key: Some("key".into()),
            ..Default::default()
        });
        let second = compile(&UpstreamTlsTrustConfig {
            san_uri: vec!["spiffe://a".into()],
            client_cert: Some("cert".into()),
            client_key: Some("extra|client_key=key".into()),
            ..Default::default()
        });
        assert_ne!(first.pool_key(), second.pool_key());

        let first = compile(&UpstreamTlsTrustConfig {
            issuer: vec!["a;suffix=;glob=;regex=|san_dns=exact=b".into()],
            ..Default::default()
        });
        let second = compile(&UpstreamTlsTrustConfig {
            issuer: vec!["a".into()],
            san_dns: vec!["b;suffix=;glob=;regex=|san_dns=exact=".into()],
            ..Default::default()
        });
        assert_ne!(first.pool_key(), second.pool_key());

        let raw = UpstreamTlsTrustConfig {
            san_uri: vec!["spiffe://a".into()],
            ..Default::default()
        };
        let absent = compile(&raw);
        let present = compile(&UpstreamTlsTrustConfig {
            client_cert: Some(String::new()),
            client_key: Some(String::new()),
            ..raw
        });
        assert_ne!(absent.pool_key(), present.pool_key());
    }

    #[test]
    fn pool_key_preserves_normalized_reordering_equivalence() {
        let mut raw = UpstreamTlsTrustConfig {
            pin_sha256: vec![" BB ".into(), "aa".into()],
            issuer: vec![
                "CN=B".into(),
                "cn=a".into(),
                "cn=*".into(),
                "re:cn=.*".into(),
            ],
            san_dns: vec![
                "B.EXAMPLE.".into(),
                "a.example".into(),
                "*.b.example".into(),
                "*.a.example".into(),
                "b*.example".into(),
                "a*.example".into(),
                "re:b.*".into(),
                "re:a.*".into(),
            ],
            san_uri: vec![
                "SPIFFE://B".into(),
                "spiffe://a".into(),
                "spiffe://b*".into(),
                "spiffe://a*".into(),
                "re:spiffe://b.*".into(),
                "re:spiffe://a.*".into(),
            ],
            client_cert: Some("cert".into()),
            client_key: Some("key".into()),
        };
        let first = compile(&raw);
        for values in [
            &mut raw.pin_sha256,
            &mut raw.issuer,
            &mut raw.san_dns,
            &mut raw.san_uri,
        ] {
            values.reverse();
            for value in values {
                *value = value.trim().trim_end_matches('.').to_ascii_lowercase();
            }
        }
        assert_eq!(first.pool_key(), compile(&raw).pool_key());
    }
}
