#[cfg(any(not(feature = "ldap-auth"), not(feature = "digest-auth")))]
use anyhow::anyhow;
#[cfg(feature = "ldap-auth")]
use anyhow::Context;
use anyhow::Result;
#[cfg(feature = "auth-proxy")]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(feature = "auth-proxy")]
use base64::Engine;
#[cfg(feature = "ldap-auth")]
use std::env;
#[cfg(feature = "auth-proxy")]
use std::net::IpAddr;
#[cfg(any(feature = "ldap-auth", feature = "digest-auth"))]
use std::time::Duration;
#[cfg(feature = "auth-proxy")]
use tracing::Level;

use qpx_core::config::AuthConfig;

#[cfg(feature = "ldap-auth")]
use super::cache::LdapCache;
#[cfg(feature = "digest-auth")]
use super::digest::sha256_hex;
#[cfg(feature = "digest-auth")]
use super::digest::{constant_time_eq_hex_lower, parse_digest, DigestAlgorithm, NonceStore};
#[cfg(feature = "auth-proxy")]
use super::local::LocalUserEntry;
#[cfg(feature = "auth-proxy")]
use super::util::{constant_time_eq_bytes, escape_quoted_header_value};
use super::Authenticator;
#[cfg(feature = "ldap-auth")]
use super::LdapAuthenticator;
#[cfg(feature = "auth-proxy")]
use super::{AuthChallenge, AuthOutcome, AuthenticatedUser};

impl Authenticator {
    pub fn new(config: &AuthConfig, realm: &str) -> Result<Self> {
        #[cfg(feature = "auth-proxy")]
        let mut local = std::collections::HashMap::new();
        #[cfg(feature = "auth-proxy")]
        for user in &config.users {
            local.insert(
                user.username.clone(),
                LocalUserEntry::from_config(user, realm),
            );
        }

        #[cfg(feature = "ldap-auth")]
        let ldap = match &config.ldap {
            Some(cfg) => {
                let bind_password = env::var(&cfg.bind_password_env).with_context(|| {
                    format!("missing LDAP bind password env {}", cfg.bind_password_env)
                })?;
                Some(LdapAuthenticator::new(cfg.clone(), bind_password))
            }
            None => None,
        };
        #[cfg(not(feature = "ldap-auth"))]
        if config.ldap.is_some() {
            return Err(anyhow!(
                "LDAP auth support is not enabled in this build (enable qpx-auth/ldap-auth-*)"
            ));
        }
        #[cfg(not(feature = "digest-auth"))]
        if config
            .users
            .iter()
            .any(|user| user.password.is_none() && user.ha1.is_some())
        {
            return Err(anyhow!(
                "Digest auth support is not enabled in this build (enable qpx-auth/digest-auth)"
            ));
        }

        Ok(Self {
            realm: realm.to_string(),
            #[cfg(feature = "auth-proxy")]
            local,
            #[cfg(feature = "ldap-auth")]
            ldap,
            #[cfg(feature = "digest-auth")]
            nonces: NonceStore::new(Duration::from_secs(300)),
            #[cfg(feature = "ldap-auth")]
            ldap_cache: LdapCache::new(Duration::from_secs(60)),
        })
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    #[cfg(feature = "auth-proxy")]
    fn strip_auth_scheme<'a>(header_value: &'a str, scheme: &str) -> Option<&'a str> {
        let value = header_value.trim_start();
        if value.len() <= scheme.len() {
            return None;
        }
        if !value[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return None;
        }
        let rest = &value[scheme.len()..];
        let mut chars = rest.chars();
        match chars.next() {
            Some(c) if c.is_ascii_whitespace() => {}
            _ => return None,
        }
        Some(rest.trim_start_matches(|c: char| c.is_ascii_whitespace()))
    }

    #[cfg(feature = "auth-proxy")]
    pub async fn authenticate_proxy(
        &self,
        src_ip: Option<IpAddr>,
        headers: &http::HeaderMap,
        required_providers: &[String],
        method: &str,
        uri: &str,
    ) -> Result<AuthOutcome> {
        if required_providers.is_empty() {
            return Ok(AuthOutcome::Allowed(AuthenticatedUser {
                username: "anonymous".to_string(),
                groups: Vec::new(),
                provider: "none".to_string(),
            }));
        }

        let header = headers
            .get("proxy-authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if header.is_empty() {
            if tracing::enabled!(target: "audit_log", Level::INFO) {
                tracing::info!(
                    target: "audit_log",
                    event = "auth",
                    outcome = "challenge",
                    reason = "missing_proxy_authorization",
                    src_ip = src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                    method = method,
                    uri = uri,
                    required_providers = ?required_providers,
                );
            }
            return Ok(AuthOutcome::Challenge(self.build_challenge()));
        }

        if let Some(basic) = Self::strip_auth_scheme(header, "Basic") {
            if let Some(user) = self.verify_basic(basic, required_providers).await? {
                if tracing::enabled!(target: "audit_log", Level::INFO) {
                    tracing::info!(
                        target: "audit_log",
                        event = "auth",
                        outcome = "allowed",
                        src_ip = src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                        method = method,
                        uri = uri,
                        username = %user.username,
                        provider = %user.provider,
                        required_providers = ?required_providers,
                    );
                }
                return Ok(AuthOutcome::Allowed(user));
            }
            if tracing::enabled!(target: "audit_log", Level::INFO) {
                tracing::info!(
                    target: "audit_log",
                    event = "auth",
                    outcome = "challenge",
                    reason = "invalid_basic_credentials",
                    src_ip = src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                    method = method,
                    uri = uri,
                    required_providers = ?required_providers,
                );
            }
            return Ok(AuthOutcome::Challenge(self.build_challenge()));
        }

        if let Some(digest) = Self::strip_auth_scheme(header, "Digest") {
            #[cfg(feature = "digest-auth")]
            {
                if required_providers.iter().any(|p| p == "local") {
                    if let Some(user) = self.verify_digest(digest, method, uri)? {
                        if tracing::enabled!(target: "audit_log", Level::INFO) {
                            tracing::info!(
                                target: "audit_log",
                                event = "auth",
                                outcome = "allowed",
                                src_ip = src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                                method = method,
                                uri = uri,
                                username = %user.username,
                                provider = %user.provider,
                                required_providers = ?required_providers,
                            );
                        }
                        return Ok(AuthOutcome::Allowed(user));
                    }
                }
            }
            #[cfg(not(feature = "digest-auth"))]
            let _ = digest;
            if tracing::enabled!(target: "audit_log", Level::INFO) {
                tracing::info!(
                    target: "audit_log",
                    event = "auth",
                    outcome = "challenge",
                    reason = "invalid_digest_credentials",
                    src_ip = src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                    method = method,
                    uri = uri,
                    required_providers = ?required_providers,
                );
            }
            return Ok(AuthOutcome::Challenge(self.build_challenge()));
        }

        if tracing::enabled!(target: "audit_log", Level::INFO) {
            tracing::info!(
                target: "audit_log",
                event = "auth",
                outcome = "challenge",
                reason = "unsupported_proxy_authorization_scheme",
                src_ip = src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                method = method,
                uri = uri,
                required_providers = ?required_providers,
            );
        }
        Ok(AuthOutcome::Challenge(self.build_challenge()))
    }

    #[cfg(feature = "auth-proxy")]
    async fn verify_basic(
        &self,
        payload: &str,
        required_providers: &[String],
    ) -> Result<Option<AuthenticatedUser>> {
        let decoded = match BASE64.decode(payload) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(None),
        };
        let decoded = match String::from_utf8(decoded) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(None),
        };
        let mut parts = decoded.splitn(2, ':');
        let username = parts.next().unwrap_or("");
        let password = parts.next().unwrap_or("");

        if required_providers.iter().any(|p| p == "local") {
            if let Some(entry) = self.local.get(username) {
                if let Some(stored) = &entry.password {
                    if constant_time_eq_bytes(stored.as_bytes(), password.as_bytes()) {
                        return Ok(Some(AuthenticatedUser {
                            username: entry.username.clone(),
                            groups: Vec::new(),
                            provider: "local".to_string(),
                        }));
                    }
                }
            }
        }

        #[cfg(feature = "ldap-auth")]
        if required_providers.iter().any(|p| p == "ldap") {
            if let Some(ldap) = &self.ldap {
                if let Some(groups) = self.ldap_cache.get(username, password) {
                    return Ok(Some(AuthenticatedUser {
                        username: username.to_string(),
                        groups,
                        provider: "ldap".to_string(),
                    }));
                }
                if let Some(groups) = ldap.authenticate(username, password).await? {
                    self.ldap_cache.put(username, password, groups.clone());
                    return Ok(Some(AuthenticatedUser {
                        username: username.to_string(),
                        groups,
                        provider: "ldap".to_string(),
                    }));
                }
            }
        }
        #[cfg(not(feature = "ldap-auth"))]
        let _ = required_providers;

        Ok(None)
    }

    #[cfg(feature = "digest-auth")]
    fn verify_digest(
        &self,
        payload: &str,
        method: &str,
        uri: &str,
    ) -> Result<Option<AuthenticatedUser>> {
        let params = parse_digest(payload);
        let username = params.get("username").map(String::as_str).unwrap_or("");
        let realm = params.get("realm").map(String::as_str).unwrap_or("");
        let nonce = params.get("nonce").map(String::as_str).unwrap_or("");
        let digest_uri = params.get("uri").map(String::as_str).unwrap_or("");
        let response = params.get("response").map(String::as_str).unwrap_or("");
        let qop = params.get("qop").map(String::as_str);
        let algorithm = params.get("algorithm").map(String::as_str);
        let nc = params.get("nc").map(String::as_str).unwrap_or("");
        let cnonce = params.get("cnonce").map(String::as_str).unwrap_or("");

        if realm != self.realm {
            return Ok(None);
        }
        if digest_uri.is_empty() || digest_uri != uri {
            return Ok(None);
        }
        let algo = match algorithm {
            None => DigestAlgorithm::Sha256,
            Some(v) if v.eq_ignore_ascii_case("SHA-256") => DigestAlgorithm::Sha256,
            Some(v) if v.eq_ignore_ascii_case("SHA-256-sess") => DigestAlgorithm::Sha256Sess,
            Some(_) => return Ok(None),
        };
        if !matches!(qop, Some(q) if q.eq_ignore_ascii_case("auth")) {
            return Ok(None);
        }
        if cnonce.is_empty() {
            return Ok(None);
        }
        let Some(parsed_nc) = self.nonces.parse_digest_nc(nonce, nc) else {
            return Ok(None);
        };

        let entry = match self.local.get(username) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let ha1 = entry
            .digest_ha1_sha256
            .as_ref()
            .cloned()
            .or_else(|| {
                entry
                    .password
                    .as_ref()
                    .map(|p| sha256_hex(format!("{}:{}:{}", username, self.realm, p).as_bytes()))
            })
            .ok_or_else(|| anyhow::anyhow!("missing ha1/password for digest user"))?;
        let ha1 = match algo {
            DigestAlgorithm::Sha256 => ha1,
            DigestAlgorithm::Sha256Sess => {
                sha256_hex(format!("{}:{}:{}", ha1, nonce, cnonce).as_bytes())
            }
        };

        let ha2 = sha256_hex(format!("{}:{}", method, uri).as_bytes());
        let expected = sha256_hex(
            format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, "auth", ha2).as_bytes(),
        );

        if constant_time_eq_hex_lower(expected.as_str(), response) {
            if !self.nonces.mark_digest_nc_used(nonce, parsed_nc) {
                return Ok(None);
            }
            return Ok(Some(AuthenticatedUser {
                username: username.to_string(),
                groups: Vec::new(),
                provider: "local".to_string(),
            }));
        }

        Ok(None)
    }

    #[cfg(feature = "auth-proxy")]
    fn build_challenge(&self) -> AuthChallenge {
        let mut headers = Vec::new();
        let escaped_realm = escape_quoted_header_value(self.realm.as_str());
        headers.push(format!("Basic realm=\"{}\"", escaped_realm));
        #[cfg(feature = "digest-auth")]
        {
            let nonce = self.nonces.issue_digest_nonce();
            let opaque = NonceStore::issue_opaque();
            headers.push(format!(
                "Digest realm=\"{}\", qop=\"auth\", nonce=\"{}\", opaque=\"{}\", algorithm=SHA-256",
                escaped_realm, nonce, opaque
            ));
        }
        AuthChallenge {
            header_values: headers,
            stale: false,
        }
    }
}
