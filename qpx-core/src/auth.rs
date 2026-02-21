use crate::config::{AuthConfig, LdapConfig, LocalUser};
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::collections::HashMap;
use std::env;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::Level;

#[cfg(feature = "digest-auth")]
use rand::RngCore;

#[cfg(feature = "digest-auth")]
use sha2::Digest as _;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub username: String,
    pub groups: Vec<String>,
    pub provider: String,
}

#[derive(Debug, Clone)]
pub struct AuthChallenge {
    pub header_values: Vec<String>,
    pub stale: bool,
}

#[derive(Debug, Clone)]
pub enum AuthOutcome {
    Allowed(AuthenticatedUser),
    Challenge(AuthChallenge),
    Denied(String),
}

#[derive(Debug, Clone)]
pub struct Authenticator {
    realm: String,
    local: HashMap<String, LocalUserEntry>,
    ldap: Option<LdapAuthenticator>,
    #[cfg(feature = "digest-auth")]
    nonces: NonceStore,
    ldap_cache: LdapCache,
}

#[derive(Debug, Clone)]
struct LocalUserEntry {
    username: String,
    password: Option<String>,
    #[cfg(feature = "digest-auth")]
    digest_ha1_sha256: Option<String>,
}

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone)]
struct NonceStore {
    ttl: Duration,
    max_entries: usize,
    inner: std::sync::Arc<Mutex<HashMap<String, NonceState>>>,
}

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone)]
struct NonceState {
    created: Instant,
    last_nc: u32,
}

#[derive(Debug, Clone)]
struct LdapCache {
    ttl: Duration,
    max_entries: usize,
    inner: std::sync::Arc<Mutex<HashMap<String, LdapCacheEntry>>>,
}

#[derive(Debug, Clone)]
struct LdapCacheEntry {
    groups: Vec<String>,
    created: Instant,
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<Vec<String>>>;
}

#[derive(Debug, Clone)]
pub struct LdapAuthenticator {
    config: LdapConfig,
    bind_password: String,
}

impl Authenticator {
    pub fn new(config: &AuthConfig, realm: &str) -> Result<Self> {
        let mut local = HashMap::new();
        for user in &config.users {
            local.insert(
                user.username.clone(),
                LocalUserEntry::from_config(user, realm),
            );
        }

        let ldap = match &config.ldap {
            Some(cfg) => {
                let bind_password = env::var(&cfg.bind_password_env).with_context(|| {
                    format!("missing LDAP bind password env {}", cfg.bind_password_env)
                })?;
                Some(LdapAuthenticator::new(cfg.clone(), bind_password))
            }
            None => None,
        };

        Ok(Self {
            realm: realm.to_string(),
            local,
            ldap,
            #[cfg(feature = "digest-auth")]
            nonces: NonceStore::new(Duration::from_secs(300)),
            ldap_cache: LdapCache::new(Duration::from_secs(60)),
        })
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    fn strip_auth_scheme<'a>(header_value: &'a str, scheme: &str) -> Option<&'a str> {
        // RFC 9110 / RFC 7616: auth scheme names are case-insensitive.
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

        if let Some(_digest) = Self::strip_auth_scheme(header, "Digest") {
            #[cfg(feature = "digest-auth")]
            {
                if required_providers.iter().any(|p| p == "local") {
                    if let Some(user) = self.verify_digest(_digest, method, uri)? {
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
        // We issue qop="auth" challenges and require qop/nc/cnonce to enable
        // replay protection based on nonce-count progression.
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

impl LocalUserEntry {
    fn from_config(user: &LocalUser, _realm: &str) -> Self {
        #[cfg(feature = "digest-auth")]
        let digest_ha1_sha256 = user.ha1.as_deref().and_then(parse_sha256_ha1).or_else(|| {
            user.password.as_ref().map(|password| {
                sha256_hex(format!("{}:{}:{}", user.username, _realm, password).as_bytes())
            })
        });
        Self {
            username: user.username.clone(),
            password: user.password.clone(),
            #[cfg(feature = "digest-auth")]
            digest_ha1_sha256,
        }
    }
}

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestAlgorithm {
    Sha256,
    Sha256Sess,
}

#[cfg(feature = "digest-auth")]
impl NonceStore {
    const DEFAULT_MAX_ENTRIES: usize = 65_536;

    fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            inner: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn random_token() -> String {
        let mut buf = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut buf);
        BASE64.encode(buf)
    }

    fn issue_opaque() -> String {
        Self::random_token()
    }

    fn issue_digest_nonce(&self) -> String {
        let nonce = Self::random_token();
        let mut guard = self.inner.lock().expect("nonce mutex");
        Self::cleanup_expired_locked(&mut guard, self.ttl);
        while guard.len() >= self.max_entries {
            let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, state)| state.created)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            guard.remove(&oldest_key);
        }
        guard.insert(
            nonce.clone(),
            NonceState {
                created: Instant::now(),
                last_nc: 0,
            },
        );
        nonce
    }

    fn parse_digest_nc(&self, nonce: &str, nc_hex: &str) -> Option<u32> {
        let mut guard = self.inner.lock().expect("nonce mutex");
        Self::cleanup_expired_locked(&mut guard, self.ttl);

        let state = guard.get(nonce)?;
        if nc_hex.len() != 8 {
            return None;
        }
        let Ok(nc) = u32::from_str_radix(nc_hex, 16) else {
            return None;
        };
        if nc == 0 || nc <= state.last_nc {
            return None;
        }
        Some(nc)
    }

    fn mark_digest_nc_used(&self, nonce: &str, nc: u32) -> bool {
        let mut guard = self.inner.lock().expect("nonce mutex");
        Self::cleanup_expired_locked(&mut guard, self.ttl);

        let Some(state) = guard.get_mut(nonce) else {
            return false;
        };
        if nc == 0 || nc <= state.last_nc {
            return false;
        }
        state.last_nc = nc;
        true
    }

    fn cleanup_expired_locked(guard: &mut HashMap<String, NonceState>, ttl: Duration) {
        let now = Instant::now();
        guard.retain(|_, state| now.duration_since(state.created) < ttl);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().expect("nonce mutex").len()
    }
}

impl LdapCache {
    const DEFAULT_MAX_ENTRIES: usize = 16_384;

    fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            inner: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get(&self, username: &str, password: &str) -> Option<Vec<String>> {
        let key = cache_key(username, password);
        let mut guard = self.inner.lock().ok()?;
        let now = Instant::now();
        guard.retain(|_, e| now.duration_since(e.created) < self.ttl);
        guard.get(&key).map(|e| e.groups.clone())
    }

    fn put(&self, username: &str, password: &str, groups: Vec<String>) {
        let key = cache_key(username, password);
        if let Ok(mut guard) = self.inner.lock() {
            let now = Instant::now();
            guard.retain(|_, entry| now.duration_since(entry.created) < self.ttl);
            while guard.len() >= self.max_entries {
                let Some(oldest_key) = guard
                    .iter()
                    .min_by_key(|(_, entry)| entry.created)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                guard.remove(&oldest_key);
            }
            guard.insert(
                key,
                LdapCacheEntry {
                    groups,
                    created: Instant::now(),
                },
            );
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().expect("ldap cache mutex").len()
    }
}

impl LdapAuthenticator {
    fn new(config: LdapConfig, bind_password: String) -> Self {
        Self {
            config,
            bind_password,
        }
    }

    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<Vec<String>>> {
        let ldap_timeout = Duration::from_millis(self.config.timeout_ms.max(1));
        let settings = if self.config.require_starttls && self.config.url.starts_with("ldap://") {
            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            {
                LdapConnSettings::new().set_starttls(true)
            }
            #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
            {
                return Err(anyhow::anyhow!(
                    "ldap auth requires TLS backend (enable feature tls-rustls or tls-native)"
                ));
            }
        } else {
            LdapConnSettings::new()
        };
        #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
        if self.config.url.starts_with("ldaps://") {
            return Err(anyhow::anyhow!(
                "ldap auth requires TLS backend (enable feature tls-rustls or tls-native)"
            ));
        }
        let (conn, mut ldap) = timeout(
            ldap_timeout,
            LdapConnAsync::with_settings(settings, &self.config.url),
        )
        .await??;
        tokio::spawn(async move {
            if let Err(err) = conn.drive().await {
                tracing::warn!(error = ?err, "ldap connection error");
            }
        });

        timeout(
            ldap_timeout,
            ldap.simple_bind(&self.config.bind_dn, &self.bind_password),
        )
        .await??
        .success()?;

        let escaped_username = ldap_escape_filter_value(username);
        let filter = self
            .config
            .user_filter
            .replace("{username}", escaped_username.as_str());
        let (results, _res) = timeout(
            ldap_timeout,
            ldap.search(
                &self.config.user_base_dn,
                Scope::Subtree,
                &filter,
                vec!["dn"],
            ),
        )
        .await??
        .success()?;

        let entry = match results.into_iter().next() {
            Some(entry) => SearchEntry::construct(entry),
            None => return Ok(None),
        };

        let user_dn = entry.dn;
        if user_dn.is_empty() {
            return Ok(None);
        }

        let bind = timeout(ldap_timeout, ldap.simple_bind(&user_dn, password)).await??;
        if bind.success().is_err() {
            return Ok(None);
        }

        timeout(
            ldap_timeout,
            ldap.simple_bind(&self.config.bind_dn, &self.bind_password),
        )
        .await??
        .success()?;

        let escaped_user_dn = ldap_escape_filter_value(&user_dn);
        let escaped_username = ldap_escape_filter_value(username);
        let group_filter = self
            .config
            .group_filter
            .replace("{user_dn}", escaped_user_dn.as_str())
            .replace("{username}", escaped_username.as_str());
        let (groups, _res) = timeout(
            ldap_timeout,
            ldap.search(
                &self.config.group_base_dn,
                Scope::Subtree,
                &group_filter,
                vec![self.config.group_attr.as_str()],
            ),
        )
        .await??
        .success()?;

        let mut out = Vec::new();
        for entry in groups {
            let entry = SearchEntry::construct(entry);
            if let Some(values) = entry.attrs.get(&self.config.group_attr) {
                for v in values {
                    out.push(v.clone());
                }
            }
        }
        Ok(Some(out))
    }
}

#[cfg(feature = "digest-auth")]
fn parse_digest(input: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in input.chars() {
        if in_quotes {
            current.push(ch);
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            continue;
        }

        match ch {
            '"' => {
                in_quotes = true;
                current.push(ch);
            }
            ',' => {
                insert_digest_param(&mut out, current.as_str());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    insert_digest_param(&mut out, current.as_str());
    out
}

#[cfg(feature = "digest-auth")]
fn insert_digest_param(out: &mut HashMap<String, String>, raw: &str) {
    let raw = raw.trim();
    if raw.is_empty() {
        return;
    }
    let Some((key, value)) = raw.split_once('=') else {
        return;
    };
    let key = key.trim();
    if key.is_empty() {
        return;
    }
    let value = value.trim();
    let value = if value.starts_with('"') {
        unquote_http_quoted_string(value)
    } else {
        value.to_string()
    };
    out.insert(key.to_ascii_lowercase(), value);
}

#[cfg(feature = "digest-auth")]
fn unquote_http_quoted_string(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix('"') {
        s = rest;
    }
    if let Some(rest) = s.strip_suffix('"') {
        s = rest;
    }
    let mut out = String::with_capacity(s.len());
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            out.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(feature = "digest-auth")]
fn sha256_hex(input: &[u8]) -> String {
    let digest = sha2::Sha256::digest(input);
    hex_lower(digest.as_slice())
}

fn cache_key(username: &str, password: &str) -> String {
    format!(
        "{}:{}",
        username,
        password_cache_hash_hex(password.as_bytes())
    )
}

#[cfg(feature = "digest-auth")]
fn parse_sha256_ha1(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let hex = if raw.len() > 8 && raw[..8].eq_ignore_ascii_case("sha-256:") {
        &raw[8..]
    } else {
        raw
    };
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    if !hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

#[cfg(feature = "digest-auth")]
fn password_cache_hash_hex(input: &[u8]) -> String {
    sha256_hex(input)
}

#[cfg(not(feature = "digest-auth"))]
fn password_cache_hash_hex(input: &[u8]) -> String {
    // This is only used as an in-memory cache key component; it is not a security boundary.
    use std::hash::{Hash as _, Hasher as _};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(feature = "digest-auth")]
fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&left, &right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(feature = "digest-auth")]
fn constant_time_eq_hex_lower(expected_lower: &str, actual: &str) -> bool {
    let a = expected_lower.as_bytes();
    let b = actual.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&expected, &byte) in a.iter().zip(b.iter()) {
        let lower = if (b'A'..=b'F').contains(&byte) {
            byte.saturating_add(32)
        } else {
            byte
        };
        diff |= expected ^ lower;
    }
    diff == 0
}

fn ldap_escape_filter_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ if ch.is_control() => {
                let mut buf = [0u8; 4];
                for byte in ch.encode_utf8(&mut buf).as_bytes() {
                    let _ = write!(&mut out, "\\{:02x}", byte);
                }
            }
            _ => out.push(ch),
        }
    }
    out
}

fn escape_quoted_header_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\r' | '\n' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

pub fn now_rfc3339() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldap_filter_escape_escapes_reserved_chars() {
        let escaped = ldap_escape_filter_value("*()\\\u{0}");
        assert_eq!(escaped, "\\2a\\28\\29\\5c\\00");
    }

    #[cfg(feature = "digest-auth")]
    #[test]
    fn nonce_store_rejects_replayed_nc() {
        let store = NonceStore::new(Duration::from_secs(60));
        let nonce = store.issue_digest_nonce();
        let nc1 = store.parse_digest_nc(&nonce, "00000001").expect("nc1");
        assert!(store.mark_digest_nc_used(&nonce, nc1));
        assert!(store.parse_digest_nc(&nonce, "00000002").is_some());
        assert!(store.parse_digest_nc(&nonce, "00000001").is_none());
        assert!(store.parse_digest_nc(&nonce, "00000000").is_none());
        let nc2 = store.parse_digest_nc(&nonce, "00000002").expect("nc2");
        assert!(store.mark_digest_nc_used(&nonce, nc2));
        assert!(!store.mark_digest_nc_used(&nonce, nc2.saturating_sub(1)));
    }

    #[cfg(feature = "digest-auth")]
    #[test]
    fn nonce_store_caps_growth_on_issue() {
        let store = NonceStore::with_max_entries(Duration::from_secs(3600), 4);
        for _ in 0..32 {
            let _ = store.issue_digest_nonce();
        }
        assert!(store.len() <= 4);
    }

    #[test]
    fn ldap_cache_caps_growth() {
        let cache = LdapCache::with_max_entries(Duration::from_secs(3600), 4);
        for i in 0..32 {
            cache.put(
                format!("user{i}").as_str(),
                format!("pass{i}").as_str(),
                vec!["dev".to_string()],
            );
        }
        assert!(cache.len() <= 4);
    }

    #[test]
    fn quoted_header_escape_escapes_quote_and_backslash() {
        let escaped = escape_quoted_header_value("a\"b\\c");
        assert_eq!(escaped, "a\\\"b\\\\c");
    }
}
