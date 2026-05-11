#[cfg(feature = "auth-basic")]
pub(crate) use qpx_auth::{AuthChallenge, AuthOutcome, AuthenticatedUser, Authenticator};

#[cfg(not(feature = "auth-basic"))]
use anyhow::{Result, anyhow};
#[cfg(not(feature = "auth-basic"))]
use qpx_core::config::AuthConfig;
#[cfg(not(feature = "auth-basic"))]
use std::net::IpAddr;

#[cfg(not(feature = "auth-basic"))]
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub username: String,
    pub groups: Vec<String>,
    pub provider: String,
}

#[cfg(not(feature = "auth-basic"))]
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    Allowed(AuthenticatedUser),
}

#[cfg(not(feature = "auth-basic"))]
#[derive(Debug, Clone)]
pub struct Authenticator;

#[cfg(not(feature = "auth-basic"))]
impl Authenticator {
    pub(crate) fn new(config: &AuthConfig, _realm: &str) -> Result<Self> {
        if !config.users.is_empty() {
            return Err(anyhow!(
                "built-in Basic/Digest auth is configured but this qpxd build was compiled without auth-basic/auth-digest"
            ));
        }
        if config.ldap.is_some() {
            return Err(anyhow!(
                "built-in LDAP auth is configured but this qpxd build was compiled without auth-ldap-rustls/auth-ldap-native"
            ));
        }
        Ok(Self)
    }

    pub(crate) async fn authenticate_proxy(
        &self,
        _src_ip: Option<IpAddr>,
        _headers: &http::HeaderMap,
        required_providers: &[String],
        _method: &str,
        _uri: &str,
    ) -> Result<AuthOutcome> {
        if required_providers.is_empty() {
            return Ok(AuthOutcome::Allowed(AuthenticatedUser {
                username: "anonymous".to_string(),
                groups: Vec::new(),
                provider: "none".to_string(),
            }));
        }
        Err(anyhow!(
            "built-in auth provider {:?} requires qpxd auth-basic/auth-digest/auth-ldap-* build support",
            required_providers
        ))
    }
}
