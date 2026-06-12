#[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
use std::collections::HashMap;
use thiserror::Error;

mod authenticator;
#[cfg(feature = "ldap-auth")]
mod cache;
mod digest;
#[cfg(feature = "ldap-auth")]
mod ldap;
#[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
mod local;
#[cfg(any(feature = "basic-auth", feature = "digest-auth", test))]
mod util;

#[cfg(feature = "ldap-auth")]
use cache::LdapCache;
#[cfg(feature = "digest-auth")]
use digest::NonceStore;
#[cfg(feature = "ldap-auth")]
pub use ldap::LdapAuthenticator;
#[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
use local::LocalUserEntry;

#[cfg(all(test, feature = "ldap-auth"))]
use ldap::ldap_escape_filter_value;
#[cfg(all(test, feature = "basic-auth"))]
use util::constant_time_eq_bytes;
#[cfg(test)]
use util::escape_quoted_header_value;

/// Authenticated user identity returned by an auth backend.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// User name.
    pub username: String,
    /// Group names associated with the user.
    pub groups: Vec<String>,
    /// Provider that authenticated the user.
    pub provider: String,
}

/// Proxy authentication challenge to send to a client.
#[derive(Debug, Clone)]
pub struct AuthChallenge {
    /// Header values for `Proxy-Authenticate`.
    pub header_values: Vec<String>,
    /// Whether a digest nonce was stale.
    pub stale: bool,
}

/// Authentication decision.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// Request is authenticated.
    Allowed(AuthenticatedUser),
    /// Client should retry with credentials.
    Challenge(AuthChallenge),
    /// Request is denied with an audit reason.
    Denied(String),
}

/// Result type used by authentication operations.
pub type AuthResult<T> = std::result::Result<T, AuthError>;

/// Error returned by authentication operations.
#[derive(Debug, Error)]
pub enum AuthError {
    #[cfg(feature = "ldap-auth")]
    /// LDAP operation timed out.
    #[error("LDAP operation timed out")]
    LdapTimeout(#[from] tokio::time::error::Elapsed),
    #[cfg(feature = "ldap-auth")]
    /// LDAP operation failed.
    #[error("LDAP operation failed")]
    Ldap(#[from] ldap3::LdapError),
    /// Authentication backend failed.
    #[error("authentication backend error")]
    Backend(#[from] anyhow::Error),
}

/// Authenticator for configured local, digest, and LDAP providers.
#[derive(Debug, Clone)]
pub struct Authenticator {
    realm: String,
    #[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
    audit_redact_query_keys: Vec<String>,
    #[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
    local: HashMap<String, LocalUserEntry>,
    #[cfg(feature = "ldap-auth")]
    ldap: Option<LdapAuthenticator>,
    #[cfg(feature = "digest-auth")]
    nonces: NonceStore,
    #[cfg(feature = "ldap-auth")]
    ldap_cache: LdapCache,
}

#[cfg(test)]
mod tests;
