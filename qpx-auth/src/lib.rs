#[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
use std::collections::HashMap;

#[path = "auth/authenticator.rs"]
mod authenticator;
#[cfg(feature = "ldap-auth")]
#[path = "auth/cache.rs"]
mod cache;
#[path = "auth/digest.rs"]
mod digest;
#[cfg(feature = "ldap-auth")]
#[path = "auth/ldap.rs"]
mod ldap;
#[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
#[path = "auth/local.rs"]
mod local;
#[cfg(any(feature = "basic-auth", feature = "digest-auth", test))]
#[path = "auth/util.rs"]
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
#[cfg(test)]
use util::escape_quoted_header_value;

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
#[path = "auth/tests.rs"]
mod tests;
