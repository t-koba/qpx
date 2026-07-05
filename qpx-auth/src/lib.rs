//! Authentication backends and proxy authentication helpers.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod auth;

#[cfg(feature = "ldap-auth")]
pub use auth::LdapAuthenticator;
pub use auth::{
    AuthChallenge, AuthError, AuthOutcome, AuthResult, AuthenticatedUser, Authenticator,
};

#[doc(hidden)]
pub mod fuzz_support {
    #[cfg(feature = "basic-auth")]
    use base64::Engine;
    #[cfg(feature = "basic-auth")]
    use base64::engine::general_purpose::STANDARD as BASE64;

    /// Exercises configured credential parsers without performing backend I/O.
    pub fn parse_auth_credential(input: &[u8]) {
        #[cfg(not(any(feature = "basic-auth", feature = "digest-auth")))]
        let _ = input;
        #[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
        {
            let Ok(value) = std::str::from_utf8(input) else {
                return;
            };
            let value = value.trim();
            #[cfg(feature = "basic-auth")]
            if let Some(payload) = strip_scheme(value, "Basic") {
                let _ = BASE64.decode(payload);
            }
            #[cfg(feature = "digest-auth")]
            if let Some(payload) = strip_scheme(value, "Digest") {
                let _ = crate::auth::digest::parse_digest(payload);
            }
        }
    }

    #[cfg(any(feature = "basic-auth", feature = "digest-auth"))]
    fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
        let prefix = value.get(..scheme.len())?;
        if !prefix.eq_ignore_ascii_case(scheme) {
            return None;
        }
        let rest = &value[scheme.len()..];
        let mut chars = rest.chars();
        match chars.next() {
            Some(ch) if ch.is_ascii_whitespace() => Some(rest.trim_start()),
            _ => None,
        }
    }
}
