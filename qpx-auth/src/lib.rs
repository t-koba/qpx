//! Authentication backends and proxy authentication helpers.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod auth;

#[cfg(feature = "ldap-auth")]
pub use auth::LdapAuthenticator;
pub use auth::{
    AuthChallenge, AuthError, AuthOutcome, AuthResult, AuthenticatedUser, Authenticator,
};
