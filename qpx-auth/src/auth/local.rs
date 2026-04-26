use qpx_core::config::LocalUser;

#[cfg(feature = "digest-auth")]
use super::digest::{parse_sha256_ha1, sha256_hex};

#[derive(Debug, Clone)]
pub(super) struct LocalUserEntry {
    pub(super) username: String,
    pub(super) password: Option<String>,
    #[cfg(feature = "digest-auth")]
    pub(super) digest_ha1_sha256: Option<String>,
}

impl LocalUserEntry {
    pub(super) fn from_config(user: &LocalUser, realm: &str) -> Self {
        #[cfg(not(feature = "digest-auth"))]
        let _ = realm;
        #[cfg(feature = "digest-auth")]
        let digest_ha1_sha256 = user.ha1.as_deref().and_then(parse_sha256_ha1).or_else(|| {
            user.password.as_ref().map(|password| {
                sha256_hex(format!("{}:{}:{}", user.username, realm, password).as_bytes())
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
