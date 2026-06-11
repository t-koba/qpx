use qpx_core::config::LocalUser;
use zeroize::Zeroize;

#[cfg(feature = "digest-auth")]
use super::digest::{parse_sha256_ha1, sha256_hex};
#[cfg(feature = "basic-auth")]
use super::util::sha256_digest;

#[cfg(feature = "basic-auth")]
#[derive(Debug, Clone)]
pub(super) struct LocalPasswordDigest(pub(super) [u8; 32]);

#[cfg(feature = "basic-auth")]
impl Drop for LocalPasswordDigest {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "digest-auth")]
#[derive(Debug, Clone)]
pub(super) struct LocalDigestHa1(pub(super) String);

#[cfg(feature = "digest-auth")]
impl Drop for LocalDigestHa1 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone)]
pub(super) struct LocalUserEntry {
    #[cfg(feature = "basic-auth")]
    pub(super) password_digest: Option<LocalPasswordDigest>,
    #[cfg(feature = "digest-auth")]
    pub(super) digest_ha1_sha256: Option<LocalDigestHa1>,
}

impl LocalUserEntry {
    pub(super) fn from_config(user: &LocalUser, realm: &str) -> Self {
        #[cfg(not(feature = "digest-auth"))]
        let _ = realm;
        #[cfg(feature = "digest-auth")]
        let digest_ha1_sha256 = user
            .ha1
            .as_deref()
            .and_then(parse_sha256_ha1)
            .or_else(|| {
                user.password.as_ref().map(|password| {
                    sha256_hex(format!("{}:{}:{}", user.username, realm, password).as_bytes())
                })
            })
            .map(LocalDigestHa1);
        Self {
            #[cfg(feature = "basic-auth")]
            password_digest: user
                .password
                .as_ref()
                .map(|password| LocalPasswordDigest(sha256_digest(password.as_bytes()))),
            #[cfg(feature = "digest-auth")]
            digest_ha1_sha256,
        }
    }
}
