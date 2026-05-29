use super::util::{verify_hmac_signature, verify_public_key_signature};
use anyhow::{Result, anyhow};
use ring::signature;
use sha2::{Sha256, Sha384, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JwtAlgorithm {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
}

impl JwtAlgorithm {
    pub(super) fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "HS256" => Ok(Self::Hs256),
            "HS384" => Ok(Self::Hs384),
            "HS512" => Ok(Self::Hs512),
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "RS512" => Ok(Self::Rs512),
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            other => Err(anyhow!("unsupported JWT algorithm: {}", other)),
        }
    }

    pub(super) fn header_name(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
        }
    }

    pub(super) fn verify(
        self,
        hmac_secret: Option<&[u8]>,
        public_key: Option<&[u8]>,
        data: &[u8],
        signature_bytes: &[u8],
    ) -> Result<()> {
        match self {
            Self::Hs256 => verify_hmac_signature::<Sha256>(hmac_secret, data, signature_bytes, 64),
            Self::Hs384 => verify_hmac_signature::<Sha384>(hmac_secret, data, signature_bytes, 128),
            Self::Hs512 => verify_hmac_signature::<Sha512>(hmac_secret, data, signature_bytes, 128),
            Self::Rs256 => verify_public_key_signature(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                public_key,
                data,
                signature_bytes,
            ),
            Self::Rs384 => verify_public_key_signature(
                &signature::RSA_PKCS1_2048_8192_SHA384,
                public_key,
                data,
                signature_bytes,
            ),
            Self::Rs512 => verify_public_key_signature(
                &signature::RSA_PKCS1_2048_8192_SHA512,
                public_key,
                data,
                signature_bytes,
            ),
            Self::Es256 => verify_public_key_signature(
                &signature::ECDSA_P256_SHA256_FIXED,
                public_key,
                data,
                signature_bytes,
            ),
            Self::Es384 => verify_public_key_signature(
                &signature::ECDSA_P384_SHA384_FIXED,
                public_key,
                data,
                signature_bytes,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::policy_context::crypto::*;
    use crate::policy_context::util::hmac_digest;

    #[test]
    fn parse_known_algorithms() {
        for raw in [
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384",
        ] {
            assert!(JwtAlgorithm::parse(raw).is_ok(), "{raw}");
        }
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(JwtAlgorithm::parse("hs256").unwrap(), JwtAlgorithm::Hs256);
        assert_eq!(JwtAlgorithm::parse("Hs256").unwrap(), JwtAlgorithm::Hs256);
    }

    #[test]
    fn parse_unknown_algorithm() {
        assert!(JwtAlgorithm::parse("NONE").is_err());
        assert!(JwtAlgorithm::parse("PS256").is_err());
    }

    #[test]
    fn parse_empty_string() {
        assert!(JwtAlgorithm::parse("").is_err());
    }

    #[test]
    fn parse_whitespace_trimming() {
        assert_eq!(JwtAlgorithm::parse(" HS256 ").unwrap(), JwtAlgorithm::Hs256);
    }

    #[test]
    fn header_name_roundtrip() {
        for alg in [
            JwtAlgorithm::Hs256,
            JwtAlgorithm::Hs384,
            JwtAlgorithm::Hs512,
            JwtAlgorithm::Rs256,
            JwtAlgorithm::Rs384,
            JwtAlgorithm::Rs512,
            JwtAlgorithm::Es256,
            JwtAlgorithm::Es384,
        ] {
            assert_eq!(JwtAlgorithm::parse(alg.header_name()).unwrap(), alg);
        }
    }

    #[test]
    fn verify_hmac_valid() {
        let sig = hmac_digest::<Sha256>(b"secret", b"payload", 64);
        JwtAlgorithm::Hs256
            .verify(Some(b"secret"), None, b"payload", sig.as_slice())
            .unwrap();
    }

    #[test]
    fn verify_hmac_invalid() {
        let sig = hmac_digest::<Sha256>(b"secret", b"payload", 64);
        assert!(
            JwtAlgorithm::Hs256
                .verify(Some(b"other"), None, b"payload", sig.as_slice())
                .is_err()
        );
    }

    #[test]
    fn verify_hmac_missing_secret() {
        assert!(
            JwtAlgorithm::Hs256
                .verify(None, None, b"payload", b"sig")
                .is_err()
        );
    }

    #[test]
    fn verify_rsa_missing_key() {
        assert!(
            JwtAlgorithm::Rs256
                .verify(None, None, b"payload", b"sig")
                .is_err()
        );
    }

    #[test]
    fn verify_ecdsa_missing_key() {
        assert!(
            JwtAlgorithm::Es256
                .verify(None, None, b"payload", b"sig")
                .is_err()
        );
    }
}
