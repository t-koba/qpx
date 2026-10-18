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
    Ed25519,
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
            "EDDSA" => Ok(Self::Ed25519),
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
            Self::Ed25519 => "EdDSA",
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
            Self::Ed25519 => {
                verify_public_key_signature(&signature::ED25519, public_key, data, signature_bytes)
            }
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
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA",
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
            JwtAlgorithm::Ed25519,
        ] {
            assert_eq!(JwtAlgorithm::parse(alg.header_name()).unwrap(), alg);
        }
    }

    #[test]
    fn ed25519_verifies_raw_and_spki_keys_and_fails_closed() {
        use crate::policy_context::util::parse_public_key_material;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use ring::signature::KeyPair as _;

        // Deterministic synthetic key used only in tests.
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
        let public_key = pair.public_key().as_ref();
        let input = b"eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0";
        let sig = pair.sign(input);
        let raw = STANDARD.encode(public_key);
        // RFC 8410 Ed25519 SubjectPublicKeyInfo prefix.
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(public_key);
        let pem = pem::encode(&pem::Pem::new("PUBLIC KEY", spki));
        for encoded in [raw, pem] {
            let key = parse_public_key_material(&encoded).unwrap();
            assert_eq!(key, public_key);
            JwtAlgorithm::Ed25519
                .verify(None, Some(&key), input, sig.as_ref())
                .unwrap();
        }
        for key in [None, Some(&public_key[..31]), Some(&[0; 33][..])] {
            assert!(
                JwtAlgorithm::Ed25519
                    .verify(None, key, input, sig.as_ref())
                    .is_err()
            );
        }
        assert!(
            JwtAlgorithm::Ed25519
                .verify(Some(public_key), None, input, sig.as_ref())
                .is_err()
        );
        for bad_sig in [&sig.as_ref()[..63], &[0; 64][..]] {
            assert!(
                JwtAlgorithm::Ed25519
                    .verify(None, Some(public_key), input, bad_sig)
                    .is_err()
            );
        }
        assert!(
            JwtAlgorithm::Ed25519
                .verify(None, Some(public_key), b"changed", sig.as_ref())
                .is_err()
        );
        for wrong_algorithm in [JwtAlgorithm::Es256, JwtAlgorithm::Rs256] {
            assert!(
                wrong_algorithm
                    .verify(None, Some(public_key), input, sig.as_ref())
                    .is_err()
            );
        }
        assert_eq!(JwtAlgorithm::parse("eddsa").unwrap().header_name(), "EdDSA");
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
