use super::CompiledDecisionService;
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use qpx_core::config::{DecisionServiceConfig, DecisionServiceSignatureAlgorithm};
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, RSA_PSS_SHA256, RsaKeyPair,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub(super) enum CompiledSignature {
    HmacSha256 { key_id: String, secret: Vec<u8> },
    Ed25519 { key_id: String, pkcs8: Vec<u8> },
    EcdsaP256Sha256 { key_id: String, pkcs8: Vec<u8> },
    RsaPssSha256 { key_id: String, pkcs8: Vec<u8> },
}

pub(super) fn compile_signature(
    config: &DecisionServiceConfig,
) -> Result<Option<CompiledSignature>> {
    let Some(signature) = config.auth.http_message_signatures.as_ref() else {
        return Ok(None);
    };
    match signature.algorithm {
        DecisionServiceSignatureAlgorithm::HmacSha256 => {
            let env = signature.secret_env.as_deref().ok_or_else(|| {
                anyhow!(
                    "decision_service {} hmac_sha256 signature requires secret_env",
                    config.name
                )
            })?;
            Ok(Some(CompiledSignature::HmacSha256 {
                key_id: signature.key_id.clone(),
                secret: std::env::var(env)
                    .with_context(|| format!("failed to read signature secret env {env}"))?
                    .into_bytes(),
            }))
        }
        DecisionServiceSignatureAlgorithm::Ed25519 => {
            let env = signature.private_key_env.as_deref().ok_or_else(|| {
                anyhow!(
                    "decision_service {} ed25519 signature requires private_key_env",
                    config.name
                )
            })?;
            Ok(Some(CompiledSignature::Ed25519 {
                key_id: signature.key_id.clone(),
                pkcs8: BASE64
                    .decode(std::env::var(env).with_context(|| {
                        format!("failed to read signature private key env {env}")
                    })?)
                    .with_context(|| {
                        format!(
                            "decision_service {} ed25519 key must be base64 PKCS#8",
                            config.name
                        )
                    })?,
            }))
        }
        DecisionServiceSignatureAlgorithm::EcdsaP256Sha256 => {
            compile_private_key(config, signature, |key_id, pkcs8| {
                CompiledSignature::EcdsaP256Sha256 { key_id, pkcs8 }
            })
        }
        DecisionServiceSignatureAlgorithm::RsaPssSha256 => {
            compile_private_key(config, signature, |key_id, pkcs8| {
                CompiledSignature::RsaPssSha256 { key_id, pkcs8 }
            })
        }
    }
}

fn compile_private_key(
    config: &DecisionServiceConfig,
    signature: &qpx_core::config::DecisionServiceHttpMessageSignaturesConfig,
    build: impl FnOnce(String, Vec<u8>) -> CompiledSignature,
) -> Result<Option<CompiledSignature>> {
    let env = signature.private_key_env.as_deref().ok_or_else(|| {
        anyhow!(
            "decision_service {} asymmetric signature requires private_key_env",
            config.name
        )
    })?;
    let pkcs8 = BASE64
        .decode(
            std::env::var(env)
                .with_context(|| format!("failed to read signature private key env {env}"))?,
        )
        .with_context(|| {
            format!(
                "decision_service {} signing key must be base64 PKCS#8",
                config.name
            )
        })?;
    Ok(Some(build(signature.key_id.clone(), pkcs8)))
}

pub(super) fn apply_http_message_signature(
    builder: http::request::Builder,
    cfg: &CompiledDecisionService,
    body: &[u8],
) -> Result<http::request::Builder> {
    let Some(signature) = cfg.signature.as_ref() else {
        return Ok(builder);
    };
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .with_context(|| "system clock is before the Unix epoch")?
        .as_secs();
    let (digest, signature_input, signature_value) =
        build_signature_fields(signature, &cfg.endpoint, body, created)?;
    Ok(builder
        .header("content-digest", digest)
        .header("signature-input", signature_input)
        .header("signature", signature_value))
}

fn build_signature_fields(
    signature: &CompiledSignature,
    endpoint: &url::Url,
    body: &[u8],
    created: u64,
) -> Result<(String, String, String)> {
    let digest = qpx_http::digest_fields::sha256_header_value(body)?
        .to_str()
        .with_context(|| "generated Content-Digest was not ASCII")?
        .to_string();
    let mut path = endpoint.path().to_string();
    if let Some(query) = endpoint.query() {
        path.push('?');
        path.push_str(query);
    }
    let (key_id, algorithm) = match signature {
        CompiledSignature::HmacSha256 { key_id, .. } => (key_id, "hmac-sha256"),
        CompiledSignature::Ed25519 { key_id, .. } => (key_id, "ed25519"),
        CompiledSignature::EcdsaP256Sha256 { key_id, .. } => (key_id, "ecdsa-p256-sha256"),
        CompiledSignature::RsaPssSha256 { key_id, .. } => (key_id, "rsa-pss-sha256"),
    };
    let key_id = quote_sf_string(key_id)?;
    let signature_params = format!(
        r#"("@method" "@path" "content-digest" "content-type");created={created};keyid={key_id};alg="{algorithm}""#
    );
    let signature_input = format!("sig1={signature_params}");
    let base = format!(
        "\"@method\": POST\n\"@path\": {path}\n\"content-digest\": {digest}\n\"content-type\": application/json\n\"@signature-params\": {signature_params}"
    );
    let signature_bytes = match signature {
        CompiledSignature::HmacSha256 { secret, .. } => {
            let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
            hmac::sign(&key, base.as_bytes()).as_ref().to_vec()
        }
        CompiledSignature::Ed25519 { pkcs8, .. } => {
            let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8)
                .map_err(|_| anyhow!("failed to parse ed25519 PKCS#8 signing key"))?;
            key_pair.sign(base.as_bytes()).as_ref().to_vec()
        }
        CompiledSignature::EcdsaP256Sha256 { pkcs8, .. } => {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
                .map_err(|_| anyhow!("failed to parse ECDSA P-256 PKCS#8 signing key"))?;
            key_pair
                .sign(&rng, base.as_bytes())
                .map_err(|_| anyhow!("failed to sign with ECDSA P-256"))?
                .as_ref()
                .to_vec()
        }
        CompiledSignature::RsaPssSha256 { pkcs8, .. } => {
            let rng = SystemRandom::new();
            let key_pair = RsaKeyPair::from_pkcs8(pkcs8)
                .map_err(|_| anyhow!("failed to parse RSA PKCS#8 signing key"))?;
            let mut output = vec![0; key_pair.public().modulus_len()];
            key_pair
                .sign(&RSA_PSS_SHA256, &rng, base.as_bytes(), &mut output)
                .map_err(|_| anyhow!("failed to sign with RSA-PSS SHA-256"))?;
            output
        }
    };
    Ok((
        digest,
        signature_input,
        format!("sig1=:{}:", BASE64.encode(signature_bytes)),
    ))
}

fn quote_sf_string(value: &str) -> Result<String> {
    if !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(anyhow!(
            "HTTP Message Signature key_id must contain printable ASCII"
        ));
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9421_hmac_signature_uses_standard_algorithm_and_signature_params() {
        let signature = CompiledSignature::HmacSha256 {
            key_id: "pdp-client-key".to_string(),
            secret: b"test-secret".to_vec(),
        };
        let endpoint = url::Url::parse("https://pdp.example/decision?tenant=corp").unwrap();
        let (digest, input, signature_value) =
            build_signature_fields(&signature, &endpoint, br#"{"allow":true}"#, 1_700_000_000)
                .expect("signature fields");

        assert!(digest.starts_with("sha-256=:"));
        assert_eq!(
            input,
            r#"sig1=("@method" "@path" "content-digest" "content-type");created=1700000000;keyid="pdp-client-key";alg="hmac-sha256""#
        );
        assert!(signature_value.starts_with("sig1=:"));
        assert!(!input.contains("qpx-v1"));
        qpx_http::structured_fields::parse_dictionary(input.as_bytes())
            .expect("Signature-Input must be an RFC 9651 dictionary");
        qpx_http::structured_fields::parse_dictionary(signature_value.as_bytes())
            .expect("Signature must be an RFC 9651 dictionary");
    }

    #[test]
    fn signature_key_id_is_an_rfc9651_string() {
        assert_eq!(quote_sf_string("a\\\"b").unwrap(), r#""a\\\"b""#);
        assert!(quote_sf_string("invalid\nkey").is_err());
    }
}
