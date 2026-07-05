use super::CompiledDecisionService;
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use qpx_core::config::{DecisionServiceConfig, DecisionServiceSignatureAlgorithm};
use ring::hmac;
use ring::signature::Ed25519KeyPair;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub(super) enum CompiledSignature {
    HmacSha256 { key_id: String, secret: Vec<u8> },
    Ed25519 { key_id: String, pkcs8: Vec<u8> },
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
    }
}

pub(super) fn apply_http_message_signature(
    mut builder: http::request::Builder,
    cfg: &CompiledDecisionService,
    body: &[u8],
) -> Result<http::request::Builder> {
    let Some(signature) = cfg.signature.as_ref() else {
        return Ok(builder);
    };
    let digest = format!("sha-256=:{}:", BASE64.encode(Sha256::digest(body)));
    builder = builder.header("content-digest", digest.as_str());
    let mut path = cfg.endpoint.path().to_string();
    if let Some(query) = cfg.endpoint.query() {
        path.push('?');
        path.push_str(query);
    }
    let signature_input =
        r#"sig1=("@method" "@path" "content-digest" "content-type");alg="qpx-v1";keyid=""#;
    let key_id = match signature {
        CompiledSignature::HmacSha256 { key_id, .. }
        | CompiledSignature::Ed25519 { key_id, .. } => key_id,
    };
    let signature_input = format!("{signature_input}{key_id}\"");
    let base = format!(
        "\"@method\": POST\n\"@path\": {path}\n\"content-digest\": {digest}\n\"content-type\": application/json\n\"@signature-params\": {signature_input}"
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
    };
    Ok(builder.header("signature-input", signature_input).header(
        "signature",
        format!("sig1=:{}:", BASE64.encode(signature_bytes)),
    ))
}
