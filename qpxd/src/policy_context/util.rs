use anyhow::{anyhow, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use http::header::HeaderName;
use hyper::HeaderMap;
use ring::signature;
use serde_json::Value as JsonValue;
use sha2::Digest;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[cfg(feature = "tls-rustls")]
use x509_parser::certificate::X509Certificate;
#[cfg(feature = "tls-rustls")]
use x509_parser::prelude::FromDer;
#[cfg(feature = "tls-rustls")]
use x509_parser::x509::SubjectPublicKeyInfo;

pub(super) fn compile_optional_header_name(name: Option<&str>) -> Result<Option<HeaderName>> {
    name.filter(|value| !value.trim().is_empty())
        .map(|value| HeaderName::from_bytes(value.as_bytes()).map_err(Into::into))
        .transpose()
}

pub(super) fn peer_matches(peer_ip: IpAddr, trusted_peers: &[cidr::IpCidr]) -> bool {
    trusted_peers.iter().any(|cidr| cidr.contains(&peer_ip))
}

pub(super) fn extract_first_header(
    headers: &HeaderMap,
    name: Option<&HeaderName>,
) -> Option<String> {
    let name = name?;
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn extract_list_header(headers: &HeaderMap, name: Option<&HeaderName>) -> Vec<String> {
    let Some(name) = name else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for value in headers.get_all(name).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for item in value.split(',') {
            let item = item.trim();
            if !item.is_empty() && !out.iter().any(|existing| existing == item) {
                out.push(item.to_string());
            }
        }
    }
    out
}

pub(super) fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

pub(super) fn merge_identity_source_labels(
    left: Option<String>,
    right: Option<String>,
) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) if left == right => Some(left),
        (Some(left), Some(right)) => Some(format!("{left},{right}")),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

pub(super) fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let value = value.trim();
        if !value.is_empty() && !out.iter().any(|existing| existing == value) {
            out.push(value.to_string());
        }
    }
    out
}

pub(super) fn extract_assertion_token<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
    prefix: Option<&str>,
) -> Option<&'a str> {
    for value in headers.get_all(name).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if let Some(prefix) = prefix {
            if let Some(token) = value.strip_prefix(prefix) {
                let token = token.trim();
                if !token.is_empty() {
                    return Some(token);
                }
            }
            continue;
        }
        return Some(value);
    }
    None
}

pub(super) fn load_hmac_secret_from_env(env_name: &str) -> Result<Arc<[u8]>> {
    let secret = std::env::var(env_name)
        .map_err(|_| anyhow!("missing environment variable {}", env_name))?;
    Ok(Arc::<[u8]>::from(secret.into_bytes()))
}

pub(super) fn load_public_key_from_env(env_name: &str) -> Result<Arc<[u8]>> {
    let raw = std::env::var(env_name)
        .map_err(|_| anyhow!("missing environment variable {}", env_name))?;
    Ok(Arc::<[u8]>::from(parse_public_key_material(raw.as_str())?))
}

pub(super) fn parse_public_key_material(raw: &str) -> Result<Vec<u8>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("signed assertion public key is empty"));
    }
    if raw.contains("-----BEGIN") {
        let blocks = pem::parse_many(raw)?;
        for block in blocks {
            match block.tag() {
                "PUBLIC KEY" => {
                    #[cfg(feature = "tls-rustls")]
                    {
                        let der = block.into_contents();
                        let (_, spki) = SubjectPublicKeyInfo::from_der(der.as_slice())
                            .map_err(|_| anyhow!("invalid PUBLIC KEY PEM"))?;
                        return Ok(spki.subject_public_key.data.to_vec());
                    }
                    #[cfg(not(feature = "tls-rustls"))]
                    {
                        return Ok(block.into_contents());
                    }
                }
                "CERTIFICATE" => {
                    #[cfg(feature = "tls-rustls")]
                    {
                        let der = block.into_contents();
                        let (_, cert) = X509Certificate::from_der(der.as_slice())
                            .map_err(|_| anyhow!("invalid CERTIFICATE PEM"))?;
                        return Ok(cert.public_key().subject_public_key.data.to_vec());
                    }
                    #[cfg(not(feature = "tls-rustls"))]
                    {
                        return Err(anyhow!(
                            "signed assertion certificate PEM requires build feature tls-rustls"
                        ));
                    }
                }
                _ => continue,
            }
        }
        return Err(anyhow!(
            "signed assertion public_key_env did not contain a supported PEM block"
        ));
    }
    if let Ok(decoded) = STANDARD.decode(raw.as_bytes()) {
        return Ok(decoded);
    }
    URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .map_err(|e| anyhow!("invalid public key encoding: {}", e))
}

pub(super) fn decode_jwt_segment(segment: &str) -> Result<Vec<u8>> {
    let segment = segment.trim();
    if segment.is_empty() {
        return Err(anyhow!("empty JWT segment"));
    }
    URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|e| anyhow!("invalid base64url segment: {}", e))
}

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

pub(super) fn hmac_digest<D>(secret: &[u8], data: &[u8], block_size: usize) -> Vec<u8>
where
    D: Digest + Default,
{
    let mut key = vec![0u8; block_size];
    if secret.len() > block_size {
        let digest = D::digest(secret);
        key[..digest.len()].copy_from_slice(digest.as_slice());
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    for i in 0..block_size {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = D::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();

    let mut outer = D::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().to_vec()
}

pub(super) fn verify_hmac_signature<D>(
    secret: Option<&[u8]>,
    data: &[u8],
    signature_bytes: &[u8],
    block_size: usize,
) -> Result<()>
where
    D: Digest + Default,
{
    let secret = secret
        .ok_or_else(|| anyhow!("JWT algorithm requires assertion.secret_env key material"))?;
    let expected = hmac_digest::<D>(secret, data, block_size);
    if constant_time_eq(signature_bytes, expected.as_slice()) {
        return Ok(());
    }
    Err(anyhow!("JWT signature verification failed"))
}

pub(super) fn verify_public_key_signature(
    algorithm: &'static dyn signature::VerificationAlgorithm,
    public_key: Option<&[u8]>,
    data: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    let public_key = public_key
        .ok_or_else(|| anyhow!("JWT algorithm requires assertion.public_key_env key material"))?;
    signature::UnparsedPublicKey::new(algorithm, public_key)
        .verify(data, signature_bytes)
        .map_err(|_| anyhow!("JWT signature verification failed"))
}

pub(super) fn validate_registered_claims(
    payload: &JsonValue,
    expected_issuer: Option<&str>,
    expected_audience: Option<&str>,
) -> Result<()> {
    if let Some(expected_issuer) = expected_issuer {
        let issuer =
            json_string_claim(payload, "iss").ok_or_else(|| anyhow!("JWT iss claim is missing"))?;
        if issuer != expected_issuer {
            return Err(anyhow!("JWT issuer mismatch"));
        }
    }
    if let Some(expected_audience) = expected_audience {
        let aud = payload
            .get("aud")
            .ok_or_else(|| anyhow!("JWT aud claim is missing"))?;
        let matched = match aud {
            JsonValue::String(value) => value == expected_audience,
            JsonValue::Array(values) => values
                .iter()
                .filter_map(|value| value.as_str())
                .any(|value| value == expected_audience),
            _ => false,
        };
        if !matched {
            return Err(anyhow!("JWT audience mismatch"));
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    if let Some(exp) = json_i64_claim(payload, "exp") {
        if now >= exp {
            return Err(anyhow!("JWT is expired"));
        }
    }
    if let Some(nbf) = json_i64_claim(payload, "nbf") {
        if now < nbf {
            return Err(anyhow!("JWT is not yet valid"));
        }
    }
    Ok(())
}

pub(super) fn json_string_claim(payload: &JsonValue, claim: &str) -> Option<String> {
    payload
        .get(claim)?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn json_i64_claim(payload: &JsonValue, claim: &str) -> Option<i64> {
    payload.get(claim)?.as_i64()
}

pub(super) fn json_list_claim(
    payload: &JsonValue,
    claim: &str,
    separator: Option<&str>,
) -> Vec<String> {
    let Some(value) = payload.get(claim) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match value {
        JsonValue::String(raw) => {
            let separator = separator.unwrap_or(",");
            for item in raw.split(separator) {
                let item = item.trim();
                if !item.is_empty() && !out.iter().any(|existing| existing == item) {
                    out.push(item.to_string());
                }
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                if let Some(item) = value.as_str().map(str::trim) {
                    if !item.is_empty() && !out.iter().any(|existing| existing == item) {
                        out.push(item.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    out
}

pub(super) fn selected_headers_map(
    headers: Option<&HeaderMap>,
    selected: &[HeaderName],
) -> HashMap<String, Vec<String>> {
    let Some(headers) = headers else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for name in selected {
        let values = headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !values.is_empty() {
            out.insert(name.as_str().to_string(), values);
        }
    }
    out
}
