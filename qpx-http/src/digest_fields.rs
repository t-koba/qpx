use crate::structured_fields::{BareItem, ListEntry, parse_dictionary_fields};
use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub static CONTENT_DIGEST: HeaderName = HeaderName::from_static("content-digest");
pub static REPR_DIGEST: HeaderName = HeaderName::from_static("repr-digest");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestField {
    pub digests: HashMap<String, Vec<u8>>,
}

impl DigestField {
    pub fn parse(headers: &HeaderMap, name: &HeaderName) -> Result<Option<Self>> {
        let Some(dictionary) = parse_dictionary_fields(headers, name)
            .map_err(|error| anyhow!("invalid {} Structured Field: {error}", name.as_str()))?
        else {
            return Ok(None);
        };
        if dictionary.is_empty() {
            return Err(anyhow!("{} must not be empty", name.as_str()));
        }
        let mut digests = HashMap::new();
        for (algorithm, entry) in dictionary {
            let ListEntry::Item(item) = entry else {
                return Err(anyhow!("digest value must be a byte sequence"));
            };
            let BareItem::ByteSequence(value) = item.bare_item else {
                return Err(anyhow!("digest value must be a byte sequence"));
            };
            if !item.params.is_empty() {
                return Err(anyhow!("digest members must not have parameters"));
            }
            digests.insert(algorithm.as_str().to_string(), value);
        }
        Ok(Some(Self { digests }))
    }

    pub fn verify_sha256(&self, representation: &[u8]) -> Result<()> {
        let expected = self
            .digests
            .get("sha-256")
            .ok_or_else(|| anyhow!("sha-256 digest is required"))?;
        let actual = Sha256::digest(representation);
        if expected.as_slice() != actual.as_slice() {
            return Err(anyhow!("sha-256 digest mismatch"));
        }
        Ok(())
    }
}

pub fn sha256_header_value(representation: &[u8]) -> Result<HeaderValue> {
    let digest = STANDARD.encode(Sha256::digest(representation));
    HeaderValue::from_str(&format!("sha-256=:{digest}:"))
        .map_err(|error| anyhow!("failed to encode digest field: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_digest_round_trips_and_verifies() {
        let body = b"hello";
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_DIGEST.clone(), sha256_header_value(body).unwrap());
        let digest = DigestField::parse(&headers, &CONTENT_DIGEST)
            .unwrap()
            .unwrap();
        digest.verify_sha256(body).unwrap();
        assert!(digest.verify_sha256(b"modified").is_err());
    }

    #[test]
    fn rejects_non_binary_digest_members() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_DIGEST.clone(),
            HeaderValue::from_static("sha-256=wrong"),
        );
        assert!(DigestField::parse(&headers, &CONTENT_DIGEST).is_err());
    }
}
