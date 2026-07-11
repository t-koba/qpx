//! RFC 9842 Compression Dictionary Transport field and framing validation.

use crate::structured_fields::{BareItem, ListEntry, parse_dictionary, parse_item};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Cursor, Error as IoError, ErrorKind, Read};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

pub const DCB_MAGIC: [u8; 4] = [0xff, 0x44, 0x43, 0x42];
pub const DCZ_MAGIC: [u8; 8] = [0x5e, 0x2a, 0x4d, 0x18, 0x20, 0, 0, 0];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseAsDictionary {
    pub match_pattern: String,
    pub match_destinations: Vec<String>,
    pub id: Option<String>,
    pub dictionary_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompressionDictionaryError {
    #[error("field is not a valid RFC 9651 value: {0}")]
    StructuredField(String),
    #[error("Use-As-Dictionary requires a String match member")]
    MissingMatch,
    #[error("Use-As-Dictionary contains an invalid member type")]
    InvalidMember,
    #[error("dictionary id exceeds 1024 characters")]
    IdentifierTooLong,
    #[error("Available-Dictionary must contain one SHA-256 byte sequence")]
    InvalidAvailableDictionary,
    #[error("dictionary-compressed body has an invalid framing header")]
    InvalidFraming,
    #[error("dictionary hash does not match the advertised dictionary")]
    HashMismatch,
    #[error("dictionary compression failed: {0}")]
    Compression(String),
    #[error("compression dictionaries require secure same-origin URLs")]
    InsecureOrCrossOrigin,
    #[error("compression dictionary freshness must be greater than zero")]
    InvalidFreshness,
    #[error("compression dictionary exceeds the configured cache size")]
    DictionaryTooLarge,
    #[error("compression dictionary cache lock is poisoned")]
    CachePoisoned,
}

#[derive(Debug, Clone)]
pub struct CachedDictionary {
    pub source_url: Url,
    pub hash: [u8; 32],
    pub id: Option<String>,
    pub body: Vec<u8>,
    pub policy: UseAsDictionary,
    expires_at: Instant,
    inserted_at: Instant,
}

#[derive(Debug)]
pub struct CompressionDictionaryCache {
    maximum_entries: usize,
    maximum_dictionary_bytes: usize,
    entries: RwLock<HashMap<[u8; 32], CachedDictionary>>,
}

impl CompressionDictionaryCache {
    pub fn new(
        maximum_entries: usize,
        maximum_dictionary_bytes: usize,
    ) -> Result<Self, CompressionDictionaryError> {
        if maximum_entries == 0 || maximum_dictionary_bytes == 0 {
            return Err(CompressionDictionaryError::DictionaryTooLarge);
        }
        Ok(Self {
            maximum_entries,
            maximum_dictionary_bytes,
            entries: RwLock::new(HashMap::new()),
        })
    }

    pub fn insert(
        &self,
        request_url: &Url,
        source_url: Url,
        body: Vec<u8>,
        policy: UseAsDictionary,
        freshness: Duration,
    ) -> Result<[u8; 32], CompressionDictionaryError> {
        require_secure_same_origin(request_url, &source_url)?;
        if freshness.is_zero() {
            return Err(CompressionDictionaryError::InvalidFreshness);
        }
        if body.len() > self.maximum_dictionary_bytes {
            return Err(CompressionDictionaryError::DictionaryTooLarge);
        }
        let hash: [u8; 32] = Sha256::digest(&body).into();
        let now = Instant::now();
        let entry = CachedDictionary {
            source_url,
            hash,
            id: policy.id.clone(),
            body,
            policy,
            expires_at: now + freshness,
            inserted_at: now,
        };
        let mut entries = self
            .entries
            .write()
            .map_err(|_| CompressionDictionaryError::CachePoisoned)?;
        entries.retain(|_, candidate| candidate.expires_at > now);
        if entries.len() >= self.maximum_entries
            && !entries.contains_key(&hash)
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, candidate)| candidate.inserted_at)
                .map(|(hash, _)| *hash)
        {
            entries.remove(&oldest);
        }
        entries.insert(hash, entry);
        Ok(hash)
    }

    pub fn lookup(
        &self,
        request_url: &Url,
        destination: &str,
        advertised_hash: [u8; 32],
        dictionary_id: Option<&str>,
    ) -> Result<Option<CachedDictionary>, CompressionDictionaryError> {
        let now = Instant::now();
        let mut entries = self
            .entries
            .write()
            .map_err(|_| CompressionDictionaryError::CachePoisoned)?;
        entries.retain(|_, candidate| candidate.expires_at > now);
        let Some(entry) = entries.get(&advertised_hash) else {
            return Ok(None);
        };
        require_secure_same_origin(request_url, &entry.source_url)?;
        if entry.id.as_deref() != dictionary_id
            || !destination_matches(&entry.policy.match_destinations, destination)
            || !path_pattern_matches(&entry.policy.match_pattern, request_url.path())
        {
            return Ok(None);
        }
        Ok(Some(entry.clone()))
    }
}

fn require_secure_same_origin(
    request_url: &Url,
    source_url: &Url,
) -> Result<(), CompressionDictionaryError> {
    if request_url.scheme() != "https"
        || source_url.scheme() != "https"
        || request_url.origin() != source_url.origin()
    {
        return Err(CompressionDictionaryError::InsecureOrCrossOrigin);
    }
    Ok(())
}

fn destination_matches(configured: &[String], destination: &str) -> bool {
    configured.is_empty() || configured.iter().any(|value| value == destination)
}

fn path_pattern_matches(pattern: &str, path: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        !suffix.contains('*') && path.starts_with(prefix) && path.ends_with(suffix)
    } else {
        pattern == path
    }
}

pub fn parse_use_as_dictionary(
    value: &[u8],
) -> Result<UseAsDictionary, CompressionDictionaryError> {
    let dictionary = parse_dictionary(value)
        .map_err(|error| CompressionDictionaryError::StructuredField(error.to_string()))?;
    let match_pattern =
        string_member(dictionary.get("match"))?.ok_or(CompressionDictionaryError::MissingMatch)?;
    let match_destinations = match dictionary.get("match-dest") {
        None => Vec::new(),
        Some(ListEntry::InnerList(list)) => list
            .items
            .iter()
            .map(|item| match &item.bare_item {
                BareItem::String(value) => Ok(value.as_str().to_owned()),
                _ => Err(CompressionDictionaryError::InvalidMember),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(CompressionDictionaryError::InvalidMember),
    };
    let id = string_member(dictionary.get("id"))?;
    if id
        .as_ref()
        .is_some_and(|value| value.chars().count() > 1024)
    {
        return Err(CompressionDictionaryError::IdentifierTooLong);
    }
    let dictionary_type = match dictionary.get("type") {
        None => "raw".to_owned(),
        Some(ListEntry::Item(item)) => match &item.bare_item {
            BareItem::Token(value) => value.as_str().to_owned(),
            _ => return Err(CompressionDictionaryError::InvalidMember),
        },
        Some(_) => return Err(CompressionDictionaryError::InvalidMember),
    };
    Ok(UseAsDictionary {
        match_pattern,
        match_destinations,
        id,
        dictionary_type,
    })
}

pub fn parse_available_dictionary(value: &[u8]) -> Result<[u8; 32], CompressionDictionaryError> {
    let item = parse_item(value)
        .map_err(|error| CompressionDictionaryError::StructuredField(error.to_string()))?;
    let BareItem::ByteSequence(bytes) = item.bare_item else {
        return Err(CompressionDictionaryError::InvalidAvailableDictionary);
    };
    bytes
        .try_into()
        .map_err(|_| CompressionDictionaryError::InvalidAvailableDictionary)
}

pub fn parse_dictionary_id(value: &[u8]) -> Result<String, CompressionDictionaryError> {
    let item = parse_item(value)
        .map_err(|error| CompressionDictionaryError::StructuredField(error.to_string()))?;
    let BareItem::String(value) = item.bare_item else {
        return Err(CompressionDictionaryError::InvalidMember);
    };
    if value.as_str().chars().count() > 1024 {
        return Err(CompressionDictionaryError::IdentifierTooLong);
    }
    Ok(value.as_str().to_owned())
}

pub fn validate_encoded_dictionary_hash(
    encoding: &str,
    body: &[u8],
    dictionary: &[u8],
) -> Result<usize, CompressionDictionaryError> {
    let (magic, hash_offset) = match encoding {
        "dcb" => (DCB_MAGIC.as_slice(), DCB_MAGIC.len()),
        "dcz" => (DCZ_MAGIC.as_slice(), DCZ_MAGIC.len()),
        _ => return Err(CompressionDictionaryError::InvalidFraming),
    };
    let header_len = hash_offset + 32;
    if body.len() < header_len || &body[..magic.len()] != magic {
        return Err(CompressionDictionaryError::InvalidFraming);
    }
    let expected = Sha256::digest(dictionary);
    if body[hash_offset..header_len] != expected[..] {
        return Err(CompressionDictionaryError::HashMismatch);
    }
    Ok(header_len)
}

pub fn encode_dcz(
    content: &[u8],
    dictionary: &[u8],
    level: i32,
) -> Result<Vec<u8>, CompressionDictionaryError> {
    let mut compressor = zstd::bulk::Compressor::with_dictionary(level, dictionary)
        .map_err(|error| CompressionDictionaryError::Compression(error.to_string()))?;
    let payload = compressor
        .compress(content)
        .map_err(|error| CompressionDictionaryError::Compression(error.to_string()))?;
    let mut encoded = Vec::with_capacity(DCZ_MAGIC.len() + 32 + payload.len());
    encoded.extend_from_slice(&DCZ_MAGIC);
    encoded.extend_from_slice(&Sha256::digest(dictionary));
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

pub fn decode_dcz(
    encoded: &[u8],
    dictionary: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<u8>, CompressionDictionaryError> {
    let payload_offset = validate_encoded_dictionary_hash("dcz", encoded, dictionary)?;
    let mut decompressor = zstd::bulk::Decompressor::with_dictionary(dictionary)
        .map_err(|error| CompressionDictionaryError::Compression(error.to_string()))?;
    decompressor
        .decompress(&encoded[payload_offset..], max_output_bytes)
        .map_err(|error| CompressionDictionaryError::Compression(error.to_string()))
}

pub fn encode_dcb(
    content: &[u8],
    dictionary: &[u8],
    quality: u32,
) -> Result<Vec<u8>, CompressionDictionaryError> {
    if quality > 11 {
        return Err(CompressionDictionaryError::Compression(
            "Brotli quality must be in 0..=11".to_owned(),
        ));
    }
    let mut input = Cursor::new(content);
    let mut payload = Vec::new();
    let mut input_buffer = vec![0; 4096];
    let mut output_buffer = vec![0; 4096];
    let params = brotli::enc::BrotliEncoderParams {
        quality: quality as i32,
        lgwin: 24,
        ..Default::default()
    };
    let mut callback = ignore_brotli_metablock;
    brotli::BrotliCompressCustomIoCustomDict(
        &mut brotli::IoReaderWrapper(&mut input),
        &mut brotli::IoWriterWrapper(&mut payload),
        &mut input_buffer,
        &mut output_buffer,
        &params,
        brotli::enc::StandardAlloc::default(),
        &mut callback,
        dictionary,
        IoError::new(ErrorKind::UnexpectedEof, "unexpected Brotli input end"),
    )
    .map_err(|error| CompressionDictionaryError::Compression(error.to_string()))?;
    let mut encoded = Vec::with_capacity(DCB_MAGIC.len() + 32 + payload.len());
    encoded.extend_from_slice(&DCB_MAGIC);
    encoded.extend_from_slice(&Sha256::digest(dictionary));
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

fn ignore_brotli_metablock<'a, 'b>(
    _: &mut brotli::interface::PredictionModeContextMap<brotli::InputReferenceMut<'a>>,
    _: &mut [brotli::interface::StaticCommand],
    _: brotli::InputPair<'b>,
    _: &mut brotli::enc::StandardAlloc,
) {
}

pub fn decode_dcb(
    encoded: &[u8],
    dictionary: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<u8>, CompressionDictionaryError> {
    let payload_offset = validate_encoded_dictionary_hash("dcb", encoded, dictionary)?;
    let decoder = brotli::Decompressor::new_with_custom_dict(
        Cursor::new(&encoded[payload_offset..]),
        4096,
        dictionary.to_vec().into(),
    );
    let limit = u64::try_from(max_output_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut decoded = Vec::new();
    decoder
        .take(limit)
        .read_to_end(&mut decoded)
        .map_err(|error| CompressionDictionaryError::Compression(error.to_string()))?;
    if decoded.len() > max_output_bytes {
        return Err(CompressionDictionaryError::Compression(
            "dictionary decompression output exceeds configured limit".to_owned(),
        ));
    }
    Ok(decoded)
}

fn string_member(member: Option<&ListEntry>) -> Result<Option<String>, CompressionDictionaryError> {
    match member {
        None => Ok(None),
        Some(ListEntry::Item(item)) => match &item.bare_item {
            BareItem::String(value) => Ok(Some(value.as_str().to_owned())),
            _ => Err(CompressionDictionaryError::InvalidMember),
        },
        Some(_) => Err(CompressionDictionaryError::InvalidMember),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    #[test]
    fn parses_rfc9842_use_as_dictionary() {
        let value = parse_use_as_dictionary(
            br#"match="/product/*", match-dest=("document"), id="v1", type=raw"#,
        )
        .expect("valid field");
        assert_eq!(value.match_pattern, "/product/*");
        assert_eq!(value.match_destinations, ["document"]);
        assert_eq!(value.id.as_deref(), Some("v1"));
        assert_eq!(value.dictionary_type, "raw");
    }

    #[test]
    fn available_dictionary_requires_a_sha256_hash() {
        let hash = [7_u8; 32];
        let field = format!(":{}:", STANDARD.encode(hash));
        assert_eq!(parse_available_dictionary(field.as_bytes()).unwrap(), hash);
        assert!(parse_available_dictionary(b":AA==:").is_err());
    }

    #[test]
    fn validates_dcb_and_dcz_hash_binding() {
        let dictionary = b"shared dictionary";
        let hash = Sha256::digest(dictionary);
        for (encoding, magic) in [("dcb", DCB_MAGIC.as_slice()), ("dcz", DCZ_MAGIC.as_slice())] {
            let mut body = magic.to_vec();
            body.extend_from_slice(&hash);
            body.extend_from_slice(b"compressed payload");
            assert_eq!(
                validate_encoded_dictionary_hash(encoding, &body, dictionary),
                Ok(magic.len() + 32)
            );
            assert_eq!(
                validate_encoded_dictionary_hash(encoding, &body, b"wrong"),
                Err(CompressionDictionaryError::HashMismatch)
            );
        }
    }

    #[test]
    fn dcz_round_trip_uses_external_dictionary_and_output_limit() {
        let dictionary = b"common response prefix and shared field names";
        let content = b"common response prefix and shared field names: value";
        let encoded = encode_dcz(content, dictionary, 3).expect("encode dcz");
        assert_eq!(
            decode_dcz(&encoded, dictionary, content.len()).expect("decode dcz"),
            content
        );
        assert!(decode_dcz(&encoded, dictionary, content.len() - 1).is_err());
        assert!(decode_dcz(&encoded, b"different dictionary", content.len()).is_err());
    }

    #[test]
    fn dcb_round_trip_uses_external_dictionary_and_output_limit() {
        let dictionary = b"common response prefix and shared field names";
        let content = b"common response prefix and shared field names: value";
        let encoded = encode_dcb(content, dictionary, 5).expect("encode dcb");
        assert_eq!(
            decode_dcb(&encoded, dictionary, content.len()).expect("decode dcb"),
            content
        );
        assert!(decode_dcb(&encoded, dictionary, content.len() - 1).is_err());
        assert!(decode_dcb(&encoded, b"different dictionary", content.len()).is_err());
    }

    #[test]
    fn cache_enforces_https_same_origin_freshness_hash_and_policy() {
        let cache = CompressionDictionaryCache::new(2, 1024).unwrap();
        let request = Url::parse("https://example.test/product/42").unwrap();
        let source = Url::parse("https://example.test/dictionaries/product-v1").unwrap();
        let hash = cache
            .insert(
                &request,
                source,
                b"product dictionary".to_vec(),
                UseAsDictionary {
                    match_pattern: "/product/*".to_owned(),
                    match_destinations: vec!["document".to_owned()],
                    id: Some("v1".to_owned()),
                    dictionary_type: "raw".to_owned(),
                },
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(
            cache
                .lookup(&request, "document", hash, Some("v1"))
                .unwrap()
                .unwrap()
                .body,
            b"product dictionary"
        );
        assert!(
            cache
                .lookup(&request, "image", hash, Some("v1"))
                .unwrap()
                .is_none()
        );
        let cross_origin = Url::parse("https://other.test/dictionary").unwrap();
        assert_eq!(
            cache.insert(
                &request,
                cross_origin,
                Vec::new(),
                UseAsDictionary {
                    match_pattern: "/*".to_owned(),
                    match_destinations: Vec::new(),
                    id: None,
                    dictionary_type: "raw".to_owned(),
                },
                Duration::from_secs(1),
            ),
            Err(CompressionDictionaryError::InsecureOrCrossOrigin)
        );
    }
}
