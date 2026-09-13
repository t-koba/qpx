//! RFC 9440 Client-Cert and Client-Cert-Chain request fields.
//!
//! The module deliberately keeps certificate forwarding opt-in.  Callers must
//! use [`ClientCertPolicy::enabled`] (or construct an equivalent policy) before
//! a peer certificate can be copied into an origin request.  Regardless of the
//! policy state, untrusted occurrences of the two fields are removed before a
//! request is forwarded.

use crate::structured_fields::{
    BareItem, ItemSerializer, ListEntry, ListSerializer, parse_item, parse_list,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use thiserror::Error;
use x509_parser::prelude::{FromDer, X509Certificate};

/// RFC 9440 end-entity client certificate field.
pub static CLIENT_CERT: HeaderName = HeaderName::from_static("client-cert");

/// RFC 9440 client certificate chain field.
pub static CLIENT_CERT_CHAIN: HeaderName = HeaderName::from_static("client-cert-chain");

/// Default maximum size of one DER certificate before Structured Fields encoding.
pub const DEFAULT_MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

/// Default maximum number of certificates in the forwarded validation chain.
pub const DEFAULT_MAX_CHAIN_CERTIFICATES: usize = 16;

/// Default maximum size of either encoded RFC 9440 field value.
pub const DEFAULT_MAX_FIELD_BYTES: usize = 128 * 1024;

/// Default maximum combined size of encoded RFC 9440 field values.
pub const DEFAULT_MAX_TOTAL_FIELD_BYTES: usize = 256 * 1024;

/// Limits applied before and after encoding RFC 9440 certificate fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientCertLimits {
    /// Maximum DER size of each certificate.
    pub max_certificate_bytes: usize,
    /// Maximum number of certificates in `Client-Cert-Chain`.
    pub max_chain_certificates: usize,
    /// Maximum encoded size of either individual field value.
    pub max_field_bytes: usize,
    /// Maximum combined encoded size of `Client-Cert` and `Client-Cert-Chain`.
    pub max_total_field_bytes: usize,
}

impl Default for ClientCertLimits {
    fn default() -> Self {
        Self {
            max_certificate_bytes: DEFAULT_MAX_CERTIFICATE_BYTES,
            max_chain_certificates: DEFAULT_MAX_CHAIN_CERTIFICATES,
            max_field_bytes: DEFAULT_MAX_FIELD_BYTES,
            max_total_field_bytes: DEFAULT_MAX_TOTAL_FIELD_BYTES,
        }
    }
}

impl ClientCertLimits {
    /// Construct explicit certificate forwarding limits.
    #[must_use]
    pub const fn new(
        max_certificate_bytes: usize,
        max_chain_certificates: usize,
        max_field_bytes: usize,
        max_total_field_bytes: usize,
    ) -> Self {
        Self {
            max_certificate_bytes,
            max_chain_certificates,
            max_field_bytes,
            max_total_field_bytes,
        }
    }

    fn validate(self) -> Result<Self, ClientCertError> {
        if self.max_certificate_bytes == 0
            || self.max_chain_certificates == 0
            || self.max_field_bytes == 0
            || self.max_total_field_bytes == 0
        {
            return Err(ClientCertError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Errors raised while parsing or forwarding RFC 9440 fields.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClientCertError {
    #[error("invalid RFC 9651 Structured Field: {0}")]
    StructuredField(String),
    #[error("Client-Cert must be a singleton byte sequence without parameters")]
    InvalidClientCert,
    #[error("Client-Cert-Chain must contain only byte sequence items without parameters")]
    InvalidChain,
    #[error("Client-Cert-Chain requires Client-Cert")]
    ChainWithoutClientCert,
    #[error("a client certificate is required")]
    MissingCertificate,
    #[error("Client-Cert must occur at most once")]
    MultipleClientCertFields,
    #[error("certificate is not a valid DER-encoded X.509 certificate")]
    InvalidCertificate,
    #[error("certificate exceeds the configured limit of {limit} bytes")]
    CertificateTooLarge { limit: usize },
    #[error("certificate chain exceeds the configured limit of {limit} certificates")]
    ChainTooLong { limit: usize },
    #[error("{field} exceeds the configured limit of {limit} bytes")]
    FieldTooLarge { field: &'static str, limit: usize },
    #[error("RFC 9440 fields exceed the configured total limit of {limit} bytes")]
    TotalFieldsTooLarge { limit: usize },
    #[error("Client-Cert-Chain must not contain the end-entity certificate")]
    DuplicateEndEntity,
    #[error("incoming {field} must be removed or overwritten before forwarding")]
    InboundHeader { field: &'static str },
    #[error("RFC 9440 limits must be greater than zero")]
    InvalidLimits,
    #[error("RFC 9440 field cannot be represented as an HTTP field value")]
    InvalidHeaderValue,
}

/// A validated end-entity certificate and optional RFC 9440 validation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificate {
    /// DER-encoded end-entity certificate presented by the client.
    pub end_entity: Vec<u8>,
    /// DER-encoded intermediate and optional trust-anchor certificates.
    pub chain: Vec<Vec<u8>>,
}

impl ClientCertificate {
    /// Validate and own peer certificates in TLS order.
    pub fn from_peer_certificates(
        certificates: &[Vec<u8>],
        limits: &ClientCertLimits,
    ) -> Result<Option<Self>, ClientCertError> {
        let limits = (*limits).validate()?;
        let Some((end_entity, chain)) = certificates.split_first() else {
            return Ok(None);
        };
        validate_certificate(end_entity, limits)?;
        if chain.len() > limits.max_chain_certificates {
            return Err(ClientCertError::ChainTooLong {
                limit: limits.max_chain_certificates,
            });
        }
        let chain = chain
            .iter()
            .map(|certificate| {
                validate_certificate(certificate, limits)?;
                if certificate == end_entity {
                    return Err(ClientCertError::DuplicateEndEntity);
                }
                Ok(certificate.clone())
            })
            .collect::<Result<Vec<_>, ClientCertError>>()?;
        Ok(Some(Self {
            end_entity: end_entity.clone(),
            chain,
        }))
    }

    /// Validate and construct certificate material from owned DER values.
    pub fn new(
        end_entity: Vec<u8>,
        chain: Vec<Vec<u8>>,
        limits: &ClientCertLimits,
    ) -> Result<Self, ClientCertError> {
        let mut certificates = Vec::with_capacity(chain.len().saturating_add(1));
        certificates.push(end_entity);
        certificates.extend(chain);
        Self::from_peer_certificates(&certificates, limits)?
            .ok_or(ClientCertError::MissingCertificate)
    }
}

/// Encoded request fields ready to apply to an origin request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificateHeaders {
    /// Serialized singleton `Client-Cert` value.
    pub client_cert: HeaderValue,
    /// Serialized `Client-Cert-Chain` list, when a chain is configured.
    pub client_cert_chain: Option<HeaderValue>,
}

impl ClientCertificateHeaders {
    /// Encode validated DER certificates using RFC 9651 Structured Fields.
    pub fn encode(
        end_entity: &[u8],
        chain: &[Vec<u8>],
        limits: &ClientCertLimits,
    ) -> Result<Self, ClientCertError> {
        let limits = (*limits).validate()?;
        validate_certificate(end_entity, limits)?;
        if chain.len() > limits.max_chain_certificates {
            return Err(ClientCertError::ChainTooLong {
                limit: limits.max_chain_certificates,
            });
        }
        for certificate in chain {
            validate_certificate(certificate, limits)?;
            if certificate == end_entity {
                return Err(ClientCertError::DuplicateEndEntity);
            }
        }

        let client_cert = encode_byte_sequence(end_entity, "Client-Cert", limits)?;
        let client_cert_chain = encode_chain(chain, limits)?;
        let total = client_cert
            .as_bytes()
            .len()
            .checked_add(client_cert_chain.as_ref().map_or(0, HeaderValue::len));
        if total.is_none_or(|size| size > limits.max_total_field_bytes) {
            return Err(ClientCertError::TotalFieldsTooLarge {
                limit: limits.max_total_field_bytes,
            });
        }
        Ok(Self {
            client_cert,
            client_cert_chain,
        })
    }

    /// Encode all certificates from a TLS peer certificate vector.
    pub fn from_peer_certificates(
        certificates: &[Vec<u8>],
        include_chain: bool,
        limits: &ClientCertLimits,
    ) -> Result<Option<Self>, ClientCertError> {
        let Some(end_entity) = certificates.first() else {
            return Ok(None);
        };
        let chain = if include_chain {
            certificates.get(1..).unwrap_or_default()
        } else {
            &[]
        };
        Self::encode(end_entity, chain, limits).map(Some)
    }

    /// Apply the prepared fields after removing all previous occurrences.
    pub fn apply_to(&self, headers: &mut HeaderMap) {
        headers.remove(&CLIENT_CERT);
        headers.remove(&CLIENT_CERT_CHAIN);
        headers.insert(CLIENT_CERT.clone(), self.client_cert.clone());
        if let Some(value) = self.client_cert_chain.as_ref() {
            headers.insert(CLIENT_CERT_CHAIN.clone(), value.clone());
        }
    }
}

/// Explicit send-side policy for RFC 9440 fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientCertPolicy {
    /// Whether a negotiated peer certificate may be forwarded.
    pub enabled: bool,
    /// Whether certificates after the end entity are forwarded.
    pub include_chain: bool,
    /// Reject untrusted inbound RFC 9440 fields instead of sanitizing them.
    pub reject_inbound: bool,
    /// Certificate and header size limits.
    pub limits: ClientCertLimits,
}

impl Default for ClientCertPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl ClientCertPolicy {
    /// A safe default: remove untrusted fields and emit nothing.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            include_chain: false,
            reject_inbound: false,
            limits: ClientCertLimits::new(
                DEFAULT_MAX_CERTIFICATE_BYTES,
                DEFAULT_MAX_CHAIN_CERTIFICATES,
                DEFAULT_MAX_FIELD_BYTES,
                DEFAULT_MAX_TOTAL_FIELD_BYTES,
            ),
        }
    }

    /// Explicit opt-in policy for forwarding the end-entity certificate.
    #[must_use]
    pub const fn enabled() -> Self {
        Self {
            enabled: true,
            include_chain: false,
            reject_inbound: true,
            limits: ClientCertLimits::new(
                DEFAULT_MAX_CERTIFICATE_BYTES,
                DEFAULT_MAX_CHAIN_CERTIFICATES,
                DEFAULT_MAX_FIELD_BYTES,
                DEFAULT_MAX_TOTAL_FIELD_BYTES,
            ),
        }
    }

    /// Return an opt-in policy that also forwards the validation chain.
    #[must_use]
    pub const fn with_chain() -> Self {
        Self {
            enabled: true,
            include_chain: true,
            reject_inbound: true,
            limits: ClientCertLimits::new(
                DEFAULT_MAX_CERTIFICATE_BYTES,
                DEFAULT_MAX_CHAIN_CERTIFICATES,
                DEFAULT_MAX_FIELD_BYTES,
                DEFAULT_MAX_TOTAL_FIELD_BYTES,
            ),
        }
    }

    /// Sanitize and, when enabled, add RFC 9440 fields to an origin request.
    pub fn apply(
        &self,
        headers: &mut HeaderMap,
        peer_certificates: Option<&[Vec<u8>]>,
    ) -> Result<(), ClientCertError> {
        self.limits.validate()?;
        if self.reject_inbound {
            if headers.contains_key(&CLIENT_CERT) {
                return Err(ClientCertError::InboundHeader {
                    field: "Client-Cert",
                });
            }
            if headers.contains_key(&CLIENT_CERT_CHAIN) {
                return Err(ClientCertError::InboundHeader {
                    field: "Client-Cert-Chain",
                });
            }
        }

        let prepared = if self.enabled {
            peer_certificates
                .map(|certificates| {
                    ClientCertificateHeaders::from_peer_certificates(
                        certificates,
                        self.include_chain,
                        &self.limits,
                    )
                })
                .transpose()?
                .flatten()
        } else {
            None
        };

        headers.remove(&CLIENT_CERT);
        headers.remove(&CLIENT_CERT_CHAIN);
        if let Some(prepared) = prepared {
            prepared.apply_to(headers);
        }
        Ok(())
    }
}

/// Parse the singleton RFC 9440 `Client-Cert` field.
pub fn parse_client_cert(
    value: &HeaderValue,
    limits: &ClientCertLimits,
) -> Result<Vec<u8>, ClientCertError> {
    let limits = (*limits).validate()?;
    if value.len() > limits.max_field_bytes {
        return Err(ClientCertError::FieldTooLarge {
            field: "Client-Cert",
            limit: limits.max_field_bytes,
        });
    }
    let item = parse_item(value.as_bytes())
        .map_err(|error| ClientCertError::StructuredField(error.to_string()))?;
    if !item.params.is_empty() {
        return Err(ClientCertError::InvalidClientCert);
    }
    let BareItem::ByteSequence(certificate) = item.bare_item else {
        return Err(ClientCertError::InvalidClientCert);
    };
    validate_certificate(&certificate, limits)?;
    Ok(certificate)
}

/// Parse all repeated RFC 9440 `Client-Cert-Chain` field lines in wire order.
pub fn parse_client_cert_chain(
    headers: &HeaderMap,
    limits: &ClientCertLimits,
) -> Result<Option<Vec<Vec<u8>>>, ClientCertError> {
    let limits = (*limits).validate()?;
    let values = headers.get_all(&CLIENT_CERT_CHAIN);
    let mut combined = Vec::new();
    let mut present = false;
    for value in values.iter() {
        present = true;
        if !combined.is_empty() {
            combined.extend_from_slice(b", ");
        }
        combined.extend_from_slice(value.as_bytes());
        if combined.len() > limits.max_field_bytes {
            return Err(ClientCertError::FieldTooLarge {
                field: "Client-Cert-Chain",
                limit: limits.max_field_bytes,
            });
        }
    }
    if !present {
        return Ok(None);
    }
    let list = parse_list(&combined)
        .map_err(|error| ClientCertError::StructuredField(error.to_string()))?;
    if list.len() > limits.max_chain_certificates {
        return Err(ClientCertError::ChainTooLong {
            limit: limits.max_chain_certificates,
        });
    }
    let mut chain = Vec::with_capacity(list.len());
    for entry in list {
        let ListEntry::Item(item) = entry else {
            return Err(ClientCertError::InvalidChain);
        };
        if !item.params.is_empty() {
            return Err(ClientCertError::InvalidChain);
        }
        let BareItem::ByteSequence(certificate) = item.bare_item else {
            return Err(ClientCertError::InvalidChain);
        };
        validate_certificate(&certificate, limits)?;
        chain.push(certificate);
    }
    Ok(Some(chain))
}

/// Parse and validate both RFC 9440 fields from an origin request.
pub fn parse_client_certificate_headers(
    headers: &HeaderMap,
    limits: &ClientCertLimits,
) -> Result<Option<ClientCertificate>, ClientCertError> {
    let limits = (*limits).validate()?;
    let values = headers.get_all(&CLIENT_CERT);
    let mut iter = values.iter();
    let Some(value) = iter.next() else {
        if headers.contains_key(&CLIENT_CERT_CHAIN) {
            return Err(ClientCertError::ChainWithoutClientCert);
        }
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(ClientCertError::MultipleClientCertFields);
    }
    let total = value
        .len()
        .checked_add(combined_field_length(headers, &CLIENT_CERT_CHAIN)?)
        .ok_or(ClientCertError::TotalFieldsTooLarge {
            limit: limits.max_total_field_bytes,
        })?;
    if total > limits.max_total_field_bytes {
        return Err(ClientCertError::TotalFieldsTooLarge {
            limit: limits.max_total_field_bytes,
        });
    }
    let end_entity = parse_client_cert(value, &limits)?;
    let chain = parse_client_cert_chain(headers, &limits)?.unwrap_or_default();
    if chain.iter().any(|certificate| certificate == &end_entity) {
        return Err(ClientCertError::DuplicateEndEntity);
    }
    Ok(Some(ClientCertificate { end_entity, chain }))
}

fn combined_field_length(headers: &HeaderMap, name: &HeaderName) -> Result<usize, ClientCertError> {
    let mut length = 0usize;
    for (index, value) in headers.get_all(name).iter().enumerate() {
        if index != 0 {
            length = length
                .checked_add(2)
                .ok_or(ClientCertError::InvalidHeaderValue)?;
        }
        length = length
            .checked_add(value.len())
            .ok_or(ClientCertError::InvalidHeaderValue)?;
    }
    Ok(length)
}

fn encode_byte_sequence(
    certificate: &[u8],
    field: &'static str,
    limits: ClientCertLimits,
) -> Result<HeaderValue, ClientCertError> {
    let encoded_len = byte_sequence_length(certificate.len())?;
    if encoded_len > limits.max_field_bytes {
        return Err(ClientCertError::FieldTooLarge {
            field,
            limit: limits.max_field_bytes,
        });
    }
    let value = ItemSerializer::new().bare_item(certificate).finish();
    if value.len() != encoded_len {
        return Err(ClientCertError::InvalidHeaderValue);
    }
    HeaderValue::from_str(&value).map_err(|_| ClientCertError::InvalidHeaderValue)
}

fn encode_chain(
    chain: &[Vec<u8>],
    limits: ClientCertLimits,
) -> Result<Option<HeaderValue>, ClientCertError> {
    if chain.is_empty() {
        return Ok(None);
    }
    let mut encoded_len = 0usize;
    for certificate in chain {
        encoded_len = encoded_len
            .checked_add(byte_sequence_length(certificate.len())?)
            .and_then(|size| size.checked_add(2))
            .ok_or(ClientCertError::FieldTooLarge {
                field: "Client-Cert-Chain",
                limit: limits.max_field_bytes,
            })?;
    }
    encoded_len = encoded_len.saturating_sub(2);
    if encoded_len > limits.max_field_bytes {
        return Err(ClientCertError::FieldTooLarge {
            field: "Client-Cert-Chain",
            limit: limits.max_field_bytes,
        });
    }
    let mut serializer = ListSerializer::new();
    for certificate in chain {
        let _ = serializer.bare_item(certificate.as_slice()).finish();
    }
    let value = serializer
        .finish()
        .ok_or(ClientCertError::InvalidHeaderValue)?;
    if value.len() != encoded_len {
        return Err(ClientCertError::InvalidHeaderValue);
    }
    HeaderValue::from_str(&value)
        .map(Some)
        .map_err(|_| ClientCertError::InvalidHeaderValue)
}

fn byte_sequence_length(length: usize) -> Result<usize, ClientCertError> {
    length
        .checked_add(2)
        .and_then(|length| length.checked_div(3))
        .and_then(|groups| groups.checked_mul(4))
        .and_then(|encoded| encoded.checked_add(2))
        .ok_or(ClientCertError::InvalidHeaderValue)
}

fn validate_certificate(
    certificate: &[u8],
    limits: ClientCertLimits,
) -> Result<(), ClientCertError> {
    if certificate.is_empty() {
        return Err(ClientCertError::InvalidCertificate);
    }
    if certificate.len() > limits.max_certificate_bytes {
        return Err(ClientCertError::CertificateTooLarge {
            limit: limits.max_certificate_bytes,
        });
    }
    let (remaining, _) =
        X509Certificate::from_der(certificate).map_err(|_| ClientCertError::InvalidCertificate)?;
    if !remaining.is_empty() {
        return Err(ClientCertError::InvalidCertificate);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn certificate_pair() -> (Vec<u8>, Vec<u8>) {
        let end_entity = rcgen::generate_simple_self_signed(vec!["client.example".to_owned()])
            .expect("generate end-entity certificate");
        let intermediate = rcgen::generate_simple_self_signed(vec!["ca.example".to_owned()])
            .expect("generate intermediate certificate");
        (
            end_entity.cert.der().to_vec(),
            intermediate.cert.der().to_vec(),
        )
    }

    #[test]
    fn encodes_and_parses_rfc9440_certificate_fields() {
        let (end_entity, intermediate) = certificate_pair();
        let limits = ClientCertLimits::default();
        let prepared = ClientCertificateHeaders::encode(
            &end_entity,
            std::slice::from_ref(&intermediate),
            &limits,
        )
        .expect("encode RFC 9440 fields");
        assert_eq!(prepared.client_cert.as_bytes()[0], b':');
        assert!(prepared.client_cert_chain.is_some());

        let mut headers = HeaderMap::new();
        prepared.apply_to(&mut headers);
        let parsed = parse_client_certificate_headers(&headers, &limits)
            .expect("parse RFC 9440 fields")
            .expect("certificate fields present");
        assert_eq!(parsed.end_entity, end_entity);
        assert_eq!(parsed.chain, vec![intermediate]);
    }

    #[test]
    fn chain_is_a_flat_list_in_tls_order() {
        let (end_entity, intermediate) = certificate_pair();
        let (_, root) = certificate_pair();
        let value = encode_chain(
            &[intermediate.clone(), root.clone()],
            ClientCertLimits::default(),
        )
        .expect("encode chain")
        .expect("non-empty chain");
        let mut headers = HeaderMap::new();
        headers.insert(
            CLIENT_CERT.clone(),
            encode_byte_sequence(&end_entity, "Client-Cert", ClientCertLimits::default())
                .expect("encode certificate"),
        );
        headers.insert(CLIENT_CERT_CHAIN.clone(), value);
        let parsed = parse_client_certificate_headers(&headers, &ClientCertLimits::default())
            .expect("parse chain")
            .expect("certificate fields present");
        assert_eq!(parsed.chain, vec![intermediate, root]);
    }

    #[test]
    fn repeated_chain_fields_are_combined_in_wire_order() {
        let (end_entity, intermediate) = certificate_pair();
        let (_, root) = certificate_pair();
        let limits = ClientCertLimits::default();
        let client =
            encode_byte_sequence(&end_entity, "Client-Cert", limits).expect("encode certificate");
        let first = encode_chain(std::slice::from_ref(&intermediate), limits)
            .expect("encode first chain")
            .expect("first chain");
        let second = encode_chain(std::slice::from_ref(&root), limits)
            .expect("encode second chain")
            .expect("second chain");
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_CERT.clone(), client);
        headers.append(CLIENT_CERT_CHAIN.clone(), first);
        headers.append(CLIENT_CERT_CHAIN.clone(), second);
        let parsed = parse_client_certificate_headers(&headers, &limits)
            .expect("parse repeated chain")
            .expect("certificate fields present");
        assert_eq!(parsed.chain, vec![intermediate, root]);
    }

    #[test]
    fn policy_is_opt_in_and_sanitizes_untrusted_fields() {
        let (end_entity, _) = certificate_pair();
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_CERT.clone(), HeaderValue::from_static(":ZmFrZTo:"));
        headers.insert(
            CLIENT_CERT_CHAIN.clone(),
            HeaderValue::from_static(":ZmFrZTo:"),
        );
        ClientCertPolicy::default()
            .apply(&mut headers, Some(std::slice::from_ref(&end_entity)))
            .expect("disabled policy sanitizes fields");
        assert!(!headers.contains_key(&CLIENT_CERT));
        assert!(!headers.contains_key(&CLIENT_CERT_CHAIN));
    }

    #[test]
    fn enabled_policy_rejects_inbound_field_injection() {
        let (end_entity, _) = certificate_pair();
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_CERT.clone(), HeaderValue::from_static(":ZmFrZTo:"));
        let error = ClientCertPolicy::enabled()
            .apply(&mut headers, Some(std::slice::from_ref(&end_entity)))
            .expect_err("inbound RFC 9440 field must be rejected");
        assert!(matches!(error, ClientCertError::InboundHeader { .. }));
        assert!(headers.contains_key(&CLIENT_CERT));
    }

    #[test]
    fn policy_removes_fields_when_mtls_was_not_negotiated() {
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_CERT.clone(), HeaderValue::from_static(":ZmFrZTo:"));
        let mut policy = ClientCertPolicy::enabled();
        policy.reject_inbound = false;
        policy
            .apply(&mut headers, None)
            .expect("policy sanitizes request without mTLS");
        assert!(!headers.contains_key(&CLIENT_CERT));
        assert!(!headers.contains_key(&CLIENT_CERT_CHAIN));
    }

    #[test]
    fn rejects_structured_field_parameters_and_non_binary_members() {
        let limits = ClientCertLimits::default();
        assert!(matches!(
            parse_client_cert(&HeaderValue::from_static(":AQI:;foo"), &limits),
            Err(ClientCertError::InvalidClientCert)
        ));
        assert!(matches!(
            parse_client_cert(&HeaderValue::from_static("\"certificate\""), &limits),
            Err(ClientCertError::InvalidClientCert)
        ));
    }

    #[test]
    fn rejects_invalid_der_and_duplicate_end_entity() {
        let limits = ClientCertLimits::default();
        assert!(matches!(
            ClientCertificateHeaders::encode(b"not-a-certificate", &[], &limits),
            Err(ClientCertError::InvalidCertificate)
        ));
        let (end_entity, _) = certificate_pair();
        assert!(matches!(
            ClientCertificateHeaders::encode(
                &end_entity,
                std::slice::from_ref(&end_entity),
                &limits,
            ),
            Err(ClientCertError::DuplicateEndEntity)
        ));
    }

    #[test]
    fn enforces_encoded_header_limits() {
        let (end_entity, _) = certificate_pair();
        let limits = ClientCertLimits::new(end_entity.len(), 1, 8, 16);
        assert!(matches!(
            ClientCertificateHeaders::encode(&end_entity, &[], &limits),
            Err(ClientCertError::FieldTooLarge {
                field: "Client-Cert",
                ..
            })
        ));
    }

    #[test]
    fn rejects_multiple_client_cert_field_lines() {
        let (end_entity, _) = certificate_pair();
        let limits = ClientCertLimits::default();
        let value =
            encode_byte_sequence(&end_entity, "Client-Cert", limits).expect("encode certificate");
        let mut headers = HeaderMap::new();
        headers.append(CLIENT_CERT.clone(), value.clone());
        headers.append(CLIENT_CERT.clone(), value);
        assert!(matches!(
            parse_client_certificate_headers(&headers, &limits),
            Err(ClientCertError::MultipleClientCertFields)
        ));
    }

    #[test]
    fn rejects_chain_without_client_certificate() {
        let (_, intermediate) = certificate_pair();
        let limits = ClientCertLimits::default();
        let chain = encode_chain(std::slice::from_ref(&intermediate), limits)
            .expect("encode chain")
            .expect("non-empty chain");
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_CERT_CHAIN.clone(), chain);
        assert!(matches!(
            parse_client_certificate_headers(&headers, &limits),
            Err(ClientCertError::ChainWithoutClientCert)
        ));
    }
}
