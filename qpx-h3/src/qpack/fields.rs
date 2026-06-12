use super::errors::HeaderDecodeError;
use super::{DecodedRequestHead, DecodedResponseHead, HEADER_ENTRY_OVERHEAD};
use crate::H3Result as Result;
use crate::qpack_fields::{
    append_header, validate_h3_regular_field, validate_h3_response_field, validate_h3_trailer_field,
};
use anyhow::anyhow;
use bytes::Bytes;
use http::{HeaderMap, Method, Uri};
use std::sync::Arc;

enum DecodedFieldName {
    Static(&'static str),
    Shared(Arc<str>),
    Owned(String),
}

impl DecodedFieldName {
    fn as_str(&self) -> &str {
        match self {
            Self::Static(value) => value,
            Self::Shared(value) => value.as_ref(),
            Self::Owned(value) => value.as_str(),
        }
    }
}

pub(super) struct DecodedField {
    name: DecodedFieldName,
    value: Bytes,
}

impl DecodedField {
    pub(super) fn static_field(name: &'static str, value: &'static str) -> Self {
        Self {
            name: DecodedFieldName::Static(name),
            value: Bytes::from_static(value.as_bytes()),
        }
    }

    pub(super) fn shared(name: Arc<str>, value: Bytes) -> Self {
        Self {
            name: DecodedFieldName::Shared(name),
            value,
        }
    }

    pub(super) fn owned(name: String, value: Bytes) -> Self {
        Self {
            name: DecodedFieldName::Owned(name),
            value,
        }
    }
}

pub(super) trait FieldSink {
    type Output;

    fn push(&mut self, field: DecodedField) -> std::result::Result<(), HeaderDecodeError>;
    fn finish(self) -> std::result::Result<Self::Output, HeaderDecodeError>;
}

#[derive(Default)]
pub(super) struct RequestHeadSink {
    method: Option<Method>,
    scheme: Option<String>,
    authority: Option<String>,
    path: Option<String>,
    protocol: Option<String>,
    headers: HeaderMap,
    regular_seen: bool,
}

impl FieldSink for RequestHeadSink {
    type Output = DecodedRequestHead;

    fn push(&mut self, field: DecodedField) -> std::result::Result<(), HeaderDecodeError> {
        let name = field.name.as_str();
        let is_pseudo = name.starts_with(':');
        if is_pseudo && self.regular_seen {
            return Err(HeaderDecodeError::message(format!(
                "pseudo header {name} appeared after a regular header"
            )));
        }
        match name {
            ":method" => {
                if self.method.is_some() {
                    return Err(HeaderDecodeError::message(
                        "duplicate :method pseudo header",
                    ));
                }
                self.method = Some(
                    Method::from_bytes(field.value.as_ref())
                        .map_err(|err| HeaderDecodeError::message(err.to_string()))?,
                );
            }
            ":scheme" => {
                if self
                    .scheme
                    .replace(pseudo_value_to_string(name, field.value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message(
                        "duplicate :scheme pseudo header",
                    ));
                }
            }
            ":authority" => {
                if self
                    .authority
                    .replace(pseudo_value_to_string(name, field.value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message(
                        "duplicate :authority pseudo header",
                    ));
                }
            }
            ":path" => {
                if self
                    .path
                    .replace(pseudo_value_to_string(name, field.value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message("duplicate :path pseudo header"));
                }
            }
            ":protocol" => {
                if self
                    .protocol
                    .replace(pseudo_value_to_string(name, field.value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message(
                        "duplicate :protocol pseudo header",
                    ));
                }
            }
            other if other.starts_with(':') => {
                return Err(HeaderDecodeError::message(format!(
                    "unsupported pseudo header {other}"
                )));
            }
            _ => {
                self.regular_seen = true;
                validate_h3_regular_field(name, field.value.as_ref())?;
                append_header(&mut self.headers, name, field.value.as_ref())
                    .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
            }
        }
        Ok(())
    }

    fn finish(self) -> std::result::Result<Self::Output, HeaderDecodeError> {
        let method = self
            .method
            .ok_or_else(|| HeaderDecodeError::message("missing :method"))?;
        if self.protocol.is_some() && method != Method::CONNECT {
            return Err(HeaderDecodeError::message(
                ":protocol is only valid on CONNECT requests",
            ));
        }
        if method == Method::CONNECT && self.protocol.is_none() {
            if self.authority.is_none() {
                return Err(HeaderDecodeError::message(
                    "traditional CONNECT requires :authority",
                ));
            }
            if self.scheme.is_some() || self.path.is_some() {
                return Err(HeaderDecodeError::message(
                    "traditional CONNECT must not include :scheme or :path",
                ));
            }
        } else {
            if self.scheme.is_none() {
                return Err(HeaderDecodeError::message("missing :scheme"));
            }
            if self.path.is_none() {
                return Err(HeaderDecodeError::message("missing :path"));
            }
        }
        let uri = build_uri(
            self.scheme.as_deref(),
            self.authority.as_deref(),
            self.path.as_deref(),
            method == Method::CONNECT && self.protocol.is_none(),
        )
        .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
        let mut request = http::Request::builder()
            .method(method)
            .uri(uri)
            .body(())
            .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
        *request.headers_mut() = self.headers;
        Ok(DecodedRequestHead {
            request,
            protocol: self.protocol,
        })
    }
}

#[derive(Default)]
pub(super) struct ResponseHeadSink {
    status: Option<http::StatusCode>,
    headers: HeaderMap,
    regular_seen: bool,
}

impl FieldSink for ResponseHeadSink {
    type Output = DecodedResponseHead;

    fn push(&mut self, field: DecodedField) -> std::result::Result<(), HeaderDecodeError> {
        let name = field.name.as_str();
        let is_pseudo = name.starts_with(':');
        if is_pseudo && self.regular_seen {
            return Err(HeaderDecodeError::message(format!(
                "pseudo header {name} appeared after a regular header"
            )));
        }
        match name {
            ":status" => {
                if self.status.is_some() {
                    return Err(HeaderDecodeError::message(
                        "duplicate :status pseudo header",
                    ));
                }
                let value = pseudo_value_to_string(name, field.value)?;
                self.status = Some(decode_response_status(value.as_str())?);
            }
            other if other.starts_with(':') => {
                return Err(HeaderDecodeError::message(format!(
                    "unsupported pseudo header {other}"
                )));
            }
            _ => {
                self.regular_seen = true;
                validate_h3_response_field(name, field.value.as_ref())?;
                append_header(&mut self.headers, name, field.value.as_ref())
                    .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
            }
        }
        Ok(())
    }

    fn finish(self) -> std::result::Result<Self::Output, HeaderDecodeError> {
        let mut response = http::Response::builder()
            .status(
                self.status
                    .ok_or_else(|| HeaderDecodeError::message("missing :status"))?,
            )
            .body(())
            .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
        *response.headers_mut() = self.headers;
        Ok(DecodedResponseHead { response })
    }
}

#[derive(Default)]
pub(super) struct TrailerSink {
    trailers: HeaderMap,
}

impl FieldSink for TrailerSink {
    type Output = HeaderMap;

    fn push(&mut self, field: DecodedField) -> std::result::Result<(), HeaderDecodeError> {
        let name = field.name.as_str();
        if name.starts_with(':') {
            return Err(HeaderDecodeError::message(
                "trailers must not contain pseudo headers",
            ));
        }
        validate_h3_trailer_field(name, field.value.as_ref())?;
        append_header(&mut self.trailers, name, field.value.as_ref())
            .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
        Ok(())
    }

    fn finish(self) -> std::result::Result<Self::Output, HeaderDecodeError> {
        Ok(self.trailers)
    }
}

fn pseudo_value_to_string(
    name: &str,
    value: Bytes,
) -> std::result::Result<String, HeaderDecodeError> {
    String::from_utf8(value.to_vec())
        .map_err(|err| HeaderDecodeError::message(format!("invalid UTF-8 {name} value: {err}")))
}

fn build_uri(
    scheme: Option<&str>,
    authority: Option<&str>,
    path: Option<&str>,
    authority_only: bool,
) -> Result<Uri> {
    if authority_only {
        let authority = authority.ok_or_else(|| anyhow!("CONNECT requires :authority"))?;
        return Uri::builder()
            .authority(authority)
            .build()
            .map_err(Into::into);
    }

    let mut builder = Uri::builder();
    if let Some(scheme) = scheme {
        builder = builder.scheme(scheme);
    }
    if let Some(authority) = authority {
        builder = builder.authority(authority);
    }
    if let Some(path) = path {
        builder = builder.path_and_query(path);
    }
    builder.build().map_err(Into::into)
}

pub(super) fn push_decoded_field<S: FieldSink>(
    sink: &mut S,
    current_size: &mut u64,
    field: DecodedField,
    max_field_section_size: u64,
) -> std::result::Result<(), HeaderDecodeError> {
    track_decoded_field_size(
        current_size,
        field.name.as_str(),
        field.value.as_ref(),
        max_field_section_size,
    )?;
    sink.push(field)
}

fn track_decoded_field_size(
    current: &mut u64,
    name: &str,
    value: &[u8],
    max_field_section_size: u64,
) -> std::result::Result<(), HeaderDecodeError> {
    let size = name.len() as u64 + value.len() as u64 + HEADER_ENTRY_OVERHEAD;
    *current = current
        .checked_add(size)
        .ok_or_else(|| HeaderDecodeError::qpack("QPACK field section size overflow"))?;
    if *current > max_field_section_size {
        return Err(HeaderDecodeError::qpack(format!(
            "QPACK field section size {} exceeds limit {}",
            *current, max_field_section_size
        )));
    }
    Ok(())
}

pub(super) fn decode_response_status(
    value: &str,
) -> std::result::Result<http::StatusCode, HeaderDecodeError> {
    let code = value
        .parse::<u16>()
        .map_err(|_| HeaderDecodeError::message("invalid :status pseudo header"))?;
    if !(100..=599).contains(&code) {
        return Err(HeaderDecodeError::message(
            "HTTP/3 :status pseudo header is out of range",
        ));
    }
    http::StatusCode::from_u16(code).map_err(|err| HeaderDecodeError::message(err.to_string()))
}
