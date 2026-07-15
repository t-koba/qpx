//! HTTP API lifecycle metadata for RFC 8594 and RFC 9745.

use crate::structured_fields::{BareItem, Date, Integer, ItemSerializer, parse_item};
use http::{HeaderMap, HeaderValue};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkValue {
    target: String,
    relation: String,
    media_type: Option<String>,
}

impl LinkValue {
    pub fn new(
        target: impl Into<String>,
        relation: impl Into<String>,
    ) -> Result<Self, ApiMetadataError> {
        let value = Self {
            target: target.into(),
            relation: relation.into(),
            media_type: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn with_media_type(
        mut self,
        media_type: impl Into<String>,
    ) -> Result<Self, ApiMetadataError> {
        self.media_type = Some(media_type.into());
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), ApiMetadataError> {
        if self.target.is_empty()
            || self
                .target
                .bytes()
                .any(|byte| byte <= 0x20 || byte == b'>' || byte == 0x7f)
        {
            return Err(ApiMetadataError::InvalidLinkTarget);
        }
        if self.relation.is_empty()
            || self
                .relation
                .split_ascii_whitespace()
                .any(|relation| !valid_relation_type(relation))
        {
            return Err(ApiMetadataError::InvalidLinkRelation);
        }
        if let Some(media_type) = self.media_type.as_deref()
            && (media_type.is_empty() || media_type.bytes().any(|byte| byte < 0x20 || byte == 0x7f))
        {
            return Err(ApiMetadataError::InvalidMediaType);
        }
        Ok(())
    }

    fn serialize(&self) -> Result<String, ApiMetadataError> {
        self.validate()?;
        let mut value = format!("<{}>; rel=\"{}\"", self.target, quote(&self.relation));
        if let Some(media_type) = self.media_type.as_deref() {
            value.push_str("; type=\"");
            value.push_str(&quote(media_type));
            value.push('"');
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ApiMetadata {
    pub deprecation: Option<SystemTime>,
    pub sunset: Option<SystemTime>,
    pub links: Vec<LinkValue>,
}

/// Pre-serialized lifecycle fields for request-independent route metadata.
#[derive(Debug, Clone, Default)]
pub struct PreparedApiMetadata {
    deprecation: Option<HeaderValue>,
    sunset: Option<HeaderValue>,
    links: Vec<HeaderValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApiMetadataError {
    #[error("API lifecycle date is outside the RFC 9651 integer range")]
    DateRange,
    #[error("Sunset must not be earlier than Deprecation")]
    SunsetBeforeDeprecation,
    #[error("Link target is invalid")]
    InvalidLinkTarget,
    #[error("Link relation type is invalid")]
    InvalidLinkRelation,
    #[error("Link media type is invalid")]
    InvalidMediaType,
    #[error("API metadata cannot be represented as an HTTP field value")]
    InvalidHeaderValue,
    #[error("Deprecation is not an RFC 9651 Date item")]
    InvalidDeprecation,
}

impl ApiMetadata {
    pub fn prepare(&self) -> Result<PreparedApiMetadata, ApiMetadataError> {
        if let (Some(deprecation), Some(sunset)) = (self.deprecation, self.sunset)
            && sunset < deprecation
        {
            return Err(ApiMetadataError::SunsetBeforeDeprecation);
        }
        let deprecation = self
            .deprecation
            .map(|deprecation| {
                let seconds = unix_seconds(deprecation)?;
                let integer =
                    Integer::try_from(seconds).map_err(|_| ApiMetadataError::DateRange)?;
                let value = ItemSerializer::new()
                    .bare_item(Date::from_unix_seconds(integer))
                    .finish();
                HeaderValue::from_str(&value).map_err(|_| ApiMetadataError::InvalidHeaderValue)
            })
            .transpose()?;
        let sunset = self
            .sunset
            .map(|sunset| {
                HeaderValue::from_str(&httpdate::fmt_http_date(sunset))
                    .map_err(|_| ApiMetadataError::InvalidHeaderValue)
            })
            .transpose()?;
        let links = self
            .links
            .iter()
            .map(|link| {
                HeaderValue::from_str(&link.serialize()?)
                    .map_err(|_| ApiMetadataError::InvalidHeaderValue)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PreparedApiMetadata {
            deprecation,
            sunset,
            links,
        })
    }

    pub fn apply(&self, headers: &mut HeaderMap) -> Result<(), ApiMetadataError> {
        self.prepare()?.apply(headers);
        Ok(())
    }
}

impl PreparedApiMetadata {
    pub fn apply(&self, headers: &mut HeaderMap) {
        if let Some(value) = self.deprecation.as_ref() {
            headers.insert("deprecation", value.clone());
        }
        if let Some(value) = self.sunset.as_ref() {
            headers.insert("sunset", value.clone());
        }
        for value in &self.links {
            headers.append("link", value.clone());
        }
    }
}

pub fn parse_deprecation(value: &HeaderValue) -> Result<SystemTime, ApiMetadataError> {
    let item = parse_item(value.as_bytes()).map_err(|_| ApiMetadataError::InvalidDeprecation)?;
    if !item.params.is_empty() {
        return Err(ApiMetadataError::InvalidDeprecation);
    }
    let BareItem::Date(date) = item.bare_item else {
        return Err(ApiMetadataError::InvalidDeprecation);
    };
    let seconds = i64::from(date.unix_seconds());
    if seconds >= 0 {
        UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(seconds as u64))
            .ok_or(ApiMetadataError::DateRange)
    } else {
        UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(seconds.unsigned_abs()))
            .ok_or(ApiMetadataError::DateRange)
    }
}

fn unix_seconds(value: SystemTime) -> Result<i64, ApiMetadataError> {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).map_err(|_| ApiMetadataError::DateRange),
        Err(error) => i64::try_from(error.duration().as_secs())
            .map(|seconds| -seconds)
            .map_err(|_| ApiMetadataError::DateRange),
    }
}

fn valid_relation_type(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'.' | b'+' | b'-' | b'^' | b'_'
                )
        })
}

fn quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_deprecation_sunset_and_documentation_link() {
        let deprecation = UNIX_EPOCH + std::time::Duration::from_secs(1_688_169_599);
        let sunset = UNIX_EPOCH + std::time::Duration::from_secs(1_719_791_999);
        let metadata = ApiMetadata {
            deprecation: Some(deprecation),
            sunset: Some(sunset),
            links: vec![
                LinkValue::new("https://developer.example.com/deprecation", "deprecation")
                    .expect("link")
                    .with_media_type("text/html")
                    .expect("media type"),
            ],
        };
        let mut headers = HeaderMap::new();
        metadata.apply(&mut headers).expect("metadata");
        assert_eq!(headers.get("deprecation").expect("field"), "@1688169599");
        assert_eq!(
            parse_deprecation(headers.get("deprecation").expect("field")),
            Ok(deprecation)
        );
        assert_eq!(
            headers.get("sunset").expect("field"),
            "Sun, 30 Jun 2024 23:59:59 GMT"
        );
        assert_eq!(
            headers.get("link").expect("field"),
            "<https://developer.example.com/deprecation>; rel=\"deprecation\"; type=\"text/html\""
        );
    }

    #[test]
    fn rejects_sunset_before_deprecation() {
        let metadata = ApiMetadata {
            deprecation: Some(UNIX_EPOCH + std::time::Duration::from_secs(2)),
            sunset: Some(UNIX_EPOCH + std::time::Duration::from_secs(1)),
            links: Vec::new(),
        };
        assert_eq!(
            metadata.apply(&mut HeaderMap::new()),
            Err(ApiMetadataError::SunsetBeforeDeprecation)
        );
    }
}
