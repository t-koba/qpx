//! RFC 10008 `Accept-Query` field codec.

use crate::structured_fields::{BareItem, List, ListEntry, ListSerializer, parse_list_fields};
use http::{HeaderMap, HeaderName, HeaderValue};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct AcceptQuery {
    list: List,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AcceptQueryError {
    #[error("Accept-Query is not a valid RFC 9651 List: {0}")]
    StructuredField(String),
    #[error("Accept-Query must contain at least one media range")]
    Empty,
    #[error("Accept-Query list members must be String or Token items")]
    InvalidMember,
    #[error("Accept-Query media range is invalid: {0}")]
    InvalidMediaRange(String),
    #[error("Accept-Query media type parameter values must be String or Token")]
    InvalidParameter,
    #[error("Accept-Query cannot be represented as an HTTP field value")]
    InvalidHeaderValue,
}

impl AcceptQuery {
    pub fn media_ranges(&self) -> impl Iterator<Item = &str> {
        self.list.iter().filter_map(|entry| {
            let ListEntry::Item(item) = entry else {
                return None;
            };
            match &item.bare_item {
                BareItem::String(value) => Some(value.as_str()),
                BareItem::Token(value) => Some(value.as_str()),
                _ => None,
            }
        })
    }

    pub fn to_header_value(&self) -> Result<HeaderValue, AcceptQueryError> {
        let mut serializer = ListSerializer::new();
        serializer.members(&self.list);
        let value = serializer.finish().ok_or(AcceptQueryError::Empty)?;
        HeaderValue::from_str(&value).map_err(|_| AcceptQueryError::InvalidHeaderValue)
    }
}

pub fn parse_accept_query(headers: &HeaderMap) -> Result<Option<AcceptQuery>, AcceptQueryError> {
    let name = HeaderName::from_static("accept-query");
    let Some(list) = parse_list_fields(headers, &name)
        .map_err(|error| AcceptQueryError::StructuredField(error.to_string()))?
    else {
        return Ok(None);
    };
    if list.is_empty() {
        return Err(AcceptQueryError::Empty);
    }
    for entry in &list {
        let ListEntry::Item(item) = entry else {
            return Err(AcceptQueryError::InvalidMember);
        };
        let media_range = match &item.bare_item {
            BareItem::String(value) => value.as_str(),
            BareItem::Token(value) => value.as_str(),
            _ => return Err(AcceptQueryError::InvalidMember),
        };
        validate_media_range(media_range)?;
        if item
            .params
            .values()
            .any(|value| !matches!(value, BareItem::String(_) | BareItem::Token(_)))
        {
            return Err(AcceptQueryError::InvalidParameter);
        }
    }
    Ok(Some(AcceptQuery { list }))
}

fn validate_media_range(value: &str) -> Result<(), AcceptQueryError> {
    let Some((kind, subtype)) = value.split_once('/') else {
        return Err(AcceptQueryError::InvalidMediaRange(value.to_string()));
    };
    if value.matches('/').count() != 1
        || kind.is_empty()
        || subtype.is_empty()
        || (kind == "*" && subtype != "*")
        || (kind != "*" && !is_media_token(kind))
        || (subtype != "*" && !is_media_token(subtype))
    {
        return Err(AcceptQueryError::InvalidMediaRange(value.to_string()));
    }
    Ok(())
}

fn is_media_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_serializes_rfc10008_example() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept-query",
            HeaderValue::from_static("\"application/jsonpath\", application/sql;charset=\"UTF-8\""),
        );
        let parsed = parse_accept_query(&headers)
            .expect("valid Accept-Query")
            .expect("present");
        assert_eq!(
            parsed.media_ranges().collect::<Vec<_>>(),
            vec!["application/jsonpath", "application/sql"]
        );
        assert_eq!(
            parsed.to_header_value().expect("serialize"),
            "\"application/jsonpath\", application/sql;charset=\"UTF-8\""
        );
    }

    #[test]
    fn rejects_unsupported_wildcard_and_non_string_parameter() {
        let mut headers = HeaderMap::new();
        headers.insert("accept-query", HeaderValue::from_static("*/json"));
        assert!(matches!(
            parse_accept_query(&headers),
            Err(AcceptQueryError::InvalidMediaRange(_))
        ));

        headers.insert(
            "accept-query",
            HeaderValue::from_static("application/sql;charset=1"),
        );
        assert_eq!(
            parse_accept_query(&headers),
            Err(AcceptQueryError::InvalidParameter)
        );
    }
}
