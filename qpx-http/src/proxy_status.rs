//! RFC 9209 `Proxy-Status` field handling.

use crate::structured_fields::{
    BareItem, Item, ListEntry, ListSerializer, SfvString, Token, parse_list_fields,
};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::cell::RefCell;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProxyStatusError {
    #[error("Proxy-Status is not a valid RFC 9651 List: {0}")]
    StructuredField(String),
    #[error("Proxy-Status member must identify a proxy with a String or Token")]
    InvalidMember,
    #[error("proxy identifier is not a valid RFC 9651 String")]
    InvalidProxyIdentifier,
    #[error("Proxy-Status cannot be represented as an HTTP field value")]
    InvalidHeaderValue,
}

pub fn append_proxy_status(
    headers: &mut HeaderMap,
    proxy_identifier: &str,
) -> Result<(), ProxyStatusError> {
    let name = HeaderName::from_static("proxy-status");
    if !headers.contains_key(&name) && is_sfv_token(proxy_identifier.as_bytes()) {
        let value = proxy_identifier_value(proxy_identifier)?;
        headers.insert(name, value);
        return Ok(());
    }
    let mut list = parse_list_fields(headers, &name)
        .map_err(|error| ProxyStatusError::StructuredField(error.to_string()))?
        .unwrap_or_default();
    for entry in &list {
        let ListEntry::Item(item) = entry else {
            return Err(ProxyStatusError::InvalidMember);
        };
        if !matches!(item.bare_item, BareItem::String(_) | BareItem::Token(_)) {
            return Err(ProxyStatusError::InvalidMember);
        }
    }
    let bare_item = match Token::try_from(proxy_identifier.to_string()) {
        Ok(token) => BareItem::Token(token),
        Err(_) => BareItem::String(
            SfvString::try_from(proxy_identifier.to_string())
                .map_err(|_| ProxyStatusError::InvalidProxyIdentifier)?,
        ),
    };
    list.push(ListEntry::Item(Item::new(bare_item)));
    let mut serializer = ListSerializer::new();
    serializer.members(&list);
    let value = serializer
        .finish()
        .ok_or(ProxyStatusError::InvalidHeaderValue)?;
    headers.remove(&name);
    headers.insert(
        name,
        HeaderValue::from_str(&value).map_err(|_| ProxyStatusError::InvalidHeaderValue)?,
    );
    Ok(())
}

const MAX_CACHED_PROXY_IDENTIFIERS: usize = 16;

struct CachedProxyIdentifier {
    identifier: String,
    value: HeaderValue,
}

thread_local! {
    static CACHED_PROXY_IDENTIFIERS: RefCell<Vec<CachedProxyIdentifier>> = const {
        RefCell::new(Vec::new())
    };
}

pub fn proxy_identifier_value(identifier: &str) -> Result<HeaderValue, ProxyStatusError> {
    CACHED_PROXY_IDENTIFIERS.with_borrow_mut(|cached| {
        if let Some(index) = cached
            .iter()
            .position(|entry| entry.identifier == identifier)
        {
            let value = cached[index].value.clone();
            let last = cached.len() - 1;
            if index != last {
                cached.swap(index, last);
            }
            return Ok(value);
        }
        if !is_sfv_token(identifier.as_bytes()) {
            return Err(ProxyStatusError::InvalidProxyIdentifier);
        }
        let value =
            HeaderValue::from_str(identifier).map_err(|_| ProxyStatusError::InvalidHeaderValue)?;
        if cached.len() == MAX_CACHED_PROXY_IDENTIFIERS {
            cached.remove(0);
        }
        cached.push(CachedProxyIdentifier {
            identifier: identifier.to_string(),
            value: value.clone(),
        });
        Ok(value)
    })
}

fn is_sfv_token(value: &[u8]) -> bool {
    let Some((&first, rest)) = value.split_first() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'*')
        && rest.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                        | b':'
                        | b'/'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_current_proxy_after_existing_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "proxy-status",
            HeaderValue::from_static("origin-gateway;received-status=200"),
        );
        append_proxy_status(&mut headers, "edge.example").expect("append");
        assert_eq!(
            headers.get("proxy-status").expect("field"),
            "origin-gateway;received-status=200, edge.example"
        );
    }

    #[test]
    fn serializes_non_token_identifier_as_string() {
        let mut headers = HeaderMap::new();
        append_proxy_status(&mut headers, "qpx edge").expect("append");
        assert_eq!(headers.get("proxy-status").expect("field"), "\"qpx edge\"");
    }

    #[test]
    fn serializes_extended_token_identifier_without_quoting() {
        let mut headers = HeaderMap::new();
        append_proxy_status(&mut headers, "edge_1:8443/path").expect("append");
        assert_eq!(
            headers.get("proxy-status").expect("field"),
            "edge_1:8443/path"
        );
    }
}
