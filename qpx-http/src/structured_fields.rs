//! RFC 9651 Structured Field Values shared by all HTTP versions.

pub use sfv::{
    BareItem, Date, DictSerializer, Dictionary, FieldType, InnerList, Integer, Item,
    ItemSerializer, Key, KeyRef, List, ListEntry, ListSerializer, Parser, String as SfvString,
    Token,
};

/// Parses an RFC 9651 Dictionary field value.
pub fn parse_dictionary(value: &[u8]) -> Result<Dictionary, sfv::Error> {
    Parser::new(value).parse()
}

/// Parses an RFC 9651 List field value.
pub fn parse_list(value: &[u8]) -> Result<List, sfv::Error> {
    Parser::new(value).parse()
}

/// Parses an RFC 9651 Item field value.
pub fn parse_item(value: &[u8]) -> Result<Item, sfv::Error> {
    Parser::new(value).parse()
}

/// Combines repeated field lines in wire order before parsing a Dictionary.
pub fn parse_dictionary_fields(
    headers: &http::HeaderMap,
    name: &http::HeaderName,
) -> Result<Option<Dictionary>, sfv::Error> {
    let Some(value) = combine_field_lines(headers, name) else {
        return Ok(None);
    };
    parse_dictionary(&value).map(Some)
}

/// Combines repeated field lines in wire order before parsing a List.
pub fn parse_list_fields(
    headers: &http::HeaderMap,
    name: &http::HeaderName,
) -> Result<Option<List>, sfv::Error> {
    let Some(value) = combine_field_lines(headers, name) else {
        return Ok(None);
    };
    parse_list(&value).map(Some)
}

fn combine_field_lines(headers: &http::HeaderMap, name: &http::HeaderName) -> Option<Vec<u8>> {
    let mut combined = Vec::new();
    for value in headers.get_all(name) {
        if !combined.is_empty() {
            combined.extend_from_slice(b", ");
        }
        combined.extend_from_slice(value.as_bytes());
    }
    (!combined.is_empty()).then_some(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, HeaderValue, header::HeaderName};

    #[test]
    fn parses_rfc9651_extended_bare_items() {
        let dictionary = parse_dictionary(b"created=@1659578233, title=%\"f%c3%bcr\"")
            .expect("RFC 9651 dictionary");
        assert!(dictionary.contains_key("created"));
        assert!(dictionary.contains_key("title"));
    }

    #[test]
    fn combines_repeated_dictionary_field_lines() {
        let name = HeaderName::from_static("example-dictionary");
        let mut headers = HeaderMap::new();
        headers.append(name.clone(), HeaderValue::from_static("a=1"));
        headers.append(name.clone(), HeaderValue::from_static("b=?0"));
        let dictionary = parse_dictionary_fields(&headers, &name)
            .expect("valid fields")
            .expect("present fields");
        assert!(dictionary.contains_key("a"));
        assert!(dictionary.contains_key("b"));
    }

    #[test]
    fn later_dictionary_members_replace_earlier_duplicates() {
        let name = HeaderName::from_static("example-dictionary");
        let mut headers = HeaderMap::new();
        headers.append(name.clone(), HeaderValue::from_static("a=1"));
        headers.append(name.clone(), HeaderValue::from_static("a=2"));
        let dictionary = parse_dictionary_fields(&headers, &name)
            .expect("valid duplicate fields")
            .expect("present fields");
        let Some(ListEntry::Item(item)) = dictionary.get("a") else {
            panic!("missing dictionary member");
        };
        let BareItem::Integer(value) = item.bare_item else {
            panic!("dictionary member must be an integer");
        };
        assert_eq!(i64::from(value), 2);
    }
}
