use super::*;

#[test]
fn parse_request_directives_max_stale_and_only_if_cached() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached, max-stale=30, min-fresh=5"),
    );
    let parsed = parse_request_directives(&headers);
    assert!(parsed.only_if_cached);
    assert_eq!(parsed.max_stale, Some(Some(30)));
    assert_eq!(parsed.min_fresh, Some(5));
}

#[test]
fn parse_request_directives_invalid_max_stale_is_ignored() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("max-stale=invalid"),
    );
    let parsed = parse_request_directives(&headers);
    assert_eq!(parsed.max_stale, None);
}

#[test]
fn parse_request_directives_supports_single_byte_range() {
    let mut headers = http::HeaderMap::new();
    headers.insert(RANGE, http::HeaderValue::from_static("bytes=3-7"));
    headers.insert(IF_RANGE, http::HeaderValue::from_static("\"v1\""));
    let parsed = parse_request_directives(&headers);
    assert!(parsed.range.is_some());
    assert!(parsed.if_range.is_some());
    assert!(!parsed.has_unsupported_conditionals);
}

#[test]
fn parse_request_directives_no_cache_with_field_names() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("no-cache=\"set-cookie,authorization\""),
    );
    let parsed = parse_request_directives(&headers);
    assert!(parsed.no_cache);
}

#[test]
fn parse_response_directives_private_with_field_names() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("private=\"authorization\", max-age=60"),
    );
    let parsed = parse_response_directives(&headers);
    assert!(!parsed.private);
    assert_eq!(parsed.private_fields, vec!["authorization".to_string()]);
    assert_eq!(parsed.max_age, Some(60));
}

#[test]
fn parse_response_directives_no_cache_with_field_names() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("no-cache=\"set-cookie\""),
    );
    let parsed = parse_response_directives(&headers);
    assert!(!parsed.no_cache);
    assert_eq!(parsed.no_cache_fields, vec!["set-cookie".to_string()]);
}

#[test]
fn parse_response_directives_must_understand() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("public, max-age=60, must-understand"),
    );
    let parsed = parse_response_directives(&headers);
    assert!(parsed.must_understand);
    assert_eq!(parsed.max_age, Some(60));
}

#[test]
fn parse_response_directives_rfc5861_extensions() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("max-age=60, stale-while-revalidate=30, stale-if-error=120"),
    );
    let parsed = parse_response_directives(&headers);
    assert_eq!(parsed.max_age, Some(60));
    assert_eq!(parsed.stale_while_revalidate, Some(30));
    assert_eq!(parsed.stale_if_error, Some(120));
}

#[test]
fn parse_response_directives_marks_invalid_or_duplicate_freshness_stale() {
    let mut headers = http::HeaderMap::new();
    headers.insert(CACHE_CONTROL, http::HeaderValue::from_static("max-age=abc"));
    let parsed = parse_response_directives(&headers);
    assert!(parsed.invalid_freshness);

    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("max-age=60, max-age=30"),
    );
    let parsed = parse_response_directives(&headers);
    assert!(parsed.invalid_freshness);
}

#[test]
fn parse_vary_star_is_uncacheable() {
    let mut headers = http::HeaderMap::new();
    headers.insert(VARY, http::HeaderValue::from_static("*"));
    assert!(matches!(parse_vary(&headers), VarySpec::Any));
}

#[test]
fn cacheable_content_length_rejects_chunked_transfer() {
    let mut headers = http::HeaderMap::new();
    headers.insert(CONTENT_LENGTH, http::HeaderValue::from_static("10"));
    headers.insert(TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
    assert_eq!(cacheable_content_length(&headers), None);
}

#[test]
fn cacheable_content_length_rejects_inconsistent_values() {
    let mut headers = http::HeaderMap::new();
    headers.insert(CONTENT_LENGTH, http::HeaderValue::from_static("10, 11"));
    assert_eq!(cacheable_content_length(&headers), None);
}
