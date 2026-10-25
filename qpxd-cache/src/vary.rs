use qpx_core::http_content_length::{HeaderTextSelection, HeaderView};

use super::types::{CachedResponseEnvelope, VarySpec};

pub fn parse_vary(headers: &http::HeaderMap) -> VarySpec {
    let mut fields = Vec::new();
    for value in headers.get_all(http::header::VARY) {
        let Ok(v) = value.to_str() else {
            // Fail-closed: an unrepresentable Vary value cannot be negotiated
            // safely, so the response is not shareable.
            return VarySpec::Any;
        };
        for token in v.split(',') {
            let field = token.trim().to_ascii_lowercase();
            if field.is_empty() {
                continue;
            }
            if field == "*" {
                return VarySpec::Any;
            }
            if http::HeaderName::from_bytes(field.as_bytes()).is_err() {
                // Malformed Vary makes the entry unsafe to cache across requests.
                return VarySpec::Any;
            }
            if !fields.iter().any(|f| f == &field) {
                fields.push(field);
            }
        }
    }
    VarySpec::Fields(fields)
}

pub fn vary_values_from_request_headers(
    request_headers: HeaderView<'_>,
    vary_headers: &[String],
) -> Option<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(vary_headers.len());
    for name in vary_headers {
        let value = request_header_values(request_headers, name.as_str())?;
        out.push((name.clone(), value));
    }
    Some(out)
}

/// Encoded selector value for a `Vary` field name.
///
/// Returns `None` for an invalid field name or when the selector cannot be represented with
/// `HeaderValue::to_str` (e.g. obs-text). Callers treat `None` as
/// fail-closed: no store and no hit.
///
/// The encoding distinguishes absence from any present value (including
/// present-empty), per RFC 9111 section 4.1: absence encodes as a lone
/// `\x00`, while any present value list encodes as `\x01` followed by the
/// comma-joined trimmed values. `\x00`/`\x01` never appear in `to_str`
/// output (visible ASCII only), so the sentinel cannot collide with a real
/// value, nor with legacy `""` entries (which now safely miss).
pub fn request_header_values(headers: HeaderView<'_>, name: &str) -> Option<String> {
    match headers.joined_text(name) {
        HeaderTextSelection::Unrepresentable => None,
        HeaderTextSelection::Absent => Some("\x00".to_string()),
        HeaderTextSelection::Present(value) => Some(format!("\x01{value}")),
    }
}

pub fn matches_vary(
    request_headers: HeaderView<'_>,
    content_digest: Option<&str>,
    envelope: &CachedResponseEnvelope,
) -> bool {
    envelope.vary_values.iter().all(|(name, value)| {
        if name == "@query-content" {
            return content_digest == Some(value.as_str());
        }
        match request_header_values(request_headers, name.as_str()) {
            Some(current) => current == *value,
            None => false,
        }
    })
}

pub fn variant_storage_key(primary: &str, vary_values: &[(String, String)]) -> String {
    if vary_values.is_empty() {
        return format!("obj:{}:default", primary);
    }
    let mut raw = String::new();
    for (name, value) in vary_values {
        raw.push_str(name);
        raw.push('=');
        raw.push_str(value);
        raw.push('|');
    }
    let hash = super::hash::sha256_hex(raw.as_bytes());
    format!("obj:{}:{}", primary, hash)
}

pub fn index_storage_key(primary: &str) -> String {
    format!("idx:{}", primary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_map(pairs: &[(&str, Vec<Vec<u8>>)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (name, values) in pairs {
            for v in values.iter() {
                map.append(
                    http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    http::HeaderValue::from_bytes(v.as_slice()).unwrap(),
                );
            }
        }
        map
    }

    fn envelope_with(vary_values: Vec<(String, String)>) -> CachedResponseEnvelope {
        CachedResponseEnvelope {
            status: 200,
            headers: Vec::new(),
            body: crate::types::CachedBody::default(),
            body_len: 0,
            stored_at_ms: 0,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: vec!["x-tenant".to_string()],
            vary_values,
            header_map: std::sync::OnceLock::new(),
            response_directives: std::sync::OnceLock::new(),
            response_header_values: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn obs_text_selector_is_unrepresentable_so_store_is_refused() {
        let stored_headers = header_map(&[("x-tenant", vec![vec![0x80]])]);
        assert!(request_header_values(HeaderView::new(&stored_headers), "x-tenant").is_none());
        assert!(
            vary_values_from_request_headers(
                HeaderView::new(&stored_headers),
                &["x-tenant".to_string()]
            )
            .is_none()
        );
    }

    #[test]
    fn unrepresentable_selector_refuses_store_and_hit() {
        let stored = header_map(&[("x-tenant", vec![b"a".to_vec()])]);
        let values =
            vary_values_from_request_headers(HeaderView::new(&stored), &["x-tenant".to_string()])
                .expect("ascii stores");
        let envelope = envelope_with(values);
        // Distinct obs-text value must not hit.
        let other = header_map(&[("x-tenant", vec![vec![0x81]])]);
        assert!(!matches_vary(HeaderView::new(&other), None, &envelope));
        // Absent selector must not hit a present-value variant.
        let absent = header_map(&[]);
        assert!(!matches_vary(HeaderView::new(&absent), None, &envelope));
        // The obs-text request itself must not hit either (fail-closed).
        let obs = header_map(&[("x-tenant", vec![vec![0x80]])]);
        assert!(!matches_vary(HeaderView::new(&obs), None, &envelope));
    }

    #[test]
    fn present_empty_does_not_match_absence() {
        let present_empty = header_map(&[("x-tenant", vec![b"".to_vec()])]);
        let absent = header_map(&[]);
        let present_enc =
            request_header_values(HeaderView::new(&present_empty), "x-tenant").unwrap();
        let absent_enc = request_header_values(HeaderView::new(&absent), "x-tenant").unwrap();
        assert_ne!(present_enc, absent_enc);
        let envelope = envelope_with(vec![("x-tenant".to_string(), present_enc)]);
        assert!(!matches_vary(HeaderView::new(&absent), None, &envelope));
        assert!(matches_vary(
            HeaderView::new(&present_empty),
            None,
            &envelope
        ));
        let envelope_absent = envelope_with(vec![("x-tenant".to_string(), absent_enc)]);
        assert!(matches_vary(
            HeaderView::new(&absent),
            None,
            &envelope_absent
        ));
        assert!(!matches_vary(
            HeaderView::new(&present_empty),
            None,
            &envelope_absent
        ));
    }

    #[test]
    fn mixed_ascii_and_obs_text_selector_is_unrepresentable() {
        let mixed = header_map(&[("x-tenant", vec![b"en".to_vec(), vec![0x80]])]);
        assert!(request_header_values(HeaderView::new(&mixed), "x-tenant").is_none());
        assert!(
            vary_values_from_request_headers(HeaderView::new(&mixed), &["x-tenant".to_string()])
                .is_none()
        );
    }

    #[test]
    fn invalid_name_refuses_store_and_hit() {
        let headers = http::HeaderMap::new();
        let view = HeaderView::new(&headers);
        for name in ["", "bad name", "x-tenant:"] {
            assert_eq!(request_header_values(view, name), None);
            assert!(vary_values_from_request_headers(view, &[name.to_string()]).is_none());
            let envelope = envelope_with(vec![(name.to_string(), "\x00".to_string())]);
            assert!(!matches_vary(view, None, &envelope));
        }
    }

    #[test]
    fn selector_encoding_preserves_order_trims_and_ignores_name_case() {
        let headers = header_map(&[(
            "x-tenant",
            vec![
                b" \tsecond ".to_vec(),
                b"".to_vec(),
                b" first\t".to_vec(),
                b" a, b ".to_vec(),
            ],
        )]);
        let view = HeaderView::new(&headers);
        assert_eq!(
            request_header_values(view, "X-Tenant").as_deref(),
            Some("\x01second,,first,a, b")
        );
        let empty = header_map(&[("x-tenant", vec![b"".to_vec()])]);
        let absent = http::HeaderMap::new();
        assert_eq!(
            request_header_values(HeaderView::new(&empty), "x-tenant").as_deref(),
            Some("\x01")
        );
        assert_eq!(
            request_header_values(HeaderView::new(&absent), "x-tenant").as_deref(),
            Some("\x00")
        );
    }

    #[test]
    fn any_obs_text_duplicate_refuses_store_and_hit() {
        let clean = header_map(&[("x-tenant", vec![b"ascii".to_vec(), b"ascii".to_vec()])]);
        let fields = ["x-tenant".to_string()];
        let envelope = envelope_with(
            vary_values_from_request_headers(HeaderView::new(&clean), &fields).unwrap(),
        );
        for position in 0..3 {
            let mut values = vec![b"ascii".to_vec(); 3];
            values[position] = vec![0x80];
            let headers = header_map(&[("x-tenant", values)]);
            let view = HeaderView::new(&headers);
            assert!(vary_values_from_request_headers(view, &fields).is_none());
            assert!(!matches_vary(view, None, &envelope));
        }
    }

    #[test]
    fn content_length_vary_uses_literal_text_not_declared_length() {
        let mut response = http::HeaderMap::new();
        response.insert(
            http::header::VARY,
            http::HeaderValue::from_static("Content-Length"),
        );
        let VarySpec::Fields(fields) = parse_vary(&response) else {
            panic!("valid Vary")
        };
        // Neither numerically equal declarations nor conflicting duplicates
        // collapse: Vary selection does not interpret message framing.
        let cases = [
            (vec!["05"], "05"),
            (vec!["5"], "5"),
            (vec!["42, 42"], "42, 42"),
            (vec!["42"], "42"),
            (vec!["42", "43"], "42,43"),
            (vec!["43", "42"], "43,42"),
        ];
        let mut variants = Vec::new();
        for (values, expected) in cases {
            let headers = header_map(&[(
                "content-length",
                values.iter().map(|s| s.as_bytes().to_vec()).collect(),
            )]);
            let selectors =
                vary_values_from_request_headers(HeaderView::new(&headers), &fields).unwrap();
            assert_eq!(
                selectors,
                vec![("content-length".to_string(), format!("\x01{expected}"))]
            );
            let key = variant_storage_key("primary", &selectors);
            variants.push((headers, envelope_with(selectors), key));
        }
        for (i, (headers, _, key)) in variants.iter().enumerate() {
            for (j, (_, envelope, other_key)) in variants.iter().enumerate() {
                assert_eq!(
                    matches_vary(HeaderView::new(headers), None, envelope),
                    i == j
                );
                assert_eq!(key == other_key, i == j);
            }
        }
    }

    #[test]
    fn query_content_selector_still_matches_digest_not_a_header() {
        let headers = header_map(&[("x-tenant", vec![b"a".to_vec()])]);
        let view = HeaderView::new(&headers);
        let mut selectors =
            vary_values_from_request_headers(view, &["x-tenant".to_string()]).unwrap();
        selectors.push(("@query-content".to_string(), "digest-a".to_string()));
        let envelope = envelope_with(selectors);
        assert!(matches_vary(view, Some("digest-a"), &envelope));
        assert!(!matches_vary(view, Some("digest-b"), &envelope));
        assert!(!matches_vary(view, None, &envelope));
        let absent = http::HeaderMap::new();
        assert!(!matches_vary(
            HeaderView::new(&absent),
            Some("digest-a"),
            &envelope
        ));
    }

    #[test]
    fn non_ascii_response_vary_is_uncacheable() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::VARY,
            http::HeaderValue::from_bytes(&[0x80]).unwrap(),
        );
        assert!(matches!(parse_vary(&headers), VarySpec::Any));
    }
}
