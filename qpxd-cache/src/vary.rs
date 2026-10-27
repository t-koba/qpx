use qpx_core::http_content_length::VarySelector;
use qpx_core::http_message::OwnedHeaderView;

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
    request_headers: OwnedHeaderView<'_>,
    vary_headers: &[String],
) -> Option<Vec<(String, VarySelector)>> {
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
pub fn request_header_values(headers: OwnedHeaderView<'_>, name: &str) -> Option<VarySelector> {
    headers.vary_selector(name)
}

pub fn matches_vary(
    request_headers: OwnedHeaderView<'_>,
    content_digest: Option<&str>,
    envelope: &CachedResponseEnvelope,
) -> bool {
    envelope.vary_values.iter().all(|(name, value)| {
        if name == "@query-content" {
            return content_digest
                .is_some_and(|digest| VarySelector::from(digest.to_owned()) == *value);
        }
        match request_header_values(request_headers, name.as_str()) {
            Some(current) => current == *value,
            None => false,
        }
    })
}

pub fn variant_storage_key(primary: &str, vary_values: &[(String, VarySelector)]) -> String {
    if vary_values.is_empty() {
        return format!("obj:{}:default", primary);
    }
    let hash = super::hash::hex_lower(&VarySelector::variant_digest(vary_values));
    format!("obj:{}:{}", primary, hash)
}

pub fn index_storage_key(primary: &str) -> String {
    format!("idx:{}", primary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_map(pairs: &[(&str, Vec<Vec<u8>>)]) -> qpx_core::http_message::Headers {
        use qpx_core::http_message::OrdinaryHeaderName;
        let mut map = qpx_core::http_message::Headers::new();
        for (name, values) in pairs {
            if name.eq_ignore_ascii_case("content-length") {
                for v in values.iter() {
                    map.append_content_length_value(
                        http::HeaderValue::from_bytes(v.as_slice()).unwrap(),
                    );
                }
            } else {
                let ord = OrdinaryHeaderName::try_from(*name).expect("ordinary test header name");
                for v in values.iter() {
                    map.append(
                        ord.clone(),
                        http::HeaderValue::from_bytes(v.as_slice()).unwrap(),
                    );
                }
            }
        }
        map
    }

    fn envelope_with(vary_values: Vec<(String, VarySelector)>) -> CachedResponseEnvelope {
        CachedResponseEnvelope {
            status: 200,
            headers: crate::types::CachedHeaders::from_pairs(Vec::new()),
            body: crate::types::CachedBody::default(),
            body_len: 0,
            stored_at_ms: 0,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: vec!["x-tenant".to_string()],
            vary_values,
            response_directives: std::sync::OnceLock::new(),
            response_header_values: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn obs_text_selector_is_unrepresentable_so_store_is_refused() {
        let stored_headers = header_map(&[("x-tenant", vec![vec![0x80]])]);
        assert!(request_header_values(stored_headers.view(), "x-tenant").is_none());
        assert!(
            vary_values_from_request_headers(stored_headers.view(), &["x-tenant".to_string()])
                .is_none()
        );
    }

    #[test]
    fn unrepresentable_selector_refuses_store_and_hit() {
        let stored = header_map(&[("x-tenant", vec![b"a".to_vec()])]);
        let values = vary_values_from_request_headers(stored.view(), &["x-tenant".to_string()])
            .expect("ascii stores");
        let envelope = envelope_with(values);
        // Distinct obs-text value must not hit.
        let other = header_map(&[("x-tenant", vec![vec![0x81]])]);
        assert!(!matches_vary(other.view(), None, &envelope));
        // Absent selector must not hit a present-value variant.
        let absent = header_map(&[]);
        assert!(!matches_vary(absent.view(), None, &envelope));
        // The obs-text request itself must not hit either (fail-closed).
        let obs = header_map(&[("x-tenant", vec![vec![0x80]])]);
        assert!(!matches_vary(obs.view(), None, &envelope));
    }

    #[test]
    fn present_empty_does_not_match_absence() {
        let present_empty = header_map(&[("x-tenant", vec![b"".to_vec()])]);
        let absent = header_map(&[]);
        let present_enc = request_header_values(present_empty.view(), "x-tenant").unwrap();
        let absent_enc = request_header_values(absent.view(), "x-tenant").unwrap();
        assert_ne!(present_enc, absent_enc);
        let envelope = envelope_with(vec![("x-tenant".to_string(), present_enc)]);
        assert!(!matches_vary(absent.view(), None, &envelope));
        assert!(matches_vary(present_empty.view(), None, &envelope));
        let envelope_absent = envelope_with(vec![("x-tenant".to_string(), absent_enc)]);
        assert!(matches_vary(absent.view(), None, &envelope_absent));
        assert!(!matches_vary(present_empty.view(), None, &envelope_absent));
    }

    #[test]
    fn mixed_ascii_and_obs_text_selector_is_unrepresentable() {
        let mixed = header_map(&[("x-tenant", vec![b"en".to_vec(), vec![0x80]])]);
        assert!(request_header_values(mixed.view(), "x-tenant").is_none());
        assert!(
            vary_values_from_request_headers(mixed.view(), &["x-tenant".to_string()]).is_none()
        );
    }

    #[test]
    fn invalid_name_refuses_store_and_hit() {
        let headers = qpx_core::http_message::Headers::new();
        let view = headers.view();
        for name in ["", "bad name", "x-tenant:"] {
            assert_eq!(request_header_values(view, name), None);
            assert!(vary_values_from_request_headers(view, &[name.to_string()]).is_none());
            let envelope = envelope_with(vec![(name.to_string(), "\x00".to_string().into())]);
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
        let view = headers.view();
        assert_eq!(
            request_header_values(view, "X-Tenant"),
            Some("\x01second,,first,a, b".to_owned().into())
        );
        let empty = header_map(&[("x-tenant", vec![b"".to_vec()])]);
        let absent = qpx_core::http_message::Headers::new();
        assert_eq!(
            request_header_values(empty.view(), "x-tenant"),
            Some("\x01".to_owned().into())
        );
        assert_eq!(
            request_header_values(absent.view(), "x-tenant"),
            Some("\x00".to_owned().into())
        );
    }

    #[test]
    fn any_obs_text_duplicate_refuses_store_and_hit() {
        let clean = header_map(&[("x-tenant", vec![b"ascii".to_vec(), b"ascii".to_vec()])]);
        let fields = ["x-tenant".to_string()];
        let envelope =
            envelope_with(vary_values_from_request_headers(clean.view(), &fields).unwrap());
        for position in 0..3 {
            let mut values = vec![b"ascii".to_vec(); 3];
            values[position] = vec![0x80];
            let headers = header_map(&[("x-tenant", values)]);
            let view = headers.view();
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
            (vec![], None),
            (vec![""], Some("")),
            (vec!["05"], Some("05")),
            (vec!["5"], Some("5")),
            (vec!["42, 42"], Some("42, 42")),
            (vec!["42"], Some("42")),
            (vec!["42", "43"], Some("42,43")),
            (vec!["43", "42"], Some("43,42")),
        ];
        let mut variants = Vec::new();
        for (values, expected) in cases {
            let headers = header_map(&[(
                "content-length",
                values.iter().map(|s| s.as_bytes().to_vec()).collect(),
            )]);
            let selectors = vary_values_from_request_headers(headers.view(), &fields).unwrap();
            let encoded = expected.map_or_else(|| "\x00".to_owned(), |text| format!("\x01{text}"));
            assert_eq!(
                selectors,
                vec![("content-length".to_string(), encoded.into())]
            );
            let key = variant_storage_key("primary", &selectors);
            variants.push((headers, envelope_with(selectors), key));
        }
        for (i, (headers, _, key)) in variants.iter().enumerate() {
            for (j, (_, envelope, other_key)) in variants.iter().enumerate() {
                assert_eq!(matches_vary(headers.view(), None, envelope), i == j);
                assert_eq!(key == other_key, i == j);
            }
        }
    }

    #[test]
    fn joined_occurrences_have_the_same_literal_selector_and_variant_key() {
        for name in ["content-length", "x-tenant"] {
            let single = header_map(&[(name, vec![b"a,b".to_vec()])]);
            let duplicate = header_map(&[(name, vec![b" a ".to_vec(), b" b ".to_vec()])]);
            let fields = [name.to_string()];
            let single_values = vary_values_from_request_headers(single.view(), &fields).unwrap();
            let duplicate_values =
                vary_values_from_request_headers(duplicate.view(), &fields).unwrap();
            assert_eq!(single_values, duplicate_values);
            assert_eq!(
                variant_storage_key("primary", &single_values),
                variant_storage_key("primary", &duplicate_values)
            );
            assert!(matches_vary(
                single.view(),
                None,
                &envelope_with(duplicate_values)
            ));
            assert!(matches_vary(
                duplicate.view(),
                None,
                &envelope_with(single_values)
            ));
        }
    }

    #[test]
    fn content_length_obs_text_in_any_occurrence_refuses_store_and_hit() {
        let fields = ["CoNtEnT-LeNgTh".to_owned()];
        let clean = header_map(&[("content-length", vec![b"42".to_vec()])]);
        let envelope =
            envelope_with(vary_values_from_request_headers(clean.view(), &fields).unwrap());
        for values in [
            vec![vec![0x80]],
            vec![b"42".to_vec(), vec![0x80]],
            vec![vec![0x80], b"42".to_vec()],
        ] {
            let headers = header_map(&[("content-length", values)]);
            let view = headers.view();
            assert!(vary_values_from_request_headers(view, &fields).is_none());
            assert!(!matches_vary(view, None, &envelope));
        }
    }

    #[test]
    fn persisted_selectors_keep_wire_format_keys_and_matching_after_restart() {
        use crate::types::{decode_cached_response_metadata, encode_cached_response_metadata};
        use sha2::Digest as _;
        for values in [
            vec![],
            vec![""],
            vec!["05"],
            vec!["42, 42"],
            vec![" 43 ", "42"],
        ] {
            let headers = header_map(&[
                (
                    "content-length",
                    values.iter().map(|v| v.as_bytes().to_vec()).collect(),
                ),
                ("x-tenant", vec![b" a=b|c ".to_vec()]),
            ]);
            let fields = vec!["content-length".to_owned(), "x-tenant".to_owned()];
            let mut selectors = vary_values_from_request_headers(headers.view(), &fields).unwrap();
            selectors.push(("@query-content".to_owned(), "digest-a".to_owned().into()));
            let mut envelope = envelope_with(selectors.clone());
            envelope.vary_headers = fields;
            let encoded = if values.is_empty() {
                "\x00".to_owned()
            } else {
                format!(
                    "\x01{}",
                    values
                        .iter()
                        .map(|v| v.trim())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            // Historical storage is a list of pairs of plain strings, not a tagged token.
            let legacy = vec![
                ("content-length".to_owned(), encoded),
                ("x-tenant".to_owned(), "\x01a=b|c".to_owned()),
                ("@query-content".to_owned(), "digest-a".to_owned()),
            ];
            assert_eq!(
                serde_json::to_vec(&selectors).unwrap(),
                serde_json::to_vec(&legacy).unwrap()
            );
            let raw = legacy
                .iter()
                .map(|(name, value)| format!("{name}={value}|"))
                .collect::<String>();
            let legacy_key = format!(
                "obj:primary:{}",
                crate::hash::hex_lower(&sha2::Sha256::digest(raw.as_bytes()))
            );
            assert_eq!(variant_storage_key("primary", &selectors), legacy_key);
            let wire = encode_cached_response_metadata(&envelope).unwrap();
            let restarted = decode_cached_response_metadata(wire.clone().into()).unwrap();
            assert_eq!(restarted.vary_values, selectors);
            assert_eq!(encode_cached_response_metadata(&restarted).unwrap(), wire);
            assert_eq!(
                variant_storage_key("primary", &restarted.vary_values),
                legacy_key
            );
            assert!(matches_vary(headers.view(), Some("digest-a"), &restarted));
            assert!(!matches_vary(headers.view(), Some("digest-b"), &restarted));
            assert!(!matches_vary(headers.view(), None, &restarted));
        }
        assert_eq!(variant_storage_key("primary", &[]), "obj:primary:default");
        // Historical unsentinelled empty selectors must still miss, not mean absence.
        let legacy_empty = envelope_with(vec![("content-length".to_owned(), String::new().into())]);
        assert!(!matches_vary(
            qpx_core::http_message::Headers::new().view(),
            None,
            &legacy_empty
        ));
    }

    #[test]
    fn query_content_selector_still_matches_digest_not_a_header() {
        let headers = header_map(&[("x-tenant", vec![b"a".to_vec()])]);
        let view = headers.view();
        let mut selectors =
            vary_values_from_request_headers(view, &["x-tenant".to_string()]).unwrap();
        selectors.push(("@query-content".to_string(), "digest-a".to_string().into()));
        let envelope = envelope_with(selectors);
        assert!(matches_vary(view, Some("digest-a"), &envelope));
        assert!(!matches_vary(view, Some("digest-b"), &envelope));
        assert!(!matches_vary(view, None, &envelope));
        let absent = qpx_core::http_message::Headers::new();
        assert!(!matches_vary(absent.view(), Some("digest-a"), &envelope));
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
