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
    request_headers: &http::HeaderMap,
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
/// Returns `None` when the selector cannot be represented losslessly with
/// `HeaderValue::to_str` (e.g. obs-text). Callers treat `None` as
/// fail-closed: no store and no hit.
///
/// The encoding distinguishes absence from any present value (including
/// present-empty), per RFC 9111 section 4.1: absence encodes as a lone
/// `\x00`, while any present value list encodes as `\x01` followed by the
/// comma-joined trimmed values. `\x00`/`\x01` never appear in `to_str`
/// output (visible ASCII only), so the sentinel cannot collide with a real
/// value, nor with legacy `""` entries (which now safely miss).
pub fn request_header_values(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
        return None;
    };
    let mut values: Vec<String> = Vec::new();
    let mut seen = false;
    for v in headers.get_all(name).iter() {
        let Ok(s) = v.to_str() else {
            return None;
        };
        seen = true;
        values.push(s.trim().to_string());
    }
    if !seen {
        return Some("\x00".to_string());
    }
    let mut out = String::from("\x01");
    out.push_str(&values.join(","));
    Some(out)
}

pub fn matches_vary(
    request_headers: &http::HeaderMap,
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
        assert!(request_header_values(&stored_headers, "x-tenant").is_none());
        assert!(
            vary_values_from_request_headers(&stored_headers, &["x-tenant".to_string()]).is_none()
        );
    }

    #[test]
    fn unrepresentable_selector_refuses_store_and_hit() {
        let stored = header_map(&[("x-tenant", vec![b"a".to_vec()])]);
        let values = vary_values_from_request_headers(&stored, &["x-tenant".to_string()])
            .expect("ascii stores");
        let envelope = envelope_with(values);
        // Distinct obs-text value must not hit.
        let other = header_map(&[("x-tenant", vec![vec![0x81]])]);
        assert!(!matches_vary(&other, None, &envelope));
        // Absent selector must not hit a present-value variant.
        let absent = header_map(&[]);
        assert!(!matches_vary(&absent, None, &envelope));
        // The obs-text request itself must not hit either (fail-closed).
        let obs = header_map(&[("x-tenant", vec![vec![0x80]])]);
        assert!(!matches_vary(&obs, None, &envelope));
    }

    #[test]
    fn present_empty_does_not_match_absence() {
        let present_empty = header_map(&[("x-tenant", vec![b"".to_vec()])]);
        let absent = header_map(&[]);
        let present_enc = request_header_values(&present_empty, "x-tenant").unwrap();
        let absent_enc = request_header_values(&absent, "x-tenant").unwrap();
        assert_ne!(present_enc, absent_enc);
        let envelope = envelope_with(vec![("x-tenant".to_string(), present_enc)]);
        assert!(!matches_vary(&absent, None, &envelope));
        assert!(matches_vary(&present_empty, None, &envelope));
        let envelope_absent = envelope_with(vec![("x-tenant".to_string(), absent_enc)]);
        assert!(matches_vary(&absent, None, &envelope_absent));
        assert!(!matches_vary(&present_empty, None, &envelope_absent));
    }

    #[test]
    fn mixed_ascii_and_obs_text_selector_is_unrepresentable() {
        let mixed = header_map(&[("x-tenant", vec![b"en".to_vec(), vec![0x80]])]);
        assert!(request_header_values(&mixed, "x-tenant").is_none());
        assert!(vary_values_from_request_headers(&mixed, &["x-tenant".to_string()]).is_none());
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
