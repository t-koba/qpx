use super::types::{CachedResponseEnvelope, VarySpec};

pub(super) fn parse_vary(headers: &http::HeaderMap) -> VarySpec {
    let mut fields = Vec::new();
    for value in headers.get_all(http::header::VARY) {
        let Ok(v) = value.to_str() else {
            continue;
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

pub(super) fn vary_values_from_request_headers(
    request_headers: &http::HeaderMap,
    vary_headers: &[String],
) -> Vec<(String, String)> {
    vary_headers
        .iter()
        .map(|name| {
            let value = request_header_values(request_headers, name.as_str());
            (name.clone(), value)
        })
        .collect()
}

pub(super) fn request_header_values(headers: &http::HeaderMap, name: &str) -> String {
    let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
        return String::new();
    };
    let values: Vec<String> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::trim).map(str::to_string))
        .collect();
    values.join(",")
}

pub(super) fn matches_vary(
    request_headers: &http::HeaderMap,
    envelope: &CachedResponseEnvelope,
) -> bool {
    envelope
        .vary_values
        .iter()
        .all(|(name, value)| request_header_values(request_headers, name.as_str()) == *value)
}

pub(super) fn variant_storage_key(primary: &str, vary_values: &[(String, String)]) -> String {
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

pub(super) fn index_storage_key(primary: &str) -> String {
    format!("idx:{}", primary)
}
