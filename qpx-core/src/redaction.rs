use percent_encoding::percent_decode_str;

/// Compiles a simple JSON object path such as `$.token.secret`.
pub fn compile_json_redaction_path(path: &str) -> Result<Vec<String>, String> {
    let trimmed = path.trim();
    let Some(rest) = trimmed.strip_prefix("$.") else {
        return Err("must start with $. followed by one or more object keys".to_string());
    };
    if rest.is_empty() {
        return Err("must include at least one object key after $.".to_string());
    }
    let mut parts = Vec::new();
    for part in rest.split('.') {
        if part.is_empty() {
            return Err("must not contain empty path segments".to_string());
        }
        if part.trim() != part {
            return Err("path segments must not contain surrounding whitespace".to_string());
        }
        parts.push(part.to_string());
    }
    Ok(parts)
}

/// Redacts configured query keys in a URI query string and query-like fragment.
pub fn redact_uri_query_keys(uri: &str, query_keys: &[String]) -> String {
    let (before_fragment, fragment) = uri
        .split_once('#')
        .map(|(head, fragment)| (head, Some(fragment)))
        .unwrap_or((uri, None));
    let (path, query) = before_fragment
        .split_once('?')
        .map(|(path, query)| (path, Some(query)))
        .unwrap_or((before_fragment, None));

    if query.is_none() && fragment.is_none() {
        return uri.to_string();
    };

    let mut out = String::with_capacity(uri.len());
    out.push_str(path);
    if let Some(query) = query {
        out.push('?');
        out.push_str(redact_uri_pairs(query, query_keys).as_str());
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(redact_uri_pairs(fragment, query_keys).as_str());
    }
    out
}

fn redact_uri_pairs(value: &str, query_keys: &[String]) -> String {
    value
        .split('&')
        .map(|pair| {
            let key = pair.split_once('=').map(|(key, _)| key).unwrap_or(pair);
            let decoded_key = percent_decode_str(key).decode_utf8_lossy();
            if query_keys
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(decoded_key.as_ref()))
            {
                format!("{key}=<redacted>")
            } else {
                pair.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_percent_encoded_query_keys_with_configured_names() {
        let keys = vec!["api_key".to_string(), "access_token".to_string()];
        assert_eq!(
            redact_uri_query_keys("/login?api%5Fkey=secret&access_token=abc&ok=yes", &keys),
            "/login?api%5Fkey=<redacted>&access_token=<redacted>&ok=yes"
        );
    }

    #[test]
    fn redacts_query_like_fragment_keys_with_configured_names() {
        let keys = vec!["access_token".to_string(), "id_token".to_string()];
        assert_eq!(
            redact_uri_query_keys(
                "https://client.example/cb?code=ok#access_token=secret&id%5Ftoken=jwt&state=s",
                &keys
            ),
            "https://client.example/cb?code=ok#access_token=<redacted>&id%5Ftoken=<redacted>&state=s"
        );
        assert_eq!(
            redact_uri_query_keys("https://client.example/cb#access_token=secret", &keys),
            "https://client.example/cb#access_token=<redacted>"
        );
    }

    #[test]
    fn validates_supported_json_redaction_paths() {
        assert_eq!(
            compile_json_redaction_path("$.detail.secret").expect("path"),
            vec!["detail".to_string(), "secret".to_string()]
        );

        for invalid in ["", "password", "$", "$.", "$.detail.", "$.detail..secret"] {
            assert!(
                compile_json_redaction_path(invalid).is_err(),
                "{invalid} should be rejected"
            );
        }
    }
}
