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

/// Removes URI userinfo without parsing or normalizing an untrusted URI.
/// Applies only to hierarchical `scheme://` and network-path `//` URIs.
/// Opaque scheme payloads and relative paths are not authorities.
fn redact_uri_userinfo(uri: &str) -> String {
    // Header values may wrap a URI in quotes/whitespace. Preserve the wrapper,
    // but do not let it hide the authority. Scheme validation belongs to the
    // protocol parser, not this best-effort sanitizer of even rejected inputs.
    let value = uri.trim_start_matches(|c: char| c.is_whitespace() || c == '\'' || c == '"');
    let offset = uri.len() - value.len();
    let start = if value.starts_with("//") {
        offset + 2
    } else if let Some((prefix, _)) = value.split_once("://") {
        if prefix.contains(['/', ':', '?', '#']) {
            // A path, query, fragment or opaque payload can contain ://.
            return uri.to_string();
        } else {
            offset + prefix.len() + 3
        }
    } else {
        return uri.to_string();
    };
    strip_authority_userinfo(uri, start)
}

fn strip_authority_userinfo(uri: &str, start: usize) -> String {
    let end = uri[start..]
        .find(['/', '?', '#'])
        .map_or(uri.len(), |end| start + end);
    match uri[start..end].rfind('@') {
        Some(at) => format!("{}{}", &uri[..start], &uri[start + at + 1..]),
        None => uri.to_string(),
    }
}

/// Sanitizes a value known to be an authority (Host or CONNECT target).
/// Malformed syntax with an ambiguous '@' outside the authority fails closed.
pub fn redact_authority_userinfo(authority: &str) -> String {
    let redacted = redact_uri_userinfo(authority);
    let value = redacted.trim_start_matches(|c: char| c.is_whitespace() || c == '\'' || c == '"');
    let redacted = strip_authority_userinfo(&redacted, redacted.len() - value.len());
    if redacted.contains('@') {
        "<redacted>".to_string()
    } else {
        redacted
    }
}

/// Redacts a request target using its HTTP method to distinguish CONNECT's
/// authority form from generic URI references, then applies configured keys.
pub fn redact_request_target(method: &str, target: &str, query_keys: &[String]) -> String {
    if method != "CONNECT" {
        return redact_uri_query_keys(target, query_keys);
    }
    if target.starts_with('/') {
        // Extended CONNECT carries a path in :path; even a leading `//` is
        // still path data here, not a network-path authority.
        return redact_query_fragment_keys(target, query_keys);
    }

    let target_before_suffix = target.split(['?', '#']).next().unwrap_or(target);
    let has_hierarchical_scheme = target_before_suffix
        .split_once("://")
        .is_some_and(|(prefix, _)| is_valid_uri_scheme(prefix));
    if has_hierarchical_scheme {
        redact_uri_query_keys(target, query_keys)
    } else {
        // Traditional CONNECT uses authority-form. Malformed suffixes do not
        // turn its authority userinfo into ordinary URI data.
        redact_query_fragment_keys(&redact_authority_userinfo(target), query_keys)
    }
}

fn is_valid_uri_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// Redacts URI userinfo unconditionally, and configured query/fragment keys.
pub fn redact_uri_query_keys(uri: &str, query_keys: &[String]) -> String {
    let uri = redact_uri_userinfo(uri);
    redact_query_fragment_keys(&uri, query_keys)
}

fn redact_query_fragment_keys(uri: &str, query_keys: &[String]) -> String {
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

#[cfg(test)]
mod userinfo_tests {
    use super::*;

    #[test]
    fn malformed_and_wrapped_uri_userinfo_is_redacted_without_rewriting_paths() {
        for (input, expected) in [
            ("1bad://synthetic-secret@host/a", "1bad://host/a"),
            ("bad scheme://synthetic-secret@host", "bad scheme://host"),
            (
                "ht?tp://synthetic-secret@host",
                "ht?tp://synthetic-secret@host",
            ),
            ("'ftp://synthetic-secret@host/a'", "'ftp://host/a'"),
            (" \"//synthetic-secret@host\" ", " \"//host\" "),
            (" \tftp://synthetic-secret@host/a ", " \tftp://host/a "),
            (
                "  synthetic-secret@host:21  ",
                "  synthetic-secret@host:21  ",
            ),
            ("/foo://user@host", "/foo://user@host"),
            (" '/foo://user@host' ", " '/foo://user@host' "),
            ("/foo?next=ftp://user@host", "/foo?next=ftp://user@host"),
        ] {
            assert_eq!(redact_uri_userinfo(input), expected);
        }
    }

    #[test]
    fn malformed_host_is_not_treated_as_an_ordinary_origin_path() {
        assert_eq!(
            redact_authority_userinfo("/foo://synthetic-secret@host"),
            "<redacted>"
        );
        assert_eq!(
            redact_authority_userinfo("'1bad://synthetic-secret@host'"),
            "'1bad://host'"
        );
        assert_eq!(redact_authority_userinfo("[::1]:21"), "[::1]:21");
    }

    #[test]
    fn userinfo_redaction_is_scheme_independent_and_preserves_target() {
        for prefix in ["ftp://", "http://", "https://", "custom+v1://", "//"] {
            for userinfo in [
                "synthetic-user:synthetic-pass@",
                "synthetic-user@",
                "first@synthetic-pass@",
            ] {
                let uri = format!("{prefix}{userinfo}[::1]:21/file?ok=1#ok=2");
                assert_eq!(
                    redact_uri_query_keys(&uri, &[]),
                    format!("{prefix}[::1]:21/file?ok=1#ok=2")
                );
            }
        }
        assert_eq!(
            redact_uri_userinfo("/path/user@host?email=a@b"),
            "/path/user@host?email=a@b"
        );
    }
    #[test]
    fn opaque_schemes_and_relative_references_are_not_authorities() {
        for uri in [
            "mailto:alice@example.com",
            "urn:example:person@domain",
            "mailto:alice@example.com?next=ftp://user@host",
            "urn:example:ftp://user@host",
            "alice@example.com/path",
            "/path/user@host?email=a@b",
            "path?next=ftp://user@host",
            "path#ftp://user@host",
        ] {
            assert_eq!(redact_uri_userinfo(uri), uri);
            assert_eq!(redact_uri_query_keys(uri, &[]), uri);
            assert_eq!(redact_request_target("GET", uri, &[]), uri);
        }
    }

    #[test]
    fn extended_connect_paths_preserve_at_data_and_redact_query_keys() {
        let keys = vec!["token".to_string()];
        assert_eq!(
            redact_request_target("CONNECT", "/chat/@alice?room=general&token=secret", &keys),
            "/chat/@alice?room=general&token=<redacted>"
        );
        assert_eq!(
            redact_request_target("CONNECT", "//chat/@alice?room=general", &[]),
            "//chat/@alice?room=general"
        );
        assert_eq!(
            redact_request_target(
                "CONNECT",
                "https://user:pass@host/chat/@alice?room=general",
                &[]
            ),
            "https://host/chat/@alice?room=general"
        );
        assert_eq!(
            redact_request_target(
                "CONNECT",
                "synthetic-user:synthetic-pass@host:443?token=secret",
                &keys,
            ),
            "host:443?token=<redacted>"
        );
        assert_eq!(
            redact_request_target(
                "CONNECT",
                "synthetic-user:synthetic-pass@host?return=/foo",
                &[],
            ),
            "host?return=/foo"
        );
        assert_eq!(
            redact_request_target(
                "CONNECT",
                "synthetic-user:synthetic-pass@host:443/path?token=secret",
                &keys,
            ),
            "host:443/path?token=<redacted>"
        );
    }

    #[test]
    fn malformed_connect_scheme_like_prefix_is_redacted_as_authority() {
        assert_eq!(
            redact_request_target("CONNECT", "synthetic-user@host://suffix", &[]),
            "host://suffix"
        );
        let keys = vec!["token".to_string()];
        assert_eq!(
            redact_request_target(
                "CONNECT",
                "synthetic-user:synthetic-pass@host://suffix?token=synthetic-token",
                &keys,
            ),
            "host://suffix?token=<redacted>"
        );
    }

    #[test]
    fn bare_authorities_require_authority_context() {
        for authority in [
            "synthetic-user:synthetic-pass@host:443",
            "synthetic-user@host:443",
            "first@synthetic-pass@host:443",
        ] {
            assert_eq!(redact_uri_userinfo(authority), authority);
            assert_eq!(redact_authority_userinfo(authority), "host:443");
            assert_eq!(redact_request_target("CONNECT", authority, &[]), "host:443");
        }
        assert_eq!(redact_authority_userinfo("[::1]:443"), "[::1]:443");
    }
}
