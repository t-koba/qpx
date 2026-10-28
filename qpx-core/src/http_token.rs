//! The HTTP token vocabulary.
//!
//! The RFC 9110 token grammar and the comma-separated header token search
//! have one owner, so the Forwarded element names, the Prefer field names,
//! the Content-Disposition parameter names, the WebSocket subprotocol names,
//! the Connection tokens, the configuration's header names, the CORS and
//! browser-policy Vary dimensions and the DPoP method claim cannot drift
//! apart.

use http::header::{HeaderMap, HeaderName, HeaderValue};

/// Whether `value` is an RFC 9110 token.
pub fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
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
                )
        })
}

/// The comma-separated members of the header's values, each trimmed.
///
/// A value that is not text contributes no members, as a value the caller
/// cannot read contributes nothing to the header's meaning.
pub fn header_value_members<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> impl Iterator<Item = &'a str> + 'a {
    value_members(headers.get_all(name).iter())
}

/// Trimmed comma members of borrowed occurrences; non-text values are skipped.
pub fn value_members<'a>(
    values: impl Iterator<Item = &'a HeaderValue>,
) -> impl Iterator<Item = &'a str> {
    values
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(','))
        .map(str::trim)
}

/// Whether one of the header's values carries `token` among its
/// comma-separated members.
pub fn header_values_contain_token(headers: &HeaderMap, name: &HeaderName, token: &str) -> bool {
    header_value_members(headers, name).any(|member| member.eq_ignore_ascii_case(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{CONNECTION, HeaderValue, UPGRADE};

    #[test]
    fn http_token_accepts_only_the_rfc_token_characters() {
        assert!(is_http_token("token"));
        assert!(is_http_token("keep-alive"));
        assert!(is_http_token("a1!#$%&'*+-.^_`|~"));
        assert!(!is_http_token(""));
        assert!(!is_http_token("has space"));
        assert!(!is_http_token("comma,separated"));
        assert!(!is_http_token("colon:value"));
    }

    #[test]
    fn the_token_grammar_accepts_exactly_the_rfc_9110_characters() {
        // The four grammars that were folded into this owner - the Prefer
        // field names, the Forwarded element names, the Content-Disposition
        // parameter names and the browser policy's directive values - each
        // accepted exactly these bytes, so folding them changed no verdict.
        // The set is pinned here so that a later change to the owner's own
        // grammar is a visible test failure rather than a silent behaviour
        // change at every site that reaches the owner.
        let expected: Vec<u8> =
            b"!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~"
                .to_vec();
        let accepted: Vec<u8> = (0u8..=127)
            .filter(|byte| is_http_token(&char::from(*byte).to_string()))
            .collect();
        assert_eq!(accepted, expected);
        assert!(!is_http_token(""));
    }

    #[test]
    fn http_token_rejects_the_characters_a_drifted_copy_accepted() {
        // The copy that used to live in the DPoP claim validation accepted
        // these characters; the RFC 9110 token grammar does not.
        for value in ["GET,", "a/b", "x{y", "x}y"] {
            assert!(!is_http_token(value), "{value}");
        }
    }

    #[test]
    fn header_members_are_the_trimmed_comma_separated_values() {
        let mut headers = HeaderMap::new();
        headers.append(CONNECTION, HeaderValue::from_static("keep-alive, Close"));
        headers.append(CONNECTION, HeaderValue::from_static("upgrade"));
        let members = header_value_members(&headers, &CONNECTION).collect::<Vec<_>>();
        assert_eq!(members, ["keep-alive", "Close", "upgrade"]);
    }

    #[test]
    fn header_token_search_ignores_case_and_surrounding_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Close"));
        assert!(header_values_contain_token(&headers, &CONNECTION, "close"));
        assert!(header_values_contain_token(
            &headers,
            &CONNECTION,
            "keep-alive"
        ));
        assert!(!header_values_contain_token(&headers, &CONNECTION, "keep"));
        assert!(!header_values_contain_token(
            &headers,
            &UPGRADE,
            "websocket"
        ));
    }
}
