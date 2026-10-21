//! The HTTP token vocabulary.
//!
//! The RFC 9110 token grammar and the comma-separated header token search
//! have one owner, so the Forwarded element names, the WebSocket subprotocol
//! names, the Connection tokens, the configuration's header names and the
//! DPoP method claim cannot drift apart.

use http::header::{HeaderMap, HeaderName};

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

/// Whether one of the header's values carries `token` among its
/// comma-separated members.
pub fn header_values_contain_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(','))
        .any(|part| part.trim().eq_ignore_ascii_case(token))
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
    fn http_token_rejects_the_characters_a_drifted_copy_accepted() {
        // The copy that used to live in the DPoP claim validation accepted
        // these characters; the RFC 9110 token grammar does not.
        for value in ["GET,", "a/b", "x{y", "x}y"] {
            assert!(!is_http_token(value), "{value}");
        }
    }

    #[test]
    fn header_token_search_ignores_case_and_surrounding_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Close"));
        assert!(header_values_contain_token(&headers, CONNECTION, "close"));
        assert!(header_values_contain_token(
            &headers,
            CONNECTION,
            "keep-alive"
        ));
        assert!(!header_values_contain_token(&headers, CONNECTION, "keep"));
        assert!(!header_values_contain_token(&headers, UPGRADE, "websocket"));
    }
}
