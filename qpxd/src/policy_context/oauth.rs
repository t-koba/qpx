//! OAuth `client_secret_basic` credential owner.
//!
//! RFC 6749 section 2.3.1 requires the client identifier and secret to each
//! be `application/x-www-form-urlencoded` encoded before joining them with a
//! literal `:` and base64-encoding the result. This owner is intentionally
//! OAuth-specific: generic HTTP Basic authentication transmits the raw
//! `user-id:password` pair and must not use this encoding.

use anyhow::Result;
use base64::Engine as _;

/// Encode one UTF-8 credential component with form-urlencoding.
///
/// Uses the shared `url` form machinery, so the owner never invents its own
/// percent-encoding table.
pub(crate) fn oauth_form_encode_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Build the sensitive `Authorization` header for OAuth `client_secret_basic`.
pub(crate) fn oauth_client_secret_basic_header(
    client_id: &str,
    client_secret: &str,
) -> Result<http::HeaderValue> {
    let credentials = base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        oauth_form_encode_component(client_id),
        oauth_form_encode_component(client_secret),
    ));
    let mut authorization = http::HeaderValue::from_str(&format!("Basic {credentials}"))?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;

    fn decoded_userinfo(header: &http::HeaderValue) -> String {
        let value = header.to_str().expect("header is readable text");
        let encoded = value.strip_prefix("Basic ").expect("basic scheme");
        String::from_utf8(BASE64.decode(encoded).expect("base64 body")).expect("utf8 userinfo")
    }

    fn form_decode_component(encoded: &str) -> String {
        url::form_urlencoded::parse(format!("value={encoded}").as_bytes())
            .next()
            .map(|(_, value)| value.into_owned())
            .expect("single encoded component decodes")
    }

    #[test]
    fn form_encodes_reserved_and_edge_characters() {
        assert_eq!(oauth_form_encode_component(""), "");
        assert_eq!(oauth_form_encode_component("AZaz09-._"), "AZaz09-._");
        assert_eq!(
            oauth_form_encode_component("a:b/c?d@e f+g%h"),
            "a%3Ab%2Fc%3Fd%40e+f%2Bg%25h"
        );
        assert_eq!(oauth_form_encode_component("value\u{e9}"), "value%C3%A9");
    }

    #[test]
    fn header_wire_value_joins_separately_encoded_components() {
        let header =
            oauth_client_secret_basic_header("client:id", "s e+c%r:t").expect("header builds");
        let expected_userinfo = "client%3Aid:s+e%2Bc%25r%3At";
        assert_eq!(
            header.to_str().expect("header is readable text"),
            format!("Basic {}", BASE64.encode(expected_userinfo))
        );
        assert_eq!(decoded_userinfo(&header), expected_userinfo);
        assert!(header.is_sensitive());
    }

    #[test]
    fn header_round_trips_colon_bearing_credentials() {
        let client_id = "a:b";
        let client_secret = "c:d";
        let header =
            oauth_client_secret_basic_header(client_id, client_secret).expect("header builds");
        let userinfo = decoded_userinfo(&header);
        // Encoded components never contain a raw ':', so the first ':' is the
        // separator even when both credentials contain colons.
        let (encoded_id, encoded_secret) = userinfo.split_once(':').expect("separator");
        assert_eq!(form_decode_component(encoded_id), client_id);
        assert_eq!(form_decode_component(encoded_secret), client_secret);
        assert_ne!(userinfo, format!("{client_id}:{client_secret}"));
    }
}
