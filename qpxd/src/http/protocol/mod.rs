pub mod base_fields;
pub mod common;
pub(crate) mod forwarded;
pub mod header_control;
pub(crate) mod io_prefix;
pub mod l7;
pub mod preflight;
pub mod sse;
mod trailer_body;

pub mod upgrade;
pub mod websocket;

/// Returns the default port used by HTTP upstream and extended CONNECT targets.
pub(crate) fn default_port_for_http_upstream_scheme(scheme: &str) -> u16 {
    match scheme {
        "http" | "ws" | "h2c" => 80,
        "https" | "wss" | "h2" | "h3" => 443,
        _ => 443,
    }
}

/// Records an absolute-form OPTIONS target with an empty path and no query.
/// `http::Uri` normalizes that target to a trailing slash, so this marker preserves the
/// empty-path semantics until the final proxy can generate the required asterisk-form target.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EmptyPathAbsoluteOptions;

#[cfg(test)]
mod tests {
    use super::default_port_for_http_upstream_scheme;

    #[test]
    fn http_upstream_scheme_default_ports_match_existing_mapping() {
        for (scheme, expected) in [
            ("http", 80),
            ("ws", 80),
            ("h2c", 80),
            ("https", 443),
            ("wss", 443),
            ("h2", 443),
            ("h3", 443),
            ("custom", 443),
            ("HTTP", 443),
        ] {
            assert_eq!(default_port_for_http_upstream_scheme(scheme), expected);
        }
    }
}
