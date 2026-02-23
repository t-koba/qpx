use http::header::{CONNECTION, CONTENT_LENGTH, EXPECT, HOST, TRAILER, TRANSFER_ENCODING, VIA};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use std::fmt;

static WELL_KNOWN_HOP_HEADERS: &[&str] = &[
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-authentication-info",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
];

pub fn sanitize_hop_by_hop_headers(headers: &mut HeaderMap, preserve_upgrade: bool) {
    let mut keep_upgrade = false;

    let connection_tokens = parse_connection_tokens(headers);
    for token in connection_tokens {
        let lower = token.to_ascii_lowercase();
        if preserve_upgrade && lower == "upgrade" {
            keep_upgrade = true;
            continue;
        }
        if let Ok(name) = HeaderName::from_bytes(lower.as_bytes()) {
            headers.remove(name);
        }
    }

    for header in WELL_KNOWN_HOP_HEADERS {
        headers.remove(*header);
    }

    if preserve_upgrade && keep_upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(CONNECTION);
        headers.remove("upgrade");
    }
}

pub fn append_via_for_version(headers: &mut HeaderMap, version: Version, proxy_name: &str) {
    let value = format!("{} {}", via_version_token(version), proxy_name);
    if let Ok(v) = HeaderValue::from_str(&value) {
        headers.append(VIA, v);
    }
}

pub fn sync_host_header_from_absolute_target(headers: &mut HeaderMap, target: &http::Uri) {
    if let Some(authority) = target.authority() {
        if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
            headers.insert(HOST, value);
        }
    }
}

fn parse_connection_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    for value in headers.get_all(CONNECTION) {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let token = token.trim();
                if !token.is_empty() {
                    out.push(token.to_string());
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestValidationError {
    MultipleHostHeaders,
    EmptyHostHeader,
    InvalidHostHeader,
    MissingHost,
    MissingConnectAuthority,
    InvalidConnectTarget,
    InvalidRequestTarget,
    HostAuthorityMismatch,
    InvalidContentLength,
    BothTransferEncodingAndContentLength,
    InvalidH2H3ConnectionHeader,
    InvalidH2H3TeHeader,
    InvalidExpectHeader,
    InvalidTrailerField,
}

impl fmt::Display for RequestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MultipleHostHeaders => "multiple Host headers are not allowed",
            Self::EmptyHostHeader => "Host header must not be empty",
            Self::InvalidHostHeader => "invalid Host header",
            Self::MissingHost => "missing Host/authority",
            Self::MissingConnectAuthority => "CONNECT requires authority-form target",
            Self::InvalidConnectTarget => "invalid CONNECT authority-form target",
            Self::InvalidRequestTarget => "invalid request target form",
            Self::HostAuthorityMismatch => "Host header does not match request authority",
            Self::InvalidContentLength => "invalid Content-Length",
            Self::BothTransferEncodingAndContentLength => {
                "request must not contain both Transfer-Encoding and Content-Length"
            }
            Self::InvalidH2H3ConnectionHeader => {
                "HTTP/2 and HTTP/3 requests must not contain connection-specific headers"
            }
            Self::InvalidH2H3TeHeader => "HTTP/2 and HTTP/3 requests may only use TE: trailers",
            Self::InvalidExpectHeader => "invalid Expect header",
            Self::InvalidTrailerField => "invalid trailer field",
        };
        f.write_str(message)
    }
}

impl RequestValidationError {
    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::InvalidExpectHeader => StatusCode::EXPECTATION_FAILED,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

pub fn validate_incoming_request<B>(req: &http::Request<B>) -> Result<(), RequestValidationError> {
    validate_request_body_length_headers(req.headers())?;
    validate_expect_header(req.headers())?;
    validate_h2_h3_request_headers(req.version(), req.headers())?;

    let host_values: Vec<_> = req.headers().get_all(HOST).iter().collect();
    if host_values.len() > 1 {
        return Err(RequestValidationError::MultipleHostHeaders);
    }
    let host = if let Some(value) = host_values.first() {
        let raw = value
            .to_str()
            .map_err(|_| RequestValidationError::InvalidHostHeader)?
            .trim();
        if raw.is_empty() {
            return Err(RequestValidationError::EmptyHostHeader);
        }
        parse_authority_parts(raw).ok_or(RequestValidationError::InvalidHostHeader)?;
        Some(raw)
    } else {
        None
    };

    let uri_authority = req.uri().authority().map(|a| a.as_str());
    if req.method() == Method::CONNECT {
        let Some(authority) = uri_authority else {
            return Err(RequestValidationError::MissingConnectAuthority);
        };
        // RFC 9110: CONNECT target is authority-form ("host:port"), not absolute or origin-form.
        if req.uri().scheme().is_some() || req.uri().path_and_query().is_some() {
            return Err(RequestValidationError::InvalidConnectTarget);
        }
        let connect_authority =
            parse_authority_parts(authority).ok_or(RequestValidationError::InvalidConnectTarget)?;
        if connect_authority.port.is_none() {
            return Err(RequestValidationError::InvalidConnectTarget);
        }
    } else {
        if req.uri().scheme().is_none() && uri_authority.is_some() {
            return Err(RequestValidationError::InvalidRequestTarget);
        }
        if let Some(authority) = uri_authority {
            parse_authority_parts(authority).ok_or(RequestValidationError::InvalidRequestTarget)?;
        }
        let path = req.uri().path();
        if path == "*" && req.method() != Method::OPTIONS {
            return Err(RequestValidationError::InvalidRequestTarget);
        }
        if req.uri().scheme().is_none()
            && uri_authority.is_none()
            && path != "*"
            && !path.starts_with('/')
        {
            return Err(RequestValidationError::InvalidRequestTarget);
        }
    }

    if req.version() == Version::HTTP_11 && host.is_none() {
        return Err(RequestValidationError::MissingHost);
    }
    if host.is_none()
        && uri_authority.is_none()
        && req.version() != Version::HTTP_10
        && req.version() != Version::HTTP_09
    {
        return Err(RequestValidationError::MissingHost);
    }

    if let (Some(host), Some(authority)) = (host, uri_authority) {
        if !authority_equivalent(host, authority, req.uri().scheme_str()) {
            return Err(RequestValidationError::HostAuthorityMismatch);
        }
    }

    Ok(())
}

pub fn validate_request_trailers(trailers: &HeaderMap) -> Result<(), RequestValidationError> {
    // RFC 9110 Section 6.5.1: only fields explicitly defined as safe-in-trailers are allowed.
    // As an intermediary, we at least reject known-framing/routing/auth/content-format fields.
    // (Header values are already validated by HeaderMap construction.)
    if trailers
        .keys()
        .any(|name| is_prohibited_trailer_field(name.as_str()))
    {
        return Err(RequestValidationError::InvalidTrailerField);
    }
    Ok(())
}

pub fn sanitize_response_trailers(trailers: &mut HeaderMap) -> usize {
    let mut removed = Vec::new();
    for name in trailers.keys() {
        if is_prohibited_trailer_field(name.as_str()) {
            removed.push(name.clone());
        }
    }
    for name in removed.iter() {
        trailers.remove(name);
    }
    removed.len()
}

fn is_prohibited_trailer_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if is_hop_by_hop_header_name(lower.as_str()) {
        return true;
    }
    matches!(
        lower.as_str(),
        // Message framing / routing
        "content-length"
            | "host"
            // Authentication
            | "authorization"
            | "www-authenticate"
            | "authentication-info"
            | "cookie"
            | "set-cookie"
            // Request modifiers / response controls
            | "expect"
            | "range"
            | "if-match"
            | "if-none-match"
            | "if-modified-since"
            | "if-unmodified-since"
            | "if-range"
            | "max-forwards"
            | "cache-control"
            | "expires"
            | "pragma"
            | "age"
            // Content format / interpretation
            | "content-type"
            | "content-encoding"
            | "content-language"
            | "content-location"
            | "content-range"
    )
}

#[cfg(feature = "http3")]
pub fn validate_h2_h3_connect_headers(headers: &HeaderMap) -> Result<(), RequestValidationError> {
    validate_request_body_length_headers(headers)?;
    validate_h2_h3_request_headers(Version::HTTP_3, headers)
}

pub fn validate_h2_h3_request_headers(
    version: Version,
    headers: &HeaderMap,
) -> Result<(), RequestValidationError> {
    if version != Version::HTTP_2 && version != Version::HTTP_3 {
        return Ok(());
    }

    if headers.contains_key(CONNECTION)
        || headers.contains_key("proxy-connection")
        || headers.contains_key("keep-alive")
        || headers.contains_key("upgrade")
        || headers.contains_key(TRANSFER_ENCODING)
    {
        return Err(RequestValidationError::InvalidH2H3ConnectionHeader);
    }

    for value in headers.get_all("te") {
        let raw = value
            .to_str()
            .map_err(|_| RequestValidationError::InvalidH2H3TeHeader)?;
        let mut saw_token = false;
        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            saw_token = true;
            if !token.eq_ignore_ascii_case("trailers") {
                return Err(RequestValidationError::InvalidH2H3TeHeader);
            }
        }
        if !saw_token {
            return Err(RequestValidationError::InvalidH2H3TeHeader);
        }
    }

    Ok(())
}

pub fn normalize_response_for_request<B>(
    request_method: &Method,
    response: &mut http::Response<B>,
) -> bool
where
    B: Default,
{
    let status = response.status();
    let no_body = request_method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::RESET_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || (request_method == Method::CONNECT && status.is_success());
    if no_body {
        *response.body_mut() = B::default();
        if request_method == Method::HEAD {
            strip_message_body_framing_headers(response.headers_mut());
        } else {
            strip_message_body_headers(response.headers_mut());
        }
    }
    no_body
}

pub fn strip_message_body_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
    headers.remove(TRAILER);
}

pub fn strip_message_body_framing_headers(headers: &mut HeaderMap) {
    headers.remove(TRANSFER_ENCODING);
    headers.remove(TRAILER);
}

pub fn is_hop_by_hop_header_name(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "proxy-authentication-info"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn via_version_token(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "1.1",
    }
}

fn authority_equivalent(host_header: &str, authority: &str, scheme: Option<&str>) -> bool {
    let Some(host) = parse_authority_parts(host_header) else {
        return false;
    };
    let Some(auth) = parse_authority_parts(authority) else {
        return false;
    };
    if host.host != auth.host {
        return false;
    }
    if host.port == auth.port {
        return true;
    }
    let default_port = scheme.and_then(default_port_for_scheme);
    match (host.port, auth.port, default_port) {
        (Some(left), None, Some(default)) if left == default => true,
        (None, Some(right), Some(default)) if right == default => true,
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorityParts {
    host: String,
    port: Option<u16>,
}

fn parse_authority_parts(input: &str) -> Option<AuthorityParts> {
    if input.contains('@') {
        return None;
    }
    let uri = http::Uri::builder()
        .scheme("http")
        .authority(input.trim())
        .path_and_query("/")
        .build()
        .ok()?;
    let authority = uri.authority()?;
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(AuthorityParts {
        host,
        port: authority.port_u16(),
    })
}

fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        "ws" => Some(80),
        "wss" => Some(443),
        "ftp" => Some(21),
        _ => None,
    }
}

fn validate_request_body_length_headers(headers: &HeaderMap) -> Result<(), RequestValidationError> {
    let mut parsed_content_length = None::<u64>;
    for value in headers.get_all(CONTENT_LENGTH) {
        let raw = value
            .to_str()
            .map_err(|_| RequestValidationError::InvalidContentLength)?
            .trim();
        if raw.is_empty() {
            return Err(RequestValidationError::InvalidContentLength);
        }
        for part in raw.split(',') {
            let parsed = part
                .trim()
                .parse::<u64>()
                .map_err(|_| RequestValidationError::InvalidContentLength)?;
            if let Some(existing) = parsed_content_length {
                if existing != parsed {
                    return Err(RequestValidationError::InvalidContentLength);
                }
            } else {
                parsed_content_length = Some(parsed);
            }
        }
    }

    if parsed_content_length.is_some() && headers.contains_key(TRANSFER_ENCODING) {
        return Err(RequestValidationError::BothTransferEncodingAndContentLength);
    }
    Ok(())
}

pub(crate) fn validate_expect_header(headers: &HeaderMap) -> Result<(), RequestValidationError> {
    let mut saw_expect = false;
    for value in headers.get_all(EXPECT).iter() {
        let raw = value
            .to_str()
            .map_err(|_| RequestValidationError::InvalidExpectHeader)?;
        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            saw_expect = true;
            if !token.eq_ignore_ascii_case("100-continue") {
                return Err(RequestValidationError::InvalidExpectHeader);
            }
        }
    }
    if headers.contains_key(EXPECT) && !saw_expect {
        return Err(RequestValidationError::InvalidExpectHeader);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_removes_connection_tokens_and_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, x-remove"));
        headers.insert("x-remove", HeaderValue::from_static("1"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers.insert("proxy-authorization", HeaderValue::from_static("Basic abc"));
        headers.insert(
            "proxy-authenticate",
            HeaderValue::from_static("Basic realm=\"qpx\""),
        );

        sanitize_hop_by_hop_headers(&mut headers, false);

        assert!(headers.get(CONNECTION).is_none());
        assert!(headers.get("x-remove").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("te").is_none());
        assert!(headers.get("proxy-authorization").is_none());
        assert!(headers.get("proxy-authenticate").is_none());
    }

    #[test]
    fn sanitize_preserves_upgrade_pair_for_websocket() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade, keep-alive"));
        headers.insert("upgrade", HeaderValue::from_static("websocket"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));

        sanitize_hop_by_hop_headers(&mut headers, true);

        assert_eq!(
            headers.get(CONNECTION).and_then(|v| v.to_str().ok()),
            Some("upgrade")
        );
        assert_eq!(
            headers.get("upgrade").and_then(|v| v.to_str().ok()),
            Some("websocket")
        );
        assert!(headers.get("keep-alive").is_none());
    }

    #[test]
    fn append_via_appends_values() {
        let mut headers = HeaderMap::new();
        headers.insert(VIA, HeaderValue::from_static("1.0 old-proxy"));
        append_via_for_version(&mut headers, Version::HTTP_11, "qpx");

        let values: Vec<_> = headers.get_all(VIA).iter().collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[1].to_str().ok(), Some("1.1 qpx"));
    }

    #[test]
    fn validate_rejects_multiple_host_headers() {
        let mut req = http::Request::builder()
            .uri("http://example.com/")
            .body(())
            .expect("request");
        req.headers_mut()
            .append(HOST, HeaderValue::from_static("example.com"));
        req.headers_mut()
            .append(HOST, HeaderValue::from_static("example.com"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::MultipleHostHeaders);
    }

    #[test]
    fn validate_rejects_invalid_host_value() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("/path")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_static("exa mple.com"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidHostHeader);
    }

    #[test]
    fn validate_rejects_host_with_userinfo() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("/path")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_static("user@example.com"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidHostHeader);
    }

    #[test]
    fn validate_accepts_default_port_equivalence() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("http://example.com:80/path")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_static("example.com"));
        validate_incoming_request(&req).expect("must pass");
    }

    #[test]
    fn normalize_response_keeps_content_length_for_head() {
        let mut resp = http::Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, "42")
            .header(TRANSFER_ENCODING, "chunked")
            .header(TRAILER, "x-trailer")
            .body("payload".to_string())
            .expect("response");
        let changed = normalize_response_for_request(&Method::HEAD, &mut resp);
        assert!(changed);
        assert_eq!(resp.body(), "");
        assert_eq!(resp.headers().get(CONTENT_LENGTH).unwrap(), "42");
        assert!(resp.headers().get(TRANSFER_ENCODING).is_none());
        assert!(resp.headers().get(TRAILER).is_none());
    }

    #[test]
    fn validate_rejects_missing_host_for_http11() {
        let req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("/only-path")
            .body(())
            .expect("request");
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::MissingHost);
    }

    #[test]
    fn validate_rejects_host_authority_mismatch() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("http://example.com/path")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_static("other.example"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::HostAuthorityMismatch);
    }

    #[test]
    fn normalize_response_drops_body_headers_for_204() {
        let mut resp = http::Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(CONTENT_LENGTH, "10")
            .body("payload".to_string())
            .expect("response");
        let changed = normalize_response_for_request(&Method::GET, &mut resp);
        assert!(changed);
        assert_eq!(resp.body(), "");
        assert!(resp.headers().get(CONTENT_LENGTH).is_none());
    }

    #[test]
    fn normalize_response_drops_body_headers_for_205() {
        let mut resp = http::Response::builder()
            .status(StatusCode::RESET_CONTENT)
            .header(CONTENT_LENGTH, "10")
            .body("payload".to_string())
            .expect("response");
        let changed = normalize_response_for_request(&Method::GET, &mut resp);
        assert!(changed);
        assert_eq!(resp.body(), "");
        assert!(resp.headers().get(CONTENT_LENGTH).is_none());
    }

    #[test]
    fn validate_rejects_mismatched_content_length_values() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::POST)
            .uri("http://example.com/upload")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_static("example.com"));
        req.headers_mut()
            .append(CONTENT_LENGTH, HeaderValue::from_static("10"));
        req.headers_mut()
            .append(CONTENT_LENGTH, HeaderValue::from_static("12"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidContentLength);
    }

    #[test]
    fn validate_rejects_transfer_encoding_with_content_length() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::POST)
            .uri("http://example.com/upload")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_static("example.com"));
        req.headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
        req.headers_mut()
            .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(
            err,
            RequestValidationError::BothTransferEncodingAndContentLength
        );
    }

    #[test]
    fn validate_rejects_connect_without_port() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::CONNECT)
            .uri("example.com")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_static("example.com"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidConnectTarget);
    }

    #[test]
    fn validate_rejects_connection_header_for_h2() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_2)
            .method(Method::GET)
            .uri("https://example.com/")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidH2H3ConnectionHeader);
    }

    #[test]
    fn validate_accepts_te_trailers_for_h2() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_2)
            .method(Method::GET)
            .uri("https://example.com/")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert("te", HeaderValue::from_static("trailers"));
        validate_incoming_request(&req).expect("must pass");
    }

    #[test]
    fn validate_rejects_invalid_te_for_h3() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_3)
            .method(Method::GET)
            .uri("https://example.com/")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert("te", HeaderValue::from_static("gzip"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidH2H3TeHeader);
    }

    #[test]
    fn validate_rejects_transfer_encoding_for_h3() {
        let mut req = http::Request::builder()
            .version(Version::HTTP_3)
            .method(Method::POST)
            .uri("https://example.com/")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidH2H3ConnectionHeader);
    }

    #[test]
    fn validate_accepts_expect_100_continue() {
        let req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::POST)
            .uri("http://example.com/upload")
            .header(HOST, "example.com")
            .header(EXPECT, "100-continue")
            .body(())
            .expect("request");
        validate_incoming_request(&req).expect("must pass");
    }

    #[test]
    fn validate_rejects_unknown_expectations() {
        let req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::POST)
            .uri("http://example.com/upload")
            .header(HOST, "example.com")
            .header(EXPECT, "100-continue, other")
            .body(())
            .expect("request");
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidExpectHeader);
    }

    #[test]
    fn validate_rejects_star_form_for_non_options() {
        let uri = http::Uri::builder()
            .path_and_query("*")
            .build()
            .expect("uri");
        let req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri(uri)
            .header(HOST, "example.com")
            .body(())
            .expect("request");
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidRequestTarget);
    }

    #[test]
    fn validate_allows_star_form_for_options() {
        let uri = http::Uri::builder()
            .path_and_query("*")
            .build()
            .expect("uri");
        let req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::OPTIONS)
            .uri(uri)
            .header(HOST, "example.com")
            .body(())
            .expect("request");
        validate_incoming_request(&req).expect("must pass");
    }

    #[test]
    fn validate_rejects_origin_form_without_leading_slash() {
        let uri = http::Uri::builder()
            .path_and_query("relative")
            .build()
            .expect("uri");
        let req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri(uri)
            .header(HOST, "example.com")
            .body(())
            .expect("request");
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidRequestTarget);
    }

    #[test]
    fn validate_rejects_connect_missing_authority() {
        let req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::CONNECT)
            .uri("/not-authority-form")
            .header(HOST, "example.com:443")
            .body(())
            .expect("request");
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::MissingConnectAuthority);
    }

    #[test]
    fn validate_rejects_connect_absolute_form() {
        let req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::CONNECT)
            .uri("http://example.com:443/")
            .header(HOST, "example.com:443")
            .body(())
            .expect("request");
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidConnectTarget);
    }
}
