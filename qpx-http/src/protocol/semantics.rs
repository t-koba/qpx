use http::header::{CONNECTION, CONTENT_LENGTH, EXPECT, HOST, TRAILER, TRANSFER_ENCODING, VIA};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use std::cell::RefCell;
use std::fmt;

static WELL_KNOWN_HOP_HEADERS: [HeaderName; 8] = [
    HeaderName::from_static("proxy-connection"),
    HeaderName::from_static("proxy-authorization"),
    HeaderName::from_static("proxy-authenticate"),
    HeaderName::from_static("proxy-authentication-info"),
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("te"),
    HeaderName::from_static("trailer"),
    HeaderName::from_static("transfer-encoding"),
];

pub fn validate_http_status_class(status: StatusCode, context: &str) -> anyhow::Result<StatusCode> {
    let code = status.as_u16();
    if !(100..=599).contains(&code) {
        return Err(anyhow::anyhow!("{context} status is out of range: {code}"));
    }
    Ok(status)
}

pub fn sanitize_hop_by_hop_headers(headers: &mut HeaderMap, preserve_upgrade: bool) {
    if !headers.keys().any(is_hop_by_hop_header) {
        return;
    }
    let mut keep_upgrade = false;
    let mut extension_headers = Vec::new();

    for value in headers.get_all(CONNECTION) {
        if let Ok(value) = value.to_str() {
            for token in value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
            {
                if token.eq_ignore_ascii_case("upgrade") {
                    keep_upgrade |= preserve_upgrade;
                } else if !WELL_KNOWN_HOP_HEADERS
                    .iter()
                    .any(|known| token.eq_ignore_ascii_case(known.as_str()))
                    && let Ok(name) = HeaderName::from_bytes(token.as_bytes())
                {
                    extension_headers.push(name);
                }
            }
        }
    }

    for name in extension_headers {
        headers.remove(name);
    }

    for header in &WELL_KNOWN_HOP_HEADERS {
        headers.remove(header);
    }

    if preserve_upgrade && keep_upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(CONNECTION);
        headers.remove("upgrade");
    }
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authentication-info"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

pub fn append_via_for_version(headers: &mut HeaderMap, version: Version, proxy_name: &str) {
    if let Some(value) = via_header_value(version, proxy_name) {
        headers.append(VIA, value);
    }
}

pub fn via_header_value(version: Version, proxy_name: &str) -> Option<HeaderValue> {
    CACHED_VIA_VALUES.with_borrow_mut(|cached| {
        if let Some(index) = cached
            .iter()
            .position(|entry| entry.version == version && entry.proxy_name == proxy_name)
        {
            let value = cached[index].value.clone();
            let last = cached.len() - 1;
            if index != last {
                cached.swap(index, last);
            }
            return Some(value);
        }
        let value =
            HeaderValue::from_str(&format!("{} {}", via_version_token(version), proxy_name))
                .ok()?;
        if cached.len() == MAX_CACHED_VIA_VALUES {
            cached.remove(0);
        }
        cached.push(CachedViaValue {
            version,
            proxy_name: proxy_name.to_string(),
            value: value.clone(),
        });
        Some(value)
    })
}

const MAX_CACHED_VIA_VALUES: usize = 16;

struct CachedViaValue {
    version: Version,
    proxy_name: String,
    value: HeaderValue,
}

thread_local! {
    static CACHED_VIA_VALUES: RefCell<Vec<CachedViaValue>> = const {
        RefCell::new(Vec::new())
    };
}

pub fn sync_host_header_from_absolute_target(headers: &mut HeaderMap, target: &http::Uri) {
    if let Some(authority) = target.authority()
        && let Ok(value) = HeaderValue::from_str(authority.as_str())
    {
        headers.insert(HOST, value);
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIncomingRequest {
    authority: Option<http::uri::Authority>,
}

impl ValidatedIncomingRequest {
    pub fn authority(&self) -> Option<&http::uri::Authority> {
        self.authority.as_ref()
    }

    pub fn into_authority(self) -> Option<http::uri::Authority> {
        self.authority
    }
}

pub fn validate_incoming_request<B>(req: &http::Request<B>) -> Result<(), RequestValidationError> {
    validate_incoming_request_with_metadata(req).map(|_| ())
}

/// Returns true when an ordinary HTTP/2 retrieval request is valid without
/// parsing any field values or rebuilding its already parsed URI authority.
///
/// This is deliberately a sufficient, not exhaustive, predicate. Requests
/// outside this narrow shape must use [`validate_incoming_request_with_metadata`].
#[inline]
pub fn is_intrinsically_valid_common_h2_request<B>(req: &http::Request<B>) -> bool {
    if req.version() != Version::HTTP_2 || !matches!(*req.method(), Method::GET | Method::HEAD) {
        return false;
    }
    if req.headers().keys().any(|name| {
        matches!(
            name.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "expect"
                | "connection"
                | "proxy-connection"
                | "keep-alive"
                | "upgrade"
                | "te"
        )
    }) {
        return false;
    }
    let Some(authority) = req.uri().authority() else {
        return false;
    };
    req.uri().scheme().is_some()
        && !authority.host().is_empty()
        && !authority.as_str().contains('@')
        && req.uri().path().starts_with('/')
}

pub fn validate_incoming_request_with_metadata<B>(
    req: &http::Request<B>,
) -> Result<ValidatedIncomingRequest, RequestValidationError> {
    validate_request_body_length_headers(req.headers())?;
    validate_expect_header(req.headers())?;
    validate_h2_h3_request_headers(req.version(), req.headers())?;
    let is_h2_extended_connect = req.version() == Version::HTTP_2
        && req.method() == Method::CONNECT
        && req.extensions().get::<h2::ext::Protocol>().is_some();

    let mut host_values = req.headers().get_all(HOST).iter();
    let host_value = host_values.next();
    if host_values.next().is_some() {
        return Err(RequestValidationError::MultipleHostHeaders);
    }
    let host = if let Some(value) = host_value {
        let raw = value
            .to_str()
            .map_err(|_| RequestValidationError::InvalidHostHeader)?
            .trim();
        if raw.is_empty() {
            return Err(RequestValidationError::EmptyHostHeader);
        }
        Some(parse_authority_parts(raw).ok_or(RequestValidationError::InvalidHostHeader)?)
    } else {
        None
    };

    let uri_authority = req.uri().authority();
    let mut parsed_uri_authority = None;
    if req.method() == Method::CONNECT {
        let Some(authority) = uri_authority else {
            return Err(RequestValidationError::MissingConnectAuthority);
        };
        let connect_authority = authority_parts_from_uri(authority)
            .ok_or(RequestValidationError::InvalidConnectTarget)?;
        let valid_connect_target = if is_h2_extended_connect {
            req.uri().scheme().is_some() && req.uri().path_and_query().is_some()
        } else {
            connect_authority.port.is_some()
                && req.uri().scheme().is_none()
                && req.uri().path_and_query().is_none()
        };
        if !valid_connect_target {
            return Err(RequestValidationError::InvalidConnectTarget);
        }
        parsed_uri_authority = Some(connect_authority);
    } else {
        if req.uri().scheme().is_none() && uri_authority.is_some() {
            return Err(RequestValidationError::InvalidRequestTarget);
        }
        if let Some(authority) = uri_authority {
            parsed_uri_authority = Some(
                authority_parts_from_uri(authority)
                    .ok_or(RequestValidationError::InvalidRequestTarget)?,
            );
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

    if let (Some(host), Some(authority)) = (host.as_ref(), parsed_uri_authority.as_ref())
        && !authority_parts_equivalent(host, authority, req.uri().scheme_str())
    {
        return Err(RequestValidationError::HostAuthorityMismatch);
    }

    Ok(ValidatedIncomingRequest {
        authority: parsed_uri_authority.or(host).map(|parts| parts.authority),
    })
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

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
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
    normalize_response_for_request_with_options(request_method, response, false)
}

pub fn normalize_response_for_request_with_options<B>(
    request_method: &Method,
    response: &mut http::Response<B>,
    allow_switching_protocols: bool,
) -> bool
where
    B: Default,
{
    let status = response.status();
    if status.is_informational()
        && !(allow_switching_protocols && status == StatusCode::SWITCHING_PROTOCOLS)
    {
        *response.status_mut() = StatusCode::BAD_GATEWAY;
        *response.body_mut() = B::default();
        strip_message_body_headers(response.headers_mut());
        return true;
    }
    let no_body = request_method == Method::HEAD
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

pub fn sanitize_interim_response_headers(headers: &mut HeaderMap) {
    sanitize_hop_by_hop_headers(headers, false);
    strip_message_body_headers(headers);
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

fn authority_parts_equivalent(
    host: &AuthorityParts,
    auth: &AuthorityParts,
    scheme: Option<&str>,
) -> bool {
    if !host.host().eq_ignore_ascii_case(auth.host()) {
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
    authority: http::uri::Authority,
    port: Option<u16>,
}

impl AuthorityParts {
    fn host(&self) -> &str {
        self.authority.host()
    }
}

fn parse_authority_parts(input: &str) -> Option<AuthorityParts> {
    let input = input.trim();
    if input.is_empty() || input.contains('@') {
        return None;
    }
    let authority = input.parse::<http::uri::Authority>().ok()?;
    if authority.host().is_empty() {
        return None;
    }
    let port = authority.port_u16();
    Some(AuthorityParts { authority, port })
}

fn authority_parts_from_uri(authority: &http::uri::Authority) -> Option<AuthorityParts> {
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return None;
    }
    Some(AuthorityParts {
        authority: authority.clone(),
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

pub fn validate_expect_header(headers: &HeaderMap) -> Result<(), RequestValidationError> {
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
mod tests;
