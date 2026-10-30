//! Compiled Cross-Origin Resource Sharing policy and request semantics.

use crate::config::CorsConfig;
use crate::http_message::OrdinaryHeaderMut;
use crate::http_message::{Headers, OrdinaryHeaderName};
#[cfg(test)]
use http::HeaderMap;
use http::Method;
use http::header::{HeaderName, HeaderValue, ORIGIN, VARY};
use std::collections::HashSet;
use thiserror::Error;
use url::Url;

const ALLOW_ORIGIN: &str = "access-control-allow-origin";
const ALLOW_CREDENTIALS: &str = "access-control-allow-credentials";
const ALLOW_METHODS: &str = "access-control-allow-methods";
const ALLOW_HEADERS: &str = "access-control-allow-headers";
const EXPOSE_HEADERS: &str = "access-control-expose-headers";
const MAX_AGE: &str = "access-control-max-age";
const REQUEST_METHOD: &str = "access-control-request-method";
const REQUEST_HEADERS: &str = "access-control-request-headers";
const REQUEST_PRIVATE_NETWORK: &str = "access-control-request-private-network";
const ALLOW_PRIVATE_NETWORK: &str = "access-control-allow-private-network";

const ALLOW_METHODS_NAME: OrdinaryHeaderName = OrdinaryHeaderName::from_static(ALLOW_METHODS);
const ALLOW_HEADERS_NAME: OrdinaryHeaderName = OrdinaryHeaderName::from_static(ALLOW_HEADERS);
const MAX_AGE_NAME: OrdinaryHeaderName = OrdinaryHeaderName::from_static(MAX_AGE);
const ALLOW_PRIVATE_NETWORK_NAME: OrdinaryHeaderName =
    OrdinaryHeaderName::from_static(ALLOW_PRIVATE_NETWORK);

/// A validated, allocation-free-on-application CORS policy.
#[derive(Debug, Clone)]
pub struct CorsPolicy {
    origins: AllowedOrigins,
    methods: AllowedMethods,
    headers: AllowedHeaders,
    expose_headers: Option<HeaderValue>,
    allow_credentials: bool,
    max_age: Option<HeaderValue>,
    allow_private_network: bool,
}

#[derive(Debug, Clone)]
enum AllowedOrigins {
    Any,
    Exact(HashSet<String>),
}

#[derive(Debug, Clone)]
enum AllowedMethods {
    Any,
    Exact {
        values: HashSet<Method>,
        response: HeaderValue,
    },
}

#[derive(Debug, Clone)]
enum AllowedHeaders {
    Any,
    Exact {
        values: HashSet<HeaderName>,
        response: Option<HeaderValue>,
    },
}

/// Parsed CORS facts from one incoming request.
#[derive(Debug, Clone)]
pub struct CorsRequest {
    method: Method,
    origin: String,
    origin_header: HeaderValue,
    preflight: Option<CorsPreflight>,
}

/// Parsed CORS preflight facts.
#[derive(Debug, Clone)]
pub struct CorsPreflight {
    method: Method,
    headers: Vec<HeaderName>,
    private_network: bool,
}

/// Invalid CORS policy configuration.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CorsConfigError {
    /// No origin was configured.
    #[error("cors.allowed_origins must not be empty")]
    EmptyOrigins,
    /// No method was configured.
    #[error("cors.allowed_methods must not be empty")]
    EmptyMethods,
    /// A wildcard was combined with concrete values.
    #[error("{field} wildcard must be the only entry")]
    MixedWildcard {
        /// Configuration field containing the wildcard.
        field: &'static str,
    },
    /// A wildcard was used with credentialed sharing.
    #[error("{field} wildcard is not allowed when cors.allow_credentials is true")]
    CredentialedWildcard {
        /// Configuration field containing the wildcard.
        field: &'static str,
    },
    /// An origin is not a canonical HTTP(S) serialized origin.
    #[error("invalid or non-canonical CORS origin: {0}")]
    InvalidOrigin(String),
    /// The same origin appears more than once.
    #[error("duplicate CORS origin: {0}")]
    DuplicateOrigin(String),
    /// A method is invalid or forbidden by Fetch.
    #[error("invalid or forbidden CORS method: {0}")]
    InvalidMethod(String),
    /// The same method appears more than once.
    #[error("duplicate CORS method: {0}")]
    DuplicateMethod(String),
    /// A header name is invalid.
    #[error("invalid CORS header name in {field}: {value}")]
    InvalidHeader {
        /// Configuration field containing the value.
        field: &'static str,
        /// Invalid header name.
        value: String,
    },
    /// The same header name appears more than once.
    #[error("duplicate CORS header name in {field}: {value}")]
    DuplicateHeader {
        /// Configuration field containing the value.
        field: &'static str,
        /// Duplicate header name.
        value: String,
    },
    /// A forbidden response field was configured for exposure.
    #[error("CORS response header cannot be exposed: {0}")]
    ForbiddenExposeHeader(String),
    /// A generated field value is not representable by `http`.
    #[error("CORS response field value is invalid")]
    InvalidResponseValue,
}

/// Malformed CORS request fields.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CorsRequestError {
    /// A singleton field occurred more than once.
    #[error("duplicate CORS request field: {0}")]
    DuplicateField(&'static str),
    /// Origin was not a canonical serialized origin.
    #[error("invalid Origin field")]
    InvalidOrigin,
    /// The requested method was invalid or forbidden.
    #[error("invalid Access-Control-Request-Method field")]
    InvalidMethod,
    /// A requested header name was invalid.
    #[error("invalid Access-Control-Request-Headers field")]
    InvalidHeaders,
    /// The private-network request flag was malformed.
    #[error("invalid Access-Control-Request-Private-Network field")]
    InvalidPrivateNetwork,
}

/// A well-formed preflight request denied by policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CorsRejection {
    /// The request origin is outside the allowlist.
    #[error("CORS origin is not allowed")]
    Origin,
    /// The requested method is outside the allowlist.
    #[error("CORS method is not allowed")]
    Method,
    /// At least one requested header is outside the allowlist.
    #[error("CORS request header is not allowed")]
    Header,
    /// Private Network Access was requested but not allowed.
    #[error("CORS private-network access is not allowed")]
    PrivateNetwork,
    /// The request was not a preflight request.
    #[error("request is not a CORS preflight")]
    NotPreflight,
}

impl CorsPolicy {
    /// Compiles and validates a CORS configuration.
    pub fn compile(config: &CorsConfig) -> Result<Self, CorsConfigError> {
        let origins = compile_origins(config)?;
        let methods = compile_methods(config)?;
        let headers = compile_headers(config)?;
        let expose_headers = compile_expose_headers(config)?;
        let max_age = config
            .max_age_seconds
            .map(|value| HeaderValue::from_str(value.to_string().as_str()))
            .transpose()
            .map_err(|_| CorsConfigError::InvalidResponseValue)?;
        Ok(Self {
            origins,
            methods,
            headers,
            expose_headers,
            allow_credentials: config.allow_credentials,
            max_age,
            allow_private_network: config.allow_private_network,
        })
    }

    /// Applies configured CORS semantics to a non-preflight response.
    ///
    /// Existing upstream CORS fields are removed first so the configured route
    /// policy remains authoritative even for denied or malformed origins.
    pub fn apply_actual_response(
        &self,
        request: Option<&CorsRequest>,
        response_headers: &mut impl OrdinaryHeaderMut,
    ) {
        remove_cors_response_fields(response_headers);
        if !request.is_some_and(|request| request.is_preflight()) {
            // The ACAO output for actual responses depends on the request
            // Origin (exact echo, `*` versus absent, or nothing when
            // denied), so every variant through a configured policy must
            // key downstream caches on Origin - including absent and
            // denied variants that carry no ACAO at all. Preflights keep
            // their own response contract below.
            append_vary(response_headers, "Origin");
        }
        let Some(request) = request.filter(|request| !request.is_preflight()) else {
            return;
        };
        if !self.origin_allowed(request.origin()) || !self.method_allowed(request.method()) {
            return;
        }
        self.apply_origin_and_credentials(request, response_headers);
        if let Some(expose_headers) = self.expose_headers.as_ref()
            && let Ok(name) = OrdinaryHeaderName::try_from(EXPOSE_HEADERS)
        {
            response_headers.ordinary_insert(name, expose_headers.clone());
        }
    }

    /// Validates a preflight and applies the complete preflight response fields.
    pub fn apply_preflight_response(
        &self,
        request: &CorsRequest,
        response_headers: &mut impl OrdinaryHeaderMut,
    ) -> Result<(), CorsRejection> {
        remove_cors_response_fields(response_headers);
        let preflight = request.preflight().ok_or(CorsRejection::NotPreflight)?;
        if !self.origin_allowed(request.origin()) {
            return Err(CorsRejection::Origin);
        }
        if !self.method_allowed(preflight.method()) {
            return Err(CorsRejection::Method);
        }
        if !self.headers_allowed(preflight.headers()) {
            return Err(CorsRejection::Header);
        }
        if preflight.private_network() && !self.allow_private_network {
            return Err(CorsRejection::PrivateNetwork);
        }

        self.apply_origin_and_credentials(request, response_headers);
        response_headers.ordinary_insert(ALLOW_METHODS_NAME, self.methods.response_value());
        if !preflight.headers().is_empty()
            && let Some(value) = self.headers.response_value()
        {
            response_headers.ordinary_insert(ALLOW_HEADERS_NAME, value);
        }
        if let Some(max_age) = self.max_age.as_ref() {
            response_headers.ordinary_insert(MAX_AGE_NAME, max_age.clone());
        }
        if preflight.private_network() {
            response_headers
                .ordinary_insert(ALLOW_PRIVATE_NETWORK_NAME, HeaderValue::from_static("true"));
        }
        append_vary(response_headers, REQUEST_METHOD);
        append_vary(response_headers, REQUEST_HEADERS);
        append_vary(response_headers, REQUEST_PRIVATE_NETWORK);
        Ok(())
    }

    fn apply_origin_and_credentials(
        &self,
        request: &CorsRequest,
        response_headers: &mut impl OrdinaryHeaderMut,
    ) {
        match &self.origins {
            AllowedOrigins::Any => {
                if let Ok(name) = OrdinaryHeaderName::try_from(ALLOW_ORIGIN) {
                    response_headers.ordinary_insert(name, HeaderValue::from_static("*"));
                }
            }
            AllowedOrigins::Exact(_) => {
                if let Ok(name) = OrdinaryHeaderName::try_from(ALLOW_ORIGIN) {
                    response_headers.ordinary_insert(name, request.origin_header().clone());
                }
                append_vary(response_headers, "Origin");
            }
        }
        if self.allow_credentials
            && let Ok(name) = OrdinaryHeaderName::try_from(ALLOW_CREDENTIALS)
        {
            response_headers.ordinary_insert(name, HeaderValue::from_static("true"));
        }
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        match &self.origins {
            AllowedOrigins::Any => true,
            AllowedOrigins::Exact(origins) => origins.contains(origin),
        }
    }

    fn method_allowed(&self, method: &Method) -> bool {
        match &self.methods {
            AllowedMethods::Any => !is_forbidden_method(method.as_str()),
            AllowedMethods::Exact { values, .. } => values.contains(method),
        }
    }

    fn headers_allowed(&self, requested: &[HeaderName]) -> bool {
        match &self.headers {
            AllowedHeaders::Any => requested
                .iter()
                .all(|name| name != http::header::AUTHORIZATION),
            AllowedHeaders::Exact { values, .. } => {
                requested.iter().all(|name| values.contains(name))
            }
        }
    }
}

impl AllowedMethods {
    fn response_value(&self) -> HeaderValue {
        match self {
            Self::Any => HeaderValue::from_static("*"),
            Self::Exact { response, .. } => response.clone(),
        }
    }
}

impl AllowedHeaders {
    fn response_value(&self) -> Option<HeaderValue> {
        match self {
            Self::Any => Some(HeaderValue::from_static("*")),
            Self::Exact { response, .. } => response.clone(),
        }
    }
}

impl CorsRequest {
    /// Parses CORS request fields. `Ok(None)` means no `Origin` field exists.
    pub fn parse(method: &Method, headers: &Headers) -> Result<Option<Self>, CorsRequestError> {
        let Some(origin) = single_header(headers, ORIGIN.as_str())? else {
            return Ok(None);
        };
        let origin = origin
            .to_str()
            .map_err(|_| CorsRequestError::InvalidOrigin)?;
        let canonical = canonical_origin(origin).ok_or(CorsRequestError::InvalidOrigin)?;
        if canonical != origin {
            return Err(CorsRequestError::InvalidOrigin);
        }
        let origin_header = HeaderValue::from_str(canonical.as_str())
            .map_err(|_| CorsRequestError::InvalidOrigin)?;

        let preflight = if method == Method::OPTIONS {
            match single_header(headers, REQUEST_METHOD)? {
                Some(requested_method) => {
                    let raw = requested_method
                        .to_str()
                        .map_err(|_| CorsRequestError::InvalidMethod)?;
                    let requested_method = Method::from_bytes(raw.as_bytes())
                        .map_err(|_| CorsRequestError::InvalidMethod)?;
                    if is_forbidden_method(requested_method.as_str()) {
                        return Err(CorsRequestError::InvalidMethod);
                    }
                    let requested_headers = parse_request_headers(headers)?;
                    let private_network = parse_private_network(headers)?;
                    Some(CorsPreflight {
                        method: requested_method,
                        headers: requested_headers,
                        private_network,
                    })
                }
                None => None,
            }
        } else {
            None
        };

        Ok(Some(Self {
            method: method.clone(),
            origin: canonical,
            origin_header,
            preflight,
        }))
    }

    /// Returns the actual request method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the canonical serialized request origin.
    pub fn origin(&self) -> &str {
        self.origin.as_str()
    }

    /// Returns the canonical Origin field value.
    pub fn origin_header(&self) -> &HeaderValue {
        &self.origin_header
    }

    /// Returns whether the request is a CORS preflight.
    pub fn is_preflight(&self) -> bool {
        self.preflight.is_some()
    }

    /// Returns parsed preflight facts when present.
    pub fn preflight(&self) -> Option<&CorsPreflight> {
        self.preflight.as_ref()
    }
}

impl CorsPreflight {
    /// Returns the method requested by the preflight.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns lower-cased requested field names.
    pub fn headers(&self) -> &[HeaderName] {
        self.headers.as_slice()
    }

    /// Returns whether Private Network Access was requested.
    pub fn private_network(&self) -> bool {
        self.private_network
    }
}

fn compile_origins(config: &CorsConfig) -> Result<AllowedOrigins, CorsConfigError> {
    if config.allowed_origins.is_empty() {
        return Err(CorsConfigError::EmptyOrigins);
    }
    if config.allowed_origins.iter().any(|value| value == "*") {
        require_standalone_wildcard(&config.allowed_origins, "cors.allowed_origins")?;
        reject_credentialed_wildcard(config, "cors.allowed_origins")?;
        return Ok(AllowedOrigins::Any);
    }
    let mut origins = HashSet::with_capacity(config.allowed_origins.len());
    for raw in &config.allowed_origins {
        let canonical = canonical_origin(raw)
            .filter(|canonical| canonical == raw)
            .ok_or_else(|| CorsConfigError::InvalidOrigin(raw.clone()))?;
        if !origins.insert(canonical) {
            return Err(CorsConfigError::DuplicateOrigin(raw.clone()));
        }
    }
    Ok(AllowedOrigins::Exact(origins))
}

fn compile_methods(config: &CorsConfig) -> Result<AllowedMethods, CorsConfigError> {
    if config.allowed_methods.is_empty() {
        return Err(CorsConfigError::EmptyMethods);
    }
    if config.allowed_methods.iter().any(|value| value == "*") {
        require_standalone_wildcard(&config.allowed_methods, "cors.allowed_methods")?;
        reject_credentialed_wildcard(config, "cors.allowed_methods")?;
        return Ok(AllowedMethods::Any);
    }
    let mut values = HashSet::with_capacity(config.allowed_methods.len());
    let mut serialized = Vec::with_capacity(config.allowed_methods.len());
    for raw in &config.allowed_methods {
        let method = Method::from_bytes(raw.as_bytes())
            .ok()
            .filter(|method| !is_forbidden_method(method.as_str()))
            .ok_or_else(|| CorsConfigError::InvalidMethod(raw.clone()))?;
        if !values.insert(method.clone()) {
            return Err(CorsConfigError::DuplicateMethod(raw.clone()));
        }
        serialized.push(method.as_str().to_owned());
    }
    let response = HeaderValue::from_str(serialized.join(", ").as_str())
        .map_err(|_| CorsConfigError::InvalidResponseValue)?;
    Ok(AllowedMethods::Exact { values, response })
}

fn compile_headers(config: &CorsConfig) -> Result<AllowedHeaders, CorsConfigError> {
    if config.allowed_headers.iter().any(|value| value == "*") {
        require_standalone_wildcard(&config.allowed_headers, "cors.allowed_headers")?;
        reject_credentialed_wildcard(config, "cors.allowed_headers")?;
        return Ok(AllowedHeaders::Any);
    }
    let (values, response) =
        compile_header_names(config.allowed_headers.as_slice(), "cors.allowed_headers")?;
    Ok(AllowedHeaders::Exact { values, response })
}

fn compile_expose_headers(config: &CorsConfig) -> Result<Option<HeaderValue>, CorsConfigError> {
    if config.expose_headers.iter().any(|value| value == "*") {
        require_standalone_wildcard(&config.expose_headers, "cors.expose_headers")?;
        reject_credentialed_wildcard(config, "cors.expose_headers")?;
        return Ok(Some(HeaderValue::from_static("*")));
    }
    let (names, response) =
        compile_header_names(config.expose_headers.as_slice(), "cors.expose_headers")?;
    if let Some(name) = names
        .iter()
        .find(|name| matches!(name.as_str(), "set-cookie" | "set-cookie2"))
    {
        return Err(CorsConfigError::ForbiddenExposeHeader(
            name.as_str().to_owned(),
        ));
    }
    Ok(response)
}

fn compile_header_names(
    raw: &[String],
    field: &'static str,
) -> Result<(HashSet<HeaderName>, Option<HeaderValue>), CorsConfigError> {
    let mut names = HashSet::with_capacity(raw.len());
    let mut serialized = Vec::with_capacity(raw.len());
    for value in raw {
        let name = HeaderName::from_bytes(value.as_bytes()).map_err(|_| {
            CorsConfigError::InvalidHeader {
                field,
                value: value.clone(),
            }
        })?;
        if !names.insert(name.clone()) {
            return Err(CorsConfigError::DuplicateHeader {
                field,
                value: value.clone(),
            });
        }
        serialized.push(name.as_str().to_owned());
    }
    let response = (!serialized.is_empty())
        .then(|| HeaderValue::from_str(serialized.join(", ").as_str()))
        .transpose()
        .map_err(|_| CorsConfigError::InvalidResponseValue)?;
    Ok((names, response))
}

fn require_standalone_wildcard(
    values: &[String],
    field: &'static str,
) -> Result<(), CorsConfigError> {
    if values.len() == 1 && values[0] == "*" {
        return Ok(());
    }
    Err(CorsConfigError::MixedWildcard { field })
}

fn reject_credentialed_wildcard(
    config: &CorsConfig,
    field: &'static str,
) -> Result<(), CorsConfigError> {
    if config.allow_credentials {
        return Err(CorsConfigError::CredentialedWildcard { field });
    }
    Ok(())
}

fn canonical_origin(raw: &str) -> Option<String> {
    if raw == "null" {
        return Some(raw.to_owned());
    }
    let url = Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }
    let serialized = url.origin().ascii_serialization();
    (serialized != "null").then_some(serialized)
}

fn is_forbidden_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("CONNECT")
        || method.eq_ignore_ascii_case("TRACE")
        || method.eq_ignore_ascii_case("TRACK")
}

fn single_header<'a>(
    headers: &'a Headers,
    name: &'static str,
) -> Result<Option<&'a HeaderValue>, CorsRequestError> {
    let ordinary =
        OrdinaryHeaderName::try_from(name).map_err(|_| CorsRequestError::InvalidHeaders)?;
    let mut values = headers.get_all(&ordinary);
    let first = values.next();
    if values.next().is_some() {
        return Err(CorsRequestError::DuplicateField(name));
    }
    Ok(first)
}

fn parse_request_headers(headers: &Headers) -> Result<Vec<HeaderName>, CorsRequestError> {
    let mut parsed = Vec::new();
    let mut seen = HashSet::new();
    let ordinary = OrdinaryHeaderName::try_from(REQUEST_HEADERS)
        .map_err(|_| CorsRequestError::InvalidHeaders)?;
    for value in headers.get_all(&ordinary) {
        let value = value
            .to_str()
            .map_err(|_| CorsRequestError::InvalidHeaders)?;
        for raw in value.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                return Err(CorsRequestError::InvalidHeaders);
            }
            let name = HeaderName::from_bytes(raw.as_bytes())
                .map_err(|_| CorsRequestError::InvalidHeaders)?;
            if seen.insert(name.clone()) {
                parsed.push(name);
            }
        }
    }
    Ok(parsed)
}

fn parse_private_network(headers: &Headers) -> Result<bool, CorsRequestError> {
    let Some(value) = single_header(headers, REQUEST_PRIVATE_NETWORK)? else {
        return Ok(false);
    };
    if value.as_bytes() != b"true" {
        return Err(CorsRequestError::InvalidPrivateNetwork);
    }
    Ok(true)
}

fn remove_cors_response_fields(headers: &mut impl OrdinaryHeaderMut) {
    for name in [
        ALLOW_ORIGIN,
        ALLOW_CREDENTIALS,
        ALLOW_METHODS,
        ALLOW_HEADERS,
        EXPOSE_HEADERS,
        MAX_AGE,
        ALLOW_PRIVATE_NETWORK,
    ] {
        if let Ok(name) = OrdinaryHeaderName::try_from(name) {
            headers.ordinary_remove(&name);
        }
    }
}

fn append_vary(headers: &mut impl OrdinaryHeaderMut, token: &'static str) {
    // The wildcard member forbids reuse without revalidation, so it counts as
    // present as well as the token itself.
    let Ok(vary) = OrdinaryHeaderName::try_from(VARY) else {
        return;
    };
    let present = crate::http_token::value_members(headers.ordinary_values(&vary))
        .any(|member| member.eq_ignore_ascii_case(token) || member == "*");
    if !present {
        headers.ordinary_append(vary, HeaderValue::from_static(token));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CorsConfig {
        CorsConfig {
            allowed_origins: vec!["https://app.example".to_owned()],
            allowed_methods: vec!["GET".to_owned(), "PUT".to_owned()],
            allowed_headers: vec!["content-type".to_owned(), "x-request-id".to_owned()],
            expose_headers: vec!["etag".to_owned()],
            allow_credentials: true,
            max_age_seconds: Some(600),
            allow_private_network: true,
        }
    }

    #[test]
    fn compile_rejects_noncanonical_and_credentialed_wildcard_origins() {
        let mut invalid = config();
        invalid.allowed_origins = vec!["https://APP.example/".to_owned()];
        assert!(matches!(
            CorsPolicy::compile(&invalid),
            Err(CorsConfigError::InvalidOrigin(_))
        ));

        invalid.allowed_origins = vec!["*".to_owned()];
        assert!(matches!(
            CorsPolicy::compile(&invalid),
            Err(CorsConfigError::CredentialedWildcard { .. })
        ));

        invalid.allowed_origins = vec!["https://app.example".to_owned()];
        invalid.expose_headers = vec!["set-cookie".to_owned()];
        assert!(matches!(
            CorsPolicy::compile(&invalid),
            Err(CorsConfigError::ForbiddenExposeHeader(value)) if value == "set-cookie"
        ));
    }

    #[test]
    fn preflight_validates_and_emits_fetch_fields() {
        let policy = CorsPolicy::compile(&config()).expect("policy");
        let mut request_headers = Headers::new();
        request_headers.insert(
            OrdinaryHeaderName::try_from(ORIGIN).expect("ordinary"),
            HeaderValue::from_static("https://app.example"),
        );
        request_headers.insert(
            OrdinaryHeaderName::try_from(REQUEST_METHOD).expect("ordinary"),
            HeaderValue::from_static("PUT"),
        );
        request_headers.insert(
            OrdinaryHeaderName::try_from(REQUEST_HEADERS).expect("ordinary"),
            HeaderValue::from_static("Content-Type, X-Request-Id"),
        );
        request_headers.insert(
            OrdinaryHeaderName::try_from(REQUEST_PRIVATE_NETWORK).expect("ordinary"),
            HeaderValue::from_static("true"),
        );
        let request = CorsRequest::parse(&Method::OPTIONS, &request_headers)
            .expect("valid request")
            .expect("CORS request");
        let mut response = HeaderMap::new();
        policy
            .apply_preflight_response(&request, &mut response)
            .expect("allowed");
        assert_eq!(response[ALLOW_ORIGIN], "https://app.example");
        assert_eq!(response[ALLOW_CREDENTIALS], "true");
        assert_eq!(response[ALLOW_METHODS], "GET, PUT");
        assert_eq!(response[ALLOW_HEADERS], "content-type, x-request-id");
        assert_eq!(response[MAX_AGE], "600");
        assert_eq!(response[ALLOW_PRIVATE_NETWORK], "true");
        assert!(response.get_all(VARY).iter().any(|value| value == "Origin"));
    }

    #[test]
    fn actual_response_is_authoritative_and_origin_specific() {
        let policy = CorsPolicy::compile(&config()).expect("policy");
        let mut request_headers = Headers::new();
        request_headers.insert(
            OrdinaryHeaderName::try_from(ORIGIN).expect("ordinary"),
            HeaderValue::from_static("https://app.example"),
        );
        let request = CorsRequest::parse(&Method::GET, &request_headers)
            .expect("valid request")
            .expect("CORS request");
        let mut response = HeaderMap::new();
        response.insert(
            ALLOW_ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        policy.apply_actual_response(Some(&request), &mut response);
        assert_eq!(response[ALLOW_ORIGIN], "https://app.example");
        assert_eq!(response[ALLOW_CREDENTIALS], "true");
        assert_eq!(response[EXPOSE_HEADERS], "etag");
    }

    #[test]
    fn wildcard_headers_do_not_authorize_authorization() {
        let mut wildcard = config();
        wildcard.allow_credentials = false;
        wildcard.allowed_headers = vec!["*".to_owned()];
        let policy = CorsPolicy::compile(&wildcard).expect("policy");
        let mut request_headers = Headers::new();
        request_headers.insert(
            OrdinaryHeaderName::try_from(ORIGIN).expect("ordinary"),
            HeaderValue::from_static("https://app.example"),
        );
        request_headers.insert(
            OrdinaryHeaderName::try_from(REQUEST_METHOD).expect("ordinary"),
            HeaderValue::from_static("PUT"),
        );
        request_headers.insert(
            OrdinaryHeaderName::try_from(REQUEST_HEADERS).expect("ordinary"),
            HeaderValue::from_static("authorization"),
        );
        let request = CorsRequest::parse(&Method::OPTIONS, &request_headers)
            .expect("valid request")
            .expect("CORS request");
        assert_eq!(
            policy.apply_preflight_response(&request, &mut HeaderMap::new()),
            Err(CorsRejection::Header)
        );
    }
}

#[cfg(test)]
mod actual_vary_tests {
    use super::*;

    fn test_policy() -> CorsPolicy {
        CorsPolicy::compile(&CorsConfig {
            allowed_origins: vec!["https://app.example".to_owned()],
            allowed_methods: vec!["GET".to_owned()],
            allowed_headers: Vec::new(),
            expose_headers: Vec::new(),
            allow_credentials: false,
            max_age_seconds: None,
            allow_private_network: false,
        })
        .expect("policy")
    }

    fn actual_request(origin: &str) -> CorsRequest {
        let mut headers = Headers::new();
        headers.insert(
            OrdinaryHeaderName::try_from(ORIGIN).expect("ordinary"),
            HeaderValue::from_str(origin).expect("origin value"),
        );
        CorsRequest::parse(&Method::GET, &headers)
            .expect("valid request")
            .expect("CORS request")
    }

    fn vary_values(headers: &HeaderMap) -> Vec<String> {
        headers
            .get_all(VARY)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_string))
            .collect()
    }

    #[test]
    fn absent_origin_still_marks_vary_origin() {
        let policy = test_policy();
        let mut response = HeaderMap::new();
        policy.apply_actual_response(None, &mut response);
        assert!(response.get(ALLOW_ORIGIN).is_none());
        assert_eq!(vary_values(&response), vec!["Origin".to_string()]);
    }

    #[test]
    fn denied_origin_still_marks_vary_origin() {
        let policy = test_policy();
        let request = actual_request("https://denied.example");
        let mut response = HeaderMap::new();
        policy.apply_actual_response(Some(&request), &mut response);
        assert!(response.get(ALLOW_ORIGIN).is_none());
        assert_eq!(vary_values(&response), vec!["Origin".to_string()]);
    }

    #[test]
    fn allowed_origin_keeps_single_vary_origin() {
        let policy = test_policy();
        let request = actual_request("https://app.example");
        let mut response = HeaderMap::new();
        policy.apply_actual_response(Some(&request), &mut response);
        assert_eq!(response[ALLOW_ORIGIN], "https://app.example");
        assert_eq!(vary_values(&response), vec!["Origin".to_string()]);
    }

    #[test]
    fn existing_vary_lines_survive_denied_origin() {
        let policy = test_policy();
        let request = actual_request("https://denied.example");
        let mut response = HeaderMap::new();
        response.insert(VARY, HeaderValue::from_static("Accept-Encoding"));
        policy.apply_actual_response(Some(&request), &mut response);
        assert_eq!(
            vary_values(&response),
            vec!["Accept-Encoding".to_string(), "Origin".to_string()]
        );
    }

    #[test]
    fn preflight_request_keeps_own_contract_without_actual_vary() {
        let policy = test_policy();
        let mut request_head = crate::http_message::Request::new(());
        *request_head.method_mut() = Method::OPTIONS;
        request_head.headers_mut().insert(
            OrdinaryHeaderName::try_from(ORIGIN).expect("Origin is ordinary"),
            HeaderValue::from_static("https://app.example"),
        );
        request_head.headers_mut().insert(
            OrdinaryHeaderName::try_from(REQUEST_METHOD).expect("request method is ordinary"),
            HeaderValue::from_static("PUT"),
        );
        let request = CorsRequest::parse(request_head.method(), request_head.headers())
            .expect("valid request")
            .expect("CORS request");
        assert!(request.is_preflight());
        let mut response = HeaderMap::new();
        policy.apply_actual_response(Some(&request), &mut response);
        assert!(response.get(ALLOW_ORIGIN).is_none());
        assert!(vary_values(&response).is_empty());
    }
}
