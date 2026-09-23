//! Typed browser-facing HTTP policy parsing and response application.
//!
//! The web platform defines a number of security policies outside the HTTP
//! core specifications.  Treating those fields as arbitrary strings is
//! unsafe: a typo can silently weaken a policy and duplicate fields can make
//! user-agent processing differ from the operator's intent.  This module
//! therefore parses each policy before it reaches a response and applies the
//! compiled value authoritatively, removing upstream copies first.

use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

const SEC_FETCH_SITE: &str = "sec-fetch-site";
const SEC_FETCH_MODE: &str = "sec-fetch-mode";
const SEC_FETCH_DEST: &str = "sec-fetch-dest";
const SEC_FETCH_USER: &str = "sec-fetch-user";

const CONTENT_SECURITY_POLICY: &str = "content-security-policy";
const CONTENT_SECURITY_POLICY_REPORT_ONLY: &str = "content-security-policy-report-only";
const REFERRER_POLICY: &str = "referrer-policy";
const PERMISSIONS_POLICY: &str = "permissions-policy";
const PERMISSIONS_POLICY_REPORT_ONLY: &str = "permissions-policy-report-only";
const CROSS_ORIGIN_OPENER_POLICY: &str = "cross-origin-opener-policy";
const CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY: &str = "cross-origin-opener-policy-report-only";
const CROSS_ORIGIN_EMBEDDER_POLICY: &str = "cross-origin-embedder-policy";
const CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY: &str = "cross-origin-embedder-policy-report-only";
const CROSS_ORIGIN_RESOURCE_POLICY: &str = "cross-origin-resource-policy";
const X_CONTENT_TYPE_OPTIONS: &str = "x-content-type-options";
const ORIGIN_AGENT_CLUSTER: &str = "origin-agent-cluster";
const CLEAR_SITE_DATA: &str = "clear-site-data";
const REPORTING_ENDPOINTS: &str = "reporting-endpoints";
const TIMING_ALLOW_ORIGIN: &str = "timing-allow-origin";
const ACCEPT_CH: &str = "accept-ch";
const CRITICAL_CH: &str = "critical-ch";

/// A parsing or validation failure in a browser policy.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BrowserPolicyError {
    /// A field value does not satisfy the field's grammar.
    #[error("invalid {field}: {detail}")]
    Invalid {
        /// The HTTP field or policy component.
        field: &'static str,
        /// A concise parser diagnostic.
        detail: String,
    },
    /// A singleton field or directive appeared more than once.
    #[error("duplicate {field}: {value}")]
    Duplicate {
        /// The HTTP field or policy component.
        field: &'static str,
        /// The duplicated value.
        value: String,
    },
    /// Two configured policies cannot be applied coherently.
    #[error("inconsistent browser policy: {detail}")]
    Inconsistent {
        /// A description of the conflicting policies.
        detail: String,
    },
}

type Result<T> = std::result::Result<T, BrowserPolicyError>;

fn invalid(field: &'static str, detail: impl Into<String>) -> BrowserPolicyError {
    BrowserPolicyError::Invalid {
        field,
        detail: detail.into(),
    }
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    let name = HeaderName::from_static(name);
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn remove_header(headers: &mut HeaderMap, name: &'static str) {
    headers.remove(HeaderName::from_static(name));
}

fn append_vary(headers: &mut HeaderMap, field: &'static str) {
    let value = headers
        .get("vary")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    if value.as_deref().is_some_and(|value| {
        value
            .split(',')
            .any(|item| item.trim().eq_ignore_ascii_case(field))
    }) {
        return;
    }
    match value {
        Some(value) if !value.trim().is_empty() => {
            insert_header(headers, "vary", format!("{value}, {field}").as_str());
        }
        _ => insert_header(headers, "vary", field),
    }
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'0'..=b'9'
                    | b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'!'
                    | b'#'
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

fn is_ascii_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'0'..=b'9'
                    | b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'-'
                    | b'_'
                    | b'.'
            )
        })
}

fn is_sf_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == b'*')
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'*' | b'-' | b'.' | b'_')
        })
}

fn is_csp_base64(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut padding = 0;
    let mut payload = 0;
    for byte in value.bytes() {
        if byte == b'=' {
            padding += 1;
            if padding > 2 {
                return false;
            }
        } else {
            if padding != 0 {
                return false;
            }
            payload += 1;
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')) {
                return false;
            }
        }
    }
    payload != 0
}

fn is_csp_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn is_csp_host_source(value: &str) -> bool {
    let (authority, path) = value
        .split_once('/')
        .map_or((value, None), |(authority, path)| (authority, Some(path)));
    if authority.is_empty() || authority.starts_with('[') {
        return false;
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    let host = host.strip_prefix("*.").unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return false;
    }
    if let Some(port) = port
        && port != "*"
        && (port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    path.is_none_or(|path| {
        !path.is_empty()
            && !path.bytes().any(|byte| {
                byte.is_ascii_whitespace() || matches!(byte, b';' | b',' | b'"' | b'\'')
            })
    })
}

fn is_csp_host_expression(value: &str) -> bool {
    if let Some((scheme, authority)) = value.split_once("://") {
        is_csp_scheme(scheme) && is_csp_host_source(authority)
    } else {
        is_csp_host_source(value)
    }
}

fn parse_single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(BrowserPolicyError::Duplicate {
            field: name,
            value: "multiple field lines".to_string(),
        });
    }
    let value = value
        .to_str()
        .map_err(|_| invalid(name, "field value is not visible ASCII"))?
        .trim();
    if value.is_empty() {
        return Err(invalid(name, "field value must not be empty"));
    }
    Ok(Some(value))
}

fn parse_origin(value: &str, field: &'static str) -> Result<String> {
    if value == "null" {
        return Ok(value.to_string());
    }
    let url = Url::parse(value).map_err(|_| invalid(field, "origin is not an absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(field, "origin must be a canonical HTTP(S) origin"));
    }
    Ok(url.origin().ascii_serialization())
}

fn parse_http_url(value: &str, field: &'static str) -> Result<String> {
    let url = Url::parse(value).map_err(|_| invalid(field, "URL is not absolute"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            field,
            "URL must be an absolute HTTP(S) URL without credentials or fragment",
        ));
    }
    Ok(url.to_string())
}

fn parse_reporting_endpoint_url(value: &str) -> Result<String> {
    if value.starts_with('/') && !value.starts_with("//") {
        if value.contains('#')
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'"')
        {
            return Err(invalid(
                REPORTING_ENDPOINTS,
                "relative endpoint URL contains a fragment or control",
            ));
        }
        return Ok(value.to_string());
    }
    parse_http_url(value, REPORTING_ENDPOINTS)
}

fn canonical_set<T: Ord + Clone + fmt::Debug>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<BTreeSet<T>> {
    let mut set = BTreeSet::new();
    for value in values {
        if !set.insert(value.clone()) {
            return Err(BrowserPolicyError::Duplicate {
                field,
                value: format!("{value:?}"),
            });
        }
    }
    Ok(set)
}

/// Fetch Metadata's `Sec-Fetch-Site` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FetchSite {
    /// The request's origin is the same as the target origin.
    SameOrigin,
    /// The request is same-site but cross-origin.
    SameSite,
    /// The request is cross-site.
    CrossSite,
    /// The user agent has no origin context.
    None,
}

impl fmt::Display for FetchSite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SameOrigin => "same-origin",
            Self::SameSite => "same-site",
            Self::CrossSite => "cross-site",
            Self::None => "none",
        })
    }
}

impl FromStr for FetchSite {
    type Err = BrowserPolicyError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "same-origin" => Ok(Self::SameOrigin),
            "same-site" => Ok(Self::SameSite),
            "cross-site" => Ok(Self::CrossSite),
            "none" => Ok(Self::None),
            _ => Err(invalid(SEC_FETCH_SITE, "unknown value")),
        }
    }
}

/// Fetch Metadata's `Sec-Fetch-Mode` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FetchMode {
    /// A top-level navigation request.
    Navigate,
    /// A same-origin fetch.
    SameOrigin,
    /// A CORS-enabled fetch.
    Cors,
    /// A no-CORS fetch.
    NoCors,
    /// A WebSocket handshake.
    WebSocket,
}

impl fmt::Display for FetchMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Navigate => "navigate",
            Self::SameOrigin => "same-origin",
            Self::Cors => "cors",
            Self::NoCors => "no-cors",
            Self::WebSocket => "websocket",
        })
    }
}

impl FromStr for FetchMode {
    type Err = BrowserPolicyError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "navigate" => Ok(Self::Navigate),
            "same-origin" => Ok(Self::SameOrigin),
            "cors" => Ok(Self::Cors),
            "no-cors" => Ok(Self::NoCors),
            "websocket" => Ok(Self::WebSocket),
            _ => Err(invalid(SEC_FETCH_MODE, "unknown value")),
        }
    }
}

/// Fetch Metadata's `Sec-Fetch-Dest` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FetchDestination {
    /// Audio resource.
    Audio,
    /// Audio worklet resource.
    #[serde(rename = "audioworklet")]
    AudioWorklet,
    /// Beacon request.
    Beacon,
    /// Content Security Policy report.
    Csp,
    /// Document resource.
    Document,
    /// Embedded resource.
    Embed,
    /// Empty destination, used by programmatic fetches.
    Empty,
    /// Font resource.
    Font,
    /// Frame resource.
    Frame,
    /// Iframe resource.
    Iframe,
    /// Image resource.
    Image,
    /// JSON resource.
    Json,
    /// Manifest resource.
    Manifest,
    /// Object resource.
    Object,
    /// Paint worklet resource.
    #[serde(rename = "paintworklet")]
    PaintWorklet,
    /// Report upload.
    Report,
    /// Script resource.
    Script,
    /// Service worker resource.
    #[serde(rename = "serviceworker")]
    ServiceWorker,
    /// Shared worker resource.
    #[serde(rename = "sharedworker")]
    SharedWorker,
    /// Style resource.
    Style,
    /// Text resource.
    Text,
    /// Track resource.
    Track,
    /// Video resource.
    Video,
    /// Web Identity resource.
    #[serde(rename = "webidentity")]
    WebIdentity,
    /// Worker resource.
    Worker,
    /// XSLT resource.
    Xslt,
}

impl fmt::Display for FetchDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Audio => "audio",
            Self::AudioWorklet => "audioworklet",
            Self::Beacon => "beacon",
            Self::Csp => "csp",
            Self::Document => "document",
            Self::Embed => "embed",
            Self::Empty => "empty",
            Self::Font => "font",
            Self::Frame => "frame",
            Self::Iframe => "iframe",
            Self::Image => "image",
            Self::Json => "json",
            Self::Manifest => "manifest",
            Self::Object => "object",
            Self::PaintWorklet => "paintworklet",
            Self::Report => "report",
            Self::Script => "script",
            Self::ServiceWorker => "serviceworker",
            Self::SharedWorker => "sharedworker",
            Self::Style => "style",
            Self::Text => "text",
            Self::Track => "track",
            Self::Video => "video",
            Self::WebIdentity => "webidentity",
            Self::Worker => "worker",
            Self::Xslt => "xslt",
        })
    }
}

impl FromStr for FetchDestination {
    type Err = BrowserPolicyError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "audio" => Ok(Self::Audio),
            "audioworklet" => Ok(Self::AudioWorklet),
            "beacon" => Ok(Self::Beacon),
            "csp" => Ok(Self::Csp),
            "document" => Ok(Self::Document),
            "embed" => Ok(Self::Embed),
            "empty" => Ok(Self::Empty),
            "font" => Ok(Self::Font),
            "frame" => Ok(Self::Frame),
            "iframe" => Ok(Self::Iframe),
            "image" => Ok(Self::Image),
            "json" => Ok(Self::Json),
            "manifest" => Ok(Self::Manifest),
            "object" => Ok(Self::Object),
            "paintworklet" => Ok(Self::PaintWorklet),
            "report" => Ok(Self::Report),
            "script" => Ok(Self::Script),
            "serviceworker" => Ok(Self::ServiceWorker),
            "sharedworker" => Ok(Self::SharedWorker),
            "style" => Ok(Self::Style),
            "text" => Ok(Self::Text),
            "track" => Ok(Self::Track),
            "video" => Ok(Self::Video),
            "webidentity" => Ok(Self::WebIdentity),
            "worker" => Ok(Self::Worker),
            "xslt" => Ok(Self::Xslt),
            _ => Err(invalid(SEC_FETCH_DEST, "unknown value")),
        }
    }
}

/// The parsed Fetch Metadata fields from one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchMetadataRequest {
    site: Option<FetchSite>,
    mode: Option<FetchMode>,
    destination: Option<FetchDestination>,
    user_activation: bool,
}

impl FetchMetadataRequest {
    /// Parses all Fetch Metadata fields in `headers` with singleton semantics.
    pub fn parse(headers: &HeaderMap) -> Result<Option<Self>> {
        let site = parse_single_header(headers, SEC_FETCH_SITE)?
            .map(str::parse)
            .transpose()?;
        let mode = parse_single_header(headers, SEC_FETCH_MODE)?
            .map(str::parse)
            .transpose()?;
        let destination = parse_single_header(headers, SEC_FETCH_DEST)?
            .map(str::parse)
            .transpose()?;
        let user_activation = match parse_single_header(headers, SEC_FETCH_USER)? {
            Some("?1") => true,
            Some(_) => return Err(invalid(SEC_FETCH_USER, "only ?1 is valid")),
            None => false,
        };
        if site.is_none() && mode.is_none() && destination.is_none() && !user_activation {
            return Ok(None);
        }
        Ok(Some(Self {
            site,
            mode,
            destination,
            user_activation,
        }))
    }

    /// Returns the parsed `Sec-Fetch-Site` value, if present.
    pub fn site(&self) -> Option<FetchSite> {
        self.site
    }

    /// Returns the parsed `Sec-Fetch-Mode` value, if present.
    pub fn mode(&self) -> Option<FetchMode> {
        self.mode
    }

    /// Returns the parsed `Sec-Fetch-Dest` value, if present.
    pub fn destination(&self) -> Option<FetchDestination> {
        self.destination
    }

    /// Reports whether `Sec-Fetch-User: ?1` was present.
    pub fn user_activation(&self) -> bool {
        self.user_activation
    }
}

/// Raw, typed configuration for Fetch Metadata enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchMetadataPolicyConfig {
    /// Sites accepted by the policy.  This list must not be empty.
    pub allowed_sites: Vec<FetchSite>,
    /// Accepted modes.  An empty list means all known modes.
    #[serde(default)]
    pub allowed_modes: Vec<FetchMode>,
    /// Accepted destinations.  An empty list means all known destinations.
    #[serde(default)]
    pub allowed_destinations: Vec<FetchDestination>,
    /// Whether requests without any Fetch Metadata fields are accepted.
    #[serde(default)]
    pub allow_missing: bool,
    /// Whether navigations must carry `Sec-Fetch-User: ?1`.
    #[serde(default)]
    pub require_user_activation_for_navigation: bool,
}

/// A compiled Fetch Metadata enforcement policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchMetadataPolicy {
    allowed_sites: BTreeSet<FetchSite>,
    allowed_modes: Option<BTreeSet<FetchMode>>,
    allowed_destinations: Option<BTreeSet<FetchDestination>>,
    allow_missing: bool,
    require_user_activation_for_navigation: bool,
}

/// The result of evaluating one request against Fetch Metadata policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchMetadataDecision {
    /// The request satisfies the policy.
    Allowed,
    /// No Fetch Metadata was supplied and missing metadata is not accepted.
    Missing,
    /// Some, but not all, required Fetch Metadata fields were supplied.
    Incomplete,
    /// The request's site is not allowed.
    Site,
    /// The request's mode is not allowed.
    Mode,
    /// The request's destination is not allowed.
    Destination,
    /// The navigation did not carry a user activation token.
    UserActivation,
}

impl FetchMetadataPolicy {
    /// Compiles and validates Fetch Metadata policy configuration.
    pub fn compile(config: &FetchMetadataPolicyConfig) -> Result<Self> {
        let allowed_sites = canonical_set(config.allowed_sites.iter().copied(), "allowed_sites")?;
        if allowed_sites.is_empty() {
            return Err(invalid("fetch_metadata.allowed_sites", "must not be empty"));
        }
        let allowed_modes = if config.allowed_modes.is_empty() {
            None
        } else {
            Some(canonical_set(
                config.allowed_modes.iter().copied(),
                "allowed_modes",
            )?)
        };
        let allowed_destinations = if config.allowed_destinations.is_empty() {
            None
        } else {
            Some(canonical_set(
                config.allowed_destinations.iter().copied(),
                "allowed_destinations",
            )?)
        };
        Ok(Self {
            allowed_sites,
            allowed_modes,
            allowed_destinations,
            allow_missing: config.allow_missing,
            require_user_activation_for_navigation: config.require_user_activation_for_navigation,
        })
    }

    /// Evaluates a parsed request, or `None` when no Fetch Metadata exists.
    pub fn evaluate(&self, request: Option<&FetchMetadataRequest>) -> FetchMetadataDecision {
        let Some(request) = request else {
            return if self.allow_missing {
                FetchMetadataDecision::Allowed
            } else {
                FetchMetadataDecision::Missing
            };
        };
        let (Some(site), Some(mode), Some(destination)) =
            (request.site, request.mode, request.destination)
        else {
            return FetchMetadataDecision::Incomplete;
        };
        if !self.allowed_sites.contains(&site) {
            return FetchMetadataDecision::Site;
        }
        if self
            .allowed_modes
            .as_ref()
            .is_some_and(|values| !values.contains(&mode))
        {
            return FetchMetadataDecision::Mode;
        }
        if self
            .allowed_destinations
            .as_ref()
            .is_some_and(|values| !values.contains(&destination))
        {
            return FetchMetadataDecision::Destination;
        }
        if self.require_user_activation_for_navigation
            && mode == FetchMode::Navigate
            && !request.user_activation
        {
            return FetchMetadataDecision::UserActivation;
        }
        FetchMetadataDecision::Allowed
    }

    /// Parses and evaluates Fetch Metadata fields from one request header map.
    pub fn evaluate_headers(&self, headers: &HeaderMap) -> Result<FetchMetadataDecision> {
        let request = FetchMetadataRequest::parse(headers)?;
        Ok(self.evaluate(request.as_ref()))
    }

    /// Adds the Fetch Metadata fields that can affect this decision to `Vary`.
    pub fn apply_response_vary(&self, headers: &mut HeaderMap) {
        append_vary(headers, SEC_FETCH_SITE);
        append_vary(headers, SEC_FETCH_MODE);
        append_vary(headers, SEC_FETCH_DEST);
        if self.require_user_activation_for_navigation {
            append_vary(headers, SEC_FETCH_USER);
        }
    }

    /// Returns whether a parsed request is allowed.
    pub fn is_allowed(&self, request: Option<&FetchMetadataRequest>) -> bool {
        self.evaluate(request) == FetchMetadataDecision::Allowed
    }
}

/// A CSP directive name.  Unknown extension names are preserved after token validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CspDirectiveName {
    /// A standard CSP directive name.
    Standard(String),
    /// An extension directive name with a valid token spelling.
    Extension(String),
}

impl CspDirectiveName {
    fn parse(value: &str) -> Result<Self> {
        if !is_ascii_token(value)
            || !value
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic())
        {
            return Err(invalid(
                CONTENT_SECURITY_POLICY,
                "directive name is not a token",
            ));
        }
        let value = value.to_ascii_lowercase();
        let standard = matches!(
            value.as_str(),
            "base-uri"
                | "child-src"
                | "connect-src"
                | "default-src"
                | "fenced-frame-src"
                | "font-src"
                | "form-action"
                | "frame-ancestors"
                | "frame-src"
                | "img-src"
                | "manifest-src"
                | "media-src"
                | "object-src"
                | "plugin-types"
                | "prefetch-src"
                | "report-to"
                | "report-uri"
                | "require-sri-for"
                | "require-trusted-types-for"
                | "sandbox"
                | "script-src"
                | "script-src-attr"
                | "script-src-elem"
                | "style-src"
                | "style-src-attr"
                | "style-src-elem"
                | "trusted-types"
                | "upgrade-insecure-requests"
                | "worker-src"
                | "navigate-to"
                | "webrtc"
                | "block-all-mixed-content"
        );
        Ok(if standard {
            Self::Standard(value)
        } else {
            Self::Extension(value)
        })
    }

    /// Returns the canonical lower-case directive name.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Standard(value) | Self::Extension(value) => value,
        }
    }
}

/// A validated CSP source expression or directive value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CspValue {
    /// A quoted CSP keyword such as `'self'`.
    Keyword(String),
    /// A quoted nonce source.
    Nonce(String),
    /// A quoted hash source.
    Hash {
        /// Hash algorithm name.
        algorithm: CspHashAlgorithm,
        /// Base64-encoded digest.
        value: String,
    },
    /// A scheme source such as `https:`.
    Scheme(String),
    /// A host source such as `https://cdn.example`.
    Host(String),
    /// A validated CSP token used by directive-specific grammars.
    Token(String),
}

/// CSP hash algorithm names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CspHashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl fmt::Display for CspHashAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        })
    }
}

impl CspValue {
    fn parse(value: &str) -> Result<Self> {
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(invalid(
                CONTENT_SECURITY_POLICY,
                "directive value is empty or contains controls",
            ));
        }
        if value.starts_with('\'') {
            if !value.ends_with('\'') || value.len() < 2 || value[1..value.len() - 1].contains('\'')
            {
                return Err(invalid(
                    CONTENT_SECURITY_POLICY,
                    "quoted source expression is malformed",
                ));
            }
            let inner = &value[1..value.len() - 1];
            if let Some(nonce) = inner.strip_prefix("nonce-") {
                if !is_csp_base64(nonce) {
                    return Err(invalid(
                        CONTENT_SECURITY_POLICY,
                        "nonce source is not base64-like",
                    ));
                }
                return Ok(Self::Nonce(nonce.to_string()));
            }
            if matches!(
                inner,
                "none"
                    | "self"
                    | "unsafe-inline"
                    | "unsafe-eval"
                    | "unsafe-hashes"
                    | "strict-dynamic"
                    | "report-sample"
                    | "wasm-unsafe-eval"
                    | "unsafe-allow-redirects"
                    | "trusted-types-eval"
                    | "report-sha256"
                    | "report-sha384"
                    | "report-sha512"
                    | "unsafe-webtransport-hashes"
            ) {
                return Ok(Self::Keyword(inner.to_string()));
            }
            if let Some((algorithm, digest)) = inner.split_once('-') {
                let algorithm = match algorithm {
                    "sha256" => CspHashAlgorithm::Sha256,
                    "sha384" => CspHashAlgorithm::Sha384,
                    "sha512" => CspHashAlgorithm::Sha512,
                    _ => {
                        return Err(invalid(CONTENT_SECURITY_POLICY, "unknown hash algorithm"));
                    }
                };
                if !is_csp_base64(digest) {
                    return Err(invalid(
                        CONTENT_SECURITY_POLICY,
                        "hash source is not base64-like",
                    ));
                }
                return Ok(Self::Hash {
                    algorithm,
                    value: digest.to_string(),
                });
            }
            return Err(invalid(CONTENT_SECURITY_POLICY, "unknown quoted keyword"));
        }
        if value == "*" {
            return Ok(Self::Host(value.to_string()));
        }
        if value.ends_with(':') && is_csp_scheme(value.trim_end_matches(':')) {
            return Ok(Self::Scheme(value.to_ascii_lowercase()));
        }
        if is_csp_host_expression(value) {
            return Ok(Self::Host(value.to_string()));
        }
        if !is_token(value) || value.contains('\'') {
            return Err(invalid(
                CONTENT_SECURITY_POLICY,
                "directive value is not a token",
            ));
        }
        Ok(Self::Token(value.to_string()))
    }

    fn serialize(&self) -> String {
        match self {
            Self::Keyword(value) => format!("'{value}'"),
            Self::Nonce(value) => format!("'nonce-{value}'"),
            Self::Hash { algorithm, value } => format!("'{algorithm}-{value}'"),
            Self::Scheme(value) | Self::Host(value) | Self::Token(value) => value.clone(),
        }
    }
}

/// One parsed CSP directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspDirective {
    name: CspDirectiveName,
    values: Vec<CspValue>,
}

impl CspDirective {
    /// Returns the directive name.
    pub fn name(&self) -> &CspDirectiveName {
        &self.name
    }

    /// Returns validated directive values.
    pub fn values(&self) -> &[CspValue] {
        &self.values
    }
}

/// A parsed and validated Content-Security-Policy value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentSecurityPolicy {
    directives: Vec<CspDirective>,
    serialized: String,
}

impl ContentSecurityPolicy {
    /// Parses a CSP field value and rejects duplicate directives and malformed sources.
    pub fn parse(value: &str) -> Result<Self> {
        let mut directives = Vec::new();
        let mut seen = BTreeSet::new();
        for raw_directive in value.split(';') {
            let raw_directive = raw_directive.trim();
            if raw_directive.is_empty() {
                return Err(invalid(CONTENT_SECURITY_POLICY, "empty directive"));
            }
            let mut parts = raw_directive.split_ascii_whitespace();
            let name = CspDirectiveName::parse(
                parts
                    .next()
                    .ok_or_else(|| invalid(CONTENT_SECURITY_POLICY, "directive has no name"))?,
            )?;
            if !seen.insert(name.as_str().to_string()) {
                return Err(BrowserPolicyError::Duplicate {
                    field: CONTENT_SECURITY_POLICY,
                    value: name.as_str().to_string(),
                });
            }
            let values = parts.map(CspValue::parse).collect::<Result<Vec<_>>>()?;
            directives.push(CspDirective { name, values });
        }
        if directives.is_empty() {
            return Err(invalid(CONTENT_SECURITY_POLICY, "policy must not be empty"));
        }
        let serialized = directives
            .iter()
            .map(|directive| {
                let mut value = directive.name.as_str().to_string();
                for item in &directive.values {
                    value.push(' ');
                    value.push_str(item.serialize().as_str());
                }
                value
            })
            .collect::<Vec<_>>()
            .join("; ");
        Ok(Self {
            directives,
            serialized,
        })
    }

    /// Returns parsed CSP directives.
    pub fn directives(&self) -> &[CspDirective] {
        &self.directives
    }

    /// Returns the canonical field value.
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    /// Replaces upstream CSP and applies this policy as `Content-Security-Policy`.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, CONTENT_SECURITY_POLICY);
        insert_header(headers, CONTENT_SECURITY_POLICY, self.as_str());
    }

    /// Replaces upstream CSP report-only fields and applies this policy.
    pub fn apply_report_only(&self, headers: &mut HeaderMap) {
        remove_header(headers, CONTENT_SECURITY_POLICY_REPORT_ONLY);
        insert_header(headers, CONTENT_SECURITY_POLICY_REPORT_ONLY, self.as_str());
    }
}

/// Referrer-Policy tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReferrerPolicyDirective {
    /// Never send a referrer.
    #[serde(rename = "no-referrer")]
    NoReferrer,
    /// Send the full referrer except on downgrade.
    #[serde(rename = "no-referrer-when-downgrade")]
    NoReferrerWhenDowngrade,
    /// Send only the origin.
    Origin,
    /// Send the origin cross-origin and full URL same-origin.
    #[serde(rename = "origin-when-cross-origin")]
    OriginWhenCrossOrigin,
    /// Send a referrer only same-origin.
    #[serde(rename = "same-origin")]
    SameOrigin,
    /// Send a strict origin referrer.
    #[serde(rename = "strict-origin")]
    StrictOrigin,
    /// Send strict origin cross-origin and full URL same-origin.
    #[serde(rename = "strict-origin-when-cross-origin")]
    StrictOriginWhenCrossOrigin,
    /// Send the full URL in all contexts.
    #[serde(rename = "unsafe-url")]
    UnsafeUrl,
}

impl fmt::Display for ReferrerPolicyDirective {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoReferrer => "no-referrer",
            Self::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Self::Origin => "origin",
            Self::OriginWhenCrossOrigin => "origin-when-cross-origin",
            Self::SameOrigin => "same-origin",
            Self::StrictOrigin => "strict-origin",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            Self::UnsafeUrl => "unsafe-url",
        })
    }
}

impl FromStr for ReferrerPolicyDirective {
    type Err = BrowserPolicyError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "no-referrer" => Ok(Self::NoReferrer),
            "no-referrer-when-downgrade" => Ok(Self::NoReferrerWhenDowngrade),
            "origin" => Ok(Self::Origin),
            "origin-when-cross-origin" => Ok(Self::OriginWhenCrossOrigin),
            "same-origin" => Ok(Self::SameOrigin),
            "strict-origin" => Ok(Self::StrictOrigin),
            "strict-origin-when-cross-origin" => Ok(Self::StrictOriginWhenCrossOrigin),
            "unsafe-url" => Ok(Self::UnsafeUrl),
            _ => Err(invalid(REFERRER_POLICY, "unknown directive")),
        }
    }
}

/// A parsed Referrer-Policy list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferrerPolicy {
    directives: Vec<ReferrerPolicyDirective>,
    serialized: String,
}

impl ReferrerPolicy {
    /// Parses a comma-separated Referrer-Policy list.
    pub fn parse(value: &str) -> Result<Self> {
        let mut directives = Vec::new();
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() {
                return Err(invalid(REFERRER_POLICY, "empty directive"));
            }
            let directive: ReferrerPolicyDirective = item.parse()?;
            if directives.contains(&directive) {
                return Err(BrowserPolicyError::Duplicate {
                    field: REFERRER_POLICY,
                    value: directive.to_string(),
                });
            }
            directives.push(directive);
        }
        if directives.is_empty() {
            return Err(invalid(REFERRER_POLICY, "policy must not be empty"));
        }
        let serialized = directives
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Self {
            directives,
            serialized,
        })
    }

    /// Returns the policy list in order of user-agent preference.
    pub fn directives(&self) -> &[ReferrerPolicyDirective] {
        &self.directives
    }

    /// Returns the canonical field value.
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    /// Replaces upstream Referrer-Policy and applies this policy.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, REFERRER_POLICY);
        insert_header(headers, REFERRER_POLICY, self.as_str());
    }
}

/// One Permissions-Policy allowlist value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PermissionAllowlistValue {
    /// The current document origin.
    SelfOrigin,
    /// The embedding document's origin.
    Src,
    /// A serialized HTTP(S) origin or a subdomain wildcard pattern.
    Origin(String),
}

/// A Permissions-Policy feature allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionAllowlist {
    /// Every origin.
    Any,
    /// No origin.
    None,
    /// One or more explicit values.
    Values(Vec<PermissionAllowlistValue>),
}

/// One parsed Permissions-Policy directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsDirective {
    feature: String,
    allowlist: PermissionAllowlist,
}

impl PermissionsDirective {
    /// Returns the feature name.
    pub fn feature(&self) -> &str {
        &self.feature
    }

    /// Returns the validated feature allowlist.
    pub fn allowlist(&self) -> &PermissionAllowlist {
        &self.allowlist
    }
}

/// A parsed Permissions-Policy field value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsPolicy {
    directives: Vec<PermissionsDirective>,
    serialized: String,
}

impl PermissionsPolicy {
    /// Parses Permissions-Policy directives separated by commas.
    pub fn parse(value: &str) -> Result<Self> {
        let mut directives = Vec::new();
        let mut seen = BTreeSet::new();
        for raw in split_top_level(value, ',')? {
            let raw = raw.trim();
            let (feature, raw_allowlist) = raw
                .split_once('=')
                .ok_or_else(|| invalid(PERMISSIONS_POLICY, "directive must contain '='"))?;
            let feature = feature.trim();
            if !is_ascii_token(feature)
                || !feature
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphabetic())
            {
                return Err(invalid(PERMISSIONS_POLICY, "feature name is not a token"));
            }
            let feature = feature.to_ascii_lowercase();
            if !seen.insert(feature.clone()) {
                return Err(BrowserPolicyError::Duplicate {
                    field: PERMISSIONS_POLICY,
                    value: feature,
                });
            }
            let raw_allowlist = raw_allowlist.trim();
            if !raw_allowlist.starts_with('(') || !raw_allowlist.ends_with(')') {
                return Err(invalid(
                    PERMISSIONS_POLICY,
                    "allowlist must be enclosed in parentheses",
                ));
            }
            let contents = raw_allowlist[1..raw_allowlist.len() - 1].trim();
            let allowlist = parse_permission_allowlist(contents)?;
            directives.push(PermissionsDirective { feature, allowlist });
        }
        if directives.is_empty() {
            return Err(invalid(PERMISSIONS_POLICY, "policy must not be empty"));
        }
        let serialized = directives
            .iter()
            .map(serialize_permissions_directive)
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Self {
            directives,
            serialized,
        })
    }

    /// Returns parsed Permissions-Policy directives.
    pub fn directives(&self) -> &[PermissionsDirective] {
        &self.directives
    }

    /// Returns the canonical field value.
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    /// Replaces upstream Permissions-Policy and applies this policy.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, PERMISSIONS_POLICY);
        insert_header(headers, PERMISSIONS_POLICY, self.as_str());
    }

    /// Replaces upstream Permissions-Policy report-only fields and applies this policy.
    pub fn apply_report_only(&self, headers: &mut HeaderMap) {
        remove_header(headers, PERMISSIONS_POLICY_REPORT_ONLY);
        insert_header(headers, PERMISSIONS_POLICY_REPORT_ONLY, self.as_str());
    }
}

fn split_top_level(value: &str, separator: char) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0u32;
    let mut quoted = false;
    for (index, character) in value.char_indices() {
        match character {
            '"' => quoted = !quoted,
            '(' if !quoted => depth = depth.saturating_add(1),
            ')' if !quoted => {
                if depth == 0 {
                    return Err(invalid(PERMISSIONS_POLICY, "unbalanced parentheses"));
                }
                depth -= 1;
            }
            _ => {}
        }
        if character == separator && depth == 0 && !quoted {
            parts.push(value[start..index].to_string());
            start = index + character.len_utf8();
        }
    }
    if quoted || depth != 0 {
        return Err(invalid(
            PERMISSIONS_POLICY,
            "unbalanced quoted string or parentheses",
        ));
    }
    parts.push(value[start..].to_string());
    Ok(parts)
}

fn parse_permission_allowlist(value: &str) -> Result<PermissionAllowlist> {
    if value.is_empty() || value == "none" {
        return Ok(PermissionAllowlist::None);
    }
    if value == "*" {
        return Ok(PermissionAllowlist::Any);
    }
    let mut values = Vec::new();
    for token in value.split_ascii_whitespace() {
        let parsed = if token == "self" {
            PermissionAllowlistValue::SelfOrigin
        } else if token == "src" {
            PermissionAllowlistValue::Src
        } else if token == "none" {
            return Err(invalid(
                PERMISSIONS_POLICY,
                "none cannot be combined with other values",
            ));
        } else if token.starts_with('"') && token.ends_with('"') && token.len() > 2 {
            let origin = parse_permission_origin(&token[1..token.len() - 1])?;
            if origin == "null" {
                return Err(invalid(
                    PERMISSIONS_POLICY,
                    "opaque null origin is not an allowlist origin",
                ));
            }
            PermissionAllowlistValue::Origin(origin)
        } else {
            return Err(invalid(PERMISSIONS_POLICY, "allowlist value is malformed"));
        };
        if values.contains(&parsed) {
            return Err(BrowserPolicyError::Duplicate {
                field: PERMISSIONS_POLICY,
                value: token.to_string(),
            });
        }
        values.push(parsed);
    }
    if values.is_empty() {
        Ok(PermissionAllowlist::None)
    } else {
        Ok(PermissionAllowlist::Values(values))
    }
}

fn parse_permission_origin(value: &str) -> Result<String> {
    if let Some(rest) = value
        .strip_prefix("https://*.")
        .or_else(|| value.strip_prefix("http://*."))
    {
        if rest.is_empty()
            || rest.contains('/')
            || rest.contains(':')
            || rest.contains('?')
            || rest.contains('#')
            || !rest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            || rest.starts_with('.')
            || rest.ends_with('.')
            || rest.contains("..")
        {
            return Err(invalid(
                PERMISSIONS_POLICY,
                "subdomain wildcard origin is malformed",
            ));
        }
        let scheme = if value.starts_with("https://") {
            "https://*."
        } else {
            "http://*."
        };
        return Ok(format!("{scheme}{rest}"));
    }
    parse_origin(value, PERMISSIONS_POLICY).and_then(|origin| {
        if origin == "null" {
            Err(invalid(
                PERMISSIONS_POLICY,
                "opaque null origin is not an allowlist origin",
            ))
        } else {
            Ok(origin)
        }
    })
}

fn serialize_permissions_directive(directive: &PermissionsDirective) -> String {
    let allowlist = match &directive.allowlist {
        PermissionAllowlist::Any => "*".to_string(),
        PermissionAllowlist::None => String::new(),
        PermissionAllowlist::Values(values) => values
            .iter()
            .map(|value| match value {
                PermissionAllowlistValue::SelfOrigin => "self".to_string(),
                PermissionAllowlistValue::Src => "src".to_string(),
                PermissionAllowlistValue::Origin(origin) => format!("\"{origin}\""),
            })
            .collect::<Vec<_>>()
            .join(" "),
    };
    format!("{}=({allowlist})", directive.feature)
}

/// Cross-Origin-Opener-Policy values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CoopValue {
    /// Do not isolate the browsing context group.
    #[serde(rename = "unsafe-none")]
    UnsafeNone,
    /// Isolate unless opened by a same-origin-allow-popups context.
    #[serde(rename = "same-origin-allow-popups")]
    SameOriginAllowPopups,
    /// Isolate the browsing context group.
    #[serde(rename = "same-origin")]
    SameOrigin,
    /// Isolate while allowing controlled opener popups.
    #[serde(rename = "noopener-allow-popups")]
    NoopenerAllowPopups,
}

impl fmt::Display for CoopValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeNone => "unsafe-none",
            Self::SameOriginAllowPopups => "same-origin-allow-popups",
            Self::SameOrigin => "same-origin",
            Self::NoopenerAllowPopups => "noopener-allow-popups",
        })
    }
}

/// A parsed Cross-Origin-Opener-Policy value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossOriginOpenerPolicy {
    value: CoopValue,
    report_to: Option<String>,
}

impl CrossOriginOpenerPolicy {
    /// Parses COOP and its optional `report-to` parameter.
    pub fn parse(value: &str) -> Result<Self> {
        let (value, report_to) = parse_policy_parameter(value, CROSS_ORIGIN_OPENER_POLICY)?;
        let value = match value {
            "unsafe-none" => CoopValue::UnsafeNone,
            "same-origin-allow-popups" => CoopValue::SameOriginAllowPopups,
            "same-origin" => CoopValue::SameOrigin,
            "noopener-allow-popups" => CoopValue::NoopenerAllowPopups,
            _ => return Err(invalid(CROSS_ORIGIN_OPENER_POLICY, "unknown policy value")),
        };
        Ok(Self { value, report_to })
    }

    /// Returns the COOP value.
    pub fn value(&self) -> CoopValue {
        self.value
    }

    /// Returns the optional reporting endpoint URL.
    pub fn report_to(&self) -> Option<&str> {
        self.report_to.as_deref()
    }

    /// Replaces upstream COOP and applies this policy.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, CROSS_ORIGIN_OPENER_POLICY);
        insert_header(
            headers,
            CROSS_ORIGIN_OPENER_POLICY,
            self.serialize().as_str(),
        );
    }

    /// Replaces upstream COOP report-only fields and applies this policy.
    pub fn apply_report_only(&self, headers: &mut HeaderMap) {
        remove_header(headers, CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY);
        insert_header(
            headers,
            CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY,
            self.serialize().as_str(),
        );
    }

    fn serialize(&self) -> String {
        serialize_policy_parameter(self.value.to_string().as_str(), self.report_to.as_deref())
    }
}

/// Cross-Origin-Embedder-Policy values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CoepValue {
    /// Do not require cross-origin resource policy.
    #[serde(rename = "unsafe-none")]
    UnsafeNone,
    /// Require CORP or CORS for cross-origin resources.
    #[serde(rename = "require-corp")]
    RequireCorp,
    /// Use credentialless cross-origin fetches.
    Credentialless,
}

impl fmt::Display for CoepValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeNone => "unsafe-none",
            Self::RequireCorp => "require-corp",
            Self::Credentialless => "credentialless",
        })
    }
}

/// A parsed Cross-Origin-Embedder-Policy value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossOriginEmbedderPolicy {
    value: CoepValue,
    report_to: Option<String>,
}

impl CrossOriginEmbedderPolicy {
    /// Parses COEP and its optional `report-to` parameter.
    pub fn parse(value: &str) -> Result<Self> {
        let (value, report_to) = parse_policy_parameter(value, CROSS_ORIGIN_EMBEDDER_POLICY)?;
        let value = match value {
            "unsafe-none" => CoepValue::UnsafeNone,
            "require-corp" => CoepValue::RequireCorp,
            "credentialless" => CoepValue::Credentialless,
            _ => {
                return Err(invalid(
                    CROSS_ORIGIN_EMBEDDER_POLICY,
                    "unknown policy value",
                ));
            }
        };
        Ok(Self { value, report_to })
    }

    /// Returns the COEP value.
    pub fn value(&self) -> CoepValue {
        self.value
    }

    /// Returns the optional reporting endpoint URL.
    pub fn report_to(&self) -> Option<&str> {
        self.report_to.as_deref()
    }

    /// Replaces upstream COEP and applies this policy.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, CROSS_ORIGIN_EMBEDDER_POLICY);
        insert_header(
            headers,
            CROSS_ORIGIN_EMBEDDER_POLICY,
            self.serialize().as_str(),
        );
    }

    /// Replaces upstream COEP report-only fields and applies this policy.
    pub fn apply_report_only(&self, headers: &mut HeaderMap) {
        remove_header(headers, CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY);
        insert_header(
            headers,
            CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY,
            self.serialize().as_str(),
        );
    }

    fn serialize(&self) -> String {
        serialize_policy_parameter(self.value.to_string().as_str(), self.report_to.as_deref())
    }
}

fn parse_policy_parameter<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<(&'a str, Option<String>)> {
    let mut parts = value.split(';');
    let primary = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(field, "policy value is empty"))?;
    if !is_ascii_token(primary) {
        return Err(invalid(field, "primary policy value is not a token"));
    }
    let mut report_to = None;
    for raw_param in parts {
        let (name, raw_value) = raw_param
            .trim()
            .split_once('=')
            .ok_or_else(|| invalid(field, "parameter must contain '='"))?;
        if name.trim() != "report-to" || report_to.is_some() {
            return Err(if report_to.is_some() {
                BrowserPolicyError::Duplicate {
                    field,
                    value: name.trim().to_string(),
                }
            } else {
                invalid(field, "unknown parameter")
            });
        }
        let raw_value = raw_value.trim();
        if !raw_value.starts_with('"') || !raw_value.ends_with('"') || raw_value.len() < 2 {
            return Err(invalid(field, "report-to parameter must be a string URL"));
        }
        let inner = &raw_value[1..raw_value.len() - 1];
        if inner.contains('"') || inner.contains('\\') {
            return Err(invalid(field, "report-to parameter contains an escape"));
        }
        let endpoint = parse_http_url(inner, field)?;
        report_to = Some(endpoint);
    }
    Ok((primary, report_to))
}

fn serialize_policy_parameter(primary: &str, report_to: Option<&str>) -> String {
    match report_to {
        Some(endpoint) => format!("{primary}; report-to=\"{endpoint}\""),
        None => primary.to_string(),
    }
}

/// Cross-Origin-Resource-Policy values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CorpValue {
    /// Allow resources only to same-origin documents.
    #[serde(rename = "same-origin")]
    SameOrigin,
    /// Allow resources to same-site documents.
    #[serde(rename = "same-site")]
    SameSite,
    /// Allow resources cross-origin.
    #[serde(rename = "cross-origin")]
    CrossOrigin,
}

impl fmt::Display for CorpValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SameOrigin => "same-origin",
            Self::SameSite => "same-site",
            Self::CrossOrigin => "cross-origin",
        })
    }
}

/// A parsed Cross-Origin-Resource-Policy value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossOriginResourcePolicy {
    value: CorpValue,
}

impl CrossOriginResourcePolicy {
    /// Parses CORP.
    pub fn parse(value: &str) -> Result<Self> {
        let value = match value.trim() {
            "same-origin" => CorpValue::SameOrigin,
            "same-site" => CorpValue::SameSite,
            "cross-origin" => CorpValue::CrossOrigin,
            _ => {
                return Err(invalid(
                    CROSS_ORIGIN_RESOURCE_POLICY,
                    "unknown policy value",
                ));
            }
        };
        Ok(Self { value })
    }

    /// Returns the CORP value.
    pub fn value(&self) -> CorpValue {
        self.value
    }

    /// Replaces upstream CORP and applies this policy.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, CROSS_ORIGIN_RESOURCE_POLICY);
        insert_header(
            headers,
            CROSS_ORIGIN_RESOURCE_POLICY,
            self.value.to_string().as_str(),
        );
    }
}

/// The only valid X-Content-Type-Options value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentTypeOptions;

impl ContentTypeOptions {
    /// Parses `nosniff`.
    pub fn parse(value: &str) -> Result<Self> {
        if !value.trim().eq_ignore_ascii_case("nosniff") {
            return Err(invalid(X_CONTENT_TYPE_OPTIONS, "only nosniff is valid"));
        }
        Ok(Self)
    }

    /// Replaces upstream X-Content-Type-Options and applies `nosniff`.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, X_CONTENT_TYPE_OPTIONS);
        insert_header(headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
    }
}

/// A parsed Origin-Agent-Cluster boolean value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginAgentCluster {
    enabled: bool,
}

impl OriginAgentCluster {
    /// Parses `?1` or `?0`.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "?1" => Ok(Self { enabled: true }),
            "?0" => Ok(Self { enabled: false }),
            _ => Err(invalid(ORIGIN_AGENT_CLUSTER, "only ?1 or ?0 is valid")),
        }
    }

    /// Returns whether origin-keyed agent clustering is requested.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Replaces upstream Origin-Agent-Cluster and applies this value.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, ORIGIN_AGENT_CLUSTER);
        insert_header(
            headers,
            ORIGIN_AGENT_CLUSTER,
            if self.enabled { "?1" } else { "?0" },
        );
    }
}

/// Clear-Site-Data directives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClearSiteDataDirective {
    /// Clear HTTP cache.
    Cache,
    /// Clear cookies and other credentials.
    Cookies,
    /// Clear DOM storage and related data.
    Storage,
    /// Clear execution contexts.
    ExecutionContexts,
    /// Clear client hints.
    ClientHints,
    /// Clear all supported data types.
    Wildcard,
}

impl ClearSiteDataDirective {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "cache" => Ok(Self::Cache),
            "cookies" => Ok(Self::Cookies),
            "storage" => Ok(Self::Storage),
            "executionContexts" => Ok(Self::ExecutionContexts),
            "clientHints" => Ok(Self::ClientHints),
            "*" => Ok(Self::Wildcard),
            _ => Err(invalid(CLEAR_SITE_DATA, "unknown directive")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Cookies => "cookies",
            Self::Storage => "storage",
            Self::ExecutionContexts => "executionContexts",
            Self::ClientHints => "clientHints",
            Self::Wildcard => "*",
        }
    }
}

/// A parsed Clear-Site-Data field value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearSiteData {
    directives: Vec<ClearSiteDataDirective>,
    serialized: String,
}

impl ClearSiteData {
    /// Parses quoted Clear-Site-Data directives.
    pub fn parse(value: &str) -> Result<Self> {
        let mut directives = Vec::new();
        for raw in value.split(',') {
            let raw = raw.trim();
            if raw.len() < 2 || !raw.starts_with('"') || !raw.ends_with('"') {
                return Err(invalid(
                    CLEAR_SITE_DATA,
                    "directive must be a quoted string",
                ));
            }
            let directive = ClearSiteDataDirective::parse(&raw[1..raw.len() - 1])?;
            if directives.contains(&directive) {
                return Err(BrowserPolicyError::Duplicate {
                    field: CLEAR_SITE_DATA,
                    value: directive.as_str().to_string(),
                });
            }
            if directive == ClearSiteDataDirective::Wildcard && !directives.is_empty() {
                return Err(invalid(CLEAR_SITE_DATA, "wildcard cannot be combined"));
            }
            if directives.contains(&ClearSiteDataDirective::Wildcard) {
                return Err(invalid(CLEAR_SITE_DATA, "wildcard cannot be combined"));
            }
            directives.push(directive);
        }
        if directives.is_empty() {
            return Err(invalid(CLEAR_SITE_DATA, "policy must not be empty"));
        }
        let serialized = directives
            .iter()
            .map(|directive| format!("\"{}\"", directive.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Self {
            directives,
            serialized,
        })
    }

    /// Returns parsed directives.
    pub fn directives(&self) -> &[ClearSiteDataDirective] {
        &self.directives
    }

    /// Returns the canonical field value.
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    /// Replaces upstream Clear-Site-Data and applies this policy.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, CLEAR_SITE_DATA);
        insert_header(headers, CLEAR_SITE_DATA, self.as_str());
    }
}

/// One Reporting-Endpoints dictionary member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportingEndpoint {
    name: String,
    url: String,
}

impl ReportingEndpoint {
    /// Returns the endpoint name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the validated endpoint URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// A parsed Reporting-Endpoints structured dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportingEndpoints {
    endpoints: Vec<ReportingEndpoint>,
    serialized: String,
}

impl ReportingEndpoints {
    /// Parses a Reporting-Endpoints dictionary with absolute or origin-relative URLs.
    pub fn parse(value: &str) -> Result<Self> {
        let mut endpoints = Vec::new();
        let mut seen = BTreeSet::new();
        for raw in split_quoted_commas(value, REPORTING_ENDPOINTS)? {
            let (raw_name, raw_url) = raw
                .trim()
                .split_once('=')
                .ok_or_else(|| invalid(REPORTING_ENDPOINTS, "member must contain '='"))?;
            let name = raw_name.trim();
            if !is_sf_key(name) || !seen.insert(name.to_string()) {
                return Err(if seen.contains(name) {
                    BrowserPolicyError::Duplicate {
                        field: REPORTING_ENDPOINTS,
                        value: name.to_string(),
                    }
                } else {
                    invalid(REPORTING_ENDPOINTS, "endpoint name is not a token")
                });
            }
            let raw_url = raw_url.trim();
            if raw_url.len() < 2 || !raw_url.starts_with('"') || !raw_url.ends_with('"') {
                return Err(invalid(REPORTING_ENDPOINTS, "endpoint URL must be quoted"));
            }
            let url = parse_reporting_endpoint_url(&raw_url[1..raw_url.len() - 1])?;
            endpoints.push(ReportingEndpoint {
                name: name.to_string(),
                url,
            });
        }
        if endpoints.is_empty() {
            return Err(invalid(REPORTING_ENDPOINTS, "dictionary must not be empty"));
        }
        let serialized = endpoints
            .iter()
            .map(|endpoint| format!("{}=\"{}\"", endpoint.name, endpoint.url))
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Self {
            endpoints,
            serialized,
        })
    }

    /// Returns reporting endpoints in wire order.
    pub fn endpoints(&self) -> &[ReportingEndpoint] {
        &self.endpoints
    }

    /// Returns the canonical dictionary value.
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    /// Replaces upstream Reporting-Endpoints and applies this dictionary.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, REPORTING_ENDPOINTS);
        insert_header(headers, REPORTING_ENDPOINTS, self.as_str());
    }
}

fn split_quoted_commas(value: &str, field: &'static str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            return Err(invalid(field, "quoted member contains an escape"));
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(value[start..index].to_string());
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || escaped {
        return Err(invalid(field, "unbalanced quoted member"));
    }
    parts.push(value[start..].to_string());
    Ok(parts)
}

/// Timing-Allow-Origin policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimingAllowOrigin {
    /// Allow every origin.
    Any,
    /// Allow the listed serialized origins.
    Origins(Vec<String>),
}

impl TimingAllowOrigin {
    /// Parses `*` or a space-separated serialized-origin list.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value == "*" {
            return Ok(Self::Any);
        }
        if value.is_empty() || value.contains(',') {
            return Err(invalid(
                TIMING_ALLOW_ORIGIN,
                "origin list must be space-separated",
            ));
        }
        let mut origins = Vec::new();
        for item in value.split_ascii_whitespace() {
            let origin = parse_origin(item, TIMING_ALLOW_ORIGIN)?;
            if origins.contains(&origin) {
                return Err(BrowserPolicyError::Duplicate {
                    field: TIMING_ALLOW_ORIGIN,
                    value: origin,
                });
            }
            origins.push(origin);
        }
        if origins.is_empty() {
            return Err(invalid(
                TIMING_ALLOW_ORIGIN,
                "origin list must not be empty",
            ));
        }
        Ok(Self::Origins(origins))
    }

    /// Returns the canonical field value.
    pub fn as_str(&self) -> String {
        match self {
            Self::Any => "*".to_string(),
            Self::Origins(origins) => origins.join(" "),
        }
    }

    /// Replaces upstream Timing-Allow-Origin and applies this policy.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, TIMING_ALLOW_ORIGIN);
        insert_header(headers, TIMING_ALLOW_ORIGIN, self.as_str().as_str());
    }
}

/// A typed list of client hint field names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHints {
    names: Vec<HeaderName>,
    serialized: String,
}

impl ClientHints {
    /// Parses an RFC 8942 comma-separated field-name list.
    pub fn parse(value: &str, field: &'static str) -> Result<Self> {
        let mut names = Vec::new();
        let mut seen = BTreeSet::new();
        for raw in value.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                return Err(invalid(field, "empty field name"));
            }
            let name = HeaderName::from_bytes(raw.as_bytes())
                .map_err(|_| invalid(field, "value is not an HTTP field name"))?;
            let key = name.as_str().to_ascii_lowercase();
            if !seen.insert(key) {
                return Err(BrowserPolicyError::Duplicate {
                    field,
                    value: raw.to_string(),
                });
            }
            names.push(name);
        }
        if names.is_empty() {
            return Err(invalid(field, "field-name list must not be empty"));
        }
        let serialized = names
            .iter()
            .map(|name| name.as_str().to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Self { names, serialized })
    }

    /// Returns the parsed field names.
    pub fn names(&self) -> &[HeaderName] {
        &self.names
    }

    /// Returns the canonical field value.
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    fn contains(&self, name: &HeaderName) -> bool {
        self.names.iter().any(|candidate| candidate == name)
    }
}

/// A typed `Accept-CH` policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptClientHints(ClientHints);

impl AcceptClientHints {
    /// Parses RFC 8942 `Accept-CH`.
    pub fn parse(value: &str) -> Result<Self> {
        Ok(Self(ClientHints::parse(value, ACCEPT_CH)?))
    }

    /// Returns requested client hint field names.
    pub fn names(&self) -> &[HeaderName] {
        self.0.names()
    }

    /// Returns the canonical field value.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Replaces upstream Accept-CH and applies this policy.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, ACCEPT_CH);
        insert_header(headers, ACCEPT_CH, self.as_str());
    }
}

/// A typed `Critical-CH` policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalClientHints(ClientHints);

impl CriticalClientHints {
    /// Parses RFC 8942 `Critical-CH`.
    pub fn parse(value: &str) -> Result<Self> {
        Ok(Self(ClientHints::parse(value, CRITICAL_CH)?))
    }

    /// Returns critical client hint field names.
    pub fn names(&self) -> &[HeaderName] {
        self.0.names()
    }

    /// Returns the canonical field value.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Replaces upstream Critical-CH and applies this policy.
    pub fn apply(&self, headers: &mut HeaderMap) {
        remove_header(headers, CRITICAL_CH);
        insert_header(headers, CRITICAL_CH, self.as_str());
    }
}

/// Raw configuration for all browser-facing response policies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserResponsePolicyConfig {
    /// Content-Security-Policy value.
    #[serde(default)]
    pub content_security_policy: Option<String>,
    /// Content-Security-Policy-Report-Only value.
    #[serde(default)]
    pub content_security_policy_report_only: Option<String>,
    /// Referrer-Policy value.
    #[serde(default)]
    pub referrer_policy: Option<String>,
    /// Permissions-Policy value.
    #[serde(default)]
    pub permissions_policy: Option<String>,
    /// Permissions-Policy-Report-Only value.
    #[serde(default)]
    pub permissions_policy_report_only: Option<String>,
    /// Cross-Origin-Opener-Policy value.
    #[serde(default)]
    pub cross_origin_opener_policy: Option<String>,
    /// Cross-Origin-Opener-Policy-Report-Only value.
    #[serde(default)]
    pub cross_origin_opener_policy_report_only: Option<String>,
    /// Cross-Origin-Embedder-Policy value.
    #[serde(default)]
    pub cross_origin_embedder_policy: Option<String>,
    /// Cross-Origin-Embedder-Policy-Report-Only value.
    #[serde(default)]
    pub cross_origin_embedder_policy_report_only: Option<String>,
    /// Cross-Origin-Resource-Policy value.
    #[serde(default)]
    pub cross_origin_resource_policy: Option<String>,
    /// X-Content-Type-Options value.
    #[serde(default)]
    pub x_content_type_options: Option<String>,
    /// Origin-Agent-Cluster value.
    #[serde(default)]
    pub origin_agent_cluster: Option<String>,
    /// Clear-Site-Data value.
    #[serde(default)]
    pub clear_site_data: Option<String>,
    /// Reporting-Endpoints value.
    #[serde(default)]
    pub reporting_endpoints: Option<String>,
    /// Timing-Allow-Origin value.
    #[serde(default)]
    pub timing_allow_origin: Option<String>,
    /// Accept-CH value.
    #[serde(default)]
    pub accept_ch: Option<String>,
    /// Critical-CH value.
    #[serde(default)]
    pub critical_ch: Option<String>,
}

/// Compiled and validated browser response policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserResponsePolicy {
    content_security_policy: Option<ContentSecurityPolicy>,
    content_security_policy_report_only: Option<ContentSecurityPolicy>,
    referrer_policy: Option<ReferrerPolicy>,
    permissions_policy: Option<PermissionsPolicy>,
    permissions_policy_report_only: Option<PermissionsPolicy>,
    cross_origin_opener_policy: Option<CrossOriginOpenerPolicy>,
    cross_origin_opener_policy_report_only: Option<CrossOriginOpenerPolicy>,
    cross_origin_embedder_policy: Option<CrossOriginEmbedderPolicy>,
    cross_origin_embedder_policy_report_only: Option<CrossOriginEmbedderPolicy>,
    cross_origin_resource_policy: Option<CrossOriginResourcePolicy>,
    x_content_type_options: Option<ContentTypeOptions>,
    origin_agent_cluster: Option<OriginAgentCluster>,
    clear_site_data: Option<ClearSiteData>,
    reporting_endpoints: Option<ReportingEndpoints>,
    timing_allow_origin: Option<TimingAllowOrigin>,
    accept_ch: Option<AcceptClientHints>,
    critical_ch: Option<CriticalClientHints>,
}

impl BrowserResponsePolicy {
    /// Compiles every configured browser response policy and checks cross-field invariants.
    pub fn compile(config: &BrowserResponsePolicyConfig) -> Result<Self> {
        let policy = Self {
            content_security_policy: config
                .content_security_policy
                .as_deref()
                .map(ContentSecurityPolicy::parse)
                .transpose()?,
            content_security_policy_report_only: config
                .content_security_policy_report_only
                .as_deref()
                .map(ContentSecurityPolicy::parse)
                .transpose()?,
            referrer_policy: config
                .referrer_policy
                .as_deref()
                .map(ReferrerPolicy::parse)
                .transpose()?,
            permissions_policy: config
                .permissions_policy
                .as_deref()
                .map(PermissionsPolicy::parse)
                .transpose()?,
            permissions_policy_report_only: config
                .permissions_policy_report_only
                .as_deref()
                .map(PermissionsPolicy::parse)
                .transpose()?,
            cross_origin_opener_policy: config
                .cross_origin_opener_policy
                .as_deref()
                .map(CrossOriginOpenerPolicy::parse)
                .transpose()?,
            cross_origin_opener_policy_report_only: config
                .cross_origin_opener_policy_report_only
                .as_deref()
                .map(CrossOriginOpenerPolicy::parse)
                .transpose()?,
            cross_origin_embedder_policy: config
                .cross_origin_embedder_policy
                .as_deref()
                .map(CrossOriginEmbedderPolicy::parse)
                .transpose()?,
            cross_origin_embedder_policy_report_only: config
                .cross_origin_embedder_policy_report_only
                .as_deref()
                .map(CrossOriginEmbedderPolicy::parse)
                .transpose()?,
            cross_origin_resource_policy: config
                .cross_origin_resource_policy
                .as_deref()
                .map(CrossOriginResourcePolicy::parse)
                .transpose()?,
            x_content_type_options: config
                .x_content_type_options
                .as_deref()
                .map(ContentTypeOptions::parse)
                .transpose()?,
            origin_agent_cluster: config
                .origin_agent_cluster
                .as_deref()
                .map(OriginAgentCluster::parse)
                .transpose()?,
            clear_site_data: config
                .clear_site_data
                .as_deref()
                .map(ClearSiteData::parse)
                .transpose()?,
            reporting_endpoints: config
                .reporting_endpoints
                .as_deref()
                .map(ReportingEndpoints::parse)
                .transpose()?,
            timing_allow_origin: config
                .timing_allow_origin
                .as_deref()
                .map(TimingAllowOrigin::parse)
                .transpose()?,
            accept_ch: config
                .accept_ch
                .as_deref()
                .map(AcceptClientHints::parse)
                .transpose()?,
            critical_ch: config
                .critical_ch
                .as_deref()
                .map(CriticalClientHints::parse)
                .transpose()?,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validates cross-policy invariants and returns the unchanged policy.
    pub fn validate(&self) -> Result<()> {
        if let Some(critical) = self.critical_ch.as_ref() {
            let Some(accept) = self.accept_ch.as_ref() else {
                return Err(BrowserPolicyError::Inconsistent {
                    detail: "critical_ch requires accept_ch".to_string(),
                });
            };
            if critical.names().iter().any(|name| !accept.0.contains(name)) {
                return Err(BrowserPolicyError::Inconsistent {
                    detail: "every critical client hint must be listed in accept_ch".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Applies all configured response fields after removing upstream copies.
    pub fn apply(&self, headers: &mut HeaderMap) {
        for name in MANAGED_RESPONSE_HEADERS {
            remove_header(headers, name);
        }
        if let Some(policy) = self.content_security_policy.as_ref() {
            insert_header(headers, CONTENT_SECURITY_POLICY, policy.as_str());
        }
        if let Some(policy) = self.content_security_policy_report_only.as_ref() {
            insert_header(
                headers,
                CONTENT_SECURITY_POLICY_REPORT_ONLY,
                policy.as_str(),
            );
        }
        if let Some(policy) = self.referrer_policy.as_ref() {
            insert_header(headers, REFERRER_POLICY, policy.as_str());
        }
        if let Some(policy) = self.permissions_policy.as_ref() {
            insert_header(headers, PERMISSIONS_POLICY, policy.as_str());
        }
        if let Some(policy) = self.permissions_policy_report_only.as_ref() {
            insert_header(headers, PERMISSIONS_POLICY_REPORT_ONLY, policy.as_str());
        }
        if let Some(policy) = self.cross_origin_opener_policy.as_ref() {
            insert_header(
                headers,
                CROSS_ORIGIN_OPENER_POLICY,
                policy.serialize().as_str(),
            );
        }
        if let Some(policy) = self.cross_origin_opener_policy_report_only.as_ref() {
            insert_header(
                headers,
                CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY,
                policy.serialize().as_str(),
            );
        }
        if let Some(policy) = self.cross_origin_embedder_policy.as_ref() {
            insert_header(
                headers,
                CROSS_ORIGIN_EMBEDDER_POLICY,
                policy.serialize().as_str(),
            );
        }
        if let Some(policy) = self.cross_origin_embedder_policy_report_only.as_ref() {
            insert_header(
                headers,
                CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY,
                policy.serialize().as_str(),
            );
        }
        if let Some(policy) = self.cross_origin_resource_policy.as_ref() {
            insert_header(
                headers,
                CROSS_ORIGIN_RESOURCE_POLICY,
                policy.value.to_string().as_str(),
            );
        }
        if self.x_content_type_options.is_some() {
            insert_header(headers, X_CONTENT_TYPE_OPTIONS, "nosniff");
        }
        if let Some(policy) = self.origin_agent_cluster.as_ref() {
            insert_header(
                headers,
                ORIGIN_AGENT_CLUSTER,
                if policy.enabled { "?1" } else { "?0" },
            );
        }
        if let Some(policy) = self.clear_site_data.as_ref() {
            insert_header(headers, CLEAR_SITE_DATA, policy.as_str());
        }
        if let Some(policy) = self.reporting_endpoints.as_ref() {
            insert_header(headers, REPORTING_ENDPOINTS, policy.as_str());
        }
        if let Some(policy) = self.timing_allow_origin.as_ref() {
            insert_header(headers, TIMING_ALLOW_ORIGIN, policy.as_str().as_str());
        }
        if let Some(policy) = self.accept_ch.as_ref() {
            insert_header(headers, ACCEPT_CH, policy.as_str());
        }
        if let Some(policy) = self.critical_ch.as_ref() {
            insert_header(headers, CRITICAL_CH, policy.as_str());
        }
    }

    /// Returns the compiled CSP policy, if configured.
    pub fn content_security_policy(&self) -> Option<&ContentSecurityPolicy> {
        self.content_security_policy.as_ref()
    }

    /// Returns the compiled Fetch-independent response policy state.
    pub fn is_empty(&self) -> bool {
        self.content_security_policy.is_none()
            && self.content_security_policy_report_only.is_none()
            && self.referrer_policy.is_none()
            && self.permissions_policy.is_none()
            && self.permissions_policy_report_only.is_none()
            && self.cross_origin_opener_policy.is_none()
            && self.cross_origin_opener_policy_report_only.is_none()
            && self.cross_origin_embedder_policy.is_none()
            && self.cross_origin_embedder_policy_report_only.is_none()
            && self.cross_origin_resource_policy.is_none()
            && self.x_content_type_options.is_none()
            && self.origin_agent_cluster.is_none()
            && self.clear_site_data.is_none()
            && self.reporting_endpoints.is_none()
            && self.timing_allow_origin.is_none()
            && self.accept_ch.is_none()
            && self.critical_ch.is_none()
    }
}

const MANAGED_RESPONSE_HEADERS: [&str; 17] = [
    CONTENT_SECURITY_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY,
    REFERRER_POLICY,
    PERMISSIONS_POLICY,
    PERMISSIONS_POLICY_REPORT_ONLY,
    CROSS_ORIGIN_OPENER_POLICY,
    CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY,
    CROSS_ORIGIN_EMBEDDER_POLICY,
    CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY,
    CROSS_ORIGIN_RESOURCE_POLICY,
    X_CONTENT_TYPE_OPTIONS,
    ORIGIN_AGENT_CLUSTER,
    CLEAR_SITE_DATA,
    REPORTING_ENDPOINTS,
    TIMING_ALLOW_ORIGIN,
    ACCEPT_CH,
    CRITICAL_CH,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_metadata_parser_is_strict_and_policy_is_deterministic() {
        let mut headers = HeaderMap::new();
        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("same-origin"));
        headers.insert(SEC_FETCH_MODE, HeaderValue::from_static("navigate"));
        headers.insert(SEC_FETCH_DEST, HeaderValue::from_static("document"));
        headers.insert(SEC_FETCH_USER, HeaderValue::from_static("?1"));
        let request = FetchMetadataRequest::parse(&headers)
            .expect("valid Fetch Metadata")
            .expect("metadata present");
        assert_eq!(request.site(), Some(FetchSite::SameOrigin));
        assert_eq!(request.mode(), Some(FetchMode::Navigate));
        assert_eq!(request.destination(), Some(FetchDestination::Document));
        assert!(request.user_activation());
        for value in ["json", "text", "video", "webidentity"] {
            assert!(value.parse::<FetchDestination>().is_ok());
        }

        let policy = FetchMetadataPolicy::compile(&FetchMetadataPolicyConfig {
            allowed_sites: vec![FetchSite::SameOrigin],
            allowed_modes: vec![FetchMode::Navigate],
            allowed_destinations: vec![FetchDestination::Document],
            allow_missing: false,
            require_user_activation_for_navigation: true,
        })
        .expect("valid policy");
        assert!(policy.is_allowed(Some(&request)));
        let mut response_headers = HeaderMap::new();
        response_headers.insert("vary", HeaderValue::from_static("accept-encoding"));
        policy.apply_response_vary(&mut response_headers);
        assert_eq!(
            response_headers["vary"],
            "accept-encoding, sec-fetch-site, sec-fetch-mode, sec-fetch-dest, sec-fetch-user"
        );

        headers.insert(SEC_FETCH_SITE, HeaderValue::from_static("cross-site"));
        let request = FetchMetadataRequest::parse(&headers)
            .expect("valid Fetch Metadata")
            .expect("metadata present");
        assert_eq!(policy.evaluate(Some(&request)), FetchMetadataDecision::Site);

        headers.insert(SEC_FETCH_USER, HeaderValue::from_static("?0"));
        assert_eq!(
            FetchMetadataRequest::parse(&headers),
            Err(invalid(SEC_FETCH_USER, "only ?1 is valid"))
        );
    }

    #[test]
    fn csp_rejects_duplicates_and_canonicalizes_sources() {
        let policy = ContentSecurityPolicy::parse(
            "default-src 'self'; script-src 'unsafe-inline' 'nonce-AbC+/=' https://cdn.example",
        )
        .expect("valid CSP");
        assert_eq!(
            policy.as_str(),
            "default-src 'self'; script-src 'unsafe-inline' 'nonce-AbC+/=' https://cdn.example"
        );
        assert!(ContentSecurityPolicy::parse("default-src 'self'; default-src *").is_err());
        assert!(ContentSecurityPolicy::parse("script-src 'unknown-keyword'").is_err());
    }

    #[test]
    fn browser_response_policy_removes_upstream_values_and_applies_all_fields() {
        let config = BrowserResponsePolicyConfig {
            content_security_policy: Some("default-src 'self'".to_string()),
            content_security_policy_report_only: Some("default-src 'none'".to_string()),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some(
                "geolocation=(self \"https://maps.example\"), camera=()".to_string(),
            ),
            permissions_policy_report_only: Some("camera=()".to_string()),
            cross_origin_opener_policy: Some(
                "same-origin; report-to=\"https://reports.example/coop\"".to_string(),
            ),
            cross_origin_opener_policy_report_only: Some("same-origin".to_string()),
            cross_origin_embedder_policy: Some(
                "require-corp; report-to=\"https://reports.example/coep\"".to_string(),
            ),
            cross_origin_embedder_policy_report_only: Some("credentialless".to_string()),
            cross_origin_resource_policy: Some("same-origin".to_string()),
            x_content_type_options: Some("nosniff".to_string()),
            origin_agent_cluster: Some("?1".to_string()),
            clear_site_data: Some("\"cache\", \"storage\"".to_string()),
            reporting_endpoints: Some("default=\"https://reports.example/csp\"".to_string()),
            timing_allow_origin: Some("https://app.example https://admin.example".to_string()),
            accept_ch: Some("Sec-CH-UA, Sec-CH-UA-Mobile".to_string()),
            critical_ch: Some("Sec-CH-UA-Mobile".to_string()),
        };
        let policy =
            BrowserResponsePolicy::compile(&config).expect("valid browser response policy");
        let mut headers = HeaderMap::new();
        for name in MANAGED_RESPONSE_HEADERS {
            headers.insert(name, HeaderValue::from_static("upstream"));
        }
        headers.insert("x-unmanaged", HeaderValue::from_static("preserve"));
        policy.apply(&mut headers);
        assert_eq!(headers[CONTENT_SECURITY_POLICY], "default-src 'self'");
        assert_eq!(
            headers[CONTENT_SECURITY_POLICY_REPORT_ONLY],
            "default-src 'none'"
        );
        assert_eq!(
            headers[PERMISSIONS_POLICY],
            "geolocation=(self \"https://maps.example\"), camera=()"
        );
        assert_eq!(headers[PERMISSIONS_POLICY_REPORT_ONLY], "camera=()");
        assert_eq!(
            headers[CROSS_ORIGIN_OPENER_POLICY],
            "same-origin; report-to=\"https://reports.example/coop\""
        );
        assert_eq!(headers[X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[ACCEPT_CH], "sec-ch-ua, sec-ch-ua-mobile");
        assert_eq!(headers["x-unmanaged"], "preserve");
    }

    #[test]
    fn structured_and_origin_policies_reject_ambiguous_values() {
        assert!(ClearSiteData::parse("\"*\", \"cache\"").is_err());
        assert!(
            ReportingEndpoints::parse("default=\"https://reports.example/a#fragment\"").is_err()
        );
        assert_eq!(
            ReportingEndpoints::parse("default=\"/reports\"")
                .expect("origin-relative reporting endpoint")
                .as_str(),
            "default=\"/reports\""
        );
        assert!(TimingAllowOrigin::parse("* https://app.example").is_err());
        assert!(TimingAllowOrigin::parse("https://app.example, https://admin.example").is_err());
        assert!(PermissionsPolicy::parse("geolocation=(self none)").is_err());
        assert!(PermissionsPolicy::parse("geolocation=(\"https://*.example.com\")").is_ok());
        assert!(AcceptClientHints::parse("Sec-CH-UA, sec-ch-ua").is_err());
    }

    #[test]
    fn critical_client_hints_must_be_accepted() {
        let config = BrowserResponsePolicyConfig {
            critical_ch: Some("Sec-CH-UA".to_string()),
            ..Default::default()
        };
        let error = BrowserResponsePolicy::compile(&config).expect_err("invalid combination");
        assert!(matches!(error, BrowserPolicyError::Inconsistent { .. }));
    }

    #[test]
    fn individual_apply_methods_are_authoritative() {
        let policy = ReferrerPolicy::parse("origin").expect("valid policy");
        let mut headers = HeaderMap::new();
        headers.append(REFERRER_POLICY, HeaderValue::from_static("unsafe-url"));
        headers.append(REFERRER_POLICY, HeaderValue::from_static("origin"));
        policy.apply(&mut headers);
        assert_eq!(headers.get_all(REFERRER_POLICY).iter().count(), 1);
        assert_eq!(headers[REFERRER_POLICY], "origin");
    }
}
