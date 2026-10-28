//! HTTP API lifecycle metadata for RFC 8594 and RFC 9745.

use crate::structured_fields::{BareItem, Date, Integer, ItemSerializer, parse_item};
use http::HeaderMap;
use http::HeaderValue;
use http::header::{HeaderName, LINK};
use qpx_core::http_message::{OrdinaryHeaderMut, OrdinaryHeaderName};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

static DEPRECATION: HeaderName = HeaderName::from_static("deprecation");
static SUNSET: HeaderName = HeaderName::from_static("sunset");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkValue {
    target: String,
    relation: String,
    media_type: Option<String>,
}

impl LinkValue {
    pub fn new(
        target: impl Into<String>,
        relation: impl Into<String>,
    ) -> Result<Self, ApiMetadataError> {
        let value = Self {
            target: target.into(),
            relation: relation.into(),
            media_type: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn with_media_type(
        mut self,
        media_type: impl Into<String>,
    ) -> Result<Self, ApiMetadataError> {
        self.media_type = Some(media_type.into());
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), ApiMetadataError> {
        if self.target.is_empty()
            || self
                .target
                .bytes()
                .any(|byte| byte <= 0x20 || byte == b'>' || byte == 0x7f)
        {
            return Err(ApiMetadataError::InvalidLinkTarget);
        }
        if self.relation.is_empty()
            || self
                .relation
                .split_ascii_whitespace()
                .any(|relation| !valid_relation_type(relation))
        {
            return Err(ApiMetadataError::InvalidLinkRelation);
        }
        if let Some(media_type) = self.media_type.as_deref()
            && (media_type.is_empty() || media_type.bytes().any(|byte| byte < 0x20 || byte == 0x7f))
        {
            return Err(ApiMetadataError::InvalidMediaType);
        }
        Ok(())
    }

    fn serialize(&self) -> Result<String, ApiMetadataError> {
        self.validate()?;
        let mut value = format!("<{}>; rel=\"{}\"", self.target, quote(&self.relation));
        if let Some(media_type) = self.media_type.as_deref() {
            value.push_str("; type=\"");
            value.push_str(&quote(media_type));
            value.push('"');
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ApiMetadata {
    pub deprecation: Option<SystemTime>,
    pub sunset: Option<SystemTime>,
    pub links: Vec<LinkValue>,
}

/// Pre-serialized lifecycle fields for request-independent route metadata.
#[derive(Debug, Clone, Default)]
pub struct PreparedApiMetadata {
    deprecation: Option<HeaderValue>,
    sunset: Option<HeaderValue>,
    links: Vec<HeaderValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApiMetadataError {
    #[error("API lifecycle date is outside the RFC 9651 integer range")]
    DateRange,
    #[error("Sunset must not be earlier than Deprecation")]
    SunsetBeforeDeprecation,
    #[error("Link target is invalid")]
    InvalidLinkTarget,
    #[error("Link relation type is invalid")]
    InvalidLinkRelation,
    #[error("Link media type is invalid")]
    InvalidMediaType,
    #[error("API metadata cannot be represented as an HTTP field value")]
    InvalidHeaderValue,
    #[error("Deprecation is not an RFC 9651 Date item")]
    InvalidDeprecation,
}

impl ApiMetadata {
    pub fn prepare(&self) -> Result<PreparedApiMetadata, ApiMetadataError> {
        if let (Some(deprecation), Some(sunset)) = (self.deprecation, self.sunset)
            && sunset < deprecation
        {
            return Err(ApiMetadataError::SunsetBeforeDeprecation);
        }
        let deprecation = self
            .deprecation
            .map(|deprecation| {
                let seconds = unix_seconds(deprecation)?;
                let integer =
                    Integer::try_from(seconds).map_err(|_| ApiMetadataError::DateRange)?;
                let value = ItemSerializer::new()
                    .bare_item(Date::from_unix_seconds(integer))
                    .finish();
                HeaderValue::from_str(&value).map_err(|_| ApiMetadataError::InvalidHeaderValue)
            })
            .transpose()?;
        let sunset = self
            .sunset
            .map(|sunset| {
                HeaderValue::from_str(&httpdate::fmt_http_date(sunset))
                    .map_err(|_| ApiMetadataError::InvalidHeaderValue)
            })
            .transpose()?;
        let links = self
            .links
            .iter()
            .map(|link| {
                HeaderValue::from_str(&link.serialize()?)
                    .map_err(|_| ApiMetadataError::InvalidHeaderValue)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PreparedApiMetadata {
            deprecation,
            sunset,
            links,
        })
    }

    pub fn apply(&self, headers: &mut HeaderMap) -> Result<(), ApiMetadataError> {
        self.prepare()?.apply(headers);
        Ok(())
    }
}

impl PreparedApiMetadata {
    /// Returns the number of field lines emitted by [`Self::apply`].
    pub fn field_line_count(&self) -> usize {
        usize::from(self.deprecation.is_some())
            + usize::from(self.sunset.is_some())
            + self.links.len()
    }

    pub fn apply(&self, headers: &mut impl OrdinaryHeaderMut) {
        headers.ordinary_reserve(self.field_line_count());
        if let Some(value) = self.deprecation.as_ref()
            && let Ok(name) = OrdinaryHeaderName::try_from(DEPRECATION.clone())
        {
            headers.ordinary_insert(name, value.clone());
        }
        if let Some(value) = self.sunset.as_ref()
            && let Ok(name) = OrdinaryHeaderName::try_from(SUNSET.clone())
        {
            headers.ordinary_insert(name, value.clone());
        }
        if let Ok(name) = OrdinaryHeaderName::try_from(LINK) {
            for value in &self.links {
                headers.ordinary_append(name.clone(), value.clone());
            }
        }
    }
}

pub fn parse_deprecation(value: &HeaderValue) -> Result<SystemTime, ApiMetadataError> {
    let item = parse_item(value.as_bytes()).map_err(|_| ApiMetadataError::InvalidDeprecation)?;
    if !item.params.is_empty() {
        return Err(ApiMetadataError::InvalidDeprecation);
    }
    let BareItem::Date(date) = item.bare_item else {
        return Err(ApiMetadataError::InvalidDeprecation);
    };
    let seconds = i64::from(date.unix_seconds());
    if seconds >= 0 {
        UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(seconds as u64))
            .ok_or(ApiMetadataError::DateRange)
    } else {
        UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(seconds.unsigned_abs()))
            .ok_or(ApiMetadataError::DateRange)
    }
}

fn unix_seconds(value: SystemTime) -> Result<i64, ApiMetadataError> {
    match value.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).map_err(|_| ApiMetadataError::DateRange),
        Err(error) => i64::try_from(error.duration().as_secs())
            .map(|seconds| -seconds)
            .map_err(|_| ApiMetadataError::DateRange),
    }
}

fn valid_relation_type(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'.' | b'+' | b'-' | b'^' | b'_'
                )
        })
}

fn quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercise the reverse terminal mutation order through the same APIs for
    // both containers, including fields whose duplicate/Vary rules differ.
    fn terminal_effects(headers: &mut impl OrdinaryHeaderMut, origin: Option<&str>) {
        use crate::cookie_policy::{CookieSecurityPolicy, SameSite};
        use qpx_core::browser_policy::{
            BrowserResponsePolicy, BrowserResponsePolicyConfig, FetchMetadataPolicy,
            FetchMetadataPolicyConfig, FetchSite,
        };
        use qpx_core::cors::{CorsPolicy, CorsRequest};
        let metadata = ApiMetadata {
            deprecation: Some(UNIX_EPOCH),
            sunset: Some(UNIX_EPOCH + std::time::Duration::from_secs(86400)),
            links: vec![LinkValue::new("/docs", "deprecation").unwrap()],
        }
        .prepare()
        .unwrap();
        metadata.apply(headers);
        headers.ordinary_insert(
            OrdinaryHeaderName::try_from("strict-transport-security").unwrap(),
            HeaderValue::from_static("max-age=60"),
        );
        let cors = CorsPolicy::compile(&qpx_core::config::CorsConfig {
            allowed_origins: vec!["https://app.example".into()],
            allowed_methods: vec!["GET".into()],
            allow_credentials: true,
            allowed_headers: vec![],
            expose_headers: vec![],
            max_age_seconds: None,
            allow_private_network: false,
        })
        .unwrap();
        let mut request = qpx_core::http_message::Request::new(());
        if let Some(origin) = origin {
            request.headers_mut().insert(
                OrdinaryHeaderName::try_from("origin").unwrap(),
                HeaderValue::from_str(origin).unwrap(),
            );
        }
        let request = CorsRequest::parse(request.method(), request.headers()).unwrap();
        cors.apply_actual_response(request.as_ref(), headers);
        CookieSecurityPolicy {
            require_secure: true,
            require_http_only: true,
            same_site: Some(SameSite::Lax),
            require_partitioned: false,
            max_field_bytes: 4096,
        }
        .apply_response(headers, true)
        .unwrap();
        FetchMetadataPolicy::compile(&FetchMetadataPolicyConfig {
            allowed_sites: vec![FetchSite::SameOrigin],
            allowed_modes: vec![],
            allowed_destinations: vec![],
            allow_missing: true,
            require_user_activation_for_navigation: true,
        })
        .unwrap()
        .apply_response_vary(headers);
        BrowserResponsePolicy::compile(&BrowserResponsePolicyConfig {
            referrer_policy: Some("same-origin".into()),
            x_content_type_options: Some("nosniff".into()),
            ..Default::default()
        })
        .unwrap()
        .apply(headers);
    }

    #[test]
    fn terminal_metadata_has_identical_map_and_owner_effects() {
        use qpx_core::http_message::Response;
        for origin in [
            None,
            Some("https://app.example"),
            Some("https://denied.example"),
        ] {
            for vary in ["ORIGIN, Cookie", "*", "Sec-Fetch-Site"] {
                let mut raw = http::Response::new(());
                for (name, value) in [
                    ("link", "</first>; rel=alternate"),
                    ("link", "</second>; rel=next"),
                    ("set-cookie", "first=1; Path=/"),
                    ("set-cookie", "second=2; HttpOnly"),
                    ("vary", "Accept-Encoding"),
                    ("vary", vary),
                    ("referrer-policy", "origin"),
                    ("referrer-policy", "unsafe-url"),
                    ("access-control-allow-origin", "upstream"),
                    ("deprecation", "upstream"),
                    ("deprecation", "duplicate"),
                    ("content-length", "0"),
                ] {
                    raw.headers_mut()
                        .append(name, HeaderValue::from_str(value).unwrap());
                }
                let mut opaque = HeaderValue::from_bytes(b"opaque\xff").unwrap();
                opaque.set_sensitive(true);
                raw.headers_mut().append("x-opaque", opaque);
                let mut owner = Response::from_http(raw.clone());
                terminal_effects(raw.headers_mut(), origin);
                terminal_effects(owner.headers_mut(), origin);
                let exported = owner.into_http_for_codec().unwrap();
                assert_eq!(raw.headers(), exported.headers());
                // HeaderMap equality alone does not prove occurrence order or sensitivity.
                for name in raw.headers().keys() {
                    let snapshot = |map: &HeaderMap| {
                        map.get_all(name)
                            .iter()
                            .map(|v| (v.as_bytes().to_vec(), v.is_sensitive()))
                            .collect::<Vec<_>>()
                    };
                    assert_eq!(
                        snapshot(raw.headers()),
                        snapshot(exported.headers()),
                        "{name}"
                    );
                }
                assert_eq!(
                    raw.headers()
                        .get_all("link")
                        .iter()
                        .map(|v| v.to_str().unwrap())
                        .collect::<Vec<_>>(),
                    [
                        "</first>; rel=alternate",
                        "</second>; rel=next",
                        "</docs>; rel=\"deprecation\""
                    ]
                );
                assert_eq!(
                    raw.headers()
                        .get_all("set-cookie")
                        .iter()
                        .map(|v| v.to_str().unwrap())
                        .collect::<Vec<_>>(),
                    [
                        "first=1; Path=/; Secure; HttpOnly; SameSite=Lax",
                        "second=2; Secure; HttpOnly; SameSite=Lax"
                    ]
                );
                assert_eq!(raw.headers()["referrer-policy"], "same-origin");
                assert_eq!(raw.headers()["x-content-type-options"], "nosniff");
                assert_eq!(raw.headers()["content-length"], "0");
                assert_eq!(
                    raw.headers().contains_key("access-control-allow-origin"),
                    origin == Some("https://app.example")
                );
                let members =
                    qpx_core::http_token::header_value_members(raw.headers(), &http::header::VARY)
                        .collect::<Vec<_>>();
                assert_eq!(members[0], "Accept-Encoding");
                for dimension in [
                    "sec-fetch-site",
                    "sec-fetch-mode",
                    "sec-fetch-dest",
                    "sec-fetch-user",
                ] {
                    assert_eq!(
                        members
                            .iter()
                            .filter(|v| v.eq_ignore_ascii_case(dimension))
                            .count(),
                        1
                    );
                }
                if vary == "*" {
                    assert!(members.contains(&"*"));
                }
            }
        }
    }

    #[test]
    fn ordinary_metadata_effects_do_not_touch_framing_distinctions() {
        use qpx_core::http_content_length::declared_content_length;
        use qpx_core::http_message::Response;
        for declarations in [vec![], vec!["0"], vec!["invalid"], vec!["1", "2"]] {
            let mut raw = http::Response::new(());
            for value in declarations {
                raw.headers_mut()
                    .append("content-length", HeaderValue::from_str(value).unwrap());
            }
            let before = declared_content_length(raw.headers());
            let mut owner = Response::from_http(raw.clone());
            terminal_effects(raw.headers_mut(), None);
            terminal_effects(owner.headers_mut(), None);
            assert_eq!(declared_content_length(raw.headers()), before);
            assert_eq!(owner.headers().declared_content_length(), before);
        }
    }

    #[test]
    fn cookie_errors_leave_both_containers_unchanged() {
        use crate::cookie_policy::CookieSecurityPolicy;
        use qpx_core::http_message::Response;
        let policy = CookieSecurityPolicy {
            require_secure: true,
            require_http_only: false,
            same_site: None,
            require_partitioned: false,
            max_field_bytes: 16,
        };
        for (value, secure) in [
            (HeaderValue::from_static("a=1"), false),
            (HeaderValue::from_static("a=too-long-for-the-limit"), true),
            (HeaderValue::from_bytes(b"a=\xff").unwrap(), true),
        ] {
            let mut raw = http::Response::new(());
            raw.headers_mut()
                .append("set-cookie", HeaderValue::from_static("first=1"));
            raw.headers_mut().append("set-cookie", value);
            let before = raw.headers().clone();
            let mut owner = Response::from_http(raw.clone());
            let raw_error = policy
                .apply_response(raw.headers_mut(), secure)
                .unwrap_err()
                .to_string();
            let owner_error = policy
                .apply_response(owner.headers_mut(), secure)
                .unwrap_err()
                .to_string();
            assert_eq!(raw_error, owner_error);
            assert_eq!(raw.headers(), &before);
            assert_eq!(owner.into_http_for_codec().unwrap().headers(), &before);
        }
    }

    #[test]
    fn emits_deprecation_sunset_and_documentation_link() {
        let deprecation = UNIX_EPOCH + std::time::Duration::from_secs(1_688_169_599);
        let sunset = UNIX_EPOCH + std::time::Duration::from_secs(1_719_791_999);
        let metadata = ApiMetadata {
            deprecation: Some(deprecation),
            sunset: Some(sunset),
            links: vec![
                LinkValue::new("https://developer.example.com/deprecation", "deprecation")
                    .expect("link")
                    .with_media_type("text/html")
                    .expect("media type"),
            ],
        };
        let mut headers = HeaderMap::new();
        metadata.apply(&mut headers).expect("metadata");
        assert_eq!(headers.get("deprecation").expect("field"), "@1688169599");
        assert_eq!(
            parse_deprecation(headers.get("deprecation").expect("field")),
            Ok(deprecation)
        );
        assert_eq!(
            headers.get("sunset").expect("field"),
            "Sun, 30 Jun 2024 23:59:59 GMT"
        );
        assert_eq!(
            headers.get("link").expect("field"),
            "<https://developer.example.com/deprecation>; rel=\"deprecation\"; type=\"text/html\""
        );
    }

    #[test]
    fn rejects_sunset_before_deprecation() {
        let metadata = ApiMetadata {
            deprecation: Some(UNIX_EPOCH + std::time::Duration::from_secs(2)),
            sunset: Some(UNIX_EPOCH + std::time::Duration::from_secs(1)),
            links: Vec::new(),
        };
        assert_eq!(
            metadata.apply(&mut HeaderMap::new()),
            Err(ApiMetadataError::SunsetBeforeDeprecation)
        );
    }
}
