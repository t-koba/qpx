//! Stored response heads. Historical wire pairs keep their persistence schema;
//! hydration and live responses use opaque headers with owner-backed framing.
use super::*;
use http::header::{AGE, CONTENT_LENGTH, CONTENT_RANGE};
use qpx_core::config::CachePolicyConfig;
use qpx_core::http_message::{CacheFields, OrdinaryHeaderName};

#[derive(Clone, Default)]
pub(crate) struct CachedHeaders {
    fields: CacheFields,
    map: OnceLock<Box<qpx_core::http_message::Headers>>,
}

impl std::fmt::Debug for CachedHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedHeaders").finish_non_exhaustive()
    }
}

impl CachedHeaders {
    #[cfg(test)]
    pub(crate) fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self {
            fields: CacheFields::from_cache_json(&serde_json::to_string(&pairs).unwrap()).unwrap(),
            map: OnceLock::new(),
        }
    }

    fn map(&self) -> &qpx_core::http_message::Headers {
        self.map.get_or_init(|| Box::new(self.fields.hydrate()))
    }

    pub(crate) fn declared_content_length(&self) -> Option<u64> {
        self.fields.declared_content_length()
    }

    /// Lookup cannot expose a stored framing declaration, even for dynamic names.
    pub(crate) fn get(&self, name: http::HeaderName) -> Option<&http::HeaderValue> {
        if name == CONTENT_LENGTH {
            return None;
        }
        self.map().get(&ord(name.as_str()))
    }

    pub(crate) fn directives(&self) -> ResponseDirectives {
        crate::directives::parse_response_directives(self.map())
    }

    pub(crate) fn freshness_lifetime_secs(
        &self,
        policy: &CachePolicyConfig,
        now: u64,
        directives: &ResponseDirectives,
    ) -> Option<u64> {
        crate::freshness::freshness_lifetime_secs(self.map(), policy, now, directives)
    }

    pub(crate) fn initial_age_secs(&self, now: u64, response_delay_secs: u64) -> u64 {
        crate::freshness::initial_age_secs(self.map(), now, response_delay_secs)
    }

    pub(crate) fn merge_after_304(&self, headers: &qpx_core::http_message::Headers) -> Self {
        let connection_nominated = connection_nominated_headers(headers);
        Self {
            fields: self.fields.merge_after_304(
                headers,
                qpx_http::protocol::semantics::is_hop_by_hop_header_name,
                |name| is_304_excluded_header(name, &connection_nominated),
            ),
            map: OnceLock::new(),
        }
    }

    /// Hot admission without a JSON round trip: direct textual capture with
    /// cache no-cache/private filtering. No raw pairs escape this adapter,
    /// and live operations use `map()`.
    pub(crate) fn from_live(
        headers: &qpx_core::http_message::Headers,
        directives: &ResponseDirectives,
    ) -> Self {
        let mut excluded = HashSet::new();
        excluded.extend(directives.no_cache_fields.iter().cloned());
        excluded.extend(directives.private_fields.iter().cloned());
        Self {
            fields: headers.cache_fields(&excluded),
            map: OnceLock::new(),
        }
    }

    pub(crate) fn sanitized(&self, directives: &ResponseDirectives) -> Self {
        Self::from_live(self.map(), directives)
    }

    pub(crate) fn is_revalidation_storable(
        &self,
        status: StatusCode,
        request_headers: &qpx_core::http_message::Headers,
        request_method: &Method,
        policy: &CachePolicyConfig,
        freshness: u64,
        directives: &ResponseDirectives,
    ) -> bool {
        // Storability inspects policy fields, never the stored framing text.
        let mut response = Response::new(Body::empty());
        *response.status_mut() = status;
        *response.headers_mut() = self.map().clone();
        response.headers_mut().remove_content_length();
        response.headers_mut().set_content_length(0);
        crate::store::is_response_storable(
            request_headers,
            request_method,
            None,
            &response,
            policy,
            Some(freshness),
            directives,
        )
    }

    /// Discard stored framing text before writing the computed (or HEAD/range
    /// override) length through the live owner. No raw map leaves persistence.
    pub(crate) fn build_response(
        &self,
        status: StatusCode,
        body: Body,
        length: u64,
        age: http::HeaderValue,
        cache_status: http::HeaderValue,
    ) -> Response<Body> {
        let mut headers = self.map().clone();
        qpx_core::http_message::OrdinaryHeaderMut::ordinary_reserve(&mut headers, 5);
        headers.remove(&ord(AGE.as_str()));
        headers.remove_content_length();
        headers.remove(&ord(CONTENT_RANGE.as_str()));
        headers.insert(ord(AGE.as_str()), age);
        headers.insert(ord(CACHE_HEADER), cache_status);
        headers.set_content_length(length);
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
    }

    #[cfg(test)]
    pub(crate) fn from_hydrated_for_test(headers: http::HeaderMap) -> Self {
        Self {
            fields: CacheFields::default(),
            map: OnceLock::from(Box::new(crate::tests::owned_headers(&headers))),
        }
    }

    #[cfg(test)]
    pub(crate) fn pairs_for_test(&self) -> Vec<(String, String)> {
        serde_json::from_str(&self.fields.to_cache_json().expect("fields encode for test"))
            .expect("fields hydrate to pairs for test")
    }
}

/// Header fields that a 304 response must not merge into the stored entry.
///
/// RFC 9111 §3.2 requires updating stored fields except narrowly justified
/// exclusions: hop-by-hop fields (including `Connection`-nominated ones, which
/// describe only the 304 transport), and the framing labels of the unchanged
/// stored body (`content-length`, `content-encoding`, `content-range`).
/// Everything else — freshness metadata, validators, `Content-Type`, security
/// policy and extension fields — is replaced or added. Policy gates such as
/// `no-store`/`private` or cookie storage remain enforced afterwards by the
/// revalidation-time storability check, not by this merge.
fn is_304_excluded_header(lower_name: &str, connection_nominated: &HashSet<String>) -> bool {
    if connection_nominated.contains(lower_name) {
        return true;
    }
    if qpx_http::protocol::semantics::is_hop_by_hop_header_name(lower_name) {
        return true;
    }
    matches!(
        lower_name,
        "content-length" | "content-encoding" | "content-range"
    )
}

fn connection_nominated_headers(
    not_modified_headers: &qpx_core::http_message::Headers,
) -> HashSet<String> {
    let mut out = HashSet::new();
    for value in not_modified_headers.get_all(&ord(http::header::CONNECTION.as_str())) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value.split(',') {
            let token = token.trim().to_ascii_lowercase();
            if !token.is_empty() {
                out.insert(token);
            }
        }
    }
    out
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedResponseMetadata {
    status: u16,
    headers: Box<serde_json::value::RawValue>,
    body_len: u64,
    stored_at_ms: u64,
    initial_age_secs: u64,
    #[serde(default)]
    response_delay_secs: u64,
    freshness_lifetime_secs: u64,
    vary_headers: Vec<String>,
    vary_values: Vec<(String, VarySelector)>,
}

const CACHE_METADATA_MAGIC: &[u8] = b"QPX-CACHE-META\0\x01";

pub fn encode_cached_response_metadata(envelope: &CachedResponseEnvelope) -> Result<Vec<u8>> {
    let metadata = CachedResponseMetadata {
        status: envelope.status,
        headers: serde_json::value::RawValue::from_string(
            envelope.headers.fields.to_cache_json()?,
        )?,
        body_len: envelope.body_len,
        stored_at_ms: envelope.stored_at_ms,
        initial_age_secs: envelope.initial_age_secs,
        response_delay_secs: envelope.response_delay_secs,
        freshness_lifetime_secs: envelope.freshness_lifetime_secs,
        vary_headers: envelope.vary_headers.clone(),
        vary_values: envelope.vary_values.clone(),
    };
    let metadata = serde_json::to_vec(&metadata)?;
    let mut out = Vec::with_capacity(CACHE_METADATA_MAGIC.len() + metadata.len());
    out.extend_from_slice(CACHE_METADATA_MAGIC);
    out.extend_from_slice(&metadata);
    Ok(out)
}

pub fn decode_cached_response_metadata(raw: Bytes) -> Result<CachedResponseEnvelope> {
    if !raw.starts_with(CACHE_METADATA_MAGIC) {
        return Err(anyhow!("invalid cache metadata format"));
    }
    let metadata: CachedResponseMetadata =
        serde_json::from_slice(&raw[CACHE_METADATA_MAGIC.len()..])?;
    qpx_http::protocol::semantics::validate_http_status_class(
        StatusCode::from_u16(metadata.status)
            .map_err(|err| anyhow!("invalid cached response status: {err}"))?,
        "cached response",
    )?;
    Ok(CachedResponseEnvelope {
        status: metadata.status,
        headers: CachedHeaders {
            fields: CacheFields::from_cache_json(metadata.headers.get())?,
            map: OnceLock::new(),
        },
        body: CachedBody::default(),
        body_len: metadata.body_len,
        stored_at_ms: metadata.stored_at_ms,
        initial_age_secs: metadata.initial_age_secs,
        response_delay_secs: metadata.response_delay_secs,
        freshness_lifetime_secs: metadata.freshness_lifetime_secs,
        vary_headers: metadata.vary_headers,
        vary_values: metadata.vary_values,
        response_directives: OnceLock::new(),
        response_header_values: OnceLock::new(),
    })
}

#[cfg(test)]
mod tests;

fn ord(name: &str) -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from(name).expect("ordinary header name")
}
