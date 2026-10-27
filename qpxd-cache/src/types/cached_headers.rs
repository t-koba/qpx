//! Stored response heads. Only this module can project the historical wire pairs
//! or hydrate a raw map; consumers see typed length and non-framing operations.
use super::*;
use http::header::{AGE, CONTENT_LENGTH, CONTENT_RANGE};
use qpx_core::config::CachePolicyConfig;

#[derive(Clone, Default)]
pub(crate) struct CachedHeaders {
    pairs: Vec<(String, String)>,
    map: OnceLock<Box<http::HeaderMap>>,
}

impl std::fmt::Debug for CachedHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedHeaders").finish_non_exhaustive()
    }
}

impl CachedHeaders {
    // Ingress only: no inverse projection is available to cache consumers.
    pub(crate) fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self {
            pairs,
            map: OnceLock::new(),
        }
    }

    fn map(&self) -> &http::HeaderMap {
        self.map
            .get_or_init(|| Box::new(header_map_from_vec(&self.pairs)))
    }

    pub(crate) fn declared_content_length(&self) -> Option<u64> {
        qpx_core::http_content_length::declared_content_length_in_named_values(
            self.pairs.iter().map(|(name, value)| (name, value)),
        )
        .ok()
        .flatten()
    }

    /// Lookup cannot expose a stored framing declaration, even for dynamic names.
    pub(crate) fn get(&self, name: http::HeaderName) -> Option<&http::HeaderValue> {
        if name == CONTENT_LENGTH {
            return None;
        }
        self.map().get(name)
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

    pub(crate) fn merge_after_304(&self, headers: &http::HeaderMap) -> Self {
        Self::from_pairs(merge_headers_after_304(&self.pairs, headers))
    }

    pub(crate) fn sanitized(&self, directives: &ResponseDirectives) -> Self {
        Self::from_pairs(crate::util::sanitize_cached_headers_for_storage(
            self.map(),
            directives,
        ))
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
        response.headers_mut().remove(CONTENT_LENGTH);
        response.headers_mut().insert(
            CONTENT_LENGTH,
            qpx_core::http_content_length::canonical_content_length_value(0),
        );
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

    /// Egress is the only map projection: discard stored framing text before
    /// writing the computed (or HEAD/range override) length as one decimal.
    pub(crate) fn build_response(
        &self,
        status: StatusCode,
        body: Body,
        length: u64,
        age: http::HeaderValue,
        cache_status: http::HeaderValue,
    ) -> Response<Body> {
        let mut headers = qpx_http::header_pool::clone_map_with_additional_capacity(self.map(), 5);
        headers.remove(AGE);
        headers.remove(CONTENT_LENGTH);
        headers.remove(CONTENT_RANGE);
        headers.insert(AGE, age);
        headers.insert(CACHE_HEADER, cache_status);
        headers.insert(
            CONTENT_LENGTH,
            qpx_core::http_content_length::canonical_content_length_value(length),
        );
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
    }

    #[cfg(test)]
    pub(crate) fn from_hydrated_for_test(headers: http::HeaderMap) -> Self {
        Self {
            pairs: Vec::new(),
            map: OnceLock::from(Box::new(headers)),
        }
    }
}

fn header_map_from_vec(headers: &[(String, String)]) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for (name, value) in headers {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::from_str(value.as_str()) else {
            continue;
        };
        out.append(name, value);
    }
    out
}

fn merge_headers_after_304(
    cached_headers: &[(String, String)],
    not_modified_headers: &http::HeaderMap,
) -> Vec<(String, String)> {
    // RFC 9111 §3.2: update the stored headers with each field provided in the
    // 304, replacing existing values, except fields that must not be persisted
    // for the stored representation (unchanged body bytes).
    let connection_nominated = connection_nominated_headers(not_modified_headers);
    let mut nm = std::collections::HashMap::<String, Vec<String>>::new();
    for (name, value) in not_modified_headers {
        let lower = name.as_str().to_ascii_lowercase();
        if is_304_excluded_header(lower.as_str(), &connection_nominated) {
            continue;
        }
        let Ok(value) = value.to_str() else {
            continue;
        };
        nm.entry(lower).or_default().push(value.to_string());
    }

    let mut out = Vec::new();
    let mut replaced = HashSet::new();
    let mut saw = HashSet::new();

    for (name, value) in cached_headers {
        let lower = name.to_ascii_lowercase();
        if qpx_http::protocol::semantics::is_hop_by_hop_header_name(lower.as_str()) {
            continue;
        }
        saw.insert(lower.clone());

        // Excluded 304 fields never reach `nm`, so stored framing labels and
        // other kept fields always survive here unchanged.
        if let Some(values) = nm.get(lower.as_str()) {
            if replaced.insert(lower.clone()) {
                for v in values {
                    out.push((name.clone(), v.clone()));
                }
            }
            continue;
        }
        out.push((name.clone(), value.clone()));
    }

    for (name, values) in nm {
        if saw.contains(name.as_str()) {
            continue;
        }
        for v in values {
            out.push((name.clone(), v));
        }
    }

    out
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

fn connection_nominated_headers(not_modified_headers: &http::HeaderMap) -> HashSet<String> {
    let mut out = HashSet::new();
    for value in not_modified_headers
        .get_all(http::header::CONNECTION)
        .iter()
    {
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
    headers: Vec<(String, String)>,
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
        headers: envelope.headers.pairs.clone(),
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
        headers: CachedHeaders::from_pairs(metadata.headers),
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
