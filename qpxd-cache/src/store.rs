use super::directives::{parse_request_directives, parse_response_directives};
use super::entry::{
    primary_from_variant_key, resolve_range, response_from_envelope_for_request,
    response_from_envelope_for_request_with_body,
};
use super::freshness::{active_range, freshness_lifetime_secs, initial_age_secs};
use super::types::{
    BodyStreamWriteOptions, CACHE_HEADER, CacheBackend, CacheRequestKey, CacheWritebackAdmission,
    CacheWritebackPermit, CachedBody, CachedHeaders, CachedResponseEnvelope, INDEX_TTL_SECS,
    MAX_CACHE_OBJECT_BYTES, RequestCollapseGuard, ResponseDirectives, RevalidationState,
    VariantIndex, VarySpec, cache_body_storage_key, cache_status_header,
    encode_cached_response_metadata,
};
use super::util::{cache_namespace, load_variant_index, now_millis, upsert_variant_with_cap};
use super::vary::{
    index_storage_key, parse_vary, variant_storage_key, vary_values_from_request_headers,
};
use anyhow::Result;
use http::header::{CONTENT_LOCATION, EXPIRES, SET_COOKIE};
use hyper::{Method, StatusCode};
use qpx_core::config::CachePolicyConfig;
use qpx_core::http_content_length::VarySelector;
use qpx_core::http_message::OwnedHeaderView;
use qpx_core::http_message::Response;
use qpx_core::http_message::{
    Headers as OwnedHeaders, OrdinaryHeaderName, Request as OwnerRequest,
};
use qpx_http::body::Body;

fn ord(name: &str) -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from(name).expect("ordinary header name")
}
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing::warn;

mod body;
pub(crate) mod commit;
use self::body::{expected_body_length, validate_body_length};

const CACHE_WRITEBACK_MIRROR_CHANNEL_CAPACITY: usize = 128;
pub struct CacheStoreTiming {
    pub response_delay_secs: u64,
    pub body_read_timeout: Duration,
    pub request_collapse_guard: Option<RequestCollapseGuard>,
}

pub struct CacheStoreContext<'a> {
    pub timing: CacheStoreTiming,
    pub writeback_admission: &'a CacheWritebackAdmission,
    pub backends: &'a HashMap<String, Arc<dyn CacheBackend>>,
}

pub async fn maybe_store(
    request: &OwnerRequest<()>,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    mut response: Response<Body>,
    context: CacheStoreContext<'_>,
) -> Result<Response<Body>> {
    if !policy.enabled {
        return Ok(response);
    }
    let request_method = request.method();
    let request_headers = request.headers();
    let req = parse_request_directives(request_headers);
    if req.no_store {
        response
            .headers_mut()
            .insert(ord(CACHE_HEADER), cache_status_header("BYPASS", None)?);
        return Ok(response);
    }

    let Some(backend) = context.backends.get(policy.backend.as_str()) else {
        return Ok(response);
    };

    let now = now_millis();
    let resp_directives = parse_response_directives(response.headers());
    let freshness = freshness_lifetime_secs(response.headers(), policy, now, &resp_directives);
    let is_storable = is_response_storable(
        request_headers,
        request_method,
        Some(key),
        &response,
        policy,
        freshness,
        &resp_directives,
    );

    let max_cacheable_body_bytes = policy.max_object_bytes.min(MAX_CACHE_OBJECT_BYTES);
    if !is_storable {
        response
            .headers_mut()
            .insert(ord(CACHE_HEADER), cache_status_header("MISS", None)?);
        return Ok(response);
    }
    let expected_body_length =
        match expected_body_length(request_method, response.status(), response.headers()) {
            Ok(length) => length,
            Err(_) => {
                // Malformed framing is not cacheable, but the client stream is
                // still the protocol writer's responsibility, not the cache's.
                response
                    .headers_mut()
                    .insert(ord(CACHE_HEADER), cache_status_header("MISS", None)?);
                return Ok(response);
            }
        };
    let vary = parse_vary(response.headers());
    let vary = match vary {
        VarySpec::Any => {
            response
                .headers_mut()
                .insert(ord(CACHE_HEADER), cache_status_header("MISS", None)?);
            return Ok(response);
        }
        VarySpec::Fields(v) => v,
    };

    let Some(freshness_lifetime_secs) = freshness else {
        response
            .headers_mut()
            .insert(ord(CACHE_HEADER), cache_status_header("MISS", None)?);
        return Ok(response);
    };

    let Some(writeback_permit) = context.writeback_admission.try_acquire() else {
        super::metrics::writeback_admission_rejected();
        response
            .headers_mut()
            .insert(ord(CACHE_HEADER), cache_status_header("MISS", None)?);
        return Ok(response);
    };

    let storage_key = response_storage_key(request_method, response.headers(), key)
        .unwrap_or_else(|| key.clone());
    let storage_primary = storage_key.primary_hash_arc();
    let initial_age_secs =
        initial_age_secs(response.headers(), now, context.timing.response_delay_secs);
    let Some(vary_values) = cache_vary_values(
        request_headers.view(),
        &vary,
        storage_key.content_digest.as_deref(),
    ) else {
        // Fail-closed: a Vary selector that cannot be represented losslessly
        // (e.g. obs-text) must neither be stored nor served to others.
        response
            .headers_mut()
            .insert(ord(CACHE_HEADER), cache_status_header("MISS", None)?);
        return Ok(response);
    };
    let variant_key = super::vary::representation_storage_key(&variant_storage_key(
        storage_primary.as_ref(),
        &vary_values,
    ));
    let namespace = cache_namespace(policy, "default");
    let ttl = object_retention_ttl_secs(freshness_lifetime_secs, &resp_directives);
    let writeback = CacheWriteback {
        backend: backend.clone(),
        namespace: namespace.to_string(),
        storage_primary,
        variant_key,
        status: response.status().as_u16(),
        headers: CachedHeaders::from_live(response.headers(), &resp_directives),
        stored_at_ms: now,
        initial_age_secs,
        response_delay_secs: context.timing.response_delay_secs,
        freshness_lifetime_secs,
        vary_headers: vary,
        vary_values,
        ttl,
        max_cacheable_body_bytes,
        body_read_timeout: context.timing.body_read_timeout,
        _request_collapse_guard: context.timing.request_collapse_guard,
        _writeback_permit: writeback_permit,
    };

    let (parts, body) = response.into_head_and_body();
    let (primary_body, mut mirrors) = qpx_http::body::tee::tee_body_lossy_with_metrics(
        body,
        vec![Some(max_cacheable_body_bytes)],
        CACHE_WRITEBACK_MIRROR_CHANNEL_CAPACITY,
        Some("cache_writeback"),
    );
    if let Some(mirror_body) = mirrors.pop() {
        tokio::spawn(async move {
            if let Err(err) = writeback
                .store(validate_body_length(mirror_body, expected_body_length))
                .await
            {
                warn!(error = ?err, "cache writeback failed");
            }
        });
    } else {
        warn!("cache writeback mirror was not created");
    }
    let mut response = parts.map_body(|()| primary_body);

    response
        .headers_mut()
        .insert(ord(CACHE_HEADER), cache_status_header("MISS", None)?);
    Ok(response)
}

struct CacheWriteback {
    backend: Arc<dyn CacheBackend>,
    namespace: String,
    storage_primary: Arc<str>,
    variant_key: String,
    status: u16,
    headers: CachedHeaders,
    stored_at_ms: u64,
    initial_age_secs: u64,
    response_delay_secs: u64,
    freshness_lifetime_secs: u64,
    vary_headers: Vec<String>,
    vary_values: Vec<(String, VarySelector)>,
    ttl: u64,
    max_cacheable_body_bytes: usize,
    body_read_timeout: Duration,
    _request_collapse_guard: Option<RequestCollapseGuard>,
    _writeback_permit: CacheWritebackPermit,
}

impl CacheWriteback {
    async fn store(self, body: Body) -> Result<()> {
        let CacheWriteback {
            status,
            headers,
            stored_at_ms,
            initial_age_secs,
            response_delay_secs,
            freshness_lifetime_secs,
            vary_headers,
            vary_values,
            ..
        } = self;
        let response_put = self.backend.put_response(
            self.namespace.as_str(),
            self.variant_key.as_str(),
            body,
            BodyStreamWriteOptions {
                max_body_bytes: self.max_cacheable_body_bytes,
                body_read_timeout: self.body_read_timeout,
                ttl_secs: self.ttl,
            },
            Box::new(move |body_len| {
                record_cache_writeback_body_stream(body_len);
                let envelope = CachedResponseEnvelope {
                    status,
                    headers,
                    body: CachedBody::default(),
                    body_len,
                    stored_at_ms,
                    initial_age_secs,
                    response_delay_secs,
                    freshness_lifetime_secs,
                    vary_headers,
                    vary_values,
                    response_directives: std::sync::OnceLock::new(),
                    response_header_values: std::sync::OnceLock::new(),
                };
                encode_cached_response_metadata(&envelope)
            }),
        );
        // Stage the immutable object before taking publication coordination:
        // backend producers/writers must release their operation permits first.
        let staged = response_put.await;
        let committed: Result<()> = async {
            staged?;
            let obsolete = {
                let _commit = commit::lock(
                    self.backend.as_ref(),
                    &self.namespace,
                    &self.storage_primary,
                )
                .await?;
                let mut index = load_variant_index(
                    self.backend.as_ref(),
                    &self.namespace,
                    &self.storage_primary,
                )
                .await?;
                let legacy_key = variant_storage_key(&self.storage_primary, &[]);
                if legacy_key != self.variant_key {
                    self.backend
                        .retire_response_metadata(&self.namespace, &legacy_key)
                        .await?;
                }
                let obsolete = upsert_variant_with_cap(&mut index, &self.variant_key)
                    .into_iter()
                    // Retirement must preserve a historical body's active readers
                    // even when that canonical key was listed in an old index.
                    .filter(|key| key != &legacy_key)
                    .collect::<Vec<_>>();
                self.backend
                    .put(
                        &self.namespace,
                        &index_storage_key(&self.storage_primary),
                        &serde_json::to_vec(&index)?,
                        self.ttl.max(INDEX_TTL_SECS),
                    )
                    .await?;
                obsolete
            };
            // Delete I/O must not hold the primary commit lock: the index
            // already excludes these variants, and invalidation coordinates
            // through the same lock before this point.
            delete_obsolete_variants(self.backend.clone(), self.namespace.clone(), obsolete).await;
            Ok(())
        }
        .await;
        if let Err(err) = committed {
            invalidate_revalidated(self.backend.as_ref(), &self.namespace, &self.variant_key).await;
            return Err(err);
        }
        Ok(())
    }
}

fn record_cache_writeback_body_stream(bytes: u64) {
    super::metrics::writeback_body_bytes(bytes);
}

async fn delete_obsolete_variants(
    backend: Arc<dyn CacheBackend>,
    namespace: String,
    variants: Vec<String>,
) {
    const DELETE_CONCURRENCY: usize = 16;
    for chunk in variants.chunks(DELETE_CONCURRENCY) {
        let mut tasks = JoinSet::new();
        for variant in chunk {
            let backend = backend.clone();
            let namespace = namespace.clone();
            let variant = variant.clone();
            tasks.spawn(async move {
                let _ = backend.delete(namespace.as_str(), variant.as_str()).await;
                let body_key = cache_body_storage_key(variant.as_str());
                let _ = backend.delete(namespace.as_str(), body_key.as_str()).await;
            });
        }
        while tasks.join_next().await.is_some() {}
    }
}

pub async fn revalidate_not_modified<B>(
    request: &OwnerRequest<B>,
    policy: &CachePolicyConfig,
    not_modified: Response<Body>,
    state: RevalidationState,
    response_delay_secs: u64,
    body_read_timeout: Duration,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<Response<Body>> {
    if !policy.enabled {
        return Ok(not_modified);
    }
    let request_method = request.method();
    let request_headers = request.headers();
    let Some(backend) = backends.get(policy.backend.as_str()) else {
        return Ok(not_modified);
    };

    let now = now_millis();
    let merged_headers = state
        .envelope
        .headers
        .merge_after_304(not_modified.headers());
    let directives = merged_headers.directives();
    let freshness = merged_headers
        .freshness_lifetime_secs(policy, now, &directives)
        .unwrap_or_else(|| policy.default_ttl_secs.unwrap_or(1));
    let parsed_vary_headers = match merged_headers.vary_spec() {
        VarySpec::Fields(fields) => Some(fields),
        VarySpec::Any => None,
    };
    let refreshed_values = parsed_vary_headers.as_deref().and_then(|vary_headers| {
        refreshed_vary_values(
            request_headers.view(),
            vary_headers,
            &state.envelope.vary_values,
        )
    });
    let selectors_unchanged = match (&parsed_vary_headers, &refreshed_values) {
        (Some(vary_headers), Some(vary_values)) => {
            vary_headers == &state.envelope.vary_headers
                && vary_values == &state.envelope.vary_values
                && primary_from_variant_key(state.variant_key.as_str()).is_some_and(|primary| {
                    variant_storage_key(primary, vary_values).as_str()
                        == super::vary::variant_identity(&state.variant_key)
                })
        }
        _ => false,
    };
    let vary_headers = parsed_vary_headers.unwrap_or_else(|| state.envelope.vary_headers.clone());
    let vary_values = refreshed_values.unwrap_or_else(|| state.envelope.vary_values.clone());
    let initial_age_secs = merged_headers.initial_age_secs(now, response_delay_secs);
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        StatusCode::from_u16(state.envelope.status)
            .map_err(|err| anyhow::anyhow!("invalid cached response status: {err}"))?,
        "cached response revalidation",
    )?;

    let policy_storable = merged_headers.is_revalidation_storable(
        status,
        request_headers,
        request_method,
        policy,
        freshness,
        &directives,
    );
    // A changed (or unrepresentable) Vary selector cannot be written under the
    // old variant key. Serve this successful revalidation to its request, but
    // evict the stale variant instead of leaving its metadata inconsistent.
    let storable = policy_storable && selectors_unchanged;
    let sanitized = if policy_storable {
        merged_headers.sanitized(&directives)
    } else {
        merged_headers
    };
    let legacy = primary_from_variant_key(&state.variant_key)
        .filter(|primary| variant_storage_key(primary, &[]) == state.variant_key)
        .map(|_| -> Result<_> {
            Ok(LegacyRefresh {
                original: encode_cached_response_metadata(&state.envelope)?,
                body_len: state.envelope.body_len,
                max_body_bytes: policy.max_object_bytes.min(MAX_CACHE_OBJECT_BYTES),
                body_read_timeout,
            })
        })
        .transpose()?;
    let updated = CachedResponseEnvelope {
        status: state.envelope.status,
        headers: sanitized,
        body: state.envelope.body,
        body_len: state.envelope.body_len,
        stored_at_ms: now,
        initial_age_secs,
        response_delay_secs,
        freshness_lifetime_secs: freshness,
        vary_headers,
        vary_values,
        response_directives: std::sync::OnceLock::new(),
        response_header_values: std::sync::OnceLock::new(),
    };

    let req = parse_request_directives(request_headers);
    let range = active_range(&req, &updated);
    let stream_range = range.and_then(|range| resolve_range(range, updated.body_len));
    // Encode/build before opening a producer, so preparation failures cannot
    // strand a body or mutate metadata while a backend permit is held.
    let refresh = if storable {
        Some((
            encode_cached_response_metadata(&updated)?,
            object_retention_ttl_secs(updated.freshness_lifetime_secs, &directives),
        ))
    } else {
        None
    };
    let response = if *request_method == Method::HEAD || (range.is_some() && stream_range.is_none())
    {
        response_from_envelope_for_request(request_method, &req, &updated, now, "REVALIDATED")?
    } else {
        let expected_len = stream_range
            .map(|(start, end)| end - start + 1)
            .unwrap_or(updated.body_len);
        let mut response = response_from_envelope_for_request_with_body(
            request_method,
            &req,
            &updated,
            now,
            "REVALIDATED",
            Body::empty(),
            expected_len,
        )?;
        let stream = match backend
            .get_object_stream(
                state.namespace.as_str(),
                cache_body_storage_key(state.variant_key.as_str()).as_str(),
                updated.body_len,
                stream_range,
            )
            .await
        {
            Ok(Some(stream)) => stream,
            result => {
                invalidate_revalidated(backend.as_ref(), &state.namespace, &state.variant_key)
                    .await;
                return Err(result.err().unwrap_or_else(|| {
                    anyhow::anyhow!("missing or invalid cached body during revalidation")
                }));
            }
        };
        if stream.len != expected_len {
            drop(stream.body);
            let _ = stream.producer_done.await;
            invalidate_revalidated(backend.as_ref(), &state.namespace, &state.variant_key).await;
            return Err(anyhow::anyhow!(
                "invalid cached body length during revalidation"
            ));
        }
        let backend = backend.clone();
        let namespace = state.namespace;
        let variant_key = state.variant_key;
        *response.body_mut() = body::after_delivery(
            body::validate_body_length(stream.body, Some(expected_len)),
            stream.producer_done,
            move |delivery| async move {
                match (delivery, refresh) {
                    (body::Delivery::Complete, Some((payload, ttl))) => {
                        update_revalidated_metadata(
                            backend.as_ref(),
                            &namespace,
                            &variant_key,
                            &payload,
                            ttl,
                            legacy,
                        )
                        .await;
                    }
                    (body::Delivery::Abandoned, Some(_)) => {}
                    _ => invalidate_revalidated(backend.as_ref(), &namespace, &variant_key).await,
                }
            },
        );
        return Ok(response);
    };

    // HEAD and unsatisfiable ranges have no stored-body producer to wait for.
    if let Some((payload, ttl)) = refresh {
        update_revalidated_metadata(
            backend.as_ref(),
            &state.namespace,
            &state.variant_key,
            &payload,
            ttl,
            legacy,
        )
        .await;
    } else {
        invalidate_revalidated(backend.as_ref(), &state.namespace, &state.variant_key).await;
    }
    Ok(response)
}

struct LegacyRefresh {
    original: Vec<u8>,
    body_len: u64,
    max_body_bytes: usize,
    body_read_timeout: Duration,
}

async fn update_revalidated_metadata(
    backend: &dyn CacheBackend,
    namespace: &str,
    variant_key: &str,
    payload: &[u8],
    ttl: u64,
    legacy: Option<LegacyRefresh>,
) {
    let Some(legacy) = legacy else {
        let _ = backend.put(namespace, variant_key, payload, ttl).await;
        return;
    };
    if let Err(err) =
        migrate_revalidated_legacy(backend, namespace, variant_key, payload, ttl, legacy).await
    {
        warn!(error = ?err, "legacy cache revalidation migration failed");
    }
}

/// A bare canonical fallback is mutable and must never be refreshed in place:
/// a delayed finalizer could undo retirement after the replacement index is
/// evicted. Copy into an immutable generation, then recheck and publish under
/// the same per-primary coordination used by ordinary response writebacks.
async fn migrate_revalidated_legacy(
    backend: &dyn CacheBackend,
    namespace: &str,
    variant_key: &str,
    payload: &[u8],
    ttl: u64,
    legacy: LegacyRefresh,
) -> Result<()> {
    let Some(primary) = primary_from_variant_key(variant_key) else {
        return Ok(());
    };
    // A cheap early check also avoids opening a retired body's producer.
    if legacy_refresh_index(backend, namespace, variant_key, primary, &legacy.original)
        .await?
        .is_none()
    {
        return Ok(());
    }
    let stream = backend
        .get_object_stream(
            namespace,
            &cache_body_storage_key(variant_key),
            legacy.body_len,
            None,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing legacy cache body"))?;
    // Bound both the spool and the producer handoff by the configured
    // body-read timeout so a stalled backend stream cannot retain a
    // task/permit indefinitely. The commit lock is only taken after staging,
    // so a timeout here never holds publication coordination.
    let spool_timeout = legacy.body_read_timeout;
    let body = CachedBody::from_body_limited(
        validate_body_length(stream.body, Some(legacy.body_len)),
        legacy.max_body_bytes,
        spool_timeout,
    )
    .await;
    // Even an unsuccessful spool must release the source producer's permit
    // before any backend operation (including cleanup or publication).
    // Dropping the spooled body wakes backpressured producers; stalled
    // upstream reads are bounded by the backend's own operation timeout, and
    // this handoff timeout keeps a never-signalling producer from hanging the
    // migration task.
    tokio::time::timeout(spool_timeout, stream.producer_done)
        .await
        .map_err(|_| anyhow::anyhow!("legacy body producer timed out"))?
        .map_err(|_| anyhow::anyhow!("legacy body producer failed"))?;
    let body = body?;
    let generation = super::vary::representation_storage_key(variant_key);
    let payload = payload.to_vec();
    let staged = backend
        .put_response(
            namespace,
            &generation,
            body.to_body(),
            BodyStreamWriteOptions {
                max_body_bytes: legacy.max_body_bytes,
                body_read_timeout: legacy.body_read_timeout,
                ttl_secs: ttl,
            },
            Box::new(move |_| Ok(payload)),
        )
        .await;
    let committed = async {
        staged?;
        let committed_pair: (bool, Vec<String>) = {
            let _commit = commit::lock(backend, namespace, primary).await?;
            if let Some(mut index) =
                legacy_refresh_index(backend, namespace, variant_key, primary, &legacy.original)
                    .await?
            {
                backend
                    .retire_response_metadata(namespace, variant_key)
                    .await?;
                // No newer generation can appear between this check and
                // publication: invalidation holds the same per-primary lock.
                let obsolete = upsert_variant_with_cap(&mut index, &generation);
                backend
                    .put(
                        namespace,
                        &index_storage_key(primary),
                        &serde_json::to_vec(&index)?,
                        ttl.max(INDEX_TTL_SECS),
                    )
                    .await?;
                (true, obsolete)
            } else {
                (false, Vec::new())
            }
        };
        let (published, evicted) = committed_pair;
        if !published {
            return Ok(false);
        }
        // Delete I/O must not hold the primary commit lock. The index already
        // excludes these variants; invalidation coordinated through the same
        // lock before publication.
        for key in evicted {
            // The historical body may still have readers. Its metadata was
            // retired above; leave the body to its original retention lifetime.
            if key != variant_key {
                invalidate_revalidated(backend, namespace, &key).await;
            }
        }
        Ok::<_, anyhow::Error>(true)
    }
    .await;
    if !matches!(committed, Ok(true)) {
        // A losing or failed staged generation is never left until TTL unless
        // the backend itself refuses cleanup.
        invalidate_revalidated(backend, namespace, &generation).await;
    }
    committed.map(|_| ())
}

async fn legacy_refresh_index(
    backend: &dyn CacheBackend,
    namespace: &str,
    variant_key: &str,
    primary: &str,
    original: &[u8],
) -> Result<Option<VariantIndex>> {
    let values = backend
        .get_decoded_response_metadata_many(namespace, &[variant_key.to_owned()])
        .await?;
    let Some(current) = values.into_iter().next().flatten() else {
        return Ok(None);
    };
    if encode_cached_response_metadata(&current)? != original {
        return Ok(None);
    }
    let index = load_variant_index(backend, namespace, primary).await?;
    Ok(index
        .variants
        .iter()
        .all(|key| key == variant_key)
        .then_some(index))
}

async fn invalidate_revalidated(backend: &dyn CacheBackend, namespace: &str, variant_key: &str) {
    // Never invalidate the primary/index here: it may already point at a new
    // representation, including another Vary selector. Only this generation is
    // owned by the revalidation that just completed.
    let _ = backend.delete(namespace, variant_key).await;
    let _ = backend
        .delete(namespace, &cache_body_storage_key(variant_key))
        .await;
}

fn object_retention_ttl_secs(freshness_lifetime_secs: u64, directives: &ResponseDirectives) -> u64 {
    let extra = directives
        .stale_while_revalidate
        .unwrap_or(0)
        .max(directives.stale_if_error.unwrap_or(0));
    freshness_lifetime_secs.saturating_add(extra).max(1)
}

pub(super) fn is_response_storable(
    request_headers: &OwnedHeaders,
    request_method: &Method,
    key: Option<&CacheRequestKey>,
    response: &Response<Body>,
    policy: &CachePolicyConfig,
    freshness_lifetime: Option<u64>,
    directives: &ResponseDirectives,
) -> bool {
    if freshness_lifetime.is_none() {
        return false;
    };
    let understands_status_requirements =
        cache_understands_status_storage_requirements(response.status());
    if directives.must_understand && !understands_status_requirements {
        return false;
    }
    if (directives.no_store && !(directives.must_understand && understands_status_requirements))
        || (directives.private && directives.private_fields.is_empty())
    {
        return false;
    }
    if response.headers().contains_key(&ord(SET_COOKIE.as_str())) {
        if !policy.allow_set_cookie_store {
            return false;
        }
        if !directives.public {
            return false;
        }
        match parse_vary(response.headers()) {
            VarySpec::Fields(fields) if fields.iter().any(|name| name == "cookie") => {}
            _ => return false,
        }
    }
    // RFC 9111 §3.5: shared reuse of Authorization-bearing responses requires
    // public, must-revalidate, or s-maxage. proxy-revalidate alone governs
    // stale revalidation, not storage permission (s-maxage implies
    // proxy-revalidate semantics, not the reverse).
    if request_headers.contains_key(&ord("authorization"))
        && !(directives.public || directives.s_maxage.is_some() || directives.must_revalidate)
    {
        return false;
    }
    // Fail-closed: an Authorization-bearing request that clears the RFC 9111
    // §3.5 shared-storage gate must also carry `Vary: Authorization`, or the
    // Vary-less canonical variant would be served to other credentials.
    // Mirrors the `Set-Cookie` gate above; operators whose representations do
    // not vary by credentials can opt out via policy.
    if request_headers.contains_key(&ord("authorization"))
        && !policy.allow_authorization_without_vary_store
    {
        match parse_vary(response.headers()) {
            VarySpec::Fields(fields) if fields.iter().any(|name| name == "authorization") => {}
            _ => return false,
        }
    }
    if response.status().is_informational() {
        return false;
    }
    if response.status() == StatusCode::PARTIAL_CONTENT {
        return false;
    }
    match *request_method {
        Method::GET | Method::HEAD | Method::QUERY => true,
        Method::POST | Method::PATCH => {
            has_explicit_freshness(response.headers(), directives)
                && key
                    .map(|key| content_location_matches_target(response.headers(), key))
                    .unwrap_or(false)
        }
        _ => false,
    }
}

fn response_storage_key(
    request_method: &Method,
    response_headers: &OwnedHeaders,
    key: &CacheRequestKey,
) -> Option<CacheRequestKey> {
    match *request_method {
        Method::GET | Method::HEAD | Method::QUERY => Some(key.clone()),
        Method::POST | Method::PATCH if content_location_matches_target(response_headers, key) => {
            Some(key.with_method_group("GET"))
        }
        _ => None,
    }
}

fn has_explicit_freshness(
    response_headers: &OwnedHeaders,
    directives: &ResponseDirectives,
) -> bool {
    directives.s_maxage.is_some()
        || directives.max_age.is_some()
        || response_headers.contains_key(&ord(EXPIRES.as_str()))
}

fn cache_vary_values(
    request_headers: OwnedHeaderView<'_>,
    vary_headers: &[String],
    content_digest: Option<&str>,
) -> Option<Vec<(String, VarySelector)>> {
    let mut values = vary_values_from_request_headers(request_headers, vary_headers)?;
    if let Some(digest) = content_digest {
        values.push(("@query-content".to_string(), digest.to_string().into()));
    }
    Some(values)
}

fn refreshed_vary_values(
    request_headers: OwnedHeaderView<'_>,
    vary_headers: &[String],
    previous: &[(String, VarySelector)],
) -> Option<Vec<(String, VarySelector)>> {
    let mut values = vary_values_from_request_headers(request_headers, vary_headers)?;
    if let Some(query_content) = previous.iter().find(|(name, _)| name == "@query-content") {
        values.push(query_content.clone());
    }
    Some(values)
}

fn content_location_matches_target(response_headers: &OwnedHeaders, key: &CacheRequestKey) -> bool {
    let Some(raw) = response_headers
        .get(&ord(CONTENT_LOCATION.as_str()))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    let Some(base) = key.absolute_url() else {
        return false;
    };
    let Ok(resolved) = base.join(raw) else {
        return false;
    };
    if resolved.fragment().is_some() {
        return false;
    }
    let Some(authority) = super::key::normalize_url_authority(&resolved) else {
        return false;
    };
    resolved.scheme().eq_ignore_ascii_case(key.scheme.as_ref())
        && authority.as_str() == key.authority.as_ref()
        && resolved.path() == base.path()
        && resolved.query() == base.query()
}

fn cache_understands_status_storage_requirements(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::OK
            | StatusCode::CREATED
            | StatusCode::ACCEPTED
            | StatusCode::NON_AUTHORITATIVE_INFORMATION
            | StatusCode::NO_CONTENT
            | StatusCode::RESET_CONTENT
            | StatusCode::MULTI_STATUS
            | StatusCode::ALREADY_REPORTED
            | StatusCode::MULTIPLE_CHOICES
            | StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
            | StatusCode::BAD_REQUEST
            | StatusCode::UNAUTHORIZED
            | StatusCode::PAYMENT_REQUIRED
            | StatusCode::FORBIDDEN
            | StatusCode::NOT_FOUND
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::NOT_ACCEPTABLE
            | StatusCode::PROXY_AUTHENTICATION_REQUIRED
            | StatusCode::REQUEST_TIMEOUT
            | StatusCode::CONFLICT
            | StatusCode::GONE
            | StatusCode::LENGTH_REQUIRED
            | StatusCode::PRECONDITION_FAILED
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::URI_TOO_LONG
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::RANGE_NOT_SATISFIABLE
            | StatusCode::EXPECTATION_FAILED
            | StatusCode::MISDIRECTED_REQUEST
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::LOCKED
            | StatusCode::FAILED_DEPENDENCY
            | StatusCode::UPGRADE_REQUIRED
            | StatusCode::PRECONDITION_REQUIRED
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            | StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::NOT_IMPLEMENTED
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
            | StatusCode::HTTP_VERSION_NOT_SUPPORTED
            | StatusCode::VARIANT_ALSO_NEGOTIATES
            | StatusCode::INSUFFICIENT_STORAGE
            | StatusCode::LOOP_DETECTED
            | StatusCode::NOT_EXTENDED
            | StatusCode::NETWORK_AUTHENTICATION_REQUIRED
    )
}

#[cfg(test)]
mod tests;
