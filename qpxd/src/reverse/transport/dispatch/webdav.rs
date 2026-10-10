use crate::reverse::router::HttpRoute;
use anyhow::{Result, anyhow};
use hyper::{Request, Response};
use qpx_http::body::Body;
use std::sync::Arc;

pub(super) fn prepare_direct_webdav_resource(
    req: &mut Request<Body>,
    route: &HttpRoute,
    service: &crate::reverse::router::WebDavOriginService,
) -> Result<qpx_webdav::ResourceId> {
    if let Some(rewrite) = route.path_rewrite.as_ref()
        && rewrite.add_prefix.is_none()
        && rewrite.regex.is_none()
        && req.uri().query().is_none()
        && let Some(prefix) = rewrite.strip_prefix.as_deref()
        && let Some(rest) = req.uri().path().strip_prefix(prefix)
    {
        if rest.is_empty() {
            return service.resource_for_path("/");
        }
        if rest.starts_with('/') {
            return service.resource_for_path(rest);
        }
        return service.resource_for_path(format!("/{rest}").as_str());
    }
    if let Some(rewrite) = route.path_rewrite.as_ref() {
        crate::reverse::transport::path_rewrite::apply_path_rewrite(req, rewrite);
    }
    service.resource_for_path(req.uri().path())
}

pub(super) struct ReverseWebDavDispatch<'a> {
    pub(super) req: Request<Body>,
    pub(super) service: Arc<crate::reverse::router::WebDavOriginService>,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) request_method: &'a http::Method,
    pub(super) request_version: http::Version,
    pub(super) proxy_name: &'a str,
    pub(super) route_headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) max_request_body_bytes: usize,
    pub(super) allow_file_backed: bool,
}

pub(super) async fn dispatch_reverse_webdav(
    input: ReverseWebDavDispatch<'_>,
) -> Result<Response<Body>> {
    let ReverseWebDavDispatch {
        req,
        service,
        identity,
        request_method,
        request_version,
        proxy_name,
        route_headers,
        http_modules,
        max_request_body_bytes,
        allow_file_backed,
    } = input;
    let response = execute_webdav_service(
        req,
        service,
        identity,
        max_request_body_bytes,
        allow_file_backed,
        None,
    )
    .await?;
    let mut response = http_modules.on_upstream_response(response).await?;
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        request_method,
        request_version,
        proxy_name,
        &mut response,
        route_headers,
        false,
    );
    Ok(response)
}

pub(super) async fn execute_webdav_service(
    req: Request<Body>,
    service: Arc<crate::reverse::router::WebDavOriginService>,
    identity: &crate::policy_context::ResolvedIdentity,
    max_request_body_bytes: usize,
    allow_file_backed: bool,
    request_resource: Option<qpx_webdav::ResourceId>,
) -> Result<Response<Body>> {
    let request_resource = match request_resource {
        Some(resource) => resource,
        None => service.resource_for_path(req.uri().path())?,
    };
    let (parts, mut body) = req.into_parts();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let next = collected
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("WebDAV request body length overflow"))?;
        if next > max_request_body_bytes {
            return Err(anyhow!(
                "WebDAV request body exceeds route limit of {} bytes",
                max_request_body_bytes
            ));
        }
        collected.extend_from_slice(&chunk);
    }
    let request = Request::from_parts(parts, collected);
    let context = qpx_webdav::WebDavRequestContext {
        subject: identity.user.clone(),
        tenant: identity.tenant.clone(),
        groups: identity.groups.clone(),
        roles: identity.roles.clone(),
        entitlements: identity.entitlements.clone(),
        assurance: identity.auth_strength.clone(),
    };
    let response = tokio::task::spawn_blocking(move || {
        if allow_file_backed {
            service.handle_bytes_for_resource_file_backed(request, &context, request_resource)
        } else {
            service.handle_bytes_for_resource(request, &context, request_resource)
        }
    })
    .await
    .map_err(|error| anyhow!("WebDAV worker failed: {error}"))??;
    let (mut parts, body) = response.into_parts();
    let file_region = parts.extensions.remove::<qpx_webdav::ResourceFileRegion>();
    let body_len = body.len() as u64;
    let body = Body::from(body).mark_trailers_sanitized();
    if let Some(region) = file_region {
        let body = apply_webdav_file_region(body, body_len, region)?;
        return Ok(Response::from_parts(parts, body));
    }
    Ok(Response::from_parts(parts, body))
}

pub(crate) fn apply_webdav_file_region(
    body: Body,
    body_len: u64,
    region: qpx_webdav::ResourceFileRegion,
) -> Result<Body> {
    if body_len != 0 && region.len != body_len {
        return Err(anyhow!(
            "WebDAV file region length does not match the response body"
        ));
    }
    if region.len >= 64 * 1024 && cfg!(any(target_os = "linux", target_os = "macos")) {
        return Ok(body.with_file_region_for_zero_copy(region.file, region.offset, region.len));
    }
    if body_len != 0 || region.len == 0 {
        return Ok(body);
    }
    let bytes = materialize_webdav_file_region(&region.file, region.offset, region.len)?;
    Ok(Body::from(bytes).mark_trailers_sanitized())
}

fn materialize_webdav_file_region(
    file: &std::fs::File,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>> {
    let length = usize::try_from(length)
        .map_err(|_| anyhow!("WebDAV file region is too large to materialize"))?;
    let mut bytes = vec![0; length];
    let mut filled = 0;
    while filled < bytes.len() {
        #[cfg(unix)]
        let read = std::os::unix::fs::FileExt::read_at(
            file,
            &mut bytes[filled..],
            offset
                .checked_add(filled as u64)
                .ok_or_else(|| anyhow!("WebDAV file region offset overflow"))?,
        )?;
        #[cfg(windows)]
        let read = std::os::windows::fs::FileExt::seek_read(
            file,
            &mut bytes[filled..],
            offset
                .checked_add(filled as u64)
                .ok_or_else(|| anyhow!("WebDAV file region offset overflow"))?,
        )?;
        #[cfg(not(any(unix, windows)))]
        let read = {
            use std::io::{Read, Seek, SeekFrom};
            let mut file = file.try_clone()?;
            file.seek(SeekFrom::Start(
                offset
                    .checked_add(filled as u64)
                    .ok_or_else(|| anyhow!("WebDAV file region offset overflow"))?,
            ))?;
            file.read(&mut bytes[filled..])?
        };
        if read == 0 {
            return Err(anyhow!(
                "WebDAV file region ended before its declared length"
            ));
        }
        filled += read;
    }
    Ok(bytes)
}
