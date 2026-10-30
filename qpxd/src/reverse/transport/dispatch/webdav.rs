use crate::reverse::router::HttpRoute;
use anyhow::{Result, anyhow};
use qpx_core::http_message::{Request as OwnerRequest, Response as OwnerResponse};
use qpx_http::body::Body;
use std::sync::Arc;

pub(super) fn prepare_direct_webdav_resource(
    req: &mut OwnerRequest<Body>,
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
    pub(super) req: OwnerRequest<Body>,
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
) -> Result<OwnerResponse<Body>> {
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
    req: OwnerRequest<Body>,
    service: Arc<crate::reverse::router::WebDavOriginService>,
    identity: &crate::policy_context::ResolvedIdentity,
    max_request_body_bytes: usize,
    allow_file_backed: bool,
    request_resource: Option<qpx_webdav::ResourceId>,
) -> Result<OwnerResponse<Body>> {
    let request_resource = match request_resource {
        Some(resource) => resource,
        None => service.resource_for_path(req.uri().path())?,
    };
    let request = collect_webdav_request(req, max_request_body_bytes).await?;
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
    let (mut head, body) = OwnerResponse::from_http(response).into_head_and_body();
    let file_region = head
        .extensions_mut()
        .remove::<qpx_webdav::ResourceFileRegion>();
    let body_len = body.len() as u64;
    let body = Body::from(body).mark_trailers_sanitized();
    if let Some(region) = file_region {
        let body = apply_webdav_file_region(body, body_len, region)?;
        return Ok(head.map_body(|()| body));
    }
    Ok(head.map_body(|()| body))
}

async fn collect_webdav_request(
    req: OwnerRequest<Body>,
    max_request_body_bytes: usize,
) -> Result<OwnerRequest<Vec<u8>>> {
    let (head, mut body) = req.into_head_and_body();
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
    Ok(head.map_body(|()| collected))
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

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::http_message::OrdinaryHeaderName;

    #[tokio::test]
    async fn request_collection_enforces_limit_and_preserves_owned_head() {
        let request = OwnerRequest::from_http(
            http::Request::builder()
                .method("PUT")
                .uri("/resource")
                .header("x-test", "first")
                .header("x-test", "second")
                .body(Body::from("abc"))
                .unwrap(),
        );
        let request = collect_webdav_request(request, 3).await.unwrap();
        assert_eq!(request.method(), http::Method::PUT);
        assert_eq!(request.uri().path(), "/resource");
        assert_eq!(request.body(), b"abc");
        let name = OrdinaryHeaderName::try_from("x-test").unwrap();
        let values: Vec<_> = request
            .headers()
            .get_all(&name)
            .map(|v| v.as_bytes())
            .collect();
        assert_eq!(values, [b"first".as_slice(), b"second".as_slice()]);

        let request = OwnerRequest::new(Body::from("abcd"));
        let error = collect_webdav_request(request, 3).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "WebDAV request body exceeds route limit of 3 bytes"
        );
        assert!(
            collect_webdav_request(OwnerRequest::new(Body::from("")), 0)
                .await
                .is_ok()
        );
        assert!(
            collect_webdav_request(OwnerRequest::new(Body::from("a")), 0)
                .await
                .is_err()
        );
    }
}
