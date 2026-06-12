use super::super::resolve_upstream;
use super::local::{
    ForwardWebsocketInput, ensure_forward_host_header, forward_authority, proxy_forward_websocket,
};
use super::request_dispatch_cache::prepare_forward_cache_keys;
use super::types::{
    ForwardDispatchPrepareInput, ForwardDispatchPrepareOutcome, ForwardDispatchReady,
};
use crate::http::dispatch::{
    DispatchError, ProxyKind, concurrency_limited_response_for_parts,
    prepare_http_module_local_response,
};
use crate::http::protocol::l7::prepare_request_with_headers_in_place;
use crate::http::protocol::websocket::is_websocket_upgrade;
use crate::policy_context::strip_untrusted_identity_headers;
use tokio::time::Duration;

pub(super) async fn prepare_forward_dispatch(
    input: ForwardDispatchPrepareInput<'_>,
) -> std::result::Result<ForwardDispatchPrepareOutcome, DispatchError> {
    let ForwardDispatchPrepareInput {
        mut req,
        state,
        effective_policy,
        remote_addr,
        proxy_name,
        listener_name,
        selected_plan,
        action,
        headers,
        cache_policy,
        identity,
        request_limits,
        mut request_limit_ctx,
        timeout_override,
        host,
        request_method,
        audit,
    } = input;
    strip_untrusted_identity_headers(
        &state,
        effective_policy,
        remote_addr.ip(),
        req.headers_mut(),
    )?;
    let websocket = is_websocket_upgrade(req.headers());
    prepare_request_with_headers_in_place(&mut req, proxy_name, headers, websocket);
    ensure_forward_host_header(&mut req, host)?;
    let mut http_modules = selected_plan.modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: ProxyKind::Forward,
            proxy_name,
            scope_name: listener_name,
            route_name: None,
            remote_ip: remote_addr.ip(),
            sni: None,
            identity_user: identity.user.as_deref(),
            cache_policy: cache_policy.cloned(),
            cache_default_scheme: Some(req.uri().scheme_str().unwrap_or("http")),
        },
    );
    if let crate::http::modules::RequestHeadersOutcome::Respond(response) =
        http_modules.on_request_headers(&mut req).await?
    {
        let response = prepare_http_module_local_response(
            &mut http_modules,
            *response,
            request_method,
            proxy_name,
            headers,
            audit,
        )
        .await?;
        let response =
            crate::http::capture::stream::limit_response_body_for_plan(response, selected_plan);
        return Ok(ForwardDispatchPrepareOutcome::Response(Box::new(response)));
    }
    let (request_headers_snapshot, cache_lookup_key, cache_target_key) =
        prepare_forward_cache_keys(&req, action, cache_policy)?;
    let upstream = resolve_upstream(action, &state, listener_name)
        .map_err(|err| DispatchError::UpstreamUnavailable(err.to_string()))?;
    request_limit_ctx.upstream = upstream.as_ref().map(|upstream| upstream.key().to_string());
    let Some(_concurrency_permits) = request_limits.acquire_concurrency(&request_limit_ctx) else {
        let response = concurrency_limited_response_for_parts(
            req.method(),
            req.version(),
            proxy_name,
            audit.clone(),
        );
        let response =
            crate::http::capture::stream::limit_response_body_for_plan(response, selected_plan);
        return Err(DispatchError::RateLimited {
            response: Box::new(response),
        });
    };
    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    let http_authority = forward_authority(host, None);
    let export_session = state.export_session_for_plan(selected_plan, remote_addr, &http_authority);
    if websocket {
        let connect_authority = forward_authority(host, Some(80));
        let host_header = forward_authority(host, None);
        let response = proxy_forward_websocket(ForwardWebsocketInput {
            req,
            upstream: upstream.as_ref(),
            connect_authority: connect_authority.as_str(),
            host_header: host_header.as_str(),
            upstream_timeout,
            upgrade_wait_timeout: Duration::from_millis(
                state.plan.limits.timeouts.upgrade_wait_timeout_ms,
            ),
            tunnel_idle_timeout: Duration::from_millis(
                state.plan.limits.timeouts.tunnel_idle_timeout_ms,
            ),
            export_session: export_session.as_ref(),
            request_method,
            proxy_name,
            headers,
            audit,
        })
        .await?;
        return Ok(ForwardDispatchPrepareOutcome::Response(Box::new(response)));
    }
    Ok(ForwardDispatchPrepareOutcome::Prepared(Box::new(
        ForwardDispatchReady {
            req,
            http_modules,
            request_headers_snapshot,
            cache_lookup_key,
            cache_target_key,
            upstream,
            upstream_timeout,
            http_authority,
            export_session,
            _concurrency_permits,
        },
    )))
}
