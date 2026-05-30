use super::{ReverseModuleDispatch, ReverseModuleInput, ReverseModuleOutcome};
use crate::http::dispatch::annotate_dispatch_response;
use crate::http::protocol::header_control::apply_request_headers;
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use crate::policy_context::strip_untrusted_identity_headers;
use crate::reverse::transport::path_rewrite::apply_path_rewrite;
use anyhow::Result;

pub(super) async fn prepare_reverse_modules(
    input: ReverseModuleInput<'_>,
) -> Result<ReverseModuleOutcome> {
    let ReverseModuleInput {
        mut req,
        state,
        selected_policy,
        conn,
        route,
        reverse_name,
        proxy_name,
        identity,
        route_headers,
        cache_bypass,
        audit_ctx,
    } = input;
    strip_untrusted_identity_headers(
        state,
        selected_policy,
        conn.remote_addr.ip(),
        req.headers_mut(),
    )?;
    if let Some(rewrite) = route.path_rewrite.as_ref() {
        apply_path_rewrite(&mut req, rewrite);
    }
    apply_request_headers(req.headers_mut(), route_headers);
    let request_cache_policy = route.plan.cache.as_ref().filter(|_| !cache_bypass).cloned();
    let mut http_modules = route.plan.modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: crate::http::dispatch::ProxyKind::Reverse,
            proxy_name,
            scope_name: reverse_name,
            route_name: route.name.as_deref(),
            remote_ip: conn.remote_addr.ip(),
            sni: conn.tls_sni.as_deref(),
            identity_user: identity.user.as_deref(),
            cache_policy: request_cache_policy.clone(),
            cache_default_scheme: Some(if conn.tls_terminated { "https" } else { "http" }),
        },
    );
    match http_modules.on_request_headers(&mut req).await? {
        crate::http::modules::RequestHeadersOutcome::Continue => Ok(
            ReverseModuleOutcome::Continue(Box::new(ReverseModuleDispatch {
                req,
                http_modules,
                request_cache_policy,
            })),
        ),
        crate::http::modules::RequestHeadersOutcome::Respond(response) => {
            let mut response = http_modules.prepare_downstream_response(*response).await?;
            let response_version = response.version();
            finalize_response_with_headers_in_place(
                &audit_ctx.request_method,
                response_version,
                proxy_name,
                &mut response,
                route_headers,
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_dispatch_response(
                &mut response,
                audit_ctx,
                crate::http::dispatch::DispatchOutcome::HttpModuleLocalResponse,
                &[],
            );
            Ok(ReverseModuleOutcome::Response(Box::new(response)))
        }
    }
}
