use super::{ReverseModuleDispatch, ReverseModuleInput, ReverseModuleOutcome};
use crate::http::dispatch::{ProxyKind, prepare_http_module_local_response};
use crate::http::protocol::l7::apply_request_header_control_in_place;
use crate::policy_context::strip_untrusted_identity_headers;
use crate::reverse::transport::path_rewrite::apply_path_rewrite;
use anyhow::Result;

pub(super) async fn prepare_reverse_modules(
    input: ReverseModuleInput<'_>,
) -> Result<ReverseModuleOutcome> {
    let ReverseModuleInput {
        base,
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
    // Reverse routing can fall back to SNI when the request has no HTTP authority.
    let module_authority = base.authority().or(base.host()).or(base.sni.as_deref());
    let ingress_scheme = if conn.tls_terminated { "https" } else { "http" };
    let module_scheme = req.uri().scheme_str().unwrap_or(ingress_scheme).to_owned();
    strip_untrusted_identity_headers(
        state,
        selected_policy,
        conn.remote_addr.ip(),
        req.headers_mut(),
    )?;
    if let Some(rewrite) = route.path_rewrite.as_ref() {
        apply_path_rewrite(&mut req, rewrite);
    }
    apply_request_header_control_in_place(&mut req, route_headers);
    let request_cache_policy = route.plan.cache.as_ref().filter(|_| !cache_bypass).cloned();
    let mut http_modules = route.plan.modules.start_for_request(state, &req, || {
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: ProxyKind::Reverse,
            proxy_name,
            scope_name: reverse_name,
            route_name: route.name.as_deref(),
            remote_ip: conn.remote_addr.ip(),
            sni: conn.tls_sni.as_deref(),
            identity_user: identity.user.as_deref(),
            cache_policy: request_cache_policy.clone(),
            cache_default_scheme: Some(ingress_scheme),
        }
    });
    http_modules.preserve_request_authority(module_authority, &module_scheme);
    if http_modules.is_empty() {
        return Ok(ReverseModuleOutcome::Continue(ReverseModuleDispatch {
            req,
            http_modules,
            request_cache_policy,
        }));
    }
    match http_modules.on_request_headers(&mut req).await? {
        crate::http::modules::RequestHeadersOutcome::Continue => {
            Ok(ReverseModuleOutcome::Continue(ReverseModuleDispatch {
                req,
                http_modules,
                request_cache_policy,
            }))
        }
        crate::http::modules::RequestHeadersOutcome::Respond(response) => {
            let response = prepare_http_module_local_response(
                &mut http_modules,
                *response,
                &audit_ctx.request_method,
                proxy_name,
                route_headers,
                audit_ctx,
            )
            .await?;
            Ok(ReverseModuleOutcome::Response(Box::new(response)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::dispatch::DispatchAuditContext;
    use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
    use crate::reverse::router::ReverseRouter;
    use crate::reverse::transport::ReverseConnInfo;
    use crate::runtime::Runtime;
    use crate::test_util::{changed_host_control, uri_rewrite_registry};
    use qpx_core::http_message::Request;
    use qpx_http::body::Body;

    #[tokio::test]
    async fn reverse_modules_pin_routing_authority_before_host_control() {
        for tls in [false, true] {
            let scheme = if tls { "https" } else { "http" };
            let port = if tls { 443 } else { 80 };
            let other_scheme = if tls { "http" } else { "https" };
            let other_port = if tls { 80 } else { 443 };
            for (original, host, target_scheme) in [
                ("/old".to_owned(), Some("selected.test"), None),
                (
                    format!("{scheme}://selected.test/old"),
                    Some("selected.test"),
                    Some(scheme),
                ),
                (
                    format!("{other_scheme}://selected.test/old"),
                    Some("selected.test"),
                    Some(other_scheme),
                ),
                (format!("{scheme}://selected.test/old"), None, Some(scheme)),
                ("/old".to_owned(), None, None),
            ] {
                let selected_authority = if !original.starts_with('/') || host.is_some() {
                    Some("selected.test")
                } else if tls {
                    Some("sni.test")
                } else {
                    None
                };
                let request_scheme = target_scheme.unwrap_or(scheme);
                let request_port = if request_scheme == "https" { 443 } else { 80 };
                for (rewrite, allowed) in [
                    (format!("{request_scheme}://changed.test/new"), false),
                    ("/new?q=1".to_owned(), true),
                    (
                        format!("{request_scheme}://SELECTED.test:{request_port}/new?q=1"),
                        selected_authority == Some("selected.test"),
                    ),
                    (
                        format!("{request_scheme}://sni.test/new"),
                        selected_authority == Some("sni.test"),
                    ),
                    (
                        format!("{other_scheme}://SELECTED.test:{other_port}/new?q=1"),
                        selected_authority == Some("selected.test")
                            && request_scheme == other_scheme,
                    ),
                ] {
                    let registry = uri_rewrite_registry(
                        &rewrite,
                        if original.starts_with('/') {
                            "changed.test"
                        } else {
                            "selected.test"
                        },
                    );
                    let runtime = Runtime::with_http_module_registry(
                        serde_yaml::from_str("{}").unwrap(),
                        registry.clone(),
                    )
                    .unwrap();
                    let state = runtime.state();
                    let config = serde_yaml::from_str(
                        "name: test\nlisten: 127.0.0.1:0\nroutes:\n  - name: selected\n    match: {}\n    target: { type: upstream, upstreams: [backend] }\n    http_modules: [{ type: rewrite }]",
                    ).unwrap();
                    let upstreams = vec![
                        serde_yaml::from_str("name: backend\nurl: http://127.0.0.1:8080").unwrap(),
                    ];
                    let router = ReverseRouter::new(config, &upstreams, &registry).unwrap();
                    let route = router.route_at(0).unwrap();
                    let mut request = http::Request::builder().uri(&original);
                    if let Some(host) = host {
                        request = request.header(http::header::HOST, host);
                    }
                    let req = Request::from_http(request.body(Body::empty()).unwrap());
                    let mut conn = ReverseConnInfo::plain("127.0.0.1:1234".parse().unwrap(), port);
                    conn.tls_terminated = tls;
                    conn.tls_sni = tls.then(|| "sni.test".into());
                    let base = extract_base_request_fields(
                        &req,
                        BaseRequestContext {
                            shared_sni: conn.tls_sni.clone(),
                            scheme: Some(if tls {
                                http::uri::Scheme::HTTPS
                            } else {
                                http::uri::Scheme::HTTP
                            }),
                            ..Default::default()
                        },
                    );
                    let audit = DispatchAuditContext::new(
                        None,
                        ProxyKind::Reverse,
                        None,
                        conn.remote_addr,
                        http::Method::GET,
                        None,
                        Default::default(),
                    );
                    let result = prepare_reverse_modules(ReverseModuleInput {
                        base: &base,
                        req,
                        state: &state,
                        selected_policy: &Default::default(),
                        conn: &conn,
                        route,
                        reverse_name: "test",
                        proxy_name: "test",
                        identity: &Default::default(),
                        route_headers: Some(&changed_host_control()),
                        cache_bypass: false,
                        audit_ctx: &audit,
                    })
                    .await;
                    if allowed {
                        let ReverseModuleOutcome::Response(response) = result.unwrap() else {
                            panic!("module response")
                        };
                        assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
                    } else {
                        let Err(err) = result else {
                            panic!("authority rewrite accepted: {original} -> {rewrite}")
                        };
                        assert!(err.to_string().contains("request URI authority changed"));
                    }
                }
            }
        }
    }
}
