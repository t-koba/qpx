use super::super::mirrors::record_reverse_upstream_status;
use super::super::request_template::{ReverseReplayRecorder, ReverseRequestTemplate};
use super::super::{InterimList, empty_interim_response};
use super::{
    ReverseAttemptOutcome, ReverseResponseRuleContinue, ReverseResponseRuleInput,
    consume_reverse_retry_budget, reverse_retry_backoff,
};
use crate::http::dispatch::DispatchResponsePolicyOutcome;
use crate::ipc_client::proxy_ipc;
use crate::reverse::router::HttpRoute;
use crate::upstream::origin::{
    OriginEndpoint, proxy_http, proxy_http_with_interim_timeout,
    proxy_http_with_interim_timeout_on_connection,
};
use anyhow::{Result, anyhow};
use hyper::{Request, Response};
use qpx_http::body::Body;
use tokio::time::{Duration, timeout};
use url::Url;

pub(super) async fn reverse_continue_response_rule(
    input: ReverseResponseRuleInput<'_>,
) -> Result<std::result::Result<ReverseResponseRuleContinue, ReverseAttemptOutcome>> {
    let ReverseResponseRuleInput {
        response_rule,
        http_modules,
        state,
        route,
        selected_upstream,
        attempt_idx,
        attempts,
        started,
    } = input;
    match response_rule {
        DispatchResponsePolicyOutcome::Continue {
            response,
            headers,
            cache_bypass,
            policy_tags,
            suppress_retry,
            mirror,
        } => {
            if response.status().is_server_error() && attempt_idx + 1 < attempts && !suppress_retry
            {
                if let Some(upstream) = selected_upstream {
                    record_reverse_upstream_status(
                        upstream,
                        &route.policy,
                        response.status(),
                        started,
                    );
                }
                let retry_reason = format!("upstream returned {}", response.status());
                let err = anyhow!(retry_reason.clone());
                if !consume_reverse_retry_budget(state, route) {
                    return Ok(Err(ReverseAttemptOutcome::Stop(err)));
                }
                http_modules
                    .on_retry(attempt_idx + 2, retry_reason.as_str())
                    .await?;
                reverse_retry_backoff(route).await;
                return Ok(Err(ReverseAttemptOutcome::Retry(err)));
            }
            Ok(Ok((response, headers, cache_bypass, policy_tags, mirror)))
        }
        DispatchResponsePolicyOutcome::Response(response) => Ok(Err(
            ReverseAttemptOutcome::Response(Box::new(empty_interim_response(response))),
        )),
    }
}

pub(super) async fn build_reverse_attempt_request(
    attempt_idx: usize,
    first_request: &mut Option<Request<Body>>,
    template: Option<&ReverseRequestTemplate>,
    replay_recorder: Option<&ReverseReplayRecorder>,
) -> Result<Request<Body>> {
    if attempt_idx == 0 {
        return match first_request.take() {
            Some(req) => Ok(req),
            None => template
                .ok_or_else(|| anyhow!("missing reverse request for first attempt"))?
                .build(),
        };
    }
    if let Some(template) = template {
        return template.build();
    }
    if let Some(recorder) = replay_recorder
        && let Some(template) = recorder.template().await
    {
        return template.build();
    }
    Err(anyhow!("reverse retry template missing or incomplete"))
}

pub(super) struct ReverseHttpAttemptTransport<'a> {
    pub(super) timeout: Duration,
    pub(super) connection_pool:
        Option<&'a crate::upstream::origin::PreparedPlainHttp1ConnectionAffinity>,
}

pub(super) async fn proxy_reverse_http_attempt(
    pools: &crate::pool::PoolRegistry,
    req_for_upstream: Request<Body>,
    upstream_origin: &OriginEndpoint,
    request_version: http::Version,
    proxy_name: &str,
    route: &HttpRoute,
    transport: ReverseHttpAttemptTransport<'_>,
) -> std::result::Result<
    Result<(
        InterimList,
        Response<Body>,
        Option<qpx_core::tls::UpstreamCertificateInfo>,
    )>,
    tokio::time::error::Elapsed,
> {
    timeout(transport.timeout, async {
        if upstream_origin.upstream.starts_with("ipc://")
            || upstream_origin.upstream.starts_with("ipc+unix://")
        {
            let url = Url::parse(upstream_origin.upstream.as_str())
                .map_err(|err| anyhow!("invalid ipc upstream url: {}", err))?;
            return Ok((
                Vec::new(),
                proxy_ipc(pools, req_for_upstream, &url, proxy_name).await?,
                None,
            ));
        }
        if matches!(
            request_version,
            http::Version::HTTP_10
                | http::Version::HTTP_11
                | http::Version::HTTP_2
                | http::Version::HTTP_3
        ) {
            let proxied = match transport.connection_pool {
                Some(connection_pool) => {
                    proxy_http_with_interim_timeout_on_connection(
                        pools,
                        req_for_upstream,
                        upstream_origin,
                        proxy_name,
                        route.upstream_trust.as_deref(),
                        transport.timeout,
                        connection_pool,
                    )
                    .await?
                }
                None => {
                    proxy_http_with_interim_timeout(
                        pools,
                        req_for_upstream,
                        upstream_origin,
                        proxy_name,
                        route.upstream_trust.as_deref(),
                        transport.timeout,
                    )
                    .await?
                }
            };
            return Ok((proxied.interim, proxied.response, proxied.upstream_cert));
        }
        Ok((
            Vec::new(),
            proxy_http(
                pools,
                req_for_upstream,
                upstream_origin,
                proxy_name,
                route.upstream_trust.as_deref(),
            )
            .await?,
            None,
        ))
    })
    .await
}
