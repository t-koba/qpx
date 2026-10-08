use super::resolved::ResolvedUpstreamProxy;
use super::sender_pool::{UpstreamProxyPool, UpstreamProxySender};
use crate::http::protocol::header_control::set_proxy_authorization_header;
use crate::upstream::http1::{
    UpstreamProxyEndpoint, UpstreamProxyScheme,
    open_upstream_proxy_sender as open_proxy_sender_once,
};
use crate::upstream::raw_http1::{Http1ResponseWithInterim, send_http1_request_with_interim};
use anyhow::{Result, anyhow};
use hyper::{Request, Response};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_http::body::Body;
use tokio::net::TcpStream;
use tokio::time::{Duration, Instant, timeout};

pub(crate) async fn send_via_upstream_proxy(
    mut req: Request<Body>,
    upstream: &ResolvedUpstreamProxy,
    timeout_dur: Duration,
    pool: &UpstreamProxyPool,
) -> Result<Response<Body>> {
    let endpoint = upstream.endpoint().clone();
    set_proxy_authorization_header(req.headers_mut(), endpoint.proxy_authorization.as_ref());
    let pool_key = upstream_proxy_pool_key(&endpoint, upstream.trust());

    let slot = pool.slot_for(&pool_key).await;

    let _permit = slot
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| anyhow!("upstream proxy concurrency limiter closed"))?;

    let sender = { slot.senders.lock().await.pop() };
    // Idle pooled senders may have been closed by the peer while parked;
    // hyper reports those as "connection was not ready" at send time, so
    // validate before reuse and fall through to a fresh dial.
    let mut sender = match sender {
        Some(mut pooled) if !pooled.is_closed() => {
            match timeout(timeout_dur, pooled.ready()).await {
                Ok(Ok(())) => pooled,
                _ => match open_upstream_proxy_sender(&endpoint, timeout_dur, upstream.trust())
                    .await
                {
                    Ok(sender) => sender,
                    Err(err) => {
                        upstream.mark_connect_error();
                        return Err(err);
                    }
                },
            }
        }
        _ => match open_upstream_proxy_sender(&endpoint, timeout_dur, upstream.trust()).await {
            Ok(sender) => sender,
            Err(err) => {
                upstream.mark_connect_error();
                return Err(err);
            }
        },
    };
    let started = Instant::now();

    // `try_send_request` recovers the request when the pooled sender rejects it
    // before dispatch, so a single retry on a fresh connection never replays a
    // request that already reached the peer. This covers the race where the
    // peer closes the connection between checkout and send, which the checkout
    // validation above cannot observe.
    match timeout(timeout_dur, sender.try_send_request(req)).await {
        Ok(Ok(response)) => {
            let response = response.map(Body::from);
            upstream.mark_http_response(response.status(), started.elapsed());
            if !sender.is_closed() {
                slot.senders.lock().await.push(sender);
            }
            Ok(response)
        }
        Ok(Err(mut err)) => {
            let Some(req) = err.take_message() else {
                upstream.mark_reset();
                return Err(err.into_error().into());
            };
            let mut fresh =
                match open_upstream_proxy_sender(&endpoint, timeout_dur, upstream.trust()).await {
                    Ok(sender) => sender,
                    Err(err) => {
                        upstream.mark_connect_error();
                        return Err(err);
                    }
                };
            match timeout(timeout_dur, fresh.send_request(req)).await {
                Ok(Ok(response)) => {
                    let response = response.map(Body::from);
                    upstream.mark_http_response(response.status(), started.elapsed());
                    if !fresh.is_closed() {
                        slot.senders.lock().await.push(fresh);
                    }
                    Ok(response)
                }
                Ok(Err(err)) => {
                    upstream.mark_reset();
                    Err(err.into())
                }
                Err(_) => {
                    upstream.mark_timeout();
                    Err(anyhow!("upstream proxy request timed out"))
                }
            }
        }
        Err(_) => {
            upstream.mark_timeout();
            Err(anyhow!("upstream proxy request timed out"))
        }
    }
}

pub(super) fn upstream_proxy_pool_key(
    endpoint: &UpstreamProxyEndpoint,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> String {
    match trust {
        Some(trust) => format!("{}|trust={}", endpoint.cache_key(), trust.pool_key()),
        None => endpoint.cache_key(),
    }
}

pub(crate) async fn send_via_upstream_proxy_with_interim(
    mut req: Request<Body>,
    upstream: &ResolvedUpstreamProxy,
    timeout_dur: Duration,
) -> Result<Http1ResponseWithInterim> {
    let endpoint = upstream.endpoint().clone();
    set_proxy_authorization_header(req.headers_mut(), endpoint.proxy_authorization.as_ref());

    let started = Instant::now();
    let stream = match timeout(
        timeout_dur,
        open_upstream_proxy_stream(&endpoint, upstream.trust()),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            upstream.mark_connect_error();
            return Err(err);
        }
        Err(_) => {
            upstream.mark_timeout();
            return Err(anyhow!("upstream proxy request timed out"));
        }
    };

    match timeout(timeout_dur, send_http1_request_with_interim(stream, req)).await {
        Ok(Ok(response)) => {
            upstream.mark_http_response(response.response.status(), started.elapsed());
            Ok(response)
        }
        Ok(Err(err)) => {
            upstream.mark_reset();
            Err(err)
        }
        Err(_) => {
            upstream.mark_timeout();
            Err(anyhow!("upstream proxy request timed out"))
        }
    }
}

async fn open_upstream_proxy_sender(
    endpoint: &UpstreamProxyEndpoint,
    timeout_dur: Duration,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<UpstreamProxySender> {
    open_proxy_sender_once(endpoint, Some(timeout_dur), "upstream proxy pooled", trust).await
}

async fn open_upstream_proxy_stream(
    endpoint: &UpstreamProxyEndpoint,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<qpx_http::tls::builder::BoxTlsStream> {
    let tcp = TcpStream::connect(endpoint.authority.as_str()).await?;
    let _ = tcp.set_nodelay(true);
    match endpoint.scheme {
        UpstreamProxyScheme::Http => Ok(Box::new(tcp)),
        UpstreamProxyScheme::Https => {
            qpx_http::tls::builder::connect_client_http1(endpoint.host.as_str(), tcp, true, trust)
                .await
                .map(|(tls, _cert)| tls)
        }
    }
}
