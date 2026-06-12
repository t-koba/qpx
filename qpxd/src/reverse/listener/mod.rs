use super::transport::{ReverseConnInfo, handle_request_with_interim};
use super::{
    ReloadableReverse, record_reverse_connection_filter_block, reverse_connection_filter_match,
};
use crate::http::codec::h1::serve_http1_with_interim_and_capacity;
use crate::http::codec::interim::{
    H2_PREFACE, serve_h2_with_interim_and_capacity, sniff_h2_preface,
};
use crate::tcp_bindings::filter::ConnectionFilterStage;
use crate::xdp::remote::resolve_remote_addr_with_xdp;
use anyhow::Result;
use http::{Request, Response};
use qpx_http::body::Body;
use qpx_observability::RequestHandler;
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::Duration;
use tracing::warn;

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
mod tls_connection;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
pub(super) use tls_connection::run_reverse_tls_acceptor;

fn reverse_body_channel_capacity(reverse: &ReloadableReverse) -> usize {
    let state = reverse.runtime.state();
    state
        .plan
        .reverse_edge(reverse.name.as_ref())
        .map(|edge| edge.streaming.body_channel_capacity)
        .unwrap_or(state.plan.limits.body.body_channel_capacity)
}

#[derive(Clone)]
struct ReverseInterimService {
    reverse: ReloadableReverse,
    conn: ReverseConnInfo,
}

impl RequestHandler<Request<Body>> for ReverseInterimService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn call(&self, req: Request<Body>) -> Self::Future {
        let reverse = self.reverse.clone();
        let conn = self.conn.clone();
        Box::pin(async move {
            let (interim, mut response) = handle_request_with_interim(req, reverse, conn).await?;
            if !interim.is_empty() {
                response.extensions_mut().insert(interim);
            }
            Ok(response)
        })
    }
}

pub(super) async fn run_reverse_http_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    reverse: ReloadableReverse,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let semaphore = reverse.runtime.state().connection_semaphore.clone();
    loop {
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            permit = semaphore.clone().acquire_owned() => Some(permit?),
        };
        let Some(permit) = permit else {
            break;
        };
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok(accepted) => Some(accepted),
                Err(err) => {
                    warn!(error = ?err, "reverse accept failed");
                    continue;
                }
            }
        };
        let Some((stream, remote_addr)) = accepted else {
            break;
        };
        let _ = stream.set_nodelay(true);
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve reverse local addr");
                continue;
            }
        };
        let xdp_cfg = xdp_cfg.clone();
        let reverse = reverse.clone();
        let reverse_name = reverse.name.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let header_read_timeout = Duration::from_millis(
                reverse
                    .runtime
                    .state()
                    .plan
                    .limits
                    .timeouts
                    .http_header_read_timeout_ms,
            );
            let (stream, remote_addr) = match resolve_remote_addr_with_xdp(
                stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            if let Some(matched_rule) =
                reverse_connection_filter_match(&reverse, remote_addr, local_port, None)
            {
                record_reverse_connection_filter_block(
                    &reverse,
                    remote_addr,
                    local_port,
                    ConnectionFilterStage::Accept,
                    matched_rule.as_str(),
                    None,
                );
                return;
            }
            let mut stream = stream;
            let preface = match sniff_h2_preface(&mut stream, header_read_timeout).await {
                Ok(preface) => preface,
                Err(err) => {
                    warn!(error = ?err, "reverse protocol sniff failed");
                    return;
                }
            };
            let stream = crate::http::protocol::io_prefix::PrefixedIo::new(stream, preface.clone());
            let conn = ReverseConnInfo::plain(remote_addr, local_port);
            if preface.as_ref() == H2_PREFACE {
                let access_cfg = reverse.runtime.state().resources.access_log.clone();
                let service = AccessLogService::new(
                    ReverseInterimService {
                        reverse: reverse.clone(),
                        conn,
                    },
                    remote_addr,
                    AccessLogContext {
                        kind: crate::http::dispatch::ProxyKind::Reverse.as_str(),
                        name: reverse_name,
                    },
                    &access_cfg,
                );
                if let Err(err) = serve_h2_with_interim_and_capacity(
                    stream,
                    service,
                    false,
                    header_read_timeout,
                    reverse_body_channel_capacity(&reverse),
                )
                .await
                {
                    warn!(error = ?err, "reverse HTTP/2 connection failed");
                }
            } else {
                let access_cfg = reverse.runtime.state().resources.access_log.clone();
                let service = AccessLogService::new(
                    ReverseInterimService {
                        reverse: reverse.clone(),
                        conn,
                    },
                    remote_addr,
                    AccessLogContext {
                        kind: crate::http::dispatch::ProxyKind::Reverse.as_str(),
                        name: reverse_name,
                    },
                    &access_cfg,
                );
                if let Err(err) = serve_http1_with_interim_and_capacity(
                    stream,
                    service,
                    header_read_timeout,
                    reverse_body_channel_capacity(&reverse),
                )
                .await
                {
                    warn!(error = ?err, "reverse connection failed");
                }
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
