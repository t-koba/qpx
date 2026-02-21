use anyhow::Result;
use qpx_core::config::{ReverseConfig, ReverseHttp3Config};
use std::net::SocketAddr;
use tokio::time::Duration;
use tracing::info;

pub(crate) async fn run_http3(
    reverse: ReverseConfig,
    http3: ReverseHttp3Config,
    reverse_rt: super::ReloadableReverse,
) -> Result<()> {
    let listen_addr: SocketAddr = http3
        .listen
        .clone()
        .unwrap_or_else(|| reverse.listen.clone())
        .parse()?;

    let passthrough_targets = http3.passthrough_upstreams.clone();
    if !passthrough_targets.is_empty() {
        let resolve_timeout =
            Duration::from_millis(reverse_rt.runtime.state().config.runtime.upstream_http_timeout_ms);
        info!(
            reverse = %reverse.name,
            listen = %listen_addr,
            upstreams = ?passthrough_targets,
            "reverse HTTP/3 passthrough listener starting"
        );
        return super::h3_passthrough::run_http3_passthrough(
            listen_addr,
            passthrough_targets,
            &http3,
            resolve_timeout,
        )
        .await;
    }

    info!(
        reverse = %reverse.name,
        listen = %listen_addr,
        "reverse HTTP/3 terminate listener starting"
    );
    super::h3_terminate::run_http3_terminate(reverse, listen_addr, reverse_rt).await
}
