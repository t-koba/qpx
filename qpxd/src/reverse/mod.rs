#[cfg(feature = "http3")]
mod h3;
#[cfg(feature = "http3")]
mod h3_passthrough;
#[cfg(feature = "http3")]
mod h3_terminate;
mod health;
mod listener;
mod request_template;
mod router;
mod security;
mod transport;

use crate::runtime::Runtime;
use anyhow::{anyhow, Result};
use qpx_core::config::ReverseConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

pub async fn run(reverse: ReverseConfig, runtime: Runtime) -> Result<()> {
    let addr: SocketAddr = reverse.listen.parse()?;
    let router = Arc::new(router::ReverseRouter::new(reverse.clone())?);
    let security_policy = Arc::new(security::ReverseTlsHostPolicy::from_config(&reverse)?);
    let unhealthy_metric = Arc::<str>::from(
        runtime
            .state()
            .metric_names
            .reverse_upstreams_unhealthy
            .as_str(),
    );
    router.spawn_health_tasks(Arc::<str>::from(reverse.name.as_str()), unhealthy_metric);
    let passthrough_only = reverse
        .http3
        .as_ref()
        .map(|h| {
            h.enabled
                && !h.passthrough_upstreams.is_empty()
                && reverse.routes.is_empty()
                && reverse.tls_passthrough_routes.is_empty()
        })
        .unwrap_or(false);

    let h3_task: Option<tokio::task::JoinHandle<Result<()>>> =
        if reverse.http3.as_ref().map(|h| h.enabled).unwrap_or(false) {
            #[cfg(feature = "http3")]
            {
                let h3_cfg = reverse.http3.clone().expect("enabled config");
                let reverse_for_h3 = reverse.clone();
                let router_for_h3 = router.clone();
                let runtime_for_h3 = runtime.clone();
                let security_for_h3 = security_policy.clone();
                Some(tokio::spawn(async move {
                    self::h3::run_http3(
                        reverse_for_h3,
                        h3_cfg,
                        router_for_h3,
                        runtime_for_h3,
                        security_for_h3,
                    )
                    .await
                }))
            }
            #[cfg(not(feature = "http3"))]
            {
                return Err(anyhow!(
                    "reverse {} enables http3, but this build was compiled without feature http3",
                    reverse.name
                ));
            }
        } else {
            None
        };

    if passthrough_only {
        if let Some(task) = h3_task {
            return task.await?;
        }
        return Ok(());
    }

    if reverse.tls.is_some() {
        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
        {
            let tls_acceptor = transport::build_tls_acceptor(&reverse)?;
            let runtime_cfg = runtime.state().config.runtime.clone();
            let listeners = crate::net::bind_tcp_listeners(addr, &runtime_cfg)?;
            let xdp_cfg = crate::xdp::compile_xdp_config(reverse.xdp.as_ref())?;
            info!(
                reverse = %reverse.name,
                addr = %addr,
                acceptors = listeners.len(),
                "reverse TLS listener starting"
            );

            let mut accept_tasks = Vec::with_capacity(listeners.len());
            for listener in listeners {
                let xdp_cfg = xdp_cfg.clone();
                let acceptor = tls_acceptor.clone();
                let router = router.clone();
                let runtime = runtime.clone();
                let security = security_policy.clone();
                accept_tasks.push(tokio::spawn(async move {
                    listener::run_reverse_tls_acceptor(
                        listener, xdp_cfg, acceptor, router, runtime, security,
                    )
                    .await
                }));
            }
            let tls_server = async move {
                for task in accept_tasks {
                    match task.await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => return Err(err),
                        Err(err) => {
                            return Err(anyhow!("reverse TLS acceptor task failed: {}", err))
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            };
            if let Some(task) = h3_task {
                tokio::select! {
                    res = tls_server => {
                        res?;
                    }
                    res = task => {
                        res??;
                    }
                }
            } else {
                tls_server.await?;
            }
            return Ok(());
        }
        #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
        {
            return Err(anyhow!(
                "reverse {} enables tls termination, but this build was compiled without a TLS backend",
                reverse.name
            ));
        }
    }

    let runtime_cfg = runtime.state().config.runtime.clone();
    let listeners = crate::net::bind_tcp_listeners(addr, &runtime_cfg)?;
    let xdp_cfg = crate::xdp::compile_xdp_config(reverse.xdp.as_ref())?;
    info!(
        reverse = %reverse.name,
        addr = %addr,
        acceptors = listeners.len(),
        "reverse listener starting"
    );
    let mut accept_tasks = Vec::with_capacity(listeners.len());
    for tcp_listener in listeners {
        let xdp_cfg = xdp_cfg.clone();
        let router = router.clone();
        let runtime = runtime.clone();
        let security = security_policy.clone();
        accept_tasks.push(tokio::spawn(async move {
            listener::run_reverse_http_acceptor(tcp_listener, xdp_cfg, router, runtime, security)
                .await
        }));
    }
    let http_server = async move {
        for task in accept_tasks {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(anyhow!("reverse acceptor task failed: {}", err)),
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    if let Some(task) = h3_task {
        tokio::select! {
            res = http_server => {
                res?;
            }
            res = task => {
                res??;
            }
        }
    } else {
        http_server.await?;
    }
    Ok(())
}
