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
use arc_swap::ArcSwap;
use qpx_core::config::{Config, ReverseConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Clone)]
pub(crate) struct CompiledReverse {
    pub(crate) router: Arc<router::ReverseRouter>,
    pub(crate) security_policy: Arc<security::ReverseTlsHostPolicy>,
    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(in crate::reverse) tls_acceptor: Option<transport::ReverseTlsAcceptor>,
}

pub(crate) fn compile_reverse(reverse: &ReverseConfig) -> Result<CompiledReverse> {
    let router = Arc::new(router::ReverseRouter::new(reverse.clone())?);
    let security_policy = Arc::new(security::ReverseTlsHostPolicy::from_config(reverse)?);

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    {
        let tls_acceptor = if reverse.tls.is_some() {
            Some(transport::build_tls_acceptor(reverse)?)
        } else {
            None
        };
        Ok(CompiledReverse {
            router,
            security_policy,
            tls_acceptor,
        })
    }

    #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
    {
        if reverse.tls.is_some() {
            return Err(anyhow!(
                "reverse {} enables tls termination, but this build was compiled without a TLS backend",
                reverse.name
            ));
        }
        Ok(CompiledReverse {
            router,
            security_policy,
        })
    }
}

#[derive(Clone)]
pub(crate) struct ReloadableReverse {
    name: Arc<str>,
    runtime: Runtime,
    unhealthy_metric: Arc<str>,
    compiled: Arc<ArcSwap<CompiledReverse>>,
    last_config: Arc<ArcSwap<Config>>,
    reload_lock: Arc<Mutex<()>>,
}

impl ReloadableReverse {
    fn new(reverse: ReverseConfig, runtime: Runtime, unhealthy_metric: Arc<str>) -> Result<Self> {
        let name = Arc::<str>::from(reverse.name.as_str());
        let compiled = compile_reverse(&reverse)?;
        compiled
            .router
            .spawn_health_tasks(name.clone(), unhealthy_metric.clone());

        let current_config = runtime.state().config.clone();
        Ok(Self {
            name,
            runtime,
            unhealthy_metric,
            compiled: Arc::new(ArcSwap::from_pointee(compiled)),
            last_config: Arc::new(ArcSwap::from(current_config)),
            reload_lock: Arc::new(Mutex::new(())),
        })
    }

    pub(crate) async fn compiled(&self) -> Arc<CompiledReverse> {
        let current_config = self.runtime.state().config.clone();
        if Arc::ptr_eq(&current_config, &self.last_config.load_full()) {
            return self.compiled.load_full();
        }

        let _guard = self.reload_lock.lock().await;
        let current_config = self.runtime.state().config.clone();
        if Arc::ptr_eq(&current_config, &self.last_config.load_full()) {
            return self.compiled.load_full();
        }

        let next_reverse = current_config
            .reverse
            .iter()
            .find(|r| r.name == self.name.as_ref())
            .cloned();
        match next_reverse {
            Some(reverse_cfg) => match compile_reverse(&reverse_cfg) {
                Ok(next) => {
                    next.router
                        .spawn_health_tasks(self.name.clone(), self.unhealthy_metric.clone());
                    self.compiled.store(Arc::new(next));
                }
                Err(err) => {
                    warn!(reverse = %self.name, error = ?err, "reverse reload compile failed; keeping previous state");
                }
            },
            None => {
                warn!(reverse = %self.name, "reverse config missing after reload; keeping previous state");
            }
        }
        // Even when compilation fails, avoid retrying on every request.
        self.last_config.store(current_config);

        self.compiled.load_full()
    }
}

pub(crate) fn check_reverse_runtime(reverse: &ReverseConfig) -> Result<()> {
    let _: SocketAddr = reverse
        .listen
        .parse()
        .map_err(|e| anyhow!("reverse {} listen is invalid: {}", reverse.name, e))?;
    let _ = compile_reverse(reverse)?;

    if reverse.http3.as_ref().map(|h| h.enabled).unwrap_or(false) {
        #[cfg(feature = "http3")]
        {
            let passthrough = reverse
                .http3
                .as_ref()
                .map(|h| !h.passthrough_upstreams.is_empty())
                .unwrap_or(false);
            if !passthrough {
                let _ = h3_terminate::build_reverse_tls_config(reverse)?;
            }
        }
        #[cfg(not(feature = "http3"))]
        {
            return Err(anyhow!(
                "reverse {} enables http3, but this build was compiled without feature http3",
                reverse.name
            ));
        }
    }

    Ok(())
}

pub async fn run(reverse: ReverseConfig, runtime: Runtime) -> Result<()> {
    let addr: SocketAddr = reverse.listen.parse()?;
    let unhealthy_metric = Arc::<str>::from(
        runtime
            .state()
            .metric_names
            .reverse_upstreams_unhealthy
            .as_str(),
    );
    let reverse_rt = ReloadableReverse::new(reverse.clone(), runtime.clone(), unhealthy_metric)?;
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
                let reverse_rt_for_h3 = reverse_rt.clone();
                Some(tokio::spawn(async move {
                    self::h3::run_http3(reverse_for_h3, h3_cfg, reverse_rt_for_h3).await
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
                let reverse_rt = reverse_rt.clone();
                accept_tasks.push(tokio::spawn(async move {
                    listener::run_reverse_tls_acceptor(listener, xdp_cfg, reverse_rt).await
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
        let reverse_rt = reverse_rt.clone();
        accept_tasks.push(tokio::spawn(async move {
            listener::run_reverse_http_acceptor(tcp_listener, xdp_cfg, reverse_rt).await
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
