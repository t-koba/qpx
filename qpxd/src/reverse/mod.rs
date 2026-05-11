#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod h3_passthrough;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-qpx",
    not(feature = "http3-backend-h3")
))]
pub(crate) mod h3_passthrough;
#[cfg(all(
    feature = "http3",
    not(any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        all(feature = "http3-backend-qpx", not(feature = "http3-backend-h3"))
    ))
))]
#[path = "h3_passthrough_invalid.rs"]
pub(crate) mod h3_passthrough;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod h3_terminate;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-qpx",
    not(feature = "http3-backend-h3")
))]
#[path = "h3_terminate_qpx.rs"]
pub(crate) mod h3_terminate;
#[cfg(all(
    feature = "http3",
    not(any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        all(feature = "http3-backend-qpx", not(feature = "http3-backend-h3"))
    ))
))]
#[path = "h3_terminate_invalid.rs"]
pub(crate) mod h3_terminate;
mod health;
mod listener;
mod request_template;
mod router;
mod security;
mod transport;

use crate::connection_filter::{
    ConnectionFilterStage, emit_connection_filter_audit, evaluate_connection_filter,
};
use crate::runtime::Runtime;
use crate::runtime::{CompiledReverseEdge, metric_names};
use crate::tls::TlsClientHelloInfo;
#[cfg(feature = "http3")]
use crate::transparent::quic::{extract_quic_client_hello_info, looks_like_quic_initial};
use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use metrics::counter;
use qpx_core::config::{Config, ReverseEdgeConfig, UpstreamConfig};
use qpx_core::rules::RuleMatchContext;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::watch;
use tracing::{info, warn};

#[derive(Clone)]
pub(crate) struct CompiledReverse {
    pub(crate) router: Arc<router::ReverseRouter>,
    pub(crate) security_policy: Arc<security::ReverseTlsHostPolicy>,
    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(in crate::reverse) tls_acceptor: Option<transport::ReverseTlsAcceptor>,
}

pub(crate) fn compile_reverse(
    reverse: &ReverseEdgeConfig,
    upstreams: &[UpstreamConfig],
    http_module_registry: &crate::http::modules::HttpModuleRegistry,
    compiled_edge: &CompiledReverseEdge,
) -> Result<CompiledReverse> {
    let router = Arc::new(router::ReverseRouter::new_with_plan(
        reverse.clone(),
        upstreams,
        http_module_registry,
        compiled_edge,
    )?);
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
    last_operational: Arc<ArcSwap<Config>>,
    reload_lock: Arc<Mutex<()>>,
}

impl ReloadableReverse {
    pub(crate) fn new(
        reverse: ReverseEdgeConfig,
        runtime: Runtime,
        unhealthy_metric: Arc<str>,
    ) -> Result<Self> {
        let name = Arc::<str>::from(reverse.name.as_str());
        let state = runtime.state();
        let current_operational = state.resources.operational.clone();
        let compiled = compile_reverse(
            &reverse,
            current_operational.upstreams.as_slice(),
            state.http_module_registry().as_ref(),
            state
                .plan
                .reverse_edge(reverse.name.as_str())
                .ok_or_else(|| anyhow!("compiled reverse edge missing for {}", reverse.name))?,
        )?;
        compiled
            .router
            .spawn_health_tasks(name.clone(), unhealthy_metric.clone());
        Ok(Self {
            name,
            runtime,
            unhealthy_metric,
            compiled: Arc::new(ArcSwap::from_pointee(compiled)),
            last_operational: Arc::new(ArcSwap::from(current_operational)),
            reload_lock: Arc::new(Mutex::new(())),
        })
    }

    pub(crate) async fn compiled(&self) -> Arc<CompiledReverse> {
        let current_operational = self.runtime.state().resources.operational.clone();
        if Arc::ptr_eq(&current_operational, &self.last_operational.load_full()) {
            return self.compiled.load_full();
        }

        let _guard = self.reload_lock.lock().await;
        let current_operational = self.runtime.state().resources.operational.clone();
        if Arc::ptr_eq(&current_operational, &self.last_operational.load_full()) {
            return self.compiled.load_full();
        }

        let next_reverse = current_operational
            .reverse_edge_configs()
            .iter()
            .find(|r| r.name == self.name.as_ref())
            .cloned();
        match next_reverse {
            Some(reverse_cfg) => {
                let state = self.runtime.state();
                let next = state
                    .plan
                    .reverse_edge(reverse_cfg.name.as_str())
                    .ok_or_else(|| {
                        anyhow!("compiled reverse edge missing for {}", reverse_cfg.name)
                    })
                    .and_then(|compiled_edge| {
                        compile_reverse(
                            reverse_cfg,
                            current_operational.upstreams.as_slice(),
                            state.http_module_registry().as_ref(),
                            compiled_edge,
                        )
                    });
                match next {
                    Ok(next) => {
                        next.router
                            .spawn_health_tasks(self.name.clone(), self.unhealthy_metric.clone());
                        self.compiled.store(Arc::new(next));
                    }
                    Err(err) => {
                        warn!(reverse = %self.name, error = ?err, "reverse reload compile failed; keeping previous state");
                    }
                }
            }
            None => {
                warn!(reverse = %self.name, "reverse config missing after reload; keeping previous state");
            }
        }
        // Even when compilation fails, avoid retrying on every request.
        self.last_operational.store(current_operational);

        self.compiled.load_full()
    }
}

pub(super) fn reverse_connection_filter_match(
    reverse: &ReloadableReverse,
    remote_addr: SocketAddr,
    local_port: u16,
    client_hello: Option<&TlsClientHelloInfo>,
) -> Option<String> {
    let state = reverse.runtime.state();
    evaluate_connection_filter(
        state
            .policy
            .connection_filters_by_reverse
            .get(reverse.name.as_ref()),
        &RuleMatchContext {
            src_ip: Some(remote_addr.ip()),
            dst_port: Some(local_port),
            sni: client_hello.and_then(|hello| hello.sni.as_deref()),
            alpn: client_hello.and_then(|hello| hello.alpn.as_deref()),
            tls_version: client_hello.and_then(|hello| hello.tls_version.as_deref()),
            ja3: client_hello.and_then(|hello| hello.ja3.as_deref()),
            ja4: client_hello.and_then(|hello| hello.ja4.as_deref()),
            ..Default::default()
        },
    )
    .map(str::to_string)
}

pub(super) fn record_reverse_connection_filter_block(
    reverse: &ReloadableReverse,
    remote_addr: SocketAddr,
    local_port: u16,
    stage: ConnectionFilterStage,
    matched_rule: &str,
    sni: Option<&str>,
) {
    counter!(metric_names().reverse_requests_total.clone(), "result" => "blocked").increment(1);
    emit_connection_filter_audit(
        "reverse",
        reverse.name.as_ref(),
        remote_addr,
        local_port,
        stage,
        matched_rule,
        sni,
    );
}

#[cfg(feature = "http3")]
pub(super) fn reverse_quic_connection_filter_match(
    reverse: &ReloadableReverse,
    remote_addr: SocketAddr,
    local_port: u16,
    packet: &[u8],
) -> Option<(ConnectionFilterStage, String, Option<String>)> {
    if let Some(matched_rule) =
        reverse_connection_filter_match(reverse, remote_addr, local_port, None)
    {
        return Some((ConnectionFilterStage::Accept, matched_rule, None));
    }
    if !looks_like_quic_initial(packet) {
        return None;
    }
    let client_hello = extract_quic_client_hello_info(packet)?;
    let matched_rule =
        reverse_connection_filter_match(reverse, remote_addr, local_port, Some(&client_hello))?;
    Some((
        ConnectionFilterStage::ClientHello,
        matched_rule,
        client_hello.sni,
    ))
}

pub(crate) fn check_reverse_runtime(
    reverse: &ReverseEdgeConfig,
    upstreams: &[UpstreamConfig],
    http_module_registry: &crate::http::modules::HttpModuleRegistry,
    compiled_edge: &CompiledReverseEdge,
) -> Result<()> {
    let _: SocketAddr = reverse
        .listen
        .parse()
        .map_err(|e| anyhow!("reverse {} listen is invalid: {}", reverse.name, e))?;
    let _ = compile_reverse(reverse, upstreams, http_module_registry, compiled_edge)?;

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

fn reverse_passthrough_only(reverse: &ReverseEdgeConfig) -> bool {
    reverse
        .http3
        .as_ref()
        .map(|h| {
            h.enabled
                && !h.passthrough_upstreams.is_empty()
                && reverse.routes.is_empty()
                && reverse.tls_passthrough_routes.is_empty()
        })
        .unwrap_or(false)
}

pub async fn run_tcp(
    reverse: ReverseEdgeConfig,
    reverse_rt: ReloadableReverse,
    shutdown: watch::Receiver<bool>,
    forward_edges: Vec<tokio::net::TcpListener>,
) -> Result<()> {
    let addr: SocketAddr = reverse.listen.parse()?;
    if reverse.tls.is_some() {
        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
        {
            let xdp_cfg = crate::xdp::compile_xdp_config(reverse.xdp.as_ref())?;
            info!(
                reverse = %reverse.name,
                addr = %addr,
                acceptors = forward_edges.len(),
                "reverse TLS listener starting"
            );

            let mut accept_tasks = Vec::with_capacity(forward_edges.len());
            for listener in forward_edges {
                let xdp_cfg = xdp_cfg.clone();
                let reverse_rt = reverse_rt.clone();
                let acceptor_shutdown = shutdown.clone();
                accept_tasks.push(tokio::spawn(async move {
                    listener::run_reverse_tls_acceptor(
                        listener,
                        xdp_cfg,
                        reverse_rt,
                        acceptor_shutdown,
                    )
                    .await
                }));
            }
            for task in accept_tasks {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(err) => return Err(anyhow!("reverse TLS acceptor task failed: {}", err)),
                }
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

    let xdp_cfg = crate::xdp::compile_xdp_config(reverse.xdp.as_ref())?;
    info!(
        reverse = %reverse.name,
        addr = %addr,
        acceptors = forward_edges.len(),
        "reverse listener starting"
    );
    let mut accept_tasks = Vec::with_capacity(forward_edges.len());
    for tcp_listener in forward_edges {
        let xdp_cfg = xdp_cfg.clone();
        let reverse_rt = reverse_rt.clone();
        let acceptor_shutdown = shutdown.clone();
        accept_tasks.push(tokio::spawn(async move {
            listener::run_reverse_http_acceptor(
                tcp_listener,
                xdp_cfg,
                reverse_rt,
                acceptor_shutdown,
            )
            .await
        }));
    }
    for task in accept_tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => return Err(anyhow!("reverse acceptor task failed: {}", err)),
        }
    }
    Ok(())
}

pub(crate) fn build_reloadable_reverse(
    reverse: &ReverseEdgeConfig,
    runtime: &Runtime,
) -> Result<ReloadableReverse> {
    let unhealthy_metric = Arc::<str>::from(
        runtime
            .state()
            .observability
            .metric_names
            .reverse_upstreams_unhealthy
            .as_str(),
    );
    ReloadableReverse::new(reverse.clone(), runtime.clone(), unhealthy_metric)
}

pub(crate) fn requires_tcp_listener(reverse: &ReverseEdgeConfig) -> bool {
    !reverse_passthrough_only(reverse)
}
