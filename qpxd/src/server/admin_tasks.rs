use crate::{runtime, tcp_bindings};
use anyhow::Result;
use qpx_core::config::Config as ProxyConfig;
use qpx_observability::start_metrics;

pub(crate) struct AdminTasks {
    metrics_task: Option<tokio::task::JoinHandle<()>>,
    http01_task: Option<tokio::task::JoinHandle<Result<()>>>,
    manager_task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl AdminTasks {
    pub(crate) fn start(
        config: &ProxyConfig,
        runtime: runtime::Runtime,
        tcp_bindings: &tcp_bindings::TcpBindings,
    ) -> Result<Self> {
        let metrics_task = config
            .telemetry
            .metrics
            .as_ref()
            .map(|metrics| start_metrics(metrics, tcp_bindings.clone_metrics()?))
            .transpose()?;

        #[cfg(feature = "acme")]
        let (http01_task, manager_task) =
            if let Some(acme_state) = qpx_acme::init(config, std::sync::Arc::new(runtime))? {
                let http_listener = tcp_bindings.clone_acme_http01()?.ok_or_else(|| {
                    anyhow::anyhow!("acme http-01 binding missing while ACME is enabled")
                })?;
                let http_state = acme_state.clone();
                let http01_task = tokio::spawn(async move {
                    qpx_acme::run_http01_server_with_std_listener(http_listener, http_state)
                        .await
                        .map_err(anyhow::Error::from)
                });
                let manager_state = acme_state.clone();
                let manager_task = tokio::spawn(async move {
                    qpx_acme::run_manager(manager_state)
                        .await
                        .map_err(anyhow::Error::from)
                });
                (Some(http01_task), Some(manager_task))
            } else {
                (None, None)
            };

        #[cfg(not(feature = "acme"))]
        let (http01_task, manager_task) = {
            let _ = runtime;
            (None, None)
        };

        Ok(Self {
            metrics_task,
            http01_task,
            manager_task,
        })
    }

    pub(crate) fn abort_all(&mut self) {
        if let Some(task) = self.metrics_task.take() {
            task.abort();
        }
        if let Some(task) = self.http01_task.take() {
            task.abort();
        }
        if let Some(task) = self.manager_task.take() {
            task.abort();
        }
    }
}
