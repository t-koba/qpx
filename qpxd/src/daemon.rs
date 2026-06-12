use crate::cli::{Cli, Command, MatchConfigRequest};
use crate::startup::{
    check_with_runtime, explain_config, init_config_template, match_config, print_config_schema,
    run, run_with_runtime,
};
use anyhow::Result;
use clap::Parser;
use qpx_core::config::Config as ProxyConfig;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "tls-rustls")]
use qpx_core::tls::write_ca_files;

#[derive(Clone)]
pub struct Daemon {
    http_module_registry: Arc<crate::http::modules::HttpModuleRegistry>,
}

impl Default for Daemon {
    fn default() -> Self {
        Self {
            http_module_registry: crate::http::modules::default_http_module_registry(),
        }
    }
}

impl Daemon {
    pub fn builder() -> DaemonBuilder {
        DaemonBuilder::default()
    }

    pub fn run_cli(&self) -> Result<()> {
        qpx_core::tls::init_rustls_crypto_provider();
        let cli = Cli::parse();
        match cli.command {
            Command::Run { config } => self.run_with_runtime(config),
            Command::Check { config } => self.check_with_runtime(config),
            Command::Init { template } => init_config_template(template),
            Command::Schema { format } => print_config_schema(format),
            Command::Explain {
                config,
                format,
                edge,
                route,
            } => explain_config(
                config,
                format,
                edge,
                route,
                self.http_module_registry.clone(),
            ),
            Command::Match {
                config,
                edge,
                src_ip,
                dst_port,
                sni,
                host,
                method,
                path,
            } => match_config(
                config,
                MatchConfigRequest {
                    edge,
                    src_ip,
                    dst_port,
                    sni,
                    host,
                    method,
                    path,
                },
                self.http_module_registry.clone(),
            ),
            #[cfg(feature = "tls-rustls")]
            Command::GenCa { state_dir } => {
                let (cert, key) = write_ca_files(&state_dir)?;
                println!("generated ca: {} {}", cert.display(), key.display());
                Ok(())
            }
            Command::Upgrade { pid } => crate::upgrade::request_upgrade(pid),
        }
    }

    pub fn run_with_runtime(&self, config_paths: Vec<PathBuf>) -> Result<()> {
        run_with_runtime(config_paths, self.http_module_registry.clone())
    }

    pub fn check_with_runtime(&self, config_paths: Vec<PathBuf>) -> Result<()> {
        check_with_runtime(config_paths, self.http_module_registry.clone())
    }

    pub fn build_runtime(&self, config: ProxyConfig) -> Result<crate::runtime::Runtime> {
        crate::runtime::Runtime::with_http_module_registry(
            config,
            self.http_module_registry.clone(),
        )
    }

    pub async fn run_loaded_config(
        &self,
        config_paths: Vec<PathBuf>,
        config: ProxyConfig,
    ) -> Result<()> {
        run(config_paths, config, self.http_module_registry.clone()).await
    }
}

pub struct DaemonBuilder {
    http_module_registry: crate::http::modules::HttpModuleRegistryBuilder,
}

impl Default for DaemonBuilder {
    fn default() -> Self {
        Self {
            http_module_registry: crate::http::modules::HttpModuleRegistry::builder(),
        }
    }
}

impl DaemonBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_http_module<F>(
        mut self,
        type_name: impl Into<String>,
        factory: F,
    ) -> Result<Self>
    where
        F: crate::http::modules::HttpModuleFactory + 'static,
    {
        self.http_module_registry
            .register_factory(type_name, factory)?;
        Ok(self)
    }

    pub fn build(self) -> Daemon {
        Daemon {
            http_module_registry: Arc::new(self.http_module_registry.build()),
        }
    }
}
