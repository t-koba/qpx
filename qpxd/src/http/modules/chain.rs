use super::execution::{HttpModuleExecution, HttpModuleSessionInit};
use super::{
    HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleRegistry, ModuleStages,
};
use crate::runtime::RuntimeState;
use anyhow::{Context, Result, anyhow};
use qpx_core::config::HttpModuleConfig;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct CompiledHttpModule {
    type_name: Arc<str>,
    id: Option<Arc<str>>,
    pub(super) module: Arc<dyn HttpModule>,
}

impl CompiledHttpModule {
    pub(super) fn label(&self) -> String {
        match &self.id {
            Some(id) => format!("{} ({id})", self.type_name),
            None => self.type_name.to_string(),
        }
    }

    fn explain(&self) -> Option<(String, Vec<String>)> {
        let detail = self.module.explain();
        (!detail.is_empty()).then(|| (self.label(), detail))
    }
}

#[derive(Clone)]
pub(crate) struct CompiledHttpModuleChain {
    pub(super) request_headers: Arc<[CompiledHttpModule]>,
    pub(super) cache_lookup: Arc<[CompiledHttpModule]>,
    pub(super) upstream_request: Arc<[CompiledHttpModule]>,
    pub(super) upstream_response: Arc<[CompiledHttpModule]>,
    pub(super) downstream_response: Arc<[CompiledHttpModule]>,
    pub(super) retry: Arc<[CompiledHttpModule]>,
    pub(super) error: Arc<[CompiledHttpModule]>,
    pub(super) log: Arc<[CompiledHttpModule]>,
    pub(super) aggregate: HttpModuleCapabilities,
}

impl Default for CompiledHttpModuleChain {
    fn default() -> Self {
        let empty: Arc<[CompiledHttpModule]> = Vec::<CompiledHttpModule>::new().into();
        Self {
            request_headers: empty.clone(),
            cache_lookup: empty.clone(),
            upstream_request: empty.clone(),
            upstream_response: empty.clone(),
            downstream_response: empty.clone(),
            retry: empty.clone(),
            error: empty.clone(),
            log: empty,
            aggregate: HttpModuleCapabilities::default(),
        }
    }
}

impl CompiledHttpModuleChain {
    pub(crate) fn aggregate(&self) -> HttpModuleCapabilities {
        self.aggregate
    }

    pub(crate) fn has_request_side_modules(&self) -> bool {
        !self.request_headers.is_empty()
            || !self.cache_lookup.is_empty()
            || !self.upstream_request.is_empty()
    }

    pub(crate) fn has_response_side_modules(&self) -> bool {
        !self.upstream_response.is_empty()
            || !self.downstream_response.is_empty()
            || !self.retry.is_empty()
            || !self.error.is_empty()
            || !self.log.is_empty()
    }

    pub(crate) fn needs_frozen_request(&self) -> bool {
        self.aggregate.needs_frozen_request
    }

    pub(crate) fn stage_labels(&self) -> Vec<(&'static str, Vec<String>)> {
        vec![
            ("request_headers", module_labels(&self.request_headers)),
            ("cache_lookup", module_labels(&self.cache_lookup)),
            ("upstream_request", module_labels(&self.upstream_request)),
            ("upstream_response", module_labels(&self.upstream_response)),
            (
                "downstream_response",
                module_labels(&self.downstream_response),
            ),
            ("retry", module_labels(&self.retry)),
            ("error", module_labels(&self.error)),
            ("log", module_labels(&self.log)),
        ]
    }

    pub(crate) fn explain_details(&self) -> Vec<(String, Vec<String>)> {
        [
            self.request_headers.as_ref(),
            self.cache_lookup.as_ref(),
            self.upstream_request.as_ref(),
            self.upstream_response.as_ref(),
            self.downstream_response.as_ref(),
            self.retry.as_ref(),
            self.error.as_ref(),
            self.log.as_ref(),
        ]
        .into_iter()
        .flat_map(|modules| modules.iter().filter_map(CompiledHttpModule::explain))
        .collect()
    }

    pub(crate) fn start(
        &self,
        runtime: Arc<RuntimeState>,
        init: HttpModuleSessionInit<'_>,
    ) -> HttpModuleExecution {
        HttpModuleExecution::new(self.clone(), HttpModuleContext::new(runtime, init))
    }
}

fn module_labels(modules: &[CompiledHttpModule]) -> Vec<String> {
    modules.iter().map(CompiledHttpModule::label).collect()
}

pub(crate) fn compile_http_modules(
    configs: &[HttpModuleConfig],
    registry: &HttpModuleRegistry,
) -> Result<Arc<CompiledHttpModuleChain>> {
    if configs.is_empty() {
        return Ok(Arc::new(CompiledHttpModuleChain::default()));
    }

    let mut modules = Vec::with_capacity(configs.len());
    for (idx, config) in configs.iter().enumerate() {
        let Some(factory) = registry.get(config.r#type.as_str()) else {
            return Err(anyhow!(
                "unknown http module type {} at index {}",
                config.r#type,
                idx
            ));
        };
        let module = factory
            .build(config)
            .with_context(|| format!("failed to build http module {}", config.r#type))?;
        let order = config.order.unwrap_or(module.order());
        modules.push((
            order,
            idx,
            CompiledHttpModule {
                type_name: Arc::<str>::from(config.r#type.as_str()),
                id: config.id.as_deref().map(Arc::<str>::from),
                module,
            },
        ));
    }
    modules.sort_by_key(|(order, idx, _)| (*order, *idx));
    let modules = modules
        .into_iter()
        .map(|(_, _, module)| module)
        .collect::<Vec<_>>();
    let mut aggregate = HttpModuleCapabilities::default();
    let mut request_headers = Vec::new();
    let mut cache_lookup = Vec::new();
    let mut upstream_request = Vec::new();
    let mut upstream_response = Vec::new();
    let mut downstream_response = Vec::new();
    let mut retry = Vec::new();
    let mut error = Vec::new();
    let mut log = Vec::new();
    for module in modules {
        let capabilities = module.module.capabilities();
        aggregate.merge(capabilities);
        if capabilities.stages.contains(ModuleStages::REQUEST_HEADERS) {
            request_headers.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::CACHE_LOOKUP) {
            cache_lookup.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::UPSTREAM_REQUEST) {
            upstream_request.push(module.clone());
        }
        if capabilities
            .stages
            .contains(ModuleStages::UPSTREAM_RESPONSE)
        {
            upstream_response.push(module.clone());
        }
        if capabilities
            .stages
            .contains(ModuleStages::DOWNSTREAM_RESPONSE)
        {
            downstream_response.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::RETRY) {
            retry.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::ERROR) {
            error.push(module.clone());
        }
        if capabilities.stages.contains(ModuleStages::LOG) {
            log.push(module);
        }
    }
    Ok(Arc::new(CompiledHttpModuleChain {
        request_headers: request_headers.into(),
        cache_lookup: cache_lookup.into(),
        upstream_request: upstream_request.into(),
        upstream_response: upstream_response.into(),
        downstream_response: downstream_response.into(),
        retry: retry.into(),
        error: error.into(),
        log: log.into(),
        aggregate,
    }))
}
