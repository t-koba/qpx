use super::{HttpModuleFactory, cache_purge, response_compression, subrequest};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

static DEFAULT_HTTP_MODULE_REGISTRY: OnceLock<Arc<HttpModuleRegistry>> = OnceLock::new();

pub(crate) fn default_http_module_registry() -> Arc<HttpModuleRegistry> {
    DEFAULT_HTTP_MODULE_REGISTRY
        .get_or_init(|| Arc::new(HttpModuleRegistryBuilder::with_builtins().build()))
        .clone()
}

pub struct HttpModuleRegistryBuilder {
    factories: HashMap<String, Arc<dyn HttpModuleFactory>>,
}

impl Default for HttpModuleRegistryBuilder {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl HttpModuleRegistryBuilder {
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    pub fn with_builtins() -> Self {
        let mut builder = Self::new();
        builder.register_builtin("cache_purge", cache_purge::CachePurgeModuleFactory);
        builder.register_builtin("subrequest", subrequest::SubrequestModuleFactory);
        builder.register_builtin(
            "response_compression",
            response_compression::ResponseCompressionModuleFactory,
        );
        builder
    }

    fn register_builtin<F>(&mut self, type_name: &'static str, factory: F)
    where
        F: HttpModuleFactory + 'static,
    {
        self.factories
            .insert(type_name.to_string(), Arc::new(factory));
    }

    pub fn register_factory<F>(
        &mut self,
        type_name: impl Into<String>,
        factory: F,
    ) -> Result<&mut Self>
    where
        F: HttpModuleFactory + 'static,
    {
        self.register_factory_arc(type_name, Arc::new(factory))
    }

    pub fn register_factory_arc(
        &mut self,
        type_name: impl Into<String>,
        factory: Arc<dyn HttpModuleFactory>,
    ) -> Result<&mut Self> {
        let type_name = type_name.into();
        if type_name.trim().is_empty() {
            return Err(anyhow!("http module type name must not be empty"));
        }
        if self.factories.insert(type_name.clone(), factory).is_some() {
            return Err(anyhow!("http module type already registered: {type_name}"));
        }
        Ok(self)
    }

    pub fn build(self) -> HttpModuleRegistry {
        HttpModuleRegistry {
            factories: self
                .factories
                .into_iter()
                .map(|(type_name, factory)| (Arc::<str>::from(type_name), factory))
                .collect(),
        }
    }
}

#[derive(Clone)]
pub struct HttpModuleRegistry {
    factories: HashMap<Arc<str>, Arc<dyn HttpModuleFactory>>,
}

impl HttpModuleRegistry {
    pub fn builder() -> HttpModuleRegistryBuilder {
        HttpModuleRegistryBuilder::with_builtins()
    }

    pub fn get(&self, type_name: &str) -> Option<&Arc<dyn HttpModuleFactory>> {
        self.factories.get(type_name)
    }
}
