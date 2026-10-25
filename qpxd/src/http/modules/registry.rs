use super::{HttpModuleFactory, cache_purge, response_compression};
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
        builder.register_builtin(
            "subrequest",
            super::execution::subrequest::SubrequestModuleFactory,
        );
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
        // Insert only into a vacant slot: a rejected duplicate must not
        // replace the original registration.
        match self.factories.entry(type_name.clone()) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(factory);
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(anyhow!("http module type already registered: {type_name}"));
            }
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

#[cfg(test)]
mod registry_tests {
    use super::super::HttpModule;
    use super::*;
    use qpx_core::config::HttpModuleConfig;

    struct IdFactory;
    impl HttpModuleFactory for IdFactory {
        fn build(&self, _spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>> {
            Err(anyhow!("stub factory never builds"))
        }
    }

    #[test]
    fn rejected_duplicate_registration_keeps_original_factory() {
        let first: Arc<dyn HttpModuleFactory> = Arc::new(IdFactory);
        let mut builder = HttpModuleRegistryBuilder::new();
        builder
            .register_factory_arc("custom", first.clone())
            .expect("first registration");
        assert!(
            builder
                .register_factory_arc("custom", Arc::new(IdFactory))
                .is_err()
        );
        let registry = builder.build();
        let kept = registry.get("custom").expect("registration survives");
        assert!(Arc::ptr_eq(kept, &first));
    }

    #[test]
    fn rejected_builtin_collision_keeps_builtin_factory() {
        let mut builder = HttpModuleRegistryBuilder::with_builtins();
        let builtin = builder
            .factories
            .get("cache_purge")
            .cloned()
            .expect("builtin");
        assert!(
            builder
                .register_factory_arc("cache_purge", Arc::new(IdFactory))
                .is_err()
        );
        let kept = builder
            .factories
            .get("cache_purge")
            .expect("builtin survives");
        assert!(Arc::ptr_eq(kept, &builtin));
    }
}
