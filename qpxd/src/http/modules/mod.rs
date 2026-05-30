mod cache_purge;
mod chain;
mod execution;
mod headers;
mod registry;
mod response_compression;
mod subrequest;
mod template;
mod traits;

#[cfg(test)]
mod tests;

pub(crate) use chain::{CompiledHttpModuleChain, compile_http_modules};
pub use execution::{HttpModuleContext, HttpModuleRequestView};
pub(crate) use execution::{HttpModuleExecution, HttpModuleSessionInit};
pub(crate) use registry::default_http_module_registry;
pub use registry::{HttpModuleRegistry, HttpModuleRegistryBuilder};
#[cfg(feature = "http3")]
pub(crate) use response_compression::is_event_stream_headers;
pub use traits::{
    BodyAccess, CacheLookupStatus, HttpModule, HttpModuleCapabilities, HttpModuleEvent,
    HttpModuleFactory, HttpModuleStage, ModuleStages, RequestHeadersOutcome, RetryEvent,
};
