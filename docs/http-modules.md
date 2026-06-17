# HTTP Modules

HTTP request/response modules are configured on canonical edges and reverse
routes:

- `edges[].http_modules` applies to forward, transparent HTTP, and MITM HTTP
  paths.
- `edges[kind=reverse].routes[].http_modules` applies per reverse route.

Every module spec accepts `type`, optional `id`, optional `order`, and
module-specific `settings`. `qpxd explain` prints compiled module details,
including subrequest templates, allowlists, redirect policy, response-size caps,
and buffering reasons.

## Built-ins

- `response_compression`: downstream response compression for `gzip`, `br`, and
  `zstd`. Compression runs after cache writeback, so cached objects remain
  identity-encoded while clients can receive compressed responses.
- `subrequest`: internal absolute-URL subrequest at `request_headers` or
  `response_headers`. Subrequests must declare `allowed_schemes`,
  `allowed_hosts`, and `max_response_bytes`. Redirects are denied by default and
  allowed redirects are still checked for private IP destinations.
- `cache_purge`: first-class HTTP purge endpoint for the configured cache key.
  Requires `cache.enabled: true` on the listener or reverse route where it is
  used.

```yaml
edges:
  - kind: forward
    name: forward
    listen: 127.0.0.1:18080
    default_action: { type: direct }
    cache:
      enabled: true
      backend: edge-cache
    http_modules:
      - type: cache_purge
      - type: response_compression
        settings:
          min_body_bytes: 512
          gzip: true
          brotli: true
          zstd: true
```

See
[`config/usecases/07-observability-debug/http-modules-advanced.yaml`](../config/usecases/07-observability-debug/http-modules-advanced.yaml)
for a fuller built-in module sample.

## Custom Modules

`qpxd` is both a library and a daemon binary. External Rust binaries can
register custom module factories and then run the normal CLI/event loop.

The public API surface is `qpxd::Daemon::builder()` plus
`qpxd::module_api::{HttpModuleFactory, HttpModule, HttpModuleCapabilities,
HttpModuleStage, HttpModuleEvent, ModuleStages, HttpModuleContext,
HttpModuleRequestView, Body}`.

Modules declare capabilities so `qpxd` compiles stage-indexed chains and only
calls modules for the stages they need. Built-in compression runs only on
downstream responses, request-phase subrequests run only on request headers, and
response-phase subrequests request a frozen request view only for routes that
need it.

<details>
<summary>Minimal custom module example</summary>

```rust
use anyhow::Result;
use async_trait::async_trait;
use qpxd::module_api::{
    Body, HttpModule, HttpModuleCapabilities, HttpModuleContext, HttpModuleEvent,
    HttpModuleFactory, HttpModuleStage, ModuleStages,
};
use qpxd::{Daemon, HttpModuleConfig};
use std::sync::Arc;

#[derive(serde::Deserialize)]
struct AddHeaderConfig {
    header_name: String,
    header_value: String,
}

struct AddHeaderFactory;
struct AddHeader {
    name: http::HeaderName,
    value: http::HeaderValue,
}

impl HttpModuleFactory for AddHeaderFactory {
    fn build(&self, spec: &HttpModuleConfig) -> Result<Arc<dyn HttpModule>> {
        let cfg: AddHeaderConfig = spec.parse_settings()?;
        Ok(Arc::new(AddHeader {
            name: cfg.header_name.parse()?,
            value: cfg.header_value.parse()?,
        }))
    }
}

#[async_trait]
impl HttpModule for AddHeader {
    fn capabilities(&self) -> HttpModuleCapabilities {
        HttpModuleCapabilities::headers_only(ModuleStages::DOWNSTREAM_RESPONSE)
    }

    async fn call<'a>(
        &self,
        stage: HttpModuleStage,
        _ctx: &mut HttpModuleContext,
        event: HttpModuleEvent<'a>,
    ) -> Result<HttpModuleEvent<'a>> {
        let HttpModuleStage::DownstreamResponse = stage else {
            return Ok(event);
        };
        let HttpModuleEvent::DownstreamResponse(mut response) = event else {
            anyhow::bail!("invalid downstream response event");
        };
        response.headers_mut().insert(self.name.clone(), self.value.clone());
        Ok(HttpModuleEvent::DownstreamResponse(response))
    }
}

fn main() -> Result<()> {
    Daemon::builder()
        .register_http_module("add_header", AddHeaderFactory)?
        .build()
        .run_cli()
}
```

</details>

