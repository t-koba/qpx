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
  identity-encoded while clients can receive compressed responses. Eligible
  identity responses also carry `Vary: Accept-Encoding`, including when the
  request omits that field, so downstream caches do not mask a later compressed
  variant. Ineligible and `no-transform` responses are not modified by the
  compression module.
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
HttpModuleRequest, HttpModuleRequestView, HttpModuleResponse,
HttpModuleResponseView, Body}`.

Request and response event payloads are opaque facades: `HttpModuleRequest`
borrows the transport request while `HttpModuleResponse` owns the transport
response. Modules use semantic views, scalar setters, named header
presence/mutation operations and body moves; raw header maps, raw values,
iterators, callbacks, `Deref`, parts and transport conversions are not
exposed. Short-circuits build responses via
`HttpModuleResponse::new(status, Body)`.

### Module bodies and the transport boundary

`module_api::{Body, BodyError, BodyFrame, Sender, Trailers}` are qpxd-owned
facades, not aliases for qpx-http types. Request/response `take_body`, `set_body`
and response construction use this `Body`; the context's absolute-request
helpers accept caller-owned `http::Request<module_api::Body>`. Request views
borrow only the request head and are independent of its body type. Built-in
transport integrations remain private to qpxd.

Use `Body::from`, `empty`, `replay` or `replay_chunks` for materialized data,
`Body::wrap(standard_body)` to accept any compatible standard streaming body
(including `hyper::body::Incoming`), or `Body::channel_with_capacity(n)` for
bounded streaming (`channel()` defaults to 16 frames). `Sender::send_data`, `send_trailers` and `send_frame` wait for
capacity; `try_send_data`/`try_send_trailers` fail immediately when full or
closed. Dropping the sender ends the stream; `abort` delivers a stream error;
dropping the body wakes blocked senders and `closed()` waiters. Canceling a
blocked send does not enqueue that frame. Body limits and existing transport
read timeouts survive body moves; a stream error is terminal.

Read `next_frame()` for ordered `BodyFrame::Data(Bytes)` and
`BodyFrame::Trailers(Trailers)` frames. Alternatively read `data()` until it
returns `None`, then `trailers()`; requesting trailers early drains unread
data. A taken body can be forwarded directly, or each frame can be passed to
`Sender::send_frame`. `to_bytes()` collects data and discards trailers; use
`limit_bytes(n)` before collection when a bound is needed.

`Trailers` can be created, cloned, forwarded, or mutated with caller-supplied
`HeaderName`/`HeaderValue` inputs via `insert`, `append` and `remove` (mutations
never return displaced values). `metadata()` returns a filtered borrowed view:
`get`, `get_all` and `iter` expose exact `HeaderValue` bytes and per-name
duplicate order only for application metadata. The shared HTTP trailer policy
and qpxd's RPC owner reserve framing/content and status/message/status-detail
fields;
reserved values are unavailable through this generic view and are available
only through parsed protocol-semantic accessors. The view has no raw
`HeaderMap`/conversion, unrestricted callback or `Deref`, and debug formatting
does not disclose values. The facade
does **not** implement standard `http_body::Body` and has no public
`mark_trailers_sanitized` trust assertion. At the private bridge, module-produced
and taken/replaced bodies are untrusted: normal response finalization sanitizes
their trailers, even if an underlying transport body had been marked sanitized.
Module-supplied and module-replaced request bodies pass through the existing
request-trailer validator before outgoing consumption, including absolute requests
and MITM requests already normalized to HTTP/1.1; no trailer declaration is
required to validate them. Untouched requests keep their existing
protocol-specific preparation policy. Internal trusted bodies
left untouched by modules retain their trust marker.

This boundary is intentionally limited to qpxd's module body API. qpx-http's
public transport `Body`/`Sender` and standard `http_body::Body`/`Frame` trailer
interoperability are unchanged. `RpcStreamObserver`/`RpcStreamSummary` use the
same facade: `RpcStreamSummary::trailers()` returns an opaque `&Trailers` with
the shared filtered application-metadata view and parsed RPC status, message,
and binary status-detail results; no raw `HeaderMap` or all-field getter
escapes. This is
not a workspace-wide header-ownership claim.

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
        let mut capabilities =
            HttpModuleCapabilities::headers_only(ModuleStages::DOWNSTREAM_RESPONSE);
        capabilities.mutates_response_headers = true;
        capabilities
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
        response.set_header(self.name.clone(), self.value.clone());
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


### Prepared local-response ownership

A module's short-circuit `HttpModuleResponse` is a module-API boundary. Dispatch
imports it once into the opaque `qpx_core::http_message::Response<Body>` before
running downstream response hooks. The same owner then passes through route
header controls and protocol finalization, module logging, dispatch annotations,
and the existing response-body limit. Individual hooks still use the public
module facade; skipped hooks do not require a standard-response conversion.
Forward (including its inner dispatch preparation) and transparent preparation
share a single owner-backed response outcome. MITM and reverse module dispatch
also retain the owner through their terminal handoffs. This changes no policy
order, configuration default, capture limit, or module API behavior.

This is not global raw-header closure: codec/library sends, raw-H1 direct relay,
legacy generated response builders and other specialized response paths remain
separate. In particular, transparent listener-policy `early_response` is not the
shared prepared-response outcome and retains its existing processing semantics.
