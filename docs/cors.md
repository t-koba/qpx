# Cross-Origin Resource Sharing

qpx can own Cross-Origin Resource Sharing (CORS) policy on a reverse route.
The policy applies uniformly to upstream, weighted, IPC, local-response, and
WebDAV targets over HTTP/1.1, HTTP/2, and HTTP/3.

Configure CORS at `edges[kind=reverse].routes[].http.cors`:

```yaml
edges:
- kind: reverse
  name: browser-api
  listen: 127.0.0.1:19080
  routes:
  - match:
      method: [GET, PUT]
      path: [/api/**]
    http:
      cors:
        allowed_origins: [https://app.example.com]
        allowed_methods: [GET, PUT]
        allowed_headers: [content-type, x-request-id]
        expose_headers: [etag]
        allow_credentials: true
        max_age_seconds: 600
        allow_private_network: false
    target:
      type: local_response
      response:
        status: 200
        body: ok
```

`allowed_origins` and `allowed_methods` are required and non-empty. Origins
must be canonical serialized HTTP or HTTPS origins, without a path, query, or
fragment. The literal `null` origin is supported. A wildcard must be the only
entry in its list.

When `allow_credentials` is true, wildcards are rejected in
`allowed_origins`, `allowed_methods`, `allowed_headers`, and `expose_headers`.
This prevents a configuration that browsers cannot interpret as credentialed
CORS. `CONNECT`, `TRACE`, and `TRACK` are rejected as CORS methods. A wildcard
`allowed_headers` value never authorizes `Authorization`; list that field
explicitly when it is required. `Set-Cookie` and `Set-Cookie2` are rejected in
`expose_headers` because Fetch never exposes those response fields to scripts.

## Request handling

An `OPTIONS` request with both `Origin` and
`Access-Control-Request-Method` is a preflight. qpx selects the reverse route
using the requested method, validates the origin, method, requested fields, and
optional Private Network Access flag, and answers directly with `204`. The
preflight does not call the selected target. A policy denial returns `403` as
Problem Details without CORS allow fields. Malformed CORS request fields return
`400` instead of falling through to ordinary routing.

For actual requests, qpx removes target-provided CORS response fields and then
emits the selected route's policy. This makes the route configuration
authoritative and prevents an upstream or local target from widening it.
Origin-specific responses include `Vary: Origin`; preflight responses also vary
on requested method, requested fields, and the Private Network Access request
flag.

If no CORS-enabled route matches a preflight's requested method and request
metadata, qpx continues normal `OPTIONS` routing. This lets an application own
CORS when no qpx route policy has claimed it.

A CORS route cannot use match dimensions that the preflight cannot reproduce:
request headers, identity, body size, response status or size, TLS fingerprint,
upstream certificate, or RPC metadata. Configuration validation rejects these
combinations instead of allowing a preflight to select a different policy from
the actual request. Put authorization enforcement in the route policy rather
than in an identity-dependent route selector when that route must serve browser
CORS traffic.

`allow_private_network` implements the current Private Network Access draft and
defaults to false. Enable it only when the browser application is intentionally
allowed to reach a more-private address space.

## Manual check

```bash
curl -i -X OPTIONS http://127.0.0.1:19080/api/item \
  -H 'Host: api.example.com' \
  -H 'Origin: https://app.example.com' \
  -H 'Access-Control-Request-Method: PUT' \
  -H 'Access-Control-Request-Headers: content-type,x-request-id'
```

See
[`reverse-cors-origin.yaml`](../config/usecases/03-service-publishing/reverse-cors-origin.yaml)
for a complete checked configuration.

Normative web-platform references:

- [WHATWG Fetch Standard](https://fetch.spec.whatwg.org/)
- [Private Network Access draft](https://wicg.github.io/private-network-access/)
