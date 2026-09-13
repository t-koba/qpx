# Browser origin security

qpx reverse routes can act as a browser-facing origin policy enforcement
point. All policy surfaces are explicit opt-ins under `routes[].http`; target
responses cannot widen a configured policy.

```yaml
http:
  cors:
    allowed_origins: [https://app.example]
    allowed_methods: [GET, POST]
    allowed_headers: [content-type, authorization]
    allow_credentials: true
    max_age_seconds: 600
  fetch_metadata:
    allowed_sites: [same-origin, same-site]
    allowed_modes: [navigate, cors]
    allowed_destinations: [document, empty]
    allow_missing: false
    require_user_activation_for_navigation: true
  browser_security:
    content_security_policy: "default-src 'self'; object-src 'none'"
    referrer_policy: strict-origin-when-cross-origin
    permissions_policy: "camera=(), geolocation=(self)"
    cross_origin_opener_policy: same-origin
    cross_origin_embedder_policy: require-corp
    cross_origin_resource_policy: same-origin
    x_content_type_options: nosniff
    origin_agent_cluster: "?1"
    reporting_endpoints: 'default="/reports"'
    timing_allow_origin: https://app.example
    accept_ch: Sec-CH-UA, Sec-CH-UA-Mobile
    critical_ch: Sec-CH-UA-Mobile
  cookies:
    require_secure: true
    require_http_only: true
    same_site: lax
    require_partitioned: false
    max_field_bytes: 16384
```

Fetch Metadata fields use singleton semantics. Unknown values, partial field
sets, and disallowed site, mode, destination, or navigation activation are
rejected before origin dispatch. `allow_missing` must be chosen deliberately:
keep it false for browser-only endpoints and enable it only when non-browser
clients must use the same route.

`browser_security` values are parsed according to their individual grammars at
configuration load. Duplicate directives and inconsistent combinations such
as a Critical-CH value absent from Accept-CH fail startup. qpx removes every
managed target-provided value before applying the configured value.

Cookie enforcement parses every Set-Cookie field independently and preserves
field multiplicity. `SameSite=None` and `Partitioned` require Secure. A policy
that requires Secure fails closed on a connection qpx does not recognize as a
secure origin; configure TLS termination consistently.

## Reporting endpoint

A dedicated route can terminate Reporting API uploads instead of proxying
them:

```yaml
- match:
    method: [POST]
    path: [/reports]
  http:
    reporting_collector:
      max_body_bytes: 262144
      max_reports: 128
      accept_legacy_csp_reports: false
  target:
    type: local_response
    response: {status: 204}
```

The collector intercepts the selected route after identity and access policy
enforcement. It accepts `application/reports+json`, validates a bounded array
of report objects, returns 204 with `Cache-Control: no-store`, writes structured
report type and URL events, and increments
`qpx_browser_reports_received_total`. The configured target is intentionally
not invoked. Legacy `application/csp-report` is available only through the
explicit compatibility switch.

## Client certificate forwarding

RFC 9440 forwarding requires reverse TLS client authentication and explicit
route opt-in:

```yaml
http:
  client_certificate:
    include_chain: true
    reject_inbound: true
    max_certificate_bytes: 65536
    max_chain_certificates: 16
    max_field_bytes: 131072
    max_total_field_bytes: 262144
```

qpx always removes untrusted inbound Client-Cert and Client-Cert-Chain fields.
With `reject_inbound: true`, an attempted injection returns 400. Only the DER
certificates authenticated on the current TLS connection are serialized as
Structured Fields; chain order is preserved and the end-entity certificate
cannot be duplicated in the chain.

## DPoP resource server

DPoP is configured on a bearer identity source:

```yaml
bearer:
  source:
    mode: jwt
    issuer: https://issuer.example
    audience: https://api.example
    jwks_url: https://issuer.example/.well-known/jwks.json
  dpop:
    required: true
    max_age_seconds: 300
    clock_skew_seconds: 5
    replay_cache_capacity: 8192
    algorithms: [ES256, ES384, RS256, RS384, RS512, EdDSA]
```

When required, the request must use `Authorization: DPoP ...` and exactly one
DPoP proof field. qpx verifies the proof signature and public JWK, normalized
HTTP method and target URI, proof age and identifier, access-token hash,
`cnf.jkt` binding, optional configured nonce, and an atomic bounded replay
cache. Crypto or replay-store failure is fail-closed. Token issuance and key
registration remain authorization-server responsibilities. Invalid tokens and
proofs return HTTP 401 with an appropriate `WWW-Authenticate` challenge. A
nonce failure uses `error="use_dpop_nonce"` together with the `DPoP-Nonce`
response field; replay and other proof failures use
`error="invalid_dpop_proof"`.

## Experimental RateLimit fields

Set `experimental_rate_limit_fields: true` on an enabled rate-limit policy with
a fixed quota to emit the current draft RateLimit-Policy and RateLimit fields.
The switch is intentionally explicit because the document is not yet an RFC.
Generated 429 responses retain Retry-After and add
`Cache-Control: private, no-store`.
