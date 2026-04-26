# Enterprise Edge Scope

Positioning guide for `qpx` as an enterprise cloud edge.

This document defines what `qpx` should own, what it should integrate with, and what it should deliberately avoid becoming.

## 1. Product position

`qpx` is a traffic-processing edge and policy enforcement point.

Its core responsibilities are:

- secure egress (`forward` / `transparent`)
- service publishing (`reverse`)
- inline protocol handling (HTTP/1.1, HTTP/2, HTTP/3, CONNECT, CONNECT-UDP / MASQUE)
- TLS termination / passthrough / selective inspection
- traffic shaping, routing, header transformation, local responses
- observability, auditing, and capture export

`qpx` is not intended to be an identity product, an IdP, or a full SASE control plane.

## 2. Architectural role

Use `qpx` as a:

- data plane
- policy enforcement point (PEP)
- protocol gateway
- observability / forensics edge

Do not use `qpx` as a:

- primary authentication authority
- session and token minting system
- user lifecycle management system
- central SaaS governance control plane
- device posture collection platform
- SD-WAN controller

The preferred deployment model is:

1. An external identity or policy system authenticates the subject.
2. That external system produces trusted identity or authorization context.
3. `qpx` receives that context only across a trusted boundary.
4. `qpx` enforces network and HTTP-layer policy on the resulting traffic.
5. `qpx` emits audit and telemetry with the identity context attached.

## 3. Capability map

### Strong fit

- SWG-style secure egress
- reverse proxy / service edge
- transparent interception on Linux
- TLS inspection and policy enforcement
- header and path transformation
- rate limiting
- upstream chaining
- load balancing, retry, and health checks
- observability, metrics, OTLP, audit log, and traffic capture

### Partial fit

- inline CASB-style SaaS traffic control at HTTP metadata level
- app-aware policy by host, SNI, path, method, headers, and external identity context
- authenticated service publishing when identity is asserted by an external system

### Weak fit or explicit non-goal

- API CASB against SaaS provider APIs
- shadow IT discovery from SaaS admin APIs
- DLP classification engines and file/content scanning suites
- browser isolation
- malware sandboxing
- device posture collection
- full ZTNA broker functionality
- central multi-tenant control plane
- administrator UI / RBAC platform

## 4. Identity stance

The identity stance is intentionally narrow.

`qpx` may keep simple built-in authentication only for:

- tests
- local development
- isolated lab deployments
- small operational setups with low integration overhead

That means the current local `Basic` / `Digest` support and the current `LDAP` integration remain acceptable as convenience features, not as the strategic center of the product.

The strategic center should be external identity integration.

## 5. Identity principles

### Principle 1: Externalize authentication

Primary authentication should be handled by systems such as:

- IdP-aware access proxy
- enterprise auth gateway
- service mesh ingress
- mutual TLS gateway
- VPN / ZTNA broker
- API gateway with identity verification

### Principle 2: Keep `qpx` as the PEP

`qpx` should execute decisions such as:

- allow
- block
- inspect
- tunnel
- proxy to a specific upstream
- return a local policy response
- attach audit annotations

It should avoid becoming the source of truth for:

- users
- passwords
- sessions
- browser login flows
- OAuth refresh state
- SAML assertions
- SCIM lifecycle state

### Principle 3: Accept identity only from trusted boundaries

Identity context should be accepted only when at least one trust mechanism is present:

- trusted proxy peer CIDR
- mutual TLS peer verification
- dedicated loopback or private network hop
- signed identity assertion that `qpx` can validate locally

All matching identity headers from untrusted clients must be stripped before policy evaluation or forwarding.

### Principle 4: Audit the decision, not the login flow

`qpx` should log:

- who the upstream trusted system says the subject is
- what policy matched
- what action was taken
- which listener / route / upstream handled the request

It should not own login UX or account lifecycle.

## 6. Recommended feature boundary

### Keep and strengthen

- forward / reverse / transparent proxying
- TLS terminate / passthrough / inspection
- matchers on `src_ip`, `dst_port`, `host`, `sni`, `method`, `path`, `headers`
- local response and header control
- capture, access log, audit log, metrics, tracing
- upstream health and routing behavior
- trust-boundary features such as trusted peers and mTLS

### Keep minimal

- local user/password auth
- digest auth
- LDAP bind/group lookup

These should stay documented as test, local-development, or small-deployment features.

### Add next

- trusted external identity assertions
- external authorization callout
- richer audit context propagation
- policy matching on externally supplied identity and device attributes

### Avoid

- full OIDC login flow implementation
- SAML SP implementation
- browser session management
- refresh token storage
- SCIM server
- in-product user/group directory
- admin RBAC subsystem

## 7. Proposed policy model

The policy model should separate:

- traffic facts
- trusted identity context
- decision inputs from external policy
- local enforcement actions

Conceptually:

```text
request metadata
  + transport metadata
  + trusted identity context
  + optional external authz decision
  -> qpx rule engine
  -> enforcement action
  -> audit / telemetry
```

### 7.1 Traffic facts

Already a strong fit for `qpx`:

- source IP
- destination port
- host
- SNI
- method
- path
- headers
- protocol version
- listener / route name

### 7.2 Trusted identity context

This should be additive and externally sourced:

- user identifier
- groups
- device identifier
- device posture labels
- tenant or workspace label
- authentication strength label
- source identity provider label

`qpx` should treat this as assertion input, not as locally managed identity state.

### 7.3 External authorization decision

Optionally, a request can be evaluated by an external policy service before final enforcement.

The external decision should be constrained to a small result surface:

- `allow`
- `deny`
- `challenge` as a proxy-local response surface, not as `qpx`-owned login UX
- `local_response`
- `inject_headers`
- `override_upstream`
- `timeout_override_ms`
- `cache_bypass` on HTTP paths
- `mirror_upstreams` on reverse HTTP paths
- `rate_limit_profile`
- `force_inspect` / `force_tunnel` on eligible CONNECT and transparent TLS paths
- `policy_tags`

This keeps the data plane simple and avoids turning `qpx` into an application auth framework.

## 8. Implemented configuration model

This section reflects the current configuration shape implemented in the repo.

### 8.1 Minimal built-in auth

Keep built-in auth explicit and visibly secondary:

```yaml
auth:
  users:
    - username: alice
      password: change-me
    - username: digest-only
      ha1: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ldap:
    url: "ldaps://ad.example.com:636"
    bind_dn: "cn=qpx,ou=svc,dc=example,dc=com"
    bind_password_env: LDAP_BIND_PASSWORD
    user_base_dn: "ou=users,dc=example,dc=com"
    group_base_dn: "ou=groups,dc=example,dc=com"
    user_filter: "(&(objectClass=person)(uid={username}))"
    group_filter: "(&(objectClass=groupOfNames)(member={user_dn}))"
    group_attr: "cn"
```

This is acceptable for tests and small deployments, but should not be the preferred path in examples aimed at enterprise operation.

### 8.2 Trusted identity ingestion

Use a separate config area for externally asserted identity:

```yaml
identity_sources:
  - name: corp-access-proxy
    type: trusted_headers
    from:
      trusted_peers: ["10.0.0.0/8"]
    headers:
      user: "x-authenticated-user"
      groups: "x-authenticated-groups"
      device_id: "x-device-id"
      posture: "x-device-posture"
    strip_from_untrusted: true

  - name: partner-mtls
    type: mtls_subject
    from:
      client_ca: "/etc/qpx/client-ca.pem"
    map:
      user_from_san_uri_prefix: "spiffe://corp.example/user/"
      user_from_subject_cn: true

  - name: edge-jwt
    type: signed_assertion
    assertion:
      header: "x-verified-jwt"
      secret_env: EDGE_JWT_HMAC_SECRET
      claims:
        user_from_sub: true
        groups: "groups"
        groups_separator: ","
```

This makes the trust boundary explicit and prevents overloading `auth:` with unrelated concerns.

### 8.3 External authorization hook

Use an optional decision hook:

```yaml
ext_authz:
  - name: central-policy
    kind: http
    endpoint: "https://policy.example.com/check"
    timeout_ms: 300
    max_response_bytes: 1048576
    send:
      request: true
      identity: true
      selected_headers: ["user-agent", "content-type"]
    on_error: deny
```

Per-listener, reverse, or per-route use:

```yaml
listeners:
  - name: egress
    mode: forward
    listen: "0.0.0.0:8080"
    default_action: { type: block }
    policy_context:
      identity_sources: ["corp-access-proxy"]
      ext_authz: central-policy

reverse:
  - name: apps
    listen: "0.0.0.0:443"
    policy_context:
      identity_sources: ["partner-mtls"]
    routes:
      - name: finance
        match:
          host: ["finance.example.com"]
        policy_context:
          ext_authz: central-policy
        upstreams: ["http://10.0.0.20:8080"]
```

### 8.4 Rule matching with trusted identity context

Extend matching carefully:

```yaml
rules:
  - name: inspect-finance
    match:
      host: ["*.finance.example.com"]
      identity:
        groups: ["finance", "security"]
        posture: ["managed", "compliant"]
    action: { type: inspect }
```

Important constraint:

- `identity.*` fields match only trusted derived context, never raw client-supplied headers.

Advanced public matchers also cover:

- `http_version`, `tls_version`, and `tls_fingerprint`
- `request_size` and `response_size`
- destination `*_source` / `*_confidence`
- `upstream_cert`, and on reverse TLS-terminated requests, `client_cert`

### 8.5 Audit enrichment

Allow explicit propagation of decision context:

```yaml
audit_log:
  include:
    - subject
    - groups
    - device_id
    - posture
    - idp
    - ext_authz_policy_id
    - matched_rule
```

## 9. Example deployment patterns

### Pattern A: SWG behind a corporate identity-aware proxy

- upstream enterprise access proxy authenticates the user
- `qpx` trusts identity headers only from that proxy network
- `qpx` performs egress routing, inspection, and auditing

### Pattern B: Reverse edge behind mTLS service gateway

- upstream gateway authenticates workload or user
- `qpx` extracts workload or subject identity from client cert context
- `qpx` applies routing, header policy, canary, and audit tagging

### Pattern C: Small standalone deployment

- `qpx` uses local auth or LDAP
- this is acceptable for small environments
- this is not the preferred enterprise reference architecture

## 10. Documentation guidance

Future docs and examples should follow these rules:

- enterprise examples should prefer external identity integration over built-in auth
- built-in auth examples should be labeled as test, local-development, or small-deployment oriented
- reverse publishing examples should emphasize mTLS and trusted upstream identity handoff where relevant
- new auth-related features should be rejected if they move `qpx` toward full identity ownership without strong data-plane justification

## 11. Short decision summary

`qpx` should aim to be:

- an enterprise cloud edge
- a policy enforcement point
- a protocol-aware data plane
- an observability and forensics edge

`qpx` should not aim to be:

- an IdP
- a full ZTNA broker
- a SaaS governance platform
- a user/session management stack
- a general-purpose authentication product
