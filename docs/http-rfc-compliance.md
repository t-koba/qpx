# qpx HTTP RFC compliance matrix

This document is the authoritative release record for qpx HTTP conformance. It
covers the HTTP core, extensions, authentication and authorization boundaries,
QUIC and HTTP/3 dependencies, tunnels, WebSocket, WebDAV, and shared protocol
foundations. A row is releasable only when its named contract is green in the
same commit. Passing a parser unit test alone does not imply protocol-wide
conformance.

## Conformance status

- `complete`: the applicable qpx roles and protocol paths are implemented and
  are required by the release gates in this document.
- `external-authority`: qpx implements the resource-server or PEP side while
  identity, token issuance, session, MFA, or policy authority remains external.
- `transport-library-with-contract`: a pinned transport or TLS implementation owns wire-level
  mechanics and qpx owns configuration, limits, parity, and interoperability
  gates.
- `not-applicable`: the specification assigns a responsibility to a user agent,
  identity provider, authorization server, or another component outside qpx.

There is no public `partial` status. A capability that has not passed every
applicable release gate is not advertised or enabled in a release build.

## Classification

- `native`: qpx parses, validates, enforces, or serves the protocol behavior.
- `external-authority`: qpx enforces a provider-neutral result obtained through
  a standard or explicitly mapped external interface.
- `transport-library-with-contract`: a transport dependency supplies the wire
  implementation and qpx owns configuration, limits, and interoperability tests.

External product names are not part of the production domain model. Provider
integration is expressed through AuthZEN, OAuth, JWT/JWKS, introspection, mTLS,
HTTP message signatures, or explicit schema mapping. Identity, login, session,
token issuance, MFA, and revocation authority are outside qpx.

## Product-role applicability

| qpx role | Owned conformance scope | Explicitly outside the role |
|---|---|---|
| Forward proxy / PEP | request routing, policy enforcement, CONNECT, cache, forwarding metadata, protocol translation | identity and policy authority |
| Reverse proxy / resource server | TLS termination, Bearer validation, external authorization enforcement, cache, upstream selection, response policy | token issuance, login, session, MFA, revocation authority |
| Origin server in qpxd | local responses, static and WebDAV resources, API metadata, HSTS, Problem Details | general identity-provider services |
| Transparent proxy / MITM | applicable HTTP semantics after protocol identification or authorized TLS inspection | semantics unavailable without inspection |
| Dynamic execution in qpxf | CGI, FastCGI, SCGI, and WASM execution with explicit verified-context opt-in | routing authority, WebDAV semantics, IdP/PDP integration |

An RFC row applies to every role and HTTP version for which that protocol
element is meaningful. Tests named in the row are supplemented by the
HTTP/1.1, HTTP/2, and HTTP/3 × forward, reverse, transparent, MITM, and origin
contract matrix. A non-applicable combination is recorded as such by the test
matrix rather than silently treated as passing.

## Complete RFC inventory

This inventory is the index of every RFC covered by the qpx HTTP conformance
program. Detailed contracts and evidence follow in the corresponding sections.

| Area | RFCs | qpx status | Detailed scope |
|---|---|---|---|
| HTTP semantics and versions | 9110, 9111, 9112, 9113, 9114 | complete / transport-library-with-contract | semantics, cache, HTTP/1.1, HTTP/2, HTTP/3 |
| Methods and status codes | 5789, 6585, 7725, 8297, 8470, 10008 | complete | PATCH, additional status codes, Early Hints, early data, QUERY |
| Fields and metadata | 6265, 6266, 7239, 7240, 7838, 8288, 8594, 9209, 9651, 9745, 9842 | complete | cookies, disposition, forwarding, preferences, links, proxy metadata, structured fields, dictionary compression |
| Cache extensions | 5861, 8246, 9211, 9213 | complete | stale controls, immutable, Cache-Status, targeted controls |
| Authentication and integrity | 6750, 6797, 7616, 7617, 9421, 9530, 9931 | complete / external-authority | resource-server Bearer handling, HSTS, Basic/Digest, signatures, digests, optimistic-data safety |
| Provider-neutral security interfaces | 6749, 7517, 7519, 7662, 8705 | external-authority | client credentials, JWK/JWKS, JWT, introspection, mTLS client authentication |
| HTTP API design | 9205, 9457 | complete | API design validation and Problem Details |
| QUIC and HTTP/3 | 9000, 9001, 9002, 9204, 9218, 9221, 9368, 9369 | transport-library-with-contract / complete | QUIC transport, TLS, recovery, QPACK, priority, DATAGRAM, v2 negotiation |
| MASQUE and tunnels | 9297, 9298, 9484 | complete | capsules, CONNECT-UDP, CONNECT-IP |
| WebSocket | 6455, 8441, 9220 | complete | HTTP/1.1, HTTP/2, and HTTP/3 WebSocket paths |
| WebDAV and CalDAV | 3253, 3744, 4791, 4918, 5323, 5689, 5842 | complete | versioning, ACL, calendars, core DAV, search, MKCOL, bindings |
| Shared foundations | 3986, 6838, 7301, 8446 | complete / transport-library-with-contract | URI, media types, ALPN, TLS 1.3 |

### HTTP core

| RFC | Classification | Implemented contract | Evidence |
|---|---|---|---|
| 9110 | native | shared semantics, methods, status codes, fields, conditional requests, ranges, authentication framework | `qpx-http` protocol tests and `qpxd/tests/http_rfc_contract.rs` |
| 9111 | native | cache keying, freshness, validation, invalidation, Vary, Age, and warning behavior | `qpxd-cache` unit/scenario tests and RFC cache contracts |
| 9112 | native | strict HTTP/1.1 framing, connection lifecycle, trailers, Upgrade, and CONNECT handling | H1 codec tests, smuggling regressions, and forward/reverse E2E |
| 9113 | transport-library-with-contract | HTTP/2 framing, stream lifecycle, extended CONNECT, limits, and forward/reverse/transparent paths | HTTP/2 contract and E2E suites |
| 9114 | transport-library-with-contract | HTTP semantics over QUIC, control streams, settings, QPACK integration, H3 errors, and backend parity | qpx-h3 unit/E2E and external H3 matrix |

## Methods, status codes, and fields

| RFC | Classification | Implemented contract | Evidence |
|---|---|---|---|
| 5789 | native | PATCH semantics, invalidation, `Accept-Patch` | `protocol::method`, RFC contract suite |
| 10008 | native | safe/idempotent QUERY, `Accept-Query`, content-derived cache key; never 0-RTT | `accept_query` tests, `query_cache_key_includes_content_metadata` |
| 6585 | native | 428 policy, 429, 431, CAPPORT-only 511 | qpxd protocol/config tests and RFC contract suite |
| 7725 | native | policy-generated 451 with legal-information `Link` | API metadata and local-response contract tests |
| 8297 | native | generation and relay of 103 across supported HTTP paths | informational-response RFC scenarios |
| 8470 | native | 425 handling and replay-safety classification; early data disabled by default | method-registry and HTTP/3 tests |
| 6265 | native | strict Cookie and Set-Cookie codec/policy; no cookie jar or session authority | `cookie_policy::tests` |
| 6266 | native | strict Content-Disposition parser/serializer and extended filename handling | `content_disposition::tests` |
| 7239 | native | strict Forwarded codec and configured trusted-chain handling | `forwarded::tests`, qpxd forwarded tests |
| 7240 | native | strict Prefer parser/serializer | `prefer::tests` |
| 8288 | native | Link generation and validation for API lifecycle metadata | `api_metadata::tests` |
| 9651 | native | shared Structured Fields codec; duplicate dictionary members use last-member semantics | `structured_fields::tests` |
| 7838 | native | authenticated Alt-Svc authority, expiry, clear, and failure handling | `h3_pool::alt_svc` tests |
| 9209 | native | Proxy-Status append on proxy responses only | `proxy_status::tests`, response-path tests |
| 8594, 9745 | native | validated Sunset and Deprecation route metadata with Link integration | `api_metadata::tests` |
| 9842 | native | HTTPS/same-origin/freshness/hash policy, dcb/dcz, bounded dictionary cache | `compression_dictionary::tests`, response-compression tests |

## Cache, integrity, authentication, and API behavior

| RFC | Classification | Implemented contract | Evidence |
|---|---|---|---|
| 5861 | native | stale-while-revalidate and stale-if-error | `qpxd-cache` freshness/scenario tests |
| 8246 | native | immutable response handling | `qpxd-cache` directive/freshness tests |
| 9211 | native | each qpx cache appends its own named Cache-Status member | cache RFC scenarios |
| 9213 | native | named targeted cache control precedence over CDN-Cache-Control and Cache-Control | `qpxd-cache` directive tests |
| 7617, 7616 | native | explicitly enabled Basic/Digest authentication | authentication contract tests |
| 6750 | external-authority | resource-server JWT/JWKS or RFC 7662 introspection; qpx never issues tokens | bearer identity tests and real-provider integration lane |
| 6797 | native | reverse TLS origin HSTS policy | `hsts::tests` and response module tests |
| 9421 | native | generic HTTP message signing/verification and external-service request signing | decision-service signature tests |
| 9530 | native | Content-Digest/Repr-Digest parse, generation, and verification | `digest_fields::tests`, body-spool tests |
| 9205 | native | origin API configuration lint | configuration validation tests |
| 9457 | native | machine-readable qpx origin errors use Problem Details | `problem::tests`, local response tests |

### Provider-neutral resource-server and PEP dependencies

| RFC | Classification | qpx responsibility | External responsibility | Evidence |
|---|---|---|---|---|
| 6749 | external-authority | client-credentials client, authenticated token endpoint use, bounded token cache, fail-closed errors | authorization server and token issuance | external-service credential tests and real-provider matrix |
| 7517 | external-authority | strict configured/static JWK and remote JWKS consumption, key selection, refresh bounds | key publication and rotation authority | bearer JWKS tests and real-provider matrix |
| 7519 | external-authority | signature, issuer, audience, algorithm, time, and required-claim validation | JWT issuance and claim authority | bearer JWT tests and real-provider matrix |
| 7662 | external-authority | authenticated introspection, `active=true`, bounded positive/negative cache | introspection endpoint and revocation authority | introspection tests and real-provider matrix |
| 8705 | external-authority | TLS client authentication for token and decision-service endpoints | certificate enrollment and authorization-server policy | TLS credential validation and provider integration lanes |

Claim mapping into `VerifiedIdentityContext` is explicit and provider-neutral.
Raw bearer tokens, authorization fields, cookies, assertions, and request bodies
are excluded from PDP input, logs, audit records, and QPX-IPC metadata.

External authorization supports only provider-neutral `authzen` and
`schema_mapped_http` drivers. Effects are mapped to `QpxEnforceableEffectV1`,
validated as one atomic set against declared capabilities and local allowlists,
and fail closed. Resource-server credentials, external-service credentials,
mTLS, and RFC 9421 transport protection are separate configuration concerns.

## HTTP/2, HTTP/3, QUIC, tunnels, and WebSocket

| RFC | Classification | Implemented contract | Evidence |
|---|---|---|---|
| 9204 | transport-library-with-contract | QPACK limits and backend parity | qpx-h3 unit/E2E suites |
| 9218 | native | RFC 9651 Priority parsing and live PRIORITY_UPDATE scheduling | qpx-h3 priority tests |
| 9000, 9001, 9002 | transport-library-with-contract | QUIC transport/TLS/loss behavior with qpx resource limits | qpx-h3 E2E and interop lane |
| 9221 | transport-library-with-contract | bounded QUIC DATAGRAM handling | qpx-h3 datagram tests |
| 9368, 9369 | transport-library-with-contract | pinned Quinn protocol implementation for compatible negotiation and QUIC v2 | `vendor/quinn-proto` tests and QUIC-v2 interop lane |
| 9297 | native | HTTP Datagrams, context IDs, Capsule fallback | both-backend datagram/capsule tests |
| 9298 | native | CONNECT-UDP URI template, flow policy, chained relay; no H1 optimistic data | both-backend MASQUE tests |
| 9484 | native | CONNECT-IP capsules, MTU/CIDR policy, chained relay, Linux TUN, macOS utun, Windows Wintun | `connect_ip` codec/relay tests; platform and interop lanes |
| 6455, 8441, 9220 | native | strict WebSocket handshake and H1/H2/H3 tunnel paths | WebSocket unit and forward/reverse E2E tests |
| 9931 | native | rejected H1 CONNECT/Upgrade closes; data is not forwarded before success | tunnel RFC scenarios |

CONNECT-IP control messages and every relayed IP packet are checked against the
configured address families, source/destination CIDRs, range containment, and
MTU. A prefix or route that merely has an allowed endpoint but escapes the
configured CIDR is rejected.

0-RTT is disabled by default. Safe mode excludes QUERY, unknown methods,
CONNECT-family requests, bodies, credentials, cookies, and signatures.

## WebDAV and origin execution

| RFC | Classification | Implemented contract | Evidence |
|---|---|---|---|
| 4918 | native | resources, properties, locks, atomic COPY/MOVE, bounded multistatus | qpx-webdav unit and DAV integration lane |
| 5323 | native | bounded basicsearch | qpx-webdav search tests and DAV integration lane |
| 3253 | native | version resource, checkout/checkin/update/merge state | qpx-webdav version tests |
| 3744 | native | ACE evaluation and protected properties using verified identity context | qpx-webdav ACL tests |
| 4791 | native | calendar collection/query/free-busy and iCalendar validation | qpx-webdav CalDAV tests and CalDAV integration lane |
| 5689 | native | Extended MKCOL | qpx-webdav tests |
| 5842 | native | BIND/UNBIND/REBIND and cycle rejection | qpx-webdav binding tests |

`qpx-webdav` is an origin service embedded by qpxd. qpxf is only the dynamic
execution substrate for CGI, FastCGI, SCGI, and WASM. Neither component knows an
IdP or PDP product name. Verified identity metadata and authorization-decision
metadata are separate QPX-IPC values and are forwarded to a handler only by
explicit opt-in.

The filesystem store rejects traversal and symlink escape. Metadata mutations
use redb transactions. OPTIONS/DAV advertises only implemented capabilities.

## Shared foundations

| RFC | Classification | Contract | Evidence |
|---|---|---|---|
| 3986 | native | strict URI/authority and URI-template validation | protocol address and template tests |
| 6838 | native | validated media types in origin/WebDAV/QUERY APIs | codec and qpx-webdav tests |
| 8446 | transport-library-with-contract | TLS 1.3 policy | TLS unit and interoperability lane |
| 7301 | transport-library-with-contract | HTTP/1.1, h2, and h3 ALPN selection | TLS/H2/H3 contract tests |

## Release gates

All gates below must pass on one commit before a release is published:

1. `cargo test --workspace --all-features --locked`
2. clippy and rustdoc with warnings denied
3. fuzz smoke and ASan lanes
4. every checked-in configuration sample
5. real AuthZEN/schema-mapped provider matrix using the same qpx binary
6. HTTP/1.1, HTTP/2, and HTTP/3 RFC contract matrix
7. QUIC v2, H3, WebSocket, CONNECT-UDP, CONNECT-IP, and WebTransport interop
8. DAV litmus and CalDAV tester against a real qpxd listener and filesystem/redb
9. memory, file-descriptor, queue, and p95 performance budgets
10. provider-neutral authorization and resource-server contract tests

Platform-specific CONNECT-IP gates run on their native OS. A cross-check that
stops before Rust compilation because the host lacks a Windows SDK is not a
passing Windows gate.
