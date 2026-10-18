//! Leaf HTTP/1 client primitives shared across crates. The qpxd-specific helpers
//! (shared client, upstream-proxy resolution) remain in `qpxd`.
//!
//! ## HTTP/1 Hyper header-byte limit (mechanism vs policy)
//!
//! Hyper owns the wire mechanics (`Builder::max_header_size` for the H1 server
//! and client builders, hyper 1.12.0); qpx owns configurability and defaults.
//! The policy input is the existing `limits.header_bytes` guard knob
//! (`qpx-core` `HttpGuardLimitsConfig`, validated `>= 1` when set). This module
//! only derives the transport bound from it:
//!
//! ```text
//! hyper_max_header_size = header_bytes + H1_HYPER_HEADER_WIRE_OVERHEAD_ALLOWANCE_BYTES
//! ```
//!
//! - Default: `None` (unset) preserves the Hyper status-quo. Neither builder
//!   sets `max_header_size`, so Hyper falls back to its `max_buf_size`
//!   behaviour (default ~400 KiB). No existing connection tightens.
//! - Allowance: [`H1_HYPER_HEADER_WIRE_OVERHEAD_ALLOWANCE_BYTES`] covers the
//!   wire framing Hyper counts but the guard does not: the request/status
//!   line, per-field `": "` and `"\r\n"` delimiters, the final `"\r\n"`, and
//!   the same framing for chunked trailers (Hyper reuses `max_header_size`
//!   for trailers). The value is fixture-derived (see tests): minimal heads
//!   cost 22 bytes over the guard sum, 128 tiny fields cost 530 bytes, and a
//!   4 KiB request target with a single Host field costs 4118 bytes; 8192
//!   covers every fixture with margin and matches Hyper's own minimum buffer
//!   (`INIT_BUFFER_SIZE` / `MINIMUM_MAX_BUFFER_SIZE = 8192`). Request targets
//!   longer than ~7 KiB with `header_bytes` at the limit may still 431 at the
//!   transport before the guard runs; that fail-closed path is documented
//!   here, and long paths remain separately bounded by `limits.path_bytes`
//!   when configured and by the transport buffer otherwise.
//! - Never silently tighten: the derived bound is always strictly looser than
//!   `header_bytes` alone (`saturating_add`, no overflow panic), so any header
//!   set the guard permits with typical framing still passes the transport and
//!   is enforced at the guard layer with policy context. Callers must not set
//!   `max_header_size` to `header_bytes` directly.

use crate::body::Body;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

/// HTTP/1 client send-request handle over the shared [`Body`] type.
pub type Http1SendRequest = hyper::client::conn::http1::SendRequest<Body>;

/// Wire framing allowance added to `limits.header_bytes` when deriving the
/// Hyper H1 `max_header_size` bound (request/status line, per-field
/// delimiters, final CRLF, and chunked-trailer framing).
///
/// Fixture-derived: 8192 covers every synthetic fixture (22 bytes minimal,
/// 530 bytes for 128 fields, 4118 bytes for a 4 KiB target) with margin and
/// equals Hyper's minimum buffer size, so it is not a guessed tuning constant.
pub const H1_HYPER_HEADER_WIRE_OVERHEAD_ALLOWANCE_BYTES: usize = 8192;

/// Derives the Hyper H1 `max_header_size` bound from the guard
/// `limits.header_bytes` knob.
///
/// Returns `None` when unset so callers leave both Hyper builders unconfigured
/// (Hyper default / status-quo). Otherwise returns
/// `header_bytes + allowance` with `saturating_add`, always strictly looser
/// than `header_bytes` alone so the transport never preempts the guard for
/// typically framed heads.
pub fn h1_hyper_max_header_size(header_bytes: Option<usize>) -> Option<usize> {
    header_bytes.map(|limit| limit.saturating_add(H1_HYPER_HEADER_WIRE_OVERHEAD_ALLOWANCE_BYTES))
}

/// Applies the derived H1 `max_header_size` to a Hyper server builder.
///
/// Does nothing when `header_bytes` is `None`, preserving the Hyper default.
pub fn apply_h1_hyper_max_header_size_to_server_builder(
    builder: &mut hyper::server::conn::http1::Builder,
    header_bytes: Option<usize>,
) {
    if let Some(max) = h1_hyper_max_header_size(header_bytes) {
        builder.max_header_size(max);
    }
}

/// Applies the derived H1 `max_header_size` to a Hyper client builder.
///
/// Does nothing when `header_bytes` is `None`, preserving the Hyper default.
pub fn apply_h1_hyper_max_header_size_to_client_builder(
    builder: &mut hyper::client::conn::http1::Builder,
    header_bytes: Option<usize>,
) {
    if let Some(max) = h1_hyper_max_header_size(header_bytes) {
        builder.max_header_size(max);
    }
}

/// Performs an HTTP/1 client handshake over `io`, returning the send-request
/// handle and the connection driver future.
pub async fn handshake_http1<T>(
    io: T,
) -> Result<
    (
        Http1SendRequest,
        hyper::client::conn::http1::Connection<TokioIo<T>, Body>,
    ),
    hyper::Error,
>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    handshake_http1_with_header_limit(io, None).await
}

/// Performs an HTTP/1 client handshake with an optional guard-derived header
/// byte bound.
///
/// `None` preserves the Hyper default (status-quo); `Some(limit)` sets the
/// client `max_header_size` to `limit + allowance` via
/// [`h1_hyper_max_header_size`].
pub async fn handshake_http1_with_header_limit<T>(
    io: T,
    header_bytes: Option<usize>,
) -> Result<
    (
        Http1SendRequest,
        hyper::client::conn::http1::Connection<TokioIo<T>, Body>,
    ),
    hyper::Error,
>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = hyper::client::conn::http1::Builder::new();
    apply_h1_hyper_max_header_size_to_client_builder(&mut builder, header_bytes);
    builder.handshake(TokioIo::new(io)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::combinators::BoxBody;
    use hyper::service::service_fn;
    use std::convert::Infallible;
    use tokio::io::duplex;

    type TestBody = BoxBody<Bytes, Infallible>;

    fn empty_test_body() -> TestBody {
        use http_body_util::BodyExt as _;
        http_body_util::Empty::new().boxed()
    }

    fn empty_client_body() -> Body {
        Body::empty()
    }

    /// Guard-style header-byte sum: `name.len() + value.len()` per field.
    fn guard_header_sum(headers: &[(&str, &str)]) -> usize {
        headers
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum()
    }

    /// Wire bytes Hyper counts for an H1 head: start line plus
    /// `name: value\r\n` per field plus the final `\r\n`.
    fn wire_head_bytes(start_line: &str, headers: &[(&str, &str)]) -> usize {
        let mut total = start_line.len();
        for (name, value) in headers {
            total += name.len() + 2 + value.len() + 2;
        }
        total + 2
    }

    #[test]
    fn unset_header_bytes_preserves_hyper_default() {
        assert_eq!(h1_hyper_max_header_size(None), None);
        // Builders stay unconfigured: applying `None` must not change behavior,
        // so there is nothing to assert beyond the `None` derivation.
        let mut server = hyper::server::conn::http1::Builder::new();
        apply_h1_hyper_max_header_size_to_server_builder(&mut server, None);
        let mut client = hyper::client::conn::http1::Builder::new();
        apply_h1_hyper_max_header_size_to_client_builder(&mut client, None);
    }

    #[test]
    fn derived_limit_covers_fixture_framing_without_tightening() {
        // Fixture 1: minimal GET with a single Host field.
        let minimal = [("Host", "example.test")];
        let minimal_wire = wire_head_bytes("GET / HTTP/1.1\r\n", &minimal);
        assert_eq!(minimal_wire - guard_header_sum(&minimal), 22);

        // Fixture 2: worst field-count shape (128 tiny fields, the H1 edge cap).
        let many: Vec<(String, String)> = (0..128)
            .map(|index| (format!("X-Test-{index}"), "v".to_string()))
            .collect();
        let many_refs: Vec<(&str, &str)> = many
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let many_wire = wire_head_bytes("GET / HTTP/1.1\r\n", &many_refs);
        assert_eq!(many_wire - guard_header_sum(&many_refs), 530);

        // Fixture 3: 4 KiB request target with a single Host field.
        let long_target = format!("/{}", "a".repeat(4096));
        let start = format!("GET {long_target} HTTP/1.1\r\n");
        let long_wire = wire_head_bytes(start.as_str(), &minimal);
        assert_eq!(long_wire - guard_header_sum(&minimal), 4118);

        // The derived bound must stay looser than every fixture wire size so
        // the transport never preempts the guard for these shapes.
        for (guard, wire) in [
            (guard_header_sum(&minimal), minimal_wire),
            (guard_header_sum(&many_refs), many_wire),
            (guard_header_sum(&minimal), long_wire),
        ] {
            let derived = h1_hyper_max_header_size(Some(guard)).unwrap_or(usize::MAX);
            assert!(
                derived >= wire,
                "derived {derived} must cover fixture wire {wire} for guard {guard}"
            );
        }

        // Spot-check the documented example shape: 16384-byte guard.
        assert_eq!(
            h1_hyper_max_header_size(Some(16_384)),
            Some(16_384 + H1_HYPER_HEADER_WIRE_OVERHEAD_ALLOWANCE_BYTES)
        );
    }

    #[test]
    fn derived_limit_saturates_without_overflow() {
        assert_eq!(h1_hyper_max_header_size(Some(usize::MAX)), Some(usize::MAX));
    }

    #[tokio::test]
    async fn hyper_server_builder_rejects_head_above_derived_limit_with_431() {
        // Guard allows 100 bytes of `name + value`; the derived Hyper bound is
        // 100 + 8192 = 8292. Send a head well above it and expect RFC 9112 /
        // RFC 6585 431 from the Hyper server.
        let header_bytes = Some(100_usize);
        let derived = h1_hyper_max_header_size(header_bytes).unwrap_or(usize::MAX);
        assert_eq!(derived, 100 + H1_HYPER_HEADER_WIRE_OVERHEAD_ALLOWANCE_BYTES);

        let (client_io, server_io) = duplex(64 * 1024);
        let mut builder = hyper::server::conn::http1::Builder::new();
        apply_h1_hyper_max_header_size_to_server_builder(&mut builder, header_bytes);
        let server = tokio::spawn(async move {
            let service = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                Ok::<_, Infallible>(hyper::Response::new(empty_test_body()))
            });
            let _ = builder
                .serve_connection(TokioIo::new(server_io), service)
                .await;
        });

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(client_io))
            .await
            .expect("client handshake");
        let conn_task = tokio::spawn(conn);
        let large_value = "x".repeat(derived + 1024);
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("http://example.test/")
            .header("Host", "example.test")
            .header("X-Large", large_value)
            .body(empty_client_body())
            .expect("request");
        let response = sender.send_request(request).await.expect("response");
        assert_eq!(
            response.status(),
            hyper::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        conn_task.abort();
        server.abort();
    }

    #[tokio::test]
    async fn hyper_client_builder_rejects_response_above_derived_limit() {
        // Same 100-byte guard: the Hyper client bound is 8292. Serve a response
        // head above it and expect the limited client to fail with
        // "message head is too large" instead of delivering the head.
        let header_bytes = Some(100_usize);
        let derived = h1_hyper_max_header_size(header_bytes).unwrap_or(usize::MAX);

        let (client_io, server_io) = duplex(64 * 1024);
        tokio::spawn(async move {
            let service = service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                let large_value = "y".repeat(derived + 1024);
                Ok::<_, Infallible>(
                    hyper::Response::builder()
                        .status(hyper::StatusCode::OK)
                        .header("X-Large", large_value)
                        .body(empty_test_body())
                        .expect("response"),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server_io), service)
                .await;
        });

        let (mut sender, conn) = handshake_http1_with_header_limit(client_io, header_bytes)
            .await
            .expect("limited client handshake");
        // Drive the connection in the background while the request runs.
        let conn_task = tokio::spawn(async move { conn.with_upgrades().await });
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("http://example.test/")
            .body(empty_client_body())
            .expect("request");
        let result = sender.send_request(request).await;
        assert!(
            result.is_err(),
            "limited client must reject the oversized response head"
        );
        conn_task.abort();
    }
}
