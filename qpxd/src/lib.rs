#![recursion_limit = "256"]

#[cfg(test)]
pub(crate) fn test_env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(all(feature = "http3", not(feature = "tls-rustls")))]
compile_error!("qpxd: feature http3 requires tls-rustls");

#[cfg(all(
    feature = "http3",
    not(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))
))]
compile_error!("qpxd: feature http3 requires at least one HTTP/3 backend feature");

#[cfg(all(feature = "mitm", not(feature = "tls-rustls")))]
compile_error!("qpxd: feature mitm requires tls-rustls");

#[cfg(all(feature = "acme", not(feature = "tls-rustls")))]
compile_error!("qpxd: feature acme requires tls-rustls");

mod cli;
mod cli_render;
mod config_reload;
#[cfg(feature = "http3-backend-qpx")]
mod connect_ip;
mod daemon;
mod destination;
mod exporter;
mod forward;
mod ftp;
mod http;
#[cfg(feature = "http3")]
mod http3;
mod ipc_client;
mod policy_context;
mod pool;
mod rate_limit;
mod reverse;
mod runtime;
mod server;
mod startup;
mod tcp_bindings;
#[cfg(test)]
mod test_util;
mod tls;
mod transparent;
mod tunnel;
mod udp_bindings;
mod udp_session_handoff;
mod udp_socket_handoff;
mod upgrade;
mod upstream;
mod windows_handoff;
mod xdp;

pub mod module_api {
    pub use crate::http::modules::{
        BodyAccess, CacheLookupStatus, HttpModule, HttpModuleCapabilities, HttpModuleContext,
        HttpModuleEvent, HttpModuleFactory, HttpModuleRegistry, HttpModuleRegistryBuilder,
        HttpModuleRequestView, HttpModuleStage, ModuleStages, RequestHeadersOutcome, RetryEvent,
    };
    pub use qpx_http::body::{Body, BodyError, Sender};

    /// Incremental observer for an RPC response stream selected from its HTTP fields.
    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub struct RpcStreamObserver {
        inner: crate::http::rpc::streaming::StreamingRpcObserver,
    }

    /// Final counts and trailers extracted from an RPC response stream.
    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub struct RpcStreamSummary {
        pub message_count: usize,
        pub message_bytes: u64,
        pub trailers: Option<http::HeaderMap>,
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    impl RpcStreamObserver {
        /// Selects the gRPC, gRPC-Web, or Connect observer for the response.
        pub fn from_headers(
            headers: &http::HeaderMap,
            fallback_protocol: Option<&str>,
            max_message_bytes: Option<u64>,
            max_trailer_bytes: Option<u64>,
        ) -> Option<Self> {
            crate::http::rpc::streaming::streaming_rpc_observer(
                headers,
                fallback_protocol,
                max_message_bytes,
                max_trailer_bytes,
            )
            .map(|inner| Self { inner })
        }

        /// Returns the selected RPC protocol name.
        pub fn protocol(&self) -> &str {
            self.inner.protocol()
        }

        /// Feeds the next response-body chunk into the observer.
        pub fn feed(&mut self, chunk: &[u8]) -> anyhow::Result<()> {
            self.inner.feed(chunk).map_err(anyhow::Error::from)
        }

        /// Finishes the stream and returns its validated summary.
        pub fn finish(self) -> anyhow::Result<RpcStreamSummary> {
            let summary = self.inner.finish().map_err(anyhow::Error::from)?;
            let (message_count, message_bytes, trailers) = summary.into_parts();
            Ok(RpcStreamSummary {
                message_count,
                message_bytes,
                trailers,
            })
        }
    }

    /// Incremental observer for Server-Sent Event streams.
    pub struct SseEventObserver {
        inner: crate::http::protocol::sse::SseEventObserver,
    }

    /// Current counts and last event ID extracted from an SSE stream.
    pub struct SseStreamSummary {
        pub event_count: u64,
        pub byte_count: u64,
        pub last_event_id: Option<String>,
    }

    impl Default for SseEventObserver {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SseEventObserver {
        /// Creates an observer with the canonical SSE streaming limits.
        pub fn new() -> Self {
            Self {
                inner: crate::http::protocol::sse::SseEventObserver::new(),
            }
        }

        /// Feeds a response-body chunk and returns the number of completed events.
        pub fn feed(&mut self, chunk: &[u8]) -> u64 {
            self.inner.feed(chunk).events
        }

        /// Returns the current stream summary without consuming the observer.
        pub fn summary(&self) -> SseStreamSummary {
            let summary = self.inner.summary();
            SseStreamSummary {
                event_count: summary.event_count,
                byte_count: summary.byte_count,
                last_event_id: summary.last_event_id,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::SseEventObserver;

        #[test]
        fn public_sse_observer_reports_completed_events() {
            let payload = b"id: 7\ndata: hello\n\n";
            let mut observer = SseEventObserver::new();

            assert_eq!(observer.feed(payload), 1);
            let summary = observer.summary();
            assert_eq!(summary.event_count, 1);
            assert_eq!(summary.byte_count, payload.len() as u64);
            assert_eq!(summary.last_event_id.as_deref(), Some("7"));
        }

        #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
        #[test]
        fn public_rpc_observer_validates_and_summarizes_grpc_frames() {
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/grpc"),
            );
            let mut observer = super::RpcStreamObserver::from_headers(
                &headers,
                None,
                Some(16 * 1024 * 1024),
                None,
            )
            .expect("gRPC observer");

            assert_eq!(observer.protocol(), "grpc");
            observer
                .feed(&[0, 0, 0, 0, 3, b'a', b'b', b'c'])
                .expect("valid gRPC frame");
            let summary = observer.finish().expect("gRPC summary");
            assert_eq!(summary.message_count, 1);
            assert_eq!(summary.message_bytes, 3);
            assert!(summary.trailers.is_none());
        }
    }
}

pub use daemon::{Daemon, DaemonBuilder};
pub use qpx_core::config::{Config, HttpModuleConfig};
pub use runtime::{Runtime, RuntimeState};

#[doc(hidden)]
pub mod fuzz_support {
    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    fn rpc_headers(content_type: &'static str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(content_type),
        );
        headers
    }

    pub fn parse_proxy_v2_frame(frame: &[u8]) {
        crate::xdp::fuzz_parse_proxy_v2_frame(frame);
    }

    pub fn parse_http1_request_head(bytes: &[u8]) {
        crate::http::codec::h1::fuzz_parse_http1_request_head(bytes);
    }

    pub fn sniff_client_hello(bytes: &[u8]) {
        crate::tls::sniff::fuzz_client_hello_parser(bytes);
    }

    pub fn parse_ftp_response(bytes: &[u8]) {
        crate::ftp::fuzz_parse_ftp_response_parser(bytes);
    }

    pub fn parse_ipc_meta_frame(bytes: &[u8]) {
        qpx_core::ipc::protocol::fuzz_decode_ipc_meta_frame(bytes);
    }

    pub fn match_dispatch_policy(bytes: &[u8]) {
        let input = String::from_utf8_lossy(bytes);
        let mut lines = input.lines();
        let method = lines.next().unwrap_or("GET").trim();
        let host = lines.next().unwrap_or("example.test").trim();
        let path = lines.next().unwrap_or("/").trim();
        let mut headers = http::HeaderMap::new();
        for line in lines.take(16) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let Ok(name) = http::header::HeaderName::from_bytes(name.trim().as_bytes()) else {
                continue;
            };
            let Ok(value) = http::HeaderValue::from_str(value.trim()) else {
                continue;
            };
            headers.append(name, value);
        }
        let Some(engine) = dispatch_policy_engine() else {
            return;
        };
        let ctx = qpx_core::rules::RuleMatchContext {
            method: (!method.is_empty()).then_some(method),
            host: (!host.is_empty()).then_some(host),
            path: (!path.is_empty()).then_some(path),
            headers: Some(&headers),
            ..Default::default()
        };
        let _ = engine.matcher_candidate_indices(&ctx);
        let _ = engine.evaluate_ref(&ctx);
    }

    pub fn derive_cache_key(bytes: &[u8]) {
        let input = String::from_utf8_lossy(bytes);
        let mut lines = input.lines();
        let path = lines.next().unwrap_or("/");
        let host = lines.next().unwrap_or("cache.example");
        let method = lines.next().unwrap_or("GET");
        let Ok(request) = http::Request::builder()
            .method(method)
            .uri(if path.starts_with('/') { path } else { "/" })
            .header(http::header::HOST, host)
            .body(qpx_http::body::Body::empty())
        else {
            return;
        };
        if let Ok(Some(key)) = qpxd_cache::CacheRequestKey::for_lookup(&request, "http") {
            let _ = key.primary_hash();
            let _ = key.absolute_url();
            let _ = key.with_method_group("GET").primary_hash();
        }
    }

    fn dispatch_policy_engine() -> Option<&'static qpx_core::rules::RuleEngine> {
        static ENGINE: std::sync::OnceLock<Option<qpx_core::rules::RuleEngine>> =
            std::sync::OnceLock::new();
        ENGINE
            .get_or_init(|| {
                qpx_core::rules::RuleEngine::new(
                    vec![
                        qpx_core::config::RuleConfig {
                            name: "host-get".to_string(),
                            r#match: Some(qpx_core::config::MatchConfig {
                                host: vec!["example.test".to_string()],
                                method: vec!["GET".to_string()],
                                ..Default::default()
                            }),
                            auth: None,
                            action: Some(qpx_core::config::ActionConfig {
                                kind: qpx_core::config::ActionKind::Direct,
                                upstream: None,
                                local_response: None,
                            }),
                            headers: None,
                            rate_limit: None,
                        },
                        qpx_core::config::RuleConfig {
                            name: "path-block".to_string(),
                            r#match: Some(qpx_core::config::MatchConfig {
                                path: vec!["/admin".to_string()],
                                ..Default::default()
                            }),
                            auth: None,
                            action: Some(qpx_core::config::ActionConfig {
                                kind: qpx_core::config::ActionKind::Block,
                                upstream: None,
                                local_response: None,
                            }),
                            headers: None,
                            rate_limit: None,
                        },
                    ],
                    qpx_core::config::ActionConfig {
                        kind: qpx_core::config::ActionKind::Proxy,
                        upstream: Some("http://127.0.0.1:8080".to_string()),
                        local_response: None,
                    },
                )
                .ok()
            })
            .as_ref()
    }

    #[cfg(feature = "http3")]
    pub fn observe_sse_events(bytes: &[u8]) {
        let mut observer = crate::http::protocol::sse::SseEventObserver::new();
        observer.feed(bytes);
        let _ = observer.summary();
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub fn observe_grpc_frames(bytes: &[u8]) {
        let headers = rpc_headers("application/grpc");
        if let Some(mut observer) =
            crate::http::rpc::streaming_rpc_observer(&headers, None, Some(16 * 1024 * 1024), None)
        {
            let _ = observer.feed(bytes);
            let _ = observer.finish();
        }
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub fn observe_grpc_web_binary_frames(bytes: &[u8]) {
        let headers = rpc_headers("application/grpc-web+proto");
        if let Some(mut observer) =
            crate::http::rpc::streaming_rpc_observer(&headers, None, Some(16 * 1024 * 1024), None)
        {
            let _ = observer.feed(bytes);
            let _ = observer.finish();
        }
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub fn observe_grpc_web_text_frames(bytes: &[u8]) {
        let headers = rpc_headers("application/grpc-web-text+proto");
        if let Some(mut observer) =
            crate::http::rpc::streaming_rpc_observer(&headers, None, Some(16 * 1024 * 1024), None)
        {
            let _ = observer.feed(bytes);
            let _ = observer.finish();
        }
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub fn observe_connect_frames(bytes: &[u8]) {
        let headers = rpc_headers("application/connect+proto");
        if let Some(mut observer) = crate::http::rpc::streaming_rpc_observer(
            &headers,
            Some("connect"),
            Some(16 * 1024 * 1024),
            Some(64 * 1024),
        ) {
            let _ = observer.feed(bytes);
            let _ = observer.finish();
        }
    }

    #[cfg(feature = "http3")]
    pub fn parse_datagram_capsules(bytes: &[u8]) {
        let mut buffer = crate::http3::capsule::CapsuleBuffer::new();
        let _ = buffer.push(bytes::Bytes::copy_from_slice(bytes), 256 * 1024);
        while let Ok(Some((_kind, _payload))) = buffer.take_next() {}
    }

    #[cfg(feature = "http3")]
    pub fn parse_h3_content_length_state(bytes: &[u8]) {
        let mut headers = http::HeaderMap::new();
        for value in bytes.split(|byte| *byte == b'\n').take(16) {
            if value.is_empty() {
                continue;
            }
            if let Ok(value) = http::HeaderValue::from_bytes(value) {
                headers.append(http::header::CONTENT_LENGTH, value);
            }
        }
        let _ = crate::http3::codec::parse_content_length_fields(&headers);
    }

    #[cfg(feature = "http3")]
    pub fn sanitize_h3_trailers(bytes: &[u8]) {
        let mut trailers = http::HeaderMap::new();
        for line in bytes.split(|byte| *byte == b'\n').take(32) {
            let Some(colon) = line.iter().position(|byte| *byte == b':') else {
                continue;
            };
            let name = &line[..colon];
            let value = line[colon + 1..].trim_ascii_start();
            let Ok(name) = http::header::HeaderName::from_bytes(name) else {
                continue;
            };
            let Ok(value) = http::HeaderValue::from_bytes(value) else {
                continue;
            };
            trailers.append(name, value);
        }
        let _ = qpx_http::protocol::semantics::validate_request_trailers(&trailers);
        let _ = qpx_http::protocol::semantics::sanitize_response_trailers(&mut trailers);
    }
}

pub fn main_entry() -> anyhow::Result<()> {
    Daemon::default().run_cli()
}
