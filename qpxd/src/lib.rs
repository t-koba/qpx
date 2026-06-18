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
}

pub use daemon::{Daemon, DaemonBuilder};
pub use qpx_core::config::{Config, HttpModuleConfig};
pub use runtime::{Runtime, RuntimeState};

#[doc(hidden)]
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub mod bench_support {
    use anyhow::Result;
    use http::HeaderMap;

    pub fn feed_grpc_frame_observer(payload: &[u8], iterations: usize) -> Result<usize> {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/grpc"),
        );
        let mut observed = 0usize;
        for _ in 0..iterations {
            let Some(mut observer) = crate::http::rpc::streaming_rpc_observer(
                &headers,
                None,
                Some(16 * 1024 * 1024),
                None,
            ) else {
                continue;
            };
            observer.feed(payload)?;
            observed = observed.saturating_add(observer.finish()?.message_count());
        }
        Ok(observed)
    }

    pub fn feed_sse_event_observer(payload: &[u8], iterations: usize) -> u64 {
        let mut events = 0u64;
        for _ in 0..iterations {
            let mut observer = crate::http::protocol::sse::SseEventObserver::new();
            observer.feed(payload);
            events = events.saturating_add(observer.summary().event_count);
        }
        events
    }
}

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
