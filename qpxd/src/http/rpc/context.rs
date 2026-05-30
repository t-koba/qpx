// Extracted from rpc/mod.rs; keep public re-exports in mod.rs.
use http::HeaderMap;

#[derive(Debug, Clone, Default)]
pub(crate) struct RpcMatchContext {
    pub(crate) protocol: Option<String>,
    pub(crate) service: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) streaming: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) message_size: Option<u64>,
    pub(crate) message: Option<String>,
    pub(crate) trailers: Option<HeaderMap>,
    pub(crate) request_message_count: Option<usize>,
    pub(crate) response_message_count: Option<usize>,
    pub(crate) request_message_bytes: Option<u64>,
    pub(crate) response_message_bytes: Option<u64>,
    pub(crate) stream_duration_ms: Option<u64>,
}

impl RpcMatchContext {
    pub(crate) fn to_log_context(&self) -> qpx_observability::access_log::RpcLogContext {
        qpx_observability::access_log::RpcLogContext {
            protocol: self.protocol.clone(),
            service: self.service.clone(),
            method: self.method.clone(),
            streaming: self.streaming.clone(),
            status: self.status.clone(),
            message_size: self.message_size,
            message: self.message.clone(),
            request_message_count: self.request_message_count,
            response_message_count: self.response_message_count,
            request_message_bytes: self.request_message_bytes,
            response_message_bytes: self.response_message_bytes,
            stream_duration_ms: self.stream_duration_ms,
        }
    }
}
