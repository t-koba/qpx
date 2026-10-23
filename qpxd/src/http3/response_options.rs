use tokio::time::{Duration, Instant};

pub(crate) struct H3ResponseSendOptions<'a> {
    pub(crate) max_body_bytes: usize,
    pub(crate) body_read_timeout: Duration,
    pub(crate) body_send_timeout: Duration,
    pub(crate) listener_name: Option<&'a str>,
    pub(crate) fallback_grpc_protocol: Option<&'a str>,
    pub(crate) max_grpc_message_bytes: Option<u64>,
    pub(crate) max_grpc_web_trailer_bytes: Option<u64>,
    pub(crate) grpc_stream_deadline: Option<Instant>,
    pub(crate) sse_policy: Option<qpx_core::config::SseStreamingPolicy>,
    pub(crate) observe_grpc_messages: bool,
}

impl H3ResponseSendOptions<'_> {
    pub(crate) fn unobserved(max_body_bytes: usize, body_read_timeout: Duration) -> Self {
        Self {
            max_body_bytes,
            body_read_timeout,
            body_send_timeout: body_read_timeout,
            listener_name: None,
            fallback_grpc_protocol: None,
            max_grpc_message_bytes: None,
            max_grpc_web_trailer_bytes: None,
            grpc_stream_deadline: None,
            sse_policy: None,
            observe_grpc_messages: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unobserved_preserves_limits_and_disables_observation() {
        let body_read_timeout = Duration::from_millis(321);
        let options = H3ResponseSendOptions::unobserved(12345, body_read_timeout);

        assert_eq!(options.max_body_bytes, 12345);
        assert_eq!(options.body_read_timeout, body_read_timeout);
        assert_eq!(options.body_send_timeout, body_read_timeout);
        assert!(options.listener_name.is_none());
        assert!(options.fallback_grpc_protocol.is_none());
        assert!(options.max_grpc_message_bytes.is_none());
        assert!(options.max_grpc_web_trailer_bytes.is_none());
        assert!(options.grpc_stream_deadline.is_none());
        assert!(options.sse_policy.is_none());
        assert!(!options.observe_grpc_messages);
    }
}
