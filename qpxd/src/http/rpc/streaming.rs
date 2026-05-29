// Extracted from rpc/mod.rs; keep public re-exports in mod.rs.
use super::frame::{FrameParseState, FramedBodySummary, GrpcFrameError, GrpcFrameObserver};
use super::protocol::{
    detect_rpc_protocol, infer_request_streaming, infer_response_streaming,
    parse_connect_end_stream_metadata, response_content_type,
};
use anyhow::{Result, anyhow};
use http::HeaderMap;

const DEFAULT_MAX_CONNECT_TRAILER_BYTES: u64 = 64 * 1024;

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[derive(Debug)]
pub(crate) struct ConnectFrameObserver {
    state: FrameParseState,
    max_message_bytes: Option<u64>,
    max_trailer_bytes: Option<u64>,
    summary: FramedBodySummary,
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
impl ConnectFrameObserver {
    pub(crate) fn new(max_message_bytes: Option<u64>, max_trailer_bytes: Option<u64>) -> Self {
        Self {
            state: FrameParseState::Header {
                buf: [0; 5],
                pos: 0,
            },
            max_message_bytes,
            max_trailer_bytes,
            summary: FramedBodySummary::default(),
        }
    }

    pub(crate) fn feed(&mut self, mut chunk: &[u8]) -> Result<(), GrpcFrameError> {
        while !chunk.is_empty() {
            match &mut self.state {
                FrameParseState::Header { buf, pos } => {
                    let take = (5 - *pos).min(chunk.len());
                    buf[*pos..*pos + take].copy_from_slice(&chunk[..take]);
                    *pos += take;
                    chunk = &chunk[take..];
                    if *pos == 5 {
                        let flags = buf[0];
                        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as u64;
                        if flags & !0x03 != 0 {
                            return Err(
                                anyhow!("unsupported Connect envelope flags {flags:#x}").into()
                            );
                        }
                        let compressed = flags & 0x01 != 0;
                        let end_stream = flags & 0x02 != 0;
                        match (compressed, end_stream) {
                            (_, false) => {
                                if let Some(max) = self.max_message_bytes
                                    && len > max
                                {
                                    return Err(GrpcFrameError::MessageTooLarge { len, max });
                                }
                                self.summary.message_count += 1;
                                self.summary.message_bytes =
                                    self.summary.message_bytes.saturating_add(len);
                                self.state = FrameParseState::Payload {
                                    remaining: len as usize,
                                    flags,
                                    trailer: None,
                                };
                            }
                            (_, true) => {
                                let max = self
                                    .max_trailer_bytes
                                    .unwrap_or(DEFAULT_MAX_CONNECT_TRAILER_BYTES);
                                if len > max {
                                    return Err(GrpcFrameError::TrailerTooLarge { len, max });
                                }
                                self.state = FrameParseState::Payload {
                                    remaining: len as usize,
                                    flags,
                                    trailer: Some(Vec::with_capacity(len as usize)),
                                };
                            }
                        }
                    }
                }
                FrameParseState::Payload {
                    remaining,
                    flags,
                    trailer,
                } => {
                    let take = (*remaining).min(chunk.len());
                    if let Some(trailer) = trailer {
                        trailer.extend_from_slice(&chunk[..take]);
                    }
                    *remaining -= take;
                    chunk = &chunk[take..];
                    if *remaining == 0 {
                        let completed_trailer =
                            (*flags & 0x02 != 0).then(|| trailer.take()).flatten();
                        self.state = FrameParseState::Header {
                            buf: [0; 5],
                            pos: 0,
                        };
                        if let Some(trailer) = completed_trailer {
                            self.summary.trailers =
                                Some(parse_connect_end_stream_metadata(&trailer)?);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<FramedBodySummary, GrpcFrameError> {
        match self.state {
            FrameParseState::Header { pos: 0, .. } => Ok(self.summary),
            _ => Err(anyhow!("connect body ended mid-frame").into()),
        }
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[derive(Debug)]
pub(crate) struct StreamingRpcObserver {
    protocol: String,
    inner: StreamingRpcInner,
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[derive(Debug)]
enum StreamingRpcInner {
    Grpc(GrpcFrameObserver),
    Connect(ConnectFrameObserver),
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
impl StreamingRpcObserver {
    pub(crate) fn protocol(&self) -> &str {
        self.protocol.as_str()
    }

    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Result<(), GrpcFrameError> {
        match &mut self.inner {
            StreamingRpcInner::Grpc(inner) => inner.feed(chunk),
            StreamingRpcInner::Connect(inner) => inner.feed(chunk),
        }
    }

    pub(crate) fn finish(self) -> Result<FramedBodySummary, GrpcFrameError> {
        match self.inner {
            StreamingRpcInner::Grpc(inner) => inner.finish(),
            StreamingRpcInner::Connect(inner) => inner.finish(),
        }
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn streaming_rpc_protocol(
    headers: &HeaderMap,
    fallback: Option<&str>,
) -> Option<String> {
    detect_rpc_protocol(headers, fallback)
        .filter(|protocol| matches!(protocol.as_str(), "grpc" | "grpc_web" | "connect"))
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn streaming_rpc_observer(
    headers: &HeaderMap,
    fallback: Option<&str>,
    max_message_bytes: Option<u64>,
    max_trailer_bytes: Option<u64>,
) -> Option<StreamingRpcObserver> {
    if fallback == Some("connect") && !is_connect_streaming_response(headers) {
        return None;
    }
    let protocol = streaming_rpc_protocol(headers, fallback)?;
    let inner = match protocol.as_str() {
        "grpc" => StreamingRpcInner::Grpc(GrpcFrameObserver::new(max_message_bytes)),
        "grpc_web" => StreamingRpcInner::Grpc(GrpcFrameObserver::grpc_web(
            response_content_type(headers)
                .as_deref()
                .map(|value| value.starts_with("application/grpc-web-text"))
                .unwrap_or(false),
            max_message_bytes,
            max_trailer_bytes,
        )),
        "connect" => StreamingRpcInner::Connect(ConnectFrameObserver::new(
            max_message_bytes,
            max_trailer_bytes,
        )),
        _ => return None,
    };
    Some(StreamingRpcObserver { protocol, inner })
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
fn is_connect_streaming_response(headers: &HeaderMap) -> bool {
    response_content_type(headers)
        .as_deref()
        .is_some_and(|value| value.starts_with("application/connect+"))
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(crate) fn grpc_streaming_label(
    protocol: &str,
    request_messages: Option<usize>,
    response_messages: Option<usize>,
) -> &'static str {
    infer_response_streaming(Some(protocol), request_messages, response_messages)
        .or_else(|| infer_request_streaming(Some(protocol), "POST", request_messages))
        .unwrap_or("unknown")
}
