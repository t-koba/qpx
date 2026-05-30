// Extracted from rpc/mod.rs; keep public re-exports in mod.rs.
use super::protocol::{detect_rpc_protocol, parse_grpc_web_trailer_block, response_content_type};
use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::HeaderMap;

pub(super) const DEFAULT_MAX_GRPC_WEB_TRAILER_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Default)]
pub(crate) struct FramedBodySummary {
    pub(super) message_count: usize,
    pub(super) message_bytes: u64,
    pub(super) trailers: Option<HeaderMap>,
}

#[derive(Debug, Clone)]
pub(crate) struct PrecomputedRpcBodySummary(pub(super) FramedBodySummary);

#[derive(Debug)]
pub(crate) struct RpcBodySummaryObserver {
    inner: GrpcFrameObserver,
}

impl RpcBodySummaryObserver {
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> bool {
        self.inner.feed(chunk).is_ok()
    }

    pub(crate) fn finish(self) -> Option<PrecomputedRpcBodySummary> {
        self.inner.finish().ok().map(PrecomputedRpcBodySummary)
    }
}

pub(crate) fn request_body_summary_observer(headers: &HeaderMap) -> Option<RpcBodySummaryObserver> {
    body_summary_observer(detect_rpc_protocol(headers, None).as_deref(), headers)
}

pub(crate) fn response_body_summary_observer(
    headers: &HeaderMap,
) -> Option<RpcBodySummaryObserver> {
    body_summary_observer(response_content_type(headers).as_deref(), headers)
        .or_else(|| body_summary_observer(detect_rpc_protocol(headers, None).as_deref(), headers))
}

fn body_summary_observer(
    protocol_or_content_type: Option<&str>,
    headers: &HeaderMap,
) -> Option<RpcBodySummaryObserver> {
    let protocol = match protocol_or_content_type {
        Some(value) if value.starts_with("application/grpc-web") => Some("grpc_web"),
        Some(value) if value.starts_with("application/grpc") => Some("grpc"),
        Some("grpc_web") => Some("grpc_web"),
        Some("grpc") => Some("grpc"),
        _ => None,
    }?;
    let content_type = response_content_type(headers);
    let inner = match protocol {
        "grpc" => GrpcFrameObserver::new(None),
        "grpc_web" => GrpcFrameObserver::grpc_web(
            content_type
                .as_deref()
                .map(|value| value.starts_with("application/grpc-web-text"))
                .unwrap_or(false),
            None,
            None,
        ),
        _ => return None,
    };
    Some(RpcBodySummaryObserver { inner })
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
impl FramedBodySummary {
    pub(crate) fn message_count(&self) -> usize {
        self.message_count
    }

    pub(crate) fn trailers(&self) -> Option<&HeaderMap> {
        self.trailers.as_ref()
    }
}

#[derive(Debug)]
pub(crate) enum GrpcFrameError {
    Invalid(anyhow::Error),
    MessageTooLarge { len: u64, max: u64 },
    TrailerTooLarge { len: u64, max: u64 },
}

impl std::fmt::Display for GrpcFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(err) => write!(f, "{err}"),
            Self::MessageTooLarge { len, max } => {
                write!(f, "grpc message length {len} exceeds limit {max}")
            }
            Self::TrailerTooLarge { len, max } => {
                write!(f, "grpc-web trailer length {len} exceeds limit {max}")
            }
        }
    }
}

impl std::error::Error for GrpcFrameError {}

impl From<anyhow::Error> for GrpcFrameError {
    fn from(value: anyhow::Error) -> Self {
        Self::Invalid(value)
    }
}

#[derive(Debug)]
pub(super) enum FrameParseState {
    Header {
        buf: [u8; 5],
        pos: usize,
    },
    Payload {
        remaining: usize,
        flags: u8,
        trailer: Option<Vec<u8>>,
    },
}

#[derive(Debug)]
pub(crate) struct GrpcFrameObserver {
    state: FrameParseState,
    summary: FramedBodySummary,
    max_message_bytes: Option<u64>,
    max_trailer_bytes: Option<u64>,
    grpc_web: bool,
    grpc_web_text: bool,
    grpc_web_text_done: bool,
    text_quantum: [u8; 4],
    text_quantum_len: usize,
}

impl GrpcFrameObserver {
    pub(crate) fn new(max_message_bytes: Option<u64>) -> Self {
        Self::for_protocol(false, false, max_message_bytes, None)
    }

    pub(crate) fn grpc_web(
        text: bool,
        max_message_bytes: Option<u64>,
        max_trailer_bytes: Option<u64>,
    ) -> Self {
        Self::for_protocol(true, text, max_message_bytes, max_trailer_bytes)
    }

    fn for_protocol(
        grpc_web: bool,
        grpc_web_text: bool,
        max_message_bytes: Option<u64>,
        max_trailer_bytes: Option<u64>,
    ) -> Self {
        Self {
            state: FrameParseState::Header {
                buf: [0; 5],
                pos: 0,
            },
            summary: FramedBodySummary::default(),
            max_message_bytes,
            max_trailer_bytes,
            grpc_web,
            grpc_web_text,
            grpc_web_text_done: false,
            text_quantum: [0; 4],
            text_quantum_len: 0,
        }
    }

    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Result<(), GrpcFrameError> {
        if self.grpc_web_text {
            return self.feed_grpc_web_text(chunk);
        }
        self.feed_binary(chunk)
    }

    fn feed_grpc_web_text(&mut self, chunk: &[u8]) -> Result<(), GrpcFrameError> {
        for byte in chunk
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
        {
            if self.grpc_web_text_done {
                return Err(anyhow!("grpc-web-text data found after base64 padding").into());
            }
            self.text_quantum[self.text_quantum_len] = byte;
            self.text_quantum_len += 1;
            if self.text_quantum_len == self.text_quantum.len() {
                let quantum = self.text_quantum;
                let padded = quantum.contains(&b'=');
                let decoded = BASE64.decode(quantum).map_err(|err| anyhow!(err))?;
                self.feed_binary(&decoded)?;
                self.text_quantum = [0; 4];
                self.text_quantum_len = 0;
                if padded {
                    self.grpc_web_text_done = true;
                }
            }
        }
        Ok(())
    }

    fn feed_binary(&mut self, mut chunk: &[u8]) -> Result<(), GrpcFrameError> {
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
                        let is_trailer = self.grpc_web && (flags & 0x80) != 0;
                        if is_trailer {
                            let max = self
                                .max_trailer_bytes
                                .unwrap_or(DEFAULT_MAX_GRPC_WEB_TRAILER_BYTES);
                            if len > max {
                                return Err(GrpcFrameError::TrailerTooLarge { len, max });
                            }
                            self.state = FrameParseState::Payload {
                                remaining: len as usize,
                                flags,
                                trailer: Some(Vec::with_capacity(len as usize)),
                            };
                        } else {
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
                            ((*flags & 0x80) != 0).then(|| trailer.take()).flatten();
                        self.state = FrameParseState::Header {
                            buf: [0; 5],
                            pos: 0,
                        };
                        if let Some(trailer) = completed_trailer {
                            self.summary.trailers = Some(parse_grpc_web_trailer_block(&trailer)?);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<FramedBodySummary, GrpcFrameError> {
        if self.grpc_web_text {
            if self.text_quantum_len > 0 {
                let len = self.text_quantum_len;
                let quantum = self.text_quantum;
                let decoded = BASE64.decode(&quantum[..len]).map_err(|err| anyhow!(err))?;
                self.feed_binary(&decoded)?;
            }
            self.grpc_web_text = false;
        }
        match self.state {
            FrameParseState::Header { pos: 0, .. } => Ok(self.summary),
            _ => Err(anyhow!("grpc body ended mid-frame").into()),
        }
    }
}
