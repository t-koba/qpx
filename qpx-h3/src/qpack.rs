use crate::huffman;
use crate::protocol::QPACK_DECOMPRESSION_FAILED;
pub(crate) use crate::qpack_fields::validate_h3_regular_field;
use crate::qpack_fields::{append_header, validate_h3_response_field, validate_h3_trailer_field};
use anyhow::{anyhow, Result};
use bytes::{Buf, BytesMut};
use http::{HeaderMap, Method, Uri};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;

pub(crate) const DEFAULT_DYNAMIC_TABLE_CAPACITY: usize = 4096;
pub(crate) const DEFAULT_MAX_BLOCKED_STREAMS: u64 = 16;
pub(crate) const DEFAULT_ENCODER_STREAM_BUFFER_BYTES: usize = 1024 * 1024;
const HEADER_ENTRY_OVERHEAD: u64 = 32;

#[derive(Debug, Clone)]
pub(crate) struct DecodedRequestHead {
    pub(crate) request: http::Request<()>,
    pub(crate) protocol: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedResponseHead {
    pub(crate) response: http::Response<()>,
}

#[derive(Debug)]
pub(crate) enum EncoderStreamError {
    Closed(String),
    Invalid(String),
}

impl EncoderStreamError {
    fn closed(message: impl Into<String>) -> Self {
        Self::Closed(message.into())
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

impl std::fmt::Display for EncoderStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(message) | Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for EncoderStreamError {}

#[derive(Clone)]
pub(crate) struct QpackConnection {
    state: Arc<Mutex<DecoderState>>,
    decoder_send: Arc<Mutex<quinn::SendStream>>,
    notify: Arc<Notify>,
    max_encoder_stream_buffer_bytes: usize,
    encoder_stream_read_timeout: Duration,
}

impl std::fmt::Debug for QpackConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QpackConnection").finish_non_exhaustive()
    }
}

impl QpackConnection {
    pub(crate) fn new(
        decoder_send: quinn::SendStream,
        max_table_capacity: usize,
        max_blocked_streams: u64,
        max_field_section_size: u64,
        max_encoder_stream_buffer_bytes: usize,
        encoder_stream_read_timeout: Duration,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(DecoderState::new(
                max_table_capacity,
                max_blocked_streams,
                max_field_section_size,
            ))),
            decoder_send: Arc::new(Mutex::new(decoder_send)),
            notify: Arc::new(Notify::new()),
            max_encoder_stream_buffer_bytes,
            encoder_stream_read_timeout,
        }
    }

    pub(crate) async fn process_encoder_stream(
        &self,
        mut recv: quinn::RecvStream,
    ) -> std::result::Result<(), EncoderStreamError> {
        let mut buffer = BytesMut::new();
        loop {
            match timeout(
                self.encoder_stream_read_timeout,
                recv.read_chunk(self.max_encoder_stream_buffer_bytes.max(1), true),
            )
            .await
            .map_err(|_| EncoderStreamError::closed("QPACK encoder stream read timed out"))?
            .map_err(|err| EncoderStreamError::closed(err.to_string()))?
            {
                Some(chunk) => {
                    let next_len =
                        buffer.len().checked_add(chunk.bytes.len()).ok_or_else(|| {
                            EncoderStreamError::invalid("QPACK encoder stream buffer overflow")
                        })?;
                    if next_len > self.max_encoder_stream_buffer_bytes {
                        return Err(EncoderStreamError::invalid(format!(
                            "QPACK encoder stream buffer length {next_len} exceeds limit {}",
                            self.max_encoder_stream_buffer_bytes
                        )));
                    }
                    buffer.extend_from_slice(chunk.bytes.as_ref());
                }
                None => {
                    return Err(EncoderStreamError::closed(
                        "peer closed QPACK encoder stream",
                    ));
                }
            }

            loop {
                let (consumed, inserted_delta) = {
                    let mut state = self.state.lock().await;
                    match state
                        .process_encoder_chunk(buffer.as_ref())
                        .map_err(|err| EncoderStreamError::invalid(err.to_string()))?
                    {
                        Some(result) => result,
                        None => break,
                    }
                };
                buffer.advance(consumed);
                if inserted_delta != 0 {
                    self.send_decoder_instruction(&encode_insert_count_increment(inserted_delta))
                        .await
                        .map_err(|err| EncoderStreamError::invalid(err.to_string()))?;
                    self.notify.notify_waiters();
                }
            }
        }
    }

    pub(crate) async fn decode_request_head(
        &self,
        stream_id: u64,
        payload: &[u8],
        wait_timeout: Duration,
    ) -> std::result::Result<DecodedRequestHead, HeaderDecodeError> {
        let fields = self
            .decode_field_lines(stream_id, payload, wait_timeout)
            .await?;
        decode_request_head_from_fields(fields)
    }

    pub(crate) async fn decode_response_head(
        &self,
        stream_id: u64,
        payload: &[u8],
        wait_timeout: Duration,
    ) -> std::result::Result<DecodedResponseHead, HeaderDecodeError> {
        let fields = self
            .decode_field_lines(stream_id, payload, wait_timeout)
            .await?;
        let mut status = None;
        let mut headers = HeaderMap::new();
        let mut regular_seen = false;

        for (name, value) in fields {
            let is_pseudo = name.starts_with(':');
            if is_pseudo && regular_seen {
                return Err(HeaderDecodeError::message(format!(
                    "pseudo header {name} appeared after a regular header"
                )));
            }
            match name.as_str() {
                ":status" => {
                    if status.is_some() {
                        return Err(HeaderDecodeError::message(
                            "duplicate :status pseudo header",
                        ));
                    }
                    let value = pseudo_value_to_string(&name, value)?;
                    status = Some(
                        http::StatusCode::from_u16(value.parse::<u16>().map_err(|_| {
                            HeaderDecodeError::message("invalid :status pseudo header")
                        })?)
                        .map_err(|err| HeaderDecodeError::message(err.to_string()))?,
                    );
                }
                other if other.starts_with(':') => {
                    return Err(HeaderDecodeError::message(format!(
                        "unsupported pseudo header {other}"
                    )));
                }
                _ => {
                    regular_seen = true;
                    validate_h3_response_field(&name, &value)?;
                    append_header(&mut headers, &name, &value)
                        .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
                }
            }
        }

        let mut response = http::Response::builder()
            .status(status.ok_or_else(|| HeaderDecodeError::message("missing :status"))?)
            .body(())
            .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
        *response.headers_mut() = headers;
        Ok(DecodedResponseHead { response })
    }

    pub(crate) async fn decode_trailers(
        &self,
        stream_id: u64,
        payload: &[u8],
        wait_timeout: Duration,
    ) -> std::result::Result<HeaderMap, HeaderDecodeError> {
        let fields = self
            .decode_field_lines(stream_id, payload, wait_timeout)
            .await?;
        let mut trailers = HeaderMap::new();
        for (name, value) in fields {
            if name.starts_with(':') {
                return Err(HeaderDecodeError::message(
                    "trailers must not contain pseudo headers",
                ));
            }
            validate_h3_trailer_field(&name, &value)?;
            append_header(&mut trailers, &name, &value)
                .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
        }
        Ok(trailers)
    }

    async fn decode_field_lines(
        &self,
        stream_id: u64,
        payload: &[u8],
        wait_timeout: Duration,
    ) -> std::result::Result<Vec<(String, Vec<u8>)>, HeaderDecodeError> {
        let mut blocked_registered = false;
        let (fields, needs_ack) = loop {
            let outcome = {
                let mut state = self.state.lock().await;
                match state.decode_field_lines(payload) {
                    Ok(decoded) => break (decoded.fields, decoded.dynamic_ref),
                    Err(FieldDecodeError::MissingRefs(required_refs)) => {
                        if !blocked_registered {
                            state
                                .register_blocked_stream(stream_id)
                                .map_err(HeaderDecodeError::qpack)?;
                            blocked_registered = true;
                        }
                        Ok::<_, HeaderDecodeError>(required_refs)
                    }
                    Err(FieldDecodeError::DecompressionFailed(message)) => {
                        if blocked_registered {
                            state.unregister_blocked_stream(stream_id);
                        }
                        return Err(HeaderDecodeError::qpack(message));
                    }
                }
            };
            let required_refs = outcome?;
            if timeout(wait_timeout, self.notify.notified()).await.is_err() {
                if blocked_registered {
                    self.state.lock().await.unregister_blocked_stream(stream_id);
                }
                return Err(HeaderDecodeError::qpack(format!(
                    "timed out waiting for QPACK dynamic state ({required_refs} refs)"
                )));
            }
        };
        if blocked_registered {
            self.state.lock().await.unregister_blocked_stream(stream_id);
        }

        if needs_ack {
            self.send_decoder_instruction(&encode_header_ack(stream_id))
                .await
                .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?;
        }
        Ok(fields)
    }

    async fn send_decoder_instruction(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let mut send = self.decoder_send.lock().await;
        send.write_all(payload).await?;
        send.flush().await?;
        Ok(())
    }
}

fn decode_request_head_from_fields(
    fields: Vec<(String, Vec<u8>)>,
) -> std::result::Result<DecodedRequestHead, HeaderDecodeError> {
    let mut method: Option<Method> = None;
    let mut scheme: Option<String> = None;
    let mut authority: Option<String> = None;
    let mut path: Option<String> = None;
    let mut protocol: Option<String> = None;
    let mut headers = HeaderMap::new();
    let mut regular_seen = false;

    for (name, value) in fields {
        let is_pseudo = name.starts_with(':');
        if is_pseudo && regular_seen {
            return Err(HeaderDecodeError::message(format!(
                "pseudo header {name} appeared after a regular header"
            )));
        }
        match name.as_str() {
            ":method" => {
                if method.is_some() {
                    return Err(HeaderDecodeError::message(
                        "duplicate :method pseudo header",
                    ));
                }
                method = Some(
                    Method::from_bytes(value.as_slice())
                        .map_err(|err| HeaderDecodeError::message(err.to_string()))?,
                )
            }
            ":scheme" => {
                if scheme
                    .replace(pseudo_value_to_string(&name, value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message(
                        "duplicate :scheme pseudo header",
                    ));
                }
            }
            ":authority" => {
                if authority
                    .replace(pseudo_value_to_string(&name, value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message(
                        "duplicate :authority pseudo header",
                    ));
                }
            }
            ":path" => {
                if path
                    .replace(pseudo_value_to_string(&name, value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message("duplicate :path pseudo header"));
                }
            }
            ":protocol" => {
                if protocol
                    .replace(pseudo_value_to_string(&name, value)?)
                    .is_some()
                {
                    return Err(HeaderDecodeError::message(
                        "duplicate :protocol pseudo header",
                    ));
                }
            }
            other if other.starts_with(':') => {
                return Err(HeaderDecodeError::message(format!(
                    "unsupported pseudo header {other}"
                )));
            }
            _ => {
                regular_seen = true;
                validate_h3_regular_field(&name, &value)?;
                append_header(&mut headers, &name, &value)
                    .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
            }
        }
    }

    let method = method.ok_or_else(|| HeaderDecodeError::message("missing :method"))?;
    if protocol.is_some() && method != Method::CONNECT {
        return Err(HeaderDecodeError::message(
            ":protocol is only valid on CONNECT requests",
        ));
    }
    if method == Method::CONNECT && protocol.is_none() {
        if authority.is_none() {
            return Err(HeaderDecodeError::message(
                "traditional CONNECT requires :authority",
            ));
        }
        if scheme.is_some() || path.is_some() {
            return Err(HeaderDecodeError::message(
                "traditional CONNECT must not include :scheme or :path",
            ));
        }
    } else {
        if scheme.is_none() {
            return Err(HeaderDecodeError::message("missing :scheme"));
        }
        if path.is_none() {
            return Err(HeaderDecodeError::message("missing :path"));
        }
    }
    let uri = build_uri(
        scheme.as_deref(),
        authority.as_deref(),
        path.as_deref(),
        method == Method::CONNECT && protocol.is_none(),
    )
    .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(())
        .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
    *request.headers_mut() = headers;
    Ok(DecodedRequestHead { request, protocol })
}

pub(crate) fn encode_request_head(
    head: &http::Request<()>,
    protocol: Option<&str>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_header_prefix(&mut out, 0, 0, 0, 0);

    encode_field(&mut out, ":method", head.method().as_str().as_bytes());
    if let Some(scheme) = head.uri().scheme_str() {
        encode_field(&mut out, ":scheme", scheme.as_bytes());
    }
    if let Some(authority) = head.uri().authority() {
        encode_field(&mut out, ":authority", authority.as_str().as_bytes());
    }
    if let Some(path) = head.uri().path_and_query() {
        encode_field(&mut out, ":path", path.as_str().as_bytes());
    }
    if let Some(protocol) = protocol {
        encode_field(&mut out, ":protocol", protocol.as_bytes());
    }
    for (name, value) in head.headers() {
        encode_field(&mut out, name.as_str(), value.as_bytes());
    }
    Ok(out)
}

pub(crate) fn encode_response_head(head: &http::Response<()>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_header_prefix(&mut out, 0, 0, 0, 0);

    let status = head.status().as_u16().to_string();
    encode_field(&mut out, ":status", status.as_bytes());
    for (name, value) in head.headers() {
        encode_field(&mut out, name.as_str(), value.as_bytes());
    }
    out
}

pub(crate) fn encode_trailers(trailers: &HeaderMap) -> Vec<u8> {
    let mut out = Vec::new();
    encode_header_prefix(&mut out, 0, 0, 0, 0);
    for (name, value) in trailers {
        encode_field(&mut out, name.as_str(), value.as_bytes());
    }
    out
}

#[derive(Debug, Clone)]
struct DynamicEntry {
    name: String,
    value: Vec<u8>,
    size: usize,
}

impl DynamicEntry {
    fn new(name: String, value: Vec<u8>) -> Self {
        let size = name.len() + value.len() + HEADER_ENTRY_OVERHEAD as usize;
        Self { name, value, size }
    }
}

#[derive(Debug)]
struct DynamicTable {
    entries: VecDeque<DynamicEntry>,
    inserted: usize,
    dropped: usize,
    current_size: usize,
    max_size: usize,
    max_capacity: usize,
}

impl DynamicTable {
    fn new(max_capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            inserted: 0,
            dropped: 0,
            current_size: 0,
            max_size: 0,
            max_capacity,
        }
    }

    fn total_inserted(&self) -> usize {
        self.inserted
    }

    fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    fn set_max_size(&mut self, new_size: usize) -> Result<()> {
        if new_size > self.max_capacity {
            return Err(anyhow!(
                "QPACK dynamic table size {new_size} exceeds advertised capacity {}",
                self.max_capacity
            ));
        }
        self.max_size = new_size;
        self.evict_to_limit(0)?;
        Ok(())
    }

    fn insert(&mut self, name: String, value: Vec<u8>) -> Result<()> {
        let entry = DynamicEntry::new(name, value);
        if entry.size > self.max_size {
            return Err(anyhow!(
                "QPACK dynamic entry size {} exceeds current table capacity {}",
                entry.size,
                self.max_size
            ));
        }
        self.evict_to_limit(entry.size)?;
        self.current_size += entry.size;
        self.entries.push_back(entry);
        self.inserted += 1;
        Ok(())
    }

    fn duplicate_latest_relative(&mut self, index: usize) -> Result<()> {
        let (name, value) = self.get_latest_relative(index)?;
        self.insert(name, value)
    }

    fn get_relative_from_base(&self, base: usize, index: usize) -> Result<(String, Vec<u8>)> {
        let absolute = base
            .checked_sub(index)
            .ok_or_else(|| anyhow!("invalid QPACK relative index {index} for base {base}"))?;
        self.get_absolute(absolute)
    }

    fn get_post_base(&self, base: usize, index: usize) -> Result<(String, Vec<u8>)> {
        let absolute = base
            .checked_add(index)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| anyhow!("QPACK post-base index overflow"))?;
        self.get_absolute(absolute)
    }

    fn get_latest_relative(&self, index: usize) -> Result<(String, Vec<u8>)> {
        let absolute = self
            .inserted
            .checked_sub(index)
            .ok_or_else(|| anyhow!("invalid QPACK latest-relative index {index}"))?;
        self.get_absolute(absolute)
    }

    fn get_absolute(&self, absolute: usize) -> Result<(String, Vec<u8>)> {
        if absolute == 0 || absolute <= self.dropped || absolute > self.inserted {
            return Err(anyhow!("invalid QPACK absolute index {absolute}"));
        }
        let position = absolute - self.dropped - 1;
        let entry = self
            .entries
            .get(position)
            .ok_or_else(|| anyhow!("missing QPACK dynamic entry {absolute}"))?;
        Ok((entry.name.clone(), entry.value.clone()))
    }

    fn evict_to_limit(&mut self, additional: usize) -> Result<()> {
        while self.current_size + additional > self.max_size {
            let Some(entry) = self.entries.pop_front() else {
                return Err(anyhow!("QPACK dynamic table eviction underflow"));
            };
            self.current_size -= entry.size;
            self.dropped += 1;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct DecoderState {
    table: DynamicTable,
    max_blocked_streams: u64,
    max_field_section_size: u64,
    blocked_streams: HashSet<u64>,
}

impl DecoderState {
    fn new(
        max_table_capacity: usize,
        max_blocked_streams: u64,
        max_field_section_size: u64,
    ) -> Self {
        Self {
            table: DynamicTable::new(max_table_capacity),
            max_blocked_streams,
            max_field_section_size,
            blocked_streams: HashSet::new(),
        }
    }

    fn register_blocked_stream(&mut self, stream_id: u64) -> std::result::Result<(), String> {
        if self.blocked_streams.insert(stream_id)
            && self.blocked_streams.len() as u64 > self.max_blocked_streams
        {
            self.blocked_streams.remove(&stream_id);
            return Err(format!(
                "QPACK blocked stream limit exceeded: advertised={}, stream_id={stream_id}",
                self.max_blocked_streams
            ));
        }
        Ok(())
    }

    fn unregister_blocked_stream(&mut self, stream_id: u64) {
        self.blocked_streams.remove(&stream_id);
    }

    fn decode_field_lines(&self, payload: &[u8]) -> Result<DecodedFields, FieldDecodeError> {
        let mut cursor = payload;
        let prefix = decode_field_section_prefix(
            &mut cursor,
            self.table.total_inserted(),
            self.table.max_capacity(),
        )?;
        if prefix.required_insert_count > self.table.total_inserted() {
            return Err(FieldDecodeError::MissingRefs(prefix.required_insert_count));
        }

        let mut out = Vec::new();
        let mut field_section_size = 0u64;
        while !cursor.is_empty() {
            let first = cursor[0];
            if (first & 0x80) != 0 {
                let (flags, index) = decode_prefixed_int(&mut cursor, 6)?;
                let field = match flags {
                    0b11 => {
                        let (name, value) = static_field(index as usize).ok_or_else(|| {
                            FieldDecodeError::decompression_failed(format!(
                                "unknown static QPACK table index {index}"
                            ))
                        })?;
                        (name.to_string(), value.as_bytes().to_vec())
                    }
                    0b10 => self
                        .table
                        .get_relative_from_base(prefix.base, index as usize)
                        .map_err(FieldDecodeError::from)?,
                    _ => {
                        return Err(FieldDecodeError::decompression_failed(format!(
                            "invalid indexed QPACK field flags {flags:#b}"
                        )));
                    }
                };
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            if (first & 0xf0) == 0x10 {
                let (flags, index) = decode_prefixed_int(&mut cursor, 4)?;
                if flags != 0b0001 {
                    return Err(FieldDecodeError::decompression_failed(format!(
                        "invalid post-base indexed QPACK flags {flags:#b}"
                    )));
                }
                let field = self
                    .table
                    .get_post_base(prefix.base, index as usize)
                    .map_err(FieldDecodeError::from)?;
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            if (first & 0xc0) == 0x40 {
                let (flags, index) = decode_prefixed_int(&mut cursor, 4)?;
                let value = decode_string(&mut cursor, 8)?;
                let field = match flags {
                    flag if (flag & 0b0101) == 0b0101 => {
                        let (name, _) = static_field(index as usize).ok_or_else(|| {
                            FieldDecodeError::decompression_failed(format!(
                                "unknown static QPACK name index {index}"
                            ))
                        })?;
                        (name.to_string(), value)
                    }
                    flag if (flag & 0b0101) == 0b0100 => {
                        let (name, _) = self
                            .table
                            .get_relative_from_base(prefix.base, index as usize)
                            .map_err(FieldDecodeError::from)?;
                        (name, value)
                    }
                    _ => {
                        return Err(FieldDecodeError::decompression_failed(format!(
                            "invalid QPACK name-reference flags {flags:#b}"
                        )));
                    }
                };
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            if (first & 0xf0) == 0x00 {
                let (flags, index) = decode_prefixed_int(&mut cursor, 3)?;
                if flags != 0 {
                    return Err(FieldDecodeError::decompression_failed(format!(
                        "invalid QPACK post-base name-reference flags {flags:#b}"
                    )));
                }
                let (name, _) = self
                    .table
                    .get_post_base(prefix.base, index as usize)
                    .map_err(FieldDecodeError::from)?;
                let value = decode_string(&mut cursor, 8)?;
                let field = (name, value);
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            if (first & 0xe0) == 0x20 {
                let name = decode_string(&mut cursor, 4)?;
                let value = decode_string(&mut cursor, 8)?;
                let field = (
                    String::from_utf8(name)
                        .map_err(|err| FieldDecodeError::decompression_failed(err.to_string()))?,
                    value,
                );
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            return Err(FieldDecodeError::decompression_failed(format!(
                "unsupported QPACK field representation: 0x{first:02x}"
            )));
        }

        Ok(DecodedFields {
            fields: out,
            dynamic_ref: prefix.required_insert_count != 0,
        })
    }

    fn process_encoder_chunk(&mut self, payload: &[u8]) -> Result<Option<(usize, u64)>> {
        let mut cursor = payload;
        let mut consumed = 0usize;
        let inserted_before = self.table.total_inserted();

        while !cursor.is_empty() {
            let before = cursor.len();
            let Some(instruction) = parse_encoder_instruction(&mut cursor)? else {
                break;
            };
            self.apply_encoder_instruction(instruction)?;
            consumed += before - cursor.len();
        }

        if consumed == 0 {
            return Ok(None);
        }
        let inserted_delta = (self.table.total_inserted() - inserted_before) as u64;
        Ok(Some((consumed, inserted_delta)))
    }

    fn apply_encoder_instruction(&mut self, instruction: EncoderInstruction) -> Result<()> {
        match instruction {
            EncoderInstruction::SetDynamicTableCapacity(size) => self.table.set_max_size(size),
            EncoderInstruction::InsertWithStaticName { index, value } => {
                let (name, _) = static_field(index)
                    .ok_or_else(|| anyhow!("unknown static QPACK name index {index}"))?;
                self.table.insert(name.to_string(), value)
            }
            EncoderInstruction::InsertWithDynamicName { index, value } => {
                let (name, _) = self.table.get_latest_relative(index)?;
                self.table.insert(name, value)
            }
            EncoderInstruction::InsertWithoutName { name, value } => self.table.insert(name, value),
            EncoderInstruction::Duplicate(index) => self.table.duplicate_latest_relative(index),
        }
    }
}

#[derive(Debug)]
struct DecodedFields {
    fields: Vec<(String, Vec<u8>)>,
    dynamic_ref: bool,
}

#[derive(Debug)]
enum FieldDecodeError {
    MissingRefs(usize),
    DecompressionFailed(String),
}

impl FieldDecodeError {
    fn decompression_failed(message: impl Into<String>) -> Self {
        Self::DecompressionFailed(message.into())
    }
}

impl From<anyhow::Error> for FieldDecodeError {
    fn from(error: anyhow::Error) -> Self {
        Self::DecompressionFailed(error.to_string())
    }
}

#[derive(Debug)]
pub(crate) enum HeaderDecodeError {
    Qpack(String),
    Message(String),
}

impl HeaderDecodeError {
    fn qpack(message: impl Into<String>) -> Self {
        Self::Qpack(message.into())
    }

    pub(crate) fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub(crate) fn code(&self) -> u64 {
        match self {
            Self::Qpack(_) => QPACK_DECOMPRESSION_FAILED,
            Self::Message(_) => crate::protocol::H3_MESSAGE_ERROR,
        }
    }
}

impl std::fmt::Display for HeaderDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Qpack(message) | Self::Message(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for HeaderDecodeError {}

enum EncoderInstruction {
    SetDynamicTableCapacity(usize),
    InsertWithStaticName { index: usize, value: Vec<u8> },
    InsertWithDynamicName { index: usize, value: Vec<u8> },
    InsertWithoutName { name: String, value: Vec<u8> },
    Duplicate(usize),
}

#[derive(Debug, Clone, Copy)]
struct FieldSectionPrefix {
    required_insert_count: usize,
    base: usize,
}

fn decode_field_section_prefix(
    cursor: &mut &[u8],
    total_inserted: usize,
    max_table_capacity: usize,
) -> Result<FieldSectionPrefix, FieldDecodeError> {
    let encoded_insert_count = decode_prefixed_int(cursor, 8)
        .map_err(FieldDecodeError::from)?
        .1 as usize;
    let (sign_bit, delta_base) = decode_prefixed_int(cursor, 7).map_err(FieldDecodeError::from)?;
    let delta_base = delta_base as usize;
    let required_insert_count =
        decode_required_insert_count(encoded_insert_count, total_inserted, max_table_capacity)?;
    let base = if required_insert_count == 0 {
        0
    } else if sign_bit == 0 {
        required_insert_count
            .checked_add(delta_base)
            .ok_or_else(|| FieldDecodeError::decompression_failed("QPACK base overflow"))?
    } else {
        required_insert_count
            .checked_sub(delta_base + 1)
            .ok_or_else(|| FieldDecodeError::decompression_failed("invalid QPACK base index"))?
    };
    Ok(FieldSectionPrefix {
        required_insert_count,
        base,
    })
}

fn decode_required_insert_count(
    encoded_insert_count: usize,
    total_inserted: usize,
    max_table_capacity: usize,
) -> Result<usize, FieldDecodeError> {
    if encoded_insert_count == 0 {
        return Ok(0);
    }
    let max_entries = max_table_capacity / 32;
    if max_entries == 0 {
        return Err(FieldDecodeError::decompression_failed(
            "dynamic QPACK references require non-zero table capacity",
        ));
    }

    let full_range = max_entries
        .checked_mul(2)
        .ok_or_else(|| FieldDecodeError::decompression_failed("QPACK full range overflow"))?;
    if encoded_insert_count > full_range {
        return Err(FieldDecodeError::decompression_failed(
            "QPACK encoded insert count exceeds full range",
        ));
    }
    let mut required = encoded_insert_count - 1;
    let mut wrapped = total_inserted % full_range;
    if wrapped >= required + max_entries {
        required += full_range;
    } else if wrapped + max_entries < required {
        wrapped += full_range;
    }
    let decoded = required + total_inserted - wrapped;
    if decoded == 0 {
        return Err(FieldDecodeError::decompression_failed(
            "non-zero QPACK encoded insert count decoded to zero",
        ));
    }
    Ok(decoded)
}

fn parse_encoder_instruction(cursor: &mut &[u8]) -> Result<Option<EncoderInstruction>> {
    let Some(&first) = cursor.first() else {
        return Ok(None);
    };
    if (first & 0x80) != 0 {
        let (flags, index) = match try_decode_prefixed_int(cursor, 6)? {
            Some(result) => result,
            None => return Ok(None),
        };
        if (flags & 0b10) != 0b10 {
            return Err(anyhow!(
                "invalid QPACK insert-with-name-reference flags {flags:#b}"
            ));
        }
        let value = match try_decode_string(cursor, 8)? {
            Some(value) => value,
            None => return Ok(None),
        };
        let instruction = if (flags & 0b01) != 0 {
            EncoderInstruction::InsertWithStaticName {
                index: index as usize,
                value,
            }
        } else {
            EncoderInstruction::InsertWithDynamicName {
                index: index as usize,
                value,
            }
        };
        return Ok(Some(instruction));
    }
    if (first & 0x40) != 0 {
        let name = match try_decode_string(cursor, 6)? {
            Some(name) => name,
            None => return Ok(None),
        };
        let value = match try_decode_string(cursor, 8)? {
            Some(value) => value,
            None => return Ok(None),
        };
        return Ok(Some(EncoderInstruction::InsertWithoutName {
            name: String::from_utf8(name)
                .map_err(|err| anyhow!("invalid utf-8 QPACK name: {err}"))?,
            value,
        }));
    }
    if (first & 0xe0) == 0x00 {
        let (flags, index) = match try_decode_prefixed_int(cursor, 5)? {
            Some(result) => result,
            None => return Ok(None),
        };
        if flags != 0 {
            return Err(anyhow!("invalid QPACK duplicate flags {flags:#b}"));
        }
        return Ok(Some(EncoderInstruction::Duplicate(index as usize)));
    }
    if (first & 0x20) != 0 {
        let (flags, size) = match try_decode_prefixed_int(cursor, 5)? {
            Some(result) => result,
            None => return Ok(None),
        };
        if flags != 0b001 {
            return Err(anyhow!(
                "invalid QPACK dynamic table size-update flags {flags:#b}"
            ));
        }
        return Ok(Some(EncoderInstruction::SetDynamicTableCapacity(
            size as usize,
        )));
    }
    Err(anyhow!(
        "unsupported QPACK encoder instruction: 0x{first:02x}"
    ))
}

pub(crate) fn fuzz_qpack_decoder(data: &[u8]) {
    let mut state = DecoderState::new(
        DEFAULT_DYNAMIC_TABLE_CAPACITY,
        DEFAULT_MAX_BLOCKED_STREAMS,
        u64::MAX,
    );
    let _ = state.decode_field_lines(data);
    let _ = state.process_encoder_chunk(data);
    let mut cursor = data;
    let _ = decode_field_section_prefix(&mut cursor, 13, DEFAULT_DYNAMIC_TABLE_CAPACITY);
}

fn encode_header_prefix(
    out: &mut Vec<u8>,
    required_insert_count: usize,
    base: usize,
    total_inserted: usize,
    max_table_capacity: usize,
) {
    if max_table_capacity == 0 || required_insert_count == 0 {
        encode_prefixed_int(out, 8, 0, 0);
        encode_prefixed_int(out, 7, 0, 0);
        return;
    }

    let max_entries = max_table_capacity / 32;
    let encoded_insert_count = required_insert_count % (2 * max_entries) + 1;
    let (sign_bit, delta_base) = if required_insert_count > base {
        (1, required_insert_count - base - 1)
    } else {
        (0, base - required_insert_count)
    };
    let _ = total_inserted;
    encode_prefixed_int(out, 8, 0, encoded_insert_count as u64);
    encode_prefixed_int(out, 7, sign_bit, delta_base as u64);
}

fn build_uri(
    scheme: Option<&str>,
    authority: Option<&str>,
    path: Option<&str>,
    authority_only: bool,
) -> Result<Uri> {
    if authority_only {
        let authority = authority.ok_or_else(|| anyhow!("CONNECT requires :authority"))?;
        return Uri::builder()
            .authority(authority)
            .build()
            .map_err(Into::into);
    }

    let mut builder = Uri::builder();
    if let Some(scheme) = scheme {
        builder = builder.scheme(scheme);
    }
    if let Some(authority) = authority {
        builder = builder.authority(authority);
    }
    if let Some(path) = path {
        builder = builder.path_and_query(path);
    }
    builder.build().map_err(Into::into)
}

fn encode_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    if let Some(index) = static_exact_match(name, value) {
        encode_prefixed_int(out, 6, 0b11, index as u64);
        return;
    }
    if let Some(index) = static_name_index(name) {
        encode_prefixed_int(out, 4, 0b0101, index as u64);
        encode_string(out, 8, 0, value);
        return;
    }
    encode_string(out, 4, 0b0010, name.as_bytes());
    encode_string(out, 8, 0, value);
}

fn pseudo_value_to_string(
    name: &str,
    value: Vec<u8>,
) -> std::result::Result<String, HeaderDecodeError> {
    String::from_utf8(value)
        .map_err(|err| HeaderDecodeError::message(format!("invalid UTF-8 {name} value: {err}")))
}

fn track_field_section_size(
    total: &mut u64,
    field: &(String, Vec<u8>),
    limit: u64,
) -> std::result::Result<(), FieldDecodeError> {
    let field_size = field
        .0
        .len()
        .checked_add(field.1.len())
        .and_then(|value| value.checked_add(HEADER_ENTRY_OVERHEAD as usize))
        .ok_or_else(|| FieldDecodeError::decompression_failed("field section size overflow"))?;
    *total = total
        .checked_add(field_size as u64)
        .ok_or_else(|| FieldDecodeError::decompression_failed("field section size overflow"))?;
    if *total > limit {
        return Err(FieldDecodeError::decompression_failed(format!(
            "field section size {} exceeds advertised limit {limit}",
            *total
        )));
    }
    Ok(())
}

fn encode_string(out: &mut Vec<u8>, total_bits: u8, flags: u8, value: &[u8]) {
    encode_prefixed_int(out, total_bits - 1, flags << 1, value.len() as u64);
    out.extend_from_slice(value);
}

fn encode_header_ack(stream_id: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_prefixed_int(&mut out, 7, 0b1, stream_id);
    out
}

fn encode_insert_count_increment(increment: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_prefixed_int(&mut out, 6, 0, increment);
    out
}

fn decode_string(cursor: &mut &[u8], total_bits: u8) -> Result<Vec<u8>> {
    try_decode_string(cursor, total_bits)?.ok_or_else(|| anyhow!("truncated string literal"))
}

fn try_decode_string(cursor: &mut &[u8], total_bits: u8) -> Result<Option<Vec<u8>>> {
    let original = *cursor;
    let Some((flags, len)) = try_decode_prefixed_int(cursor, total_bits - 1)? else {
        *cursor = original;
        return Ok(None);
    };
    let len = len as usize;
    if cursor.len() < len {
        *cursor = original;
        return Ok(None);
    }
    let (raw, rest) = cursor.split_at(len);
    *cursor = rest;
    if (flags & 0x1) == 0 {
        return Ok(Some(raw.to_vec()));
    }
    Ok(Some(huffman::decode(raw)?))
}

fn decode_prefixed_int(cursor: &mut &[u8], prefix_bits: u8) -> Result<(u8, u64)> {
    try_decode_prefixed_int(cursor, prefix_bits)?.ok_or_else(|| anyhow!("truncated integer"))
}

fn try_decode_prefixed_int(cursor: &mut &[u8], prefix_bits: u8) -> Result<Option<(u8, u64)>> {
    let Some(first) = cursor.first().copied() else {
        return Ok(None);
    };
    let (flags, mask) = if prefix_bits == 8 {
        (0, u8::MAX)
    } else {
        (first >> prefix_bits, ((1u16 << prefix_bits) - 1) as u8)
    };
    let mut value = (first & mask) as u64;
    let mut offset = 1usize;
    if value < mask as u64 {
        *cursor = &cursor[offset..];
        return Ok(Some((flags, value)));
    }
    let mut shift = 0u32;
    while offset < cursor.len() {
        let byte = cursor[offset];
        value += ((byte & 0x7f) as u64) << shift;
        offset += 1;
        if (byte & 0x80) == 0 {
            *cursor = &cursor[offset..];
            return Ok(Some((flags, value)));
        }
        shift += 7;
        if shift > 56 {
            return Err(anyhow!("prefixed integer overflow"));
        }
    }
    Ok(None)
}

fn encode_prefixed_int(out: &mut Vec<u8>, prefix_bits: u8, flags: u8, value: u64) {
    let mask = if prefix_bits == 8 {
        u8::MAX
    } else {
        ((1u16 << prefix_bits) - 1) as u8
    };
    if value < mask as u64 {
        let prefix = if prefix_bits == 8 {
            0
        } else {
            flags << prefix_bits
        };
        out.push(prefix | value as u8);
        return;
    }
    let prefix = if prefix_bits == 8 {
        0
    } else {
        flags << prefix_bits
    };
    out.push(prefix | mask);
    let mut remaining = value - mask as u64;
    while remaining >= 128 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

fn static_exact_match(name: &str, value: &[u8]) -> Option<usize> {
    STATIC_TABLE.iter().position(|(table_name, table_value)| {
        table_name == &name && table_value.as_bytes() == value
    })
}

fn static_name_index(name: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(table_name, _)| table_name == &name)
}

fn static_field(index: usize) -> Option<(&'static str, &'static str)> {
    STATIC_TABLE.get(index).copied()
}

// QPACK static table from RFC 9204 Appendix A.
const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

#[cfg(test)]
mod tests {
    use super::{
        append_header, decode_field_section_prefix, decode_request_head_from_fields,
        decode_required_insert_count, encode_header_prefix, encode_prefixed_int,
        encode_request_head, encode_response_head, encode_string, encode_trailers, static_field,
        validate_h3_regular_field, validate_h3_response_field, validate_h3_trailer_field,
        DecoderState, FieldDecodeError, DEFAULT_DYNAMIC_TABLE_CAPACITY,
        DEFAULT_MAX_BLOCKED_STREAMS, STATIC_TABLE,
    };
    use http::HeaderValue;

    #[test]
    fn decodes_literal_trailers() {
        let trailers = {
            let state = DecoderState::new(0, DEFAULT_MAX_BLOCKED_STREAMS, u64::MAX);
            state
                .decode_field_lines(&[0, 0, 0x21, b'f', 0x03, b'b', b'a', b'r'])
                .unwrap()
                .fields
        };
        assert_eq!(trailers, vec![("f".to_string(), b"bar".to_vec())]);
    }

    #[test]
    fn decodes_authority_form_connect() {
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(
                http::Uri::builder()
                    .authority("example.com:443")
                    .build()
                    .unwrap(),
            )
            .body(())
            .unwrap();
        let payload = encode_request_head(&request, None).unwrap();
        let state = DecoderState::new(0, DEFAULT_MAX_BLOCKED_STREAMS, u64::MAX);
        let decoded = state.decode_field_lines(&payload).unwrap().fields;
        assert_eq!(decoded[0], (":method".to_string(), b"CONNECT".to_vec()));
    }

    #[test]
    fn traditional_connect_rejects_scheme_and_path() {
        let fields = vec![
            (":method".to_string(), b"CONNECT".to_vec()),
            (":scheme".to_string(), b"https".to_vec()),
            (":authority".to_string(), b"example.com:443".to_vec()),
            (":path".to_string(), b"/forbidden".to_vec()),
        ];
        let err =
            decode_request_head_from_fields(fields).expect_err("traditional CONNECT must fail");
        assert!(err.to_string().contains("must not include"));
    }

    #[test]
    fn response_head_roundtrip() {
        let response = http::Response::builder()
            .status(204)
            .header("capsule-protocol", "?1")
            .body(())
            .unwrap();
        let payload = encode_response_head(&response);
        let state = DecoderState::new(0, DEFAULT_MAX_BLOCKED_STREAMS, u64::MAX);
        let decoded = state.decode_field_lines(&payload).unwrap().fields;
        assert_eq!(decoded[0], (":status".to_string(), b"204".to_vec()));
        assert!(decoded
            .iter()
            .any(|(name, value)| name == "capsule-protocol" && value.as_slice() == b"?1"));
    }

    #[test]
    fn response_fields_reject_te_trailers() {
        assert!(validate_h3_regular_field("te", b"trailers").is_ok());
        assert!(validate_h3_response_field("te", b"trailers").is_err());
    }

    #[test]
    fn dynamic_qpack_indexed_field_decodes_after_insert() {
        let mut state = DecoderState::new(
            DEFAULT_DYNAMIC_TABLE_CAPACITY,
            DEFAULT_MAX_BLOCKED_STREAMS,
            u64::MAX,
        );
        state
            .table
            .set_max_size(DEFAULT_DYNAMIC_TABLE_CAPACITY)
            .unwrap();
        state
            .table
            .insert("x-dynamic".to_string(), b"value".to_vec())
            .unwrap();

        let mut payload = Vec::new();
        encode_header_prefix(
            &mut payload,
            1,
            1,
            state.table.total_inserted(),
            DEFAULT_DYNAMIC_TABLE_CAPACITY,
        );
        encode_prefixed_int(&mut payload, 6, 0b10, 0);

        let decoded = state.decode_field_lines(&payload).unwrap();
        assert!(decoded.dynamic_ref);
        assert_eq!(
            decoded.fields,
            vec![("x-dynamic".to_string(), b"value".to_vec())]
        );
    }

    #[test]
    fn dynamic_qpack_name_reference_decodes_after_insert() {
        let mut state = DecoderState::new(
            DEFAULT_DYNAMIC_TABLE_CAPACITY,
            DEFAULT_MAX_BLOCKED_STREAMS,
            u64::MAX,
        );
        state
            .table
            .set_max_size(DEFAULT_DYNAMIC_TABLE_CAPACITY)
            .unwrap();
        state
            .table
            .insert("x-name".to_string(), b"seed".to_vec())
            .unwrap();

        let mut payload = Vec::new();
        encode_header_prefix(
            &mut payload,
            1,
            1,
            state.table.total_inserted(),
            DEFAULT_DYNAMIC_TABLE_CAPACITY,
        );
        encode_prefixed_int(&mut payload, 4, 0b0100, 0);
        encode_string(&mut payload, 8, 0, b"next");

        let decoded = state.decode_field_lines(&payload).unwrap();
        assert_eq!(
            decoded.fields,
            vec![("x-name".to_string(), b"next".to_vec())]
        );
    }

    #[test]
    fn missing_dynamic_refs_report_blocking_state() {
        let state = DecoderState::new(
            DEFAULT_DYNAMIC_TABLE_CAPACITY,
            DEFAULT_MAX_BLOCKED_STREAMS,
            u64::MAX,
        );
        let mut payload = Vec::new();
        encode_header_prefix(&mut payload, 1, 1, 0, DEFAULT_DYNAMIC_TABLE_CAPACITY);
        encode_prefixed_int(&mut payload, 6, 0b10, 0);

        match state.decode_field_lines(&payload) {
            Err(FieldDecodeError::MissingRefs(1)) => {}
            other => panic!("unexpected decode result: {other:?}"),
        }
    }

    #[test]
    fn required_insert_count_wraps_against_current_total() {
        let required =
            decode_required_insert_count(1, 128, DEFAULT_DYNAMIC_TABLE_CAPACITY).unwrap();
        assert_eq!(required, 256);
    }

    #[test]
    fn non_zero_encoded_insert_count_must_not_decode_to_zero() {
        let err = decode_required_insert_count(1, 0, DEFAULT_DYNAMIC_TABLE_CAPACITY)
            .expect_err("non-zero encoded insert count cannot represent zero");
        assert!(matches!(err, FieldDecodeError::DecompressionFailed(_)));
    }

    #[test]
    fn oversized_encoded_insert_count_is_malformed() {
        let max_entries = DEFAULT_DYNAMIC_TABLE_CAPACITY / 32;
        let err =
            decode_required_insert_count(2 * max_entries + 1, 128, DEFAULT_DYNAMIC_TABLE_CAPACITY)
                .expect_err("encoded insert count beyond full range must fail");
        assert!(matches!(err, FieldDecodeError::DecompressionFailed(_)));
    }

    #[test]
    fn field_prefix_roundtrip() {
        let mut payload = Vec::new();
        encode_header_prefix(&mut payload, 10, 5, 12, DEFAULT_DYNAMIC_TABLE_CAPACITY);
        let mut cursor = payload.as_slice();
        let decoded =
            decode_field_section_prefix(&mut cursor, 13, DEFAULT_DYNAMIC_TABLE_CAPACITY).unwrap();
        assert_eq!(decoded.required_insert_count, 10);
        assert_eq!(decoded.base, 5);
    }

    #[test]
    fn trailers_encode_roundtrip_shape() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-end", HeaderValue::from_static("done"));
        let payload = encode_trailers(&trailers);
        let state = DecoderState::new(0, DEFAULT_MAX_BLOCKED_STREAMS, u64::MAX);
        let decoded = state.decode_field_lines(&payload).unwrap().fields;
        assert_eq!(decoded, vec![("x-end".to_string(), b"done".to_vec())]);
    }

    #[test]
    fn request_trailers_reject_prohibited_fields() {
        assert!(validate_h3_trailer_field("x-end", b"done").is_ok());
        assert!(validate_h3_trailer_field("content-length", b"0").is_err());
        assert!(validate_h3_trailer_field("authorization", b"Bearer token").is_err());
        assert!(validate_h3_trailer_field("content-type", b"text/plain").is_err());
    }

    #[test]
    fn static_table_layout_is_stable() {
        assert_eq!(STATIC_TABLE.len(), 99);
        assert_eq!(static_field(17), Some((":method", "GET")));
    }

    #[test]
    fn cookie_fields_are_merged_for_generic_context() {
        let mut headers = http::HeaderMap::new();
        append_header(&mut headers, "cookie", b"a=1").expect("first cookie");
        append_header(&mut headers, "cookie", b"b=2").expect("second cookie");

        let cookie = headers
            .get(http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .expect("cookie header");
        assert_eq!(cookie, "a=1; b=2");
        assert_eq!(headers.get_all(http::header::COOKIE).iter().count(), 1);
    }

    #[test]
    fn regular_field_values_preserve_non_utf8_bytes() {
        let mut headers = http::HeaderMap::new();
        append_header(&mut headers, "x-obs", b"\xff").expect("obs-text value");
        assert_eq!(headers["x-obs"].as_bytes(), b"\xff");
    }

    #[test]
    fn h3_forbidden_regular_fields_are_rejected() {
        assert!(validate_h3_regular_field("connection", b"close").is_err());
        assert!(validate_h3_regular_field("transfer-encoding", b"chunked").is_err());
        assert!(validate_h3_regular_field("te", b"trailers").is_ok());
        assert!(validate_h3_regular_field("te", b"trailers, gzip").is_err());
    }
}
