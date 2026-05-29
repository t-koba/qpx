use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{Mutex, Notify};

use super::settings::PeerSettings;
use super::settings::read_varint_from_payload;
use super::{
    FRAME_CANCEL_PUSH, FRAME_CONTINUATION, FRAME_DATA, FRAME_GOAWAY, FRAME_HEADERS,
    FRAME_MAX_PUSH_ID, FRAME_PING, FRAME_PRIORITY, FRAME_PRIORITY_UPDATE_PUSH,
    FRAME_PRIORITY_UPDATE_REQUEST, FRAME_PUSH_PROMISE, FRAME_SETTINGS, FRAME_WINDOW_UPDATE,
    H3_EXCESSIVE_LOAD, H3_FRAME_ERROR, H3_FRAME_UNEXPECTED, H3_GENERAL_PROTOCOL_ERROR, H3_ID_ERROR,
    H3_MESSAGE_ERROR, H3_STREAM_CREATION_ERROR, read_varint_slice,
};

pub(crate) const MAX_BUFFERED_PRIORITY_UPDATES: usize = 1024;
const MAX_TRACKED_PRIORITY_REQUESTS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPriority {
    pub urgency: u8,
    pub incremental: bool,
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PriorityUpdates {
    control: PeerControlState,
    stream_id: u64,
}

impl PriorityUpdates {
    pub(crate) fn new(control: PeerControlState, stream_id: u64) -> Self {
        Self { control, stream_id }
    }

    pub async fn latest(&self) -> StreamPriority {
        self.control
            .latest_priority_for_request(self.stream_id)
            .await
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectionClose {
    pub(crate) code: u64,
    pub(crate) message: String,
}

impl ConnectionClose {
    pub(crate) fn new(code: u64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Default)]
struct PeerControlInner {
    control_stream_seen: bool,
    settings_seen: bool,
    encoder_stream_seen: bool,
    decoder_stream_seen: bool,
    max_push_id: Option<u64>,
    goaway_id: Option<u64>,
    settings: Option<PeerSettings>,
    request_priorities: HashMap<u64, StreamPriority>,
    started_request_streams: HashSet<u64>,
    started_request_priorities: HashMap<u64, StreamPriority>,
    started_request_stream_queue: VecDeque<u64>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerControlState {
    inner: Arc<Mutex<PeerControlInner>>,
    notify: Arc<Notify>,
}

impl PeerControlState {
    pub(crate) async fn register_control_stream(&self) -> std::result::Result<(), ConnectionClose> {
        let mut inner = self.inner.lock().await;
        if inner.control_stream_seen {
            return Err(ConnectionClose::new(
                H3_STREAM_CREATION_ERROR,
                "received duplicate HTTP/3 control stream",
            ));
        }
        inner.control_stream_seen = true;
        Ok(())
    }

    pub(crate) async fn register_settings(
        &self,
        settings: PeerSettings,
    ) -> std::result::Result<(), ConnectionClose> {
        let mut inner = self.inner.lock().await;
        if inner.settings_seen {
            return Err(ConnectionClose::new(
                H3_FRAME_UNEXPECTED,
                "received duplicate HTTP/3 SETTINGS frame",
            ));
        }
        inner.settings_seen = true;
        inner.settings = Some(settings);
        drop(inner);
        self.notify.notify_waiters();
        Ok(())
    }

    pub(crate) async fn settings_snapshot(&self) -> Option<PeerSettings> {
        self.inner.lock().await.settings.clone()
    }

    pub(crate) async fn register_encoder_stream(&self) -> std::result::Result<(), ConnectionClose> {
        let mut inner = self.inner.lock().await;
        if inner.encoder_stream_seen {
            return Err(ConnectionClose::new(
                H3_STREAM_CREATION_ERROR,
                "received duplicate QPACK encoder stream",
            ));
        }
        inner.encoder_stream_seen = true;
        Ok(())
    }

    pub(crate) async fn register_decoder_stream(&self) -> std::result::Result<(), ConnectionClose> {
        let mut inner = self.inner.lock().await;
        if inner.decoder_stream_seen {
            return Err(ConnectionClose::new(
                H3_STREAM_CREATION_ERROR,
                "received duplicate QPACK decoder stream",
            ));
        }
        inner.decoder_stream_seen = true;
        Ok(())
    }

    pub(crate) async fn wait_for_settings(&self) -> PeerSettings {
        loop {
            if let Some(settings) = self.settings_snapshot().await {
                return settings;
            }
            self.notify.notified().await;
        }
    }

    pub(crate) async fn goaway_id(&self) -> Option<u64> {
        self.inner.lock().await.goaway_id
    }

    pub(crate) async fn priority_for_request(
        &self,
        stream_id: u64,
        header_value: Option<&str>,
    ) -> StreamPriority {
        let mut priority = header_value.map(parse_priority).unwrap_or_default();
        let mut inner = self.inner.lock().await;
        track_started_request_stream(&mut inner, stream_id);
        if let Some(update) = inner.request_priorities.remove(&stream_id) {
            priority = update;
        }
        inner.started_request_priorities.insert(stream_id, priority);
        priority
    }

    pub(crate) async fn latest_priority_for_request(
        &self,
        stream_id: u64,
    ) -> Option<StreamPriority> {
        self.inner
            .lock()
            .await
            .started_request_priorities
            .get(&stream_id)
            .copied()
    }

    #[cfg(test)]
    pub(crate) async fn has_started_request_without_buffered_priority(
        &self,
        stream_id: u64,
    ) -> bool {
        let inner = self.inner.lock().await;
        inner.request_priorities.is_empty() && inner.started_request_streams.contains(&stream_id)
    }

    pub(crate) async fn handle_control_frame(
        &self,
        frame_ty: u64,
        payload: &[u8],
        endpoint_is_client: bool,
    ) -> std::result::Result<(), ConnectionClose> {
        validate_control_stream_frame(frame_ty, endpoint_is_client)?;
        match frame_ty {
            FRAME_CANCEL_PUSH => {
                let push_id = parse_single_varint_payload(payload, "CANCEL_PUSH")?;
                self.apply_cancel_push(push_id).await
            }
            FRAME_GOAWAY => {
                let goaway_id = parse_single_varint_payload(payload, "GOAWAY")?;
                self.apply_goaway(goaway_id, endpoint_is_client).await
            }
            FRAME_MAX_PUSH_ID => {
                let max_push_id = parse_single_varint_payload(payload, "MAX_PUSH_ID")?;
                self.apply_max_push_id(max_push_id).await
            }
            FRAME_PRIORITY_UPDATE_REQUEST => {
                let (stream_id, priority) = parse_priority_update_payload(payload)?;
                self.apply_priority_update(
                    FRAME_PRIORITY_UPDATE_REQUEST,
                    stream_id,
                    priority,
                    endpoint_is_client,
                )
                .await
            }
            FRAME_PRIORITY_UPDATE_PUSH => {
                let (_push_id, _priority) = parse_priority_update_payload(payload)?;
                self.apply_priority_update(
                    FRAME_PRIORITY_UPDATE_PUSH,
                    _push_id,
                    _priority,
                    endpoint_is_client,
                )
                .await
            }
            _ => Ok(()),
        }
    }

    pub(crate) async fn handle_control_frame_from_reader<R>(
        &self,
        reader: &mut R,
        frame_ty: u64,
        len: u64,
        max_payload_bytes: usize,
        endpoint_is_client: bool,
    ) -> std::result::Result<(), ConnectionClose>
    where
        R: AsyncRead + Unpin,
    {
        validate_control_stream_frame(frame_ty, endpoint_is_client)?;
        if len > max_payload_bytes as u64 {
            return Err(ConnectionClose::new(
                H3_MESSAGE_ERROR,
                format!(
                    "HTTP/3 control frame 0x{frame_ty:x} payload length {len} exceeds limit {max_payload_bytes}"
                ),
            ));
        }
        let mut remaining = len;
        match frame_ty {
            FRAME_CANCEL_PUSH => {
                let push_id =
                    read_single_varint_control_payload(reader, &mut remaining, "CANCEL_PUSH")
                        .await?;
                self.apply_cancel_push(push_id).await
            }
            FRAME_GOAWAY => {
                let goaway_id =
                    read_single_varint_control_payload(reader, &mut remaining, "GOAWAY").await?;
                self.apply_goaway(goaway_id, endpoint_is_client).await
            }
            FRAME_MAX_PUSH_ID => {
                let max_push_id =
                    read_single_varint_control_payload(reader, &mut remaining, "MAX_PUSH_ID")
                        .await?;
                self.apply_max_push_id(max_push_id).await
            }
            FRAME_PRIORITY_UPDATE_REQUEST | FRAME_PRIORITY_UPDATE_PUSH => {
                let (element_id, priority) =
                    read_priority_update_control_payload(reader, &mut remaining).await?;
                self.apply_priority_update(frame_ty, element_id, priority, endpoint_is_client)
                    .await
            }
            _ => Ok(()),
        }
    }

    async fn apply_cancel_push(&self, push_id: u64) -> std::result::Result<(), ConnectionClose> {
        let inner = self.inner.lock().await;
        let Some(max_push_id) = inner.max_push_id else {
            return Err(ConnectionClose::new(
                H3_ID_ERROR,
                "received CANCEL_PUSH before MAX_PUSH_ID established push space",
            ));
        };
        if push_id > max_push_id {
            return Err(ConnectionClose::new(
                H3_ID_ERROR,
                format!(
                    "received CANCEL_PUSH for push id {push_id} beyond MAX_PUSH_ID {max_push_id}"
                ),
            ));
        }
        Ok(())
    }

    async fn apply_goaway(
        &self,
        goaway_id: u64,
        endpoint_is_client: bool,
    ) -> std::result::Result<(), ConnectionClose> {
        if endpoint_is_client && !goaway_id.is_multiple_of(4) {
            return Err(ConnectionClose::new(
                H3_ID_ERROR,
                format!("received GOAWAY with non-client-bidi stream id {goaway_id}"),
            ));
        }
        let mut inner = self.inner.lock().await;
        if let Some(previous) = inner.goaway_id
            && goaway_id > previous
        {
            return Err(ConnectionClose::new(
                H3_ID_ERROR,
                format!("received GOAWAY id {goaway_id} greater than previous {previous}"),
            ));
        }
        inner.goaway_id = Some(goaway_id);
        Ok(())
    }

    async fn apply_max_push_id(
        &self,
        max_push_id: u64,
    ) -> std::result::Result<(), ConnectionClose> {
        let mut inner = self.inner.lock().await;
        if let Some(previous) = inner.max_push_id
            && max_push_id < previous
        {
            return Err(ConnectionClose::new(
                H3_ID_ERROR,
                format!("received MAX_PUSH_ID {max_push_id} lower than previous {previous}"),
            ));
        }
        inner.max_push_id = Some(max_push_id);
        Ok(())
    }

    async fn apply_priority_update(
        &self,
        frame_ty: u64,
        element_id: u64,
        priority: StreamPriority,
        endpoint_is_client: bool,
    ) -> std::result::Result<(), ConnectionClose> {
        match frame_ty {
            FRAME_PRIORITY_UPDATE_REQUEST => {
                if endpoint_is_client {
                    return Err(ConnectionClose::new(
                        H3_FRAME_UNEXPECTED,
                        "server sent HTTP/3 PRIORITY_UPDATE",
                    ));
                }
                if !is_client_initiated_bidi_stream_id(element_id) {
                    return Err(ConnectionClose::new(
                        H3_ID_ERROR,
                        format!(
                            "PRIORITY_UPDATE request target {element_id} is not a client-initiated bidirectional stream"
                        ),
                    ));
                }
                let mut inner = self.inner.lock().await;
                if inner.started_request_streams.contains(&element_id) {
                    inner
                        .started_request_priorities
                        .insert(element_id, priority);
                    return Ok(());
                }
                if !inner.request_priorities.contains_key(&element_id)
                    && inner.request_priorities.len() >= MAX_BUFFERED_PRIORITY_UPDATES
                {
                    return Err(ConnectionClose::new(
                        H3_EXCESSIVE_LOAD,
                        "too many buffered PRIORITY_UPDATE request targets",
                    ));
                }
                inner.request_priorities.insert(element_id, priority);
                Ok(())
            }
            FRAME_PRIORITY_UPDATE_PUSH => {
                if endpoint_is_client {
                    return Err(ConnectionClose::new(
                        H3_FRAME_UNEXPECTED,
                        "server sent HTTP/3 PRIORITY_UPDATE",
                    ));
                }
                Err(ConnectionClose::new(
                    H3_ID_ERROR,
                    "qpx-h3 does not negotiate server push targets for PRIORITY_UPDATE",
                ))
            }
            _ => Ok(()),
        }
    }
}

fn track_started_request_stream(inner: &mut PeerControlInner, stream_id: u64) {
    if inner.started_request_streams.insert(stream_id) {
        inner.started_request_stream_queue.push_back(stream_id);
    }
    while inner.started_request_streams.len() > MAX_TRACKED_PRIORITY_REQUESTS {
        let Some(oldest) = inner.started_request_stream_queue.pop_front() else {
            break;
        };
        inner.started_request_streams.remove(&oldest);
        inner.started_request_priorities.remove(&oldest);
        inner.request_priorities.remove(&oldest);
    }
}

pub(crate) fn validate_control_stream_frame(
    frame_ty: u64,
    endpoint_is_client: bool,
) -> std::result::Result<(), ConnectionClose> {
    match frame_ty {
        FRAME_CANCEL_PUSH | FRAME_GOAWAY => Ok(()),
        FRAME_PRIORITY_UPDATE_REQUEST | FRAME_PRIORITY_UPDATE_PUSH if !endpoint_is_client => Ok(()),
        FRAME_PRIORITY_UPDATE_REQUEST | FRAME_PRIORITY_UPDATE_PUSH => Err(ConnectionClose::new(
            H3_FRAME_UNEXPECTED,
            "servers must not send HTTP/3 PRIORITY_UPDATE frames",
        )),
        FRAME_MAX_PUSH_ID if !endpoint_is_client => Ok(()),
        FRAME_SETTINGS => Err(ConnectionClose::new(
            H3_FRAME_UNEXPECTED,
            "received duplicate HTTP/3 SETTINGS frame",
        )),
        FRAME_DATA | FRAME_HEADERS | FRAME_PUSH_PROMISE | FRAME_MAX_PUSH_ID => {
            Err(ConnectionClose::new(
                H3_FRAME_UNEXPECTED,
                format!("HTTP/3 frame type 0x{frame_ty:x} is not permitted on this control stream"),
            ))
        }
        ty if is_reserved_http2_frame_type(ty) => Err(ConnectionClose::new(
            H3_FRAME_UNEXPECTED,
            format!("HTTP/2 frame type 0x{frame_ty:x} is reserved in HTTP/3"),
        )),
        _ => Ok(()),
    }
}

pub(crate) fn control_frame_payload_is_known(frame_ty: u64) -> bool {
    matches!(
        frame_ty,
        FRAME_CANCEL_PUSH
            | FRAME_GOAWAY
            | FRAME_MAX_PUSH_ID
            | FRAME_PRIORITY_UPDATE_REQUEST
            | FRAME_PRIORITY_UPDATE_PUSH
    )
}

pub(crate) fn validate_message_stream_frame(
    frame_ty: u64,
) -> std::result::Result<(), ConnectionClose> {
    match frame_ty {
        FRAME_CANCEL_PUSH
        | FRAME_SETTINGS
        | FRAME_GOAWAY
        | FRAME_MAX_PUSH_ID
        | FRAME_PUSH_PROMISE
        | FRAME_PRIORITY_UPDATE_REQUEST
        | FRAME_PRIORITY_UPDATE_PUSH => Err(ConnectionClose::new(
            H3_FRAME_UNEXPECTED,
            format!("HTTP/3 frame type 0x{frame_ty:x} is not permitted on a message stream"),
        )),
        ty if is_reserved_http2_frame_type(ty) => Err(ConnectionClose::new(
            H3_FRAME_UNEXPECTED,
            format!("HTTP/2 frame type 0x{frame_ty:x} is reserved in HTTP/3"),
        )),
        _ => Ok(()),
    }
}

fn is_reserved_http2_frame_type(frame_ty: u64) -> bool {
    matches!(
        frame_ty,
        FRAME_PRIORITY | FRAME_PING | FRAME_WINDOW_UPDATE | FRAME_CONTINUATION
    )
}

fn parse_single_varint_payload(
    payload: &[u8],
    frame_name: &str,
) -> std::result::Result<u64, ConnectionClose> {
    let (value, used) = read_varint_slice(payload).map_err(|err| {
        ConnectionClose::new(
            H3_FRAME_ERROR,
            format!("malformed {frame_name} payload: {err}"),
        )
    })?;
    if used != payload.len() {
        return Err(ConnectionClose::new(
            H3_FRAME_ERROR,
            format!("{frame_name} payload contained trailing bytes"),
        ));
    }
    Ok(value)
}

pub(crate) fn parse_priority(value: &str) -> StreamPriority {
    let mut priority = StreamPriority::default();
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if let Some(raw) = item.strip_prefix("u=") {
            if let Ok(urgency) = raw.parse::<u8>()
                && urgency <= 7
            {
                priority.urgency = urgency;
            }
        } else if item == "i" || item == "i=?1" || item == "i=1" {
            priority.incremental = true;
        } else if item == "i=?0" || item == "i=0" {
            priority.incremental = false;
        }
    }
    priority
}

fn parse_priority_update_payload(
    payload: &[u8],
) -> std::result::Result<(u64, StreamPriority), ConnectionClose> {
    let (element_id, used) = read_varint_slice(payload).map_err(|err| {
        ConnectionClose::new(
            H3_FRAME_ERROR,
            format!("malformed PRIORITY_UPDATE target id: {err}"),
        )
    })?;
    let priority_value = &payload[used..];
    if !priority_value.is_ascii() {
        return Err(ConnectionClose::new(
            H3_GENERAL_PROTOCOL_ERROR,
            "PRIORITY_UPDATE value must be ASCII structured field text",
        ));
    }
    let priority_value = std::str::from_utf8(priority_value).map_err(|err| {
        ConnectionClose::new(
            H3_GENERAL_PROTOCOL_ERROR,
            format!("malformed PRIORITY_UPDATE value: {err}"),
        )
    })?;
    Ok((element_id, parse_priority(priority_value)))
}

async fn read_single_varint_control_payload<R>(
    reader: &mut R,
    remaining: &mut u64,
    frame_name: &str,
) -> std::result::Result<u64, ConnectionClose>
where
    R: AsyncRead + Unpin,
{
    let value = read_varint_from_payload(reader, remaining, frame_name)
        .await
        .map_err(|err| {
            ConnectionClose::new(
                H3_FRAME_ERROR,
                format!("malformed {frame_name} payload: {err}"),
            )
        })?;
    if *remaining != 0 {
        return Err(ConnectionClose::new(
            H3_FRAME_ERROR,
            format!("{frame_name} payload contained trailing bytes"),
        ));
    }
    Ok(value)
}

async fn read_priority_update_control_payload<R>(
    reader: &mut R,
    remaining: &mut u64,
) -> std::result::Result<(u64, StreamPriority), ConnectionClose>
where
    R: AsyncRead + Unpin,
{
    let element_id = read_varint_from_payload(reader, remaining, "PRIORITY_UPDATE target id")
        .await
        .map_err(|err| {
            ConnectionClose::new(
                H3_FRAME_ERROR,
                format!("malformed PRIORITY_UPDATE target id: {err}"),
            )
        })?;
    let priority = read_priority_value(reader, remaining).await?;
    Ok((element_id, priority))
}

async fn read_priority_value<R>(
    reader: &mut R,
    remaining: &mut u64,
) -> std::result::Result<StreamPriority, ConnectionClose>
where
    R: AsyncRead + Unpin,
{
    let mut parser = PriorityValueParser::default();
    let mut buf = [0u8; 1024];
    while *remaining != 0 {
        let want = (*remaining as usize).min(buf.len());
        reader.read_exact(&mut buf[..want]).await.map_err(|err| {
            ConnectionClose::new(
                H3_FRAME_ERROR,
                format!("truncated PRIORITY_UPDATE value: {err}"),
            )
        })?;
        *remaining -= want as u64;
        for byte in &buf[..want] {
            parser.push(*byte)?;
        }
    }
    parser.finish()
}

#[derive(Default)]
struct PriorityValueParser {
    priority: StreamPriority,
    token: Vec<u8>,
    token_truncated: bool,
}

impl PriorityValueParser {
    fn push(&mut self, byte: u8) -> std::result::Result<(), ConnectionClose> {
        if !byte.is_ascii() {
            return Err(ConnectionClose::new(
                H3_GENERAL_PROTOCOL_ERROR,
                "PRIORITY_UPDATE value must be ASCII structured field text",
            ));
        }
        if byte == b',' {
            self.finish_token();
            return Ok(());
        }
        if self.token.len() < 64 {
            self.token.push(byte);
        } else {
            self.token_truncated = true;
        }
        Ok(())
    }

    fn finish(mut self) -> std::result::Result<StreamPriority, ConnectionClose> {
        self.finish_token();
        Ok(self.priority)
    }

    fn finish_token(&mut self) {
        if self.token_truncated {
            self.token.clear();
            self.token_truncated = false;
            return;
        }
        let token = trim_ascii(self.token.as_slice());
        if let Some(raw) = token.strip_prefix(b"u=") {
            if let Ok(raw) = std::str::from_utf8(raw)
                && let Ok(urgency) = raw.parse::<u8>()
                && urgency <= 7
            {
                self.priority.urgency = urgency;
            }
        } else if token == b"i" || token == b"i=?1" || token == b"i=1" {
            self.priority.incremental = true;
        } else if token == b"i=?0" || token == b"i=0" {
            self.priority.incremental = false;
        }
        self.token.clear();
    }
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_client_initiated_bidi_stream_id(stream_id: u64) -> bool {
    stream_id & 0b11 == 0
}
