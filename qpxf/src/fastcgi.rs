use anyhow::{anyhow, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// FastCGI record types.
pub const FCGI_BEGIN_REQUEST: u8 = 1;
pub const FCGI_ABORT_REQUEST: u8 = 2;
pub const FCGI_END_REQUEST: u8 = 3;
pub const FCGI_PARAMS: u8 = 4;
pub const FCGI_STDIN: u8 = 5;
pub const FCGI_STDOUT: u8 = 6;
pub const FCGI_STDERR: u8 = 7;
#[allow(dead_code)]
pub const FCGI_DATA: u8 = 8;
pub const FCGI_GET_VALUES: u8 = 9;
pub const FCGI_GET_VALUES_RESULT: u8 = 10;
pub const FCGI_UNKNOWN_TYPE: u8 = 11;

// FastCGI roles.
pub const FCGI_RESPONDER: u16 = 1;

// Protocol status codes.
pub const FCGI_REQUEST_COMPLETE: u8 = 0;
pub const FCGI_CANT_MPX_CONN: u8 = 1;
pub const FCGI_OVERLOADED: u8 = 2;
pub const FCGI_UNKNOWN_ROLE: u8 = 3;

// Protocol version.
const FCGI_VERSION_1: u8 = 1;

/// Fixed 8-byte FastCGI record header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHeader {
    pub version: u8,
    pub record_type: u8,
    pub request_id: u16,
    pub content_length: u16,
    pub padding_length: u8,
}

impl RecordHeader {
    #[allow(dead_code)]
    pub const SIZE: usize = 8;

    pub fn encode(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = self.version;
        buf[1] = self.record_type;
        buf[2] = (self.request_id >> 8) as u8;
        buf[3] = (self.request_id & 0xff) as u8;
        buf[4] = (self.content_length >> 8) as u8;
        buf[5] = (self.content_length & 0xff) as u8;
        buf[6] = self.padding_length;
        buf[7] = 0; // reserved
        buf
    }

    pub fn decode(buf: &[u8; 8]) -> Self {
        Self {
            version: buf[0],
            record_type: buf[1],
            request_id: u16::from_be_bytes([buf[2], buf[3]]),
            content_length: u16::from_be_bytes([buf[4], buf[5]]),
            padding_length: buf[6],
        }
    }
}

/// A complete FastCGI record (header + content).
#[derive(Debug, Clone)]
pub struct Record {
    pub header: RecordHeader,
    pub content: Bytes,
}

/// Encode a FastCGI name-value pair into the buffer.
#[allow(dead_code)]
pub fn encode_name_value(buf: &mut BytesMut, name: &[u8], value: &[u8]) {
    fn write_len(buf: &mut BytesMut, len: usize) {
        if len < 128 {
            buf.put_u8(len as u8);
        } else {
            buf.put_u32((len as u32) | 0x8000_0000);
        }
    }
    write_len(buf, name.len());
    write_len(buf, value.len());
    buf.extend_from_slice(name);
    buf.extend_from_slice(value);
}

/// Decode all name-value pairs from a FastCGI PARAMS content buffer.
pub fn decode_name_values(mut data: &[u8]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    while !data.is_empty() {
        let name_len = read_nv_len(&mut data)?;
        let value_len = read_nv_len(&mut data)?;
        if data.len() < name_len + value_len {
            return Err(anyhow!("truncated name-value pair"));
        }
        let name = std::str::from_utf8(&data[..name_len])?.to_string();
        let value = std::str::from_utf8(&data[name_len..name_len + value_len])?.to_string();
        data = &data[name_len + value_len..];
        map.insert(name, value);
    }
    Ok(map)
}

fn read_nv_len(data: &mut &[u8]) -> Result<usize> {
    if data.is_empty() {
        return Err(anyhow!("unexpected end of name-value data"));
    }
    let first = data[0];
    if first < 128 {
        *data = &data[1..];
        Ok(first as usize)
    } else {
        if data.len() < 4 {
            return Err(anyhow!("truncated 4-byte name-value length"));
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & 0x7fff_ffff;
        *data = &data[4..];
        Ok(len as usize)
    }
}

/// Read one FastCGI record from an async reader.
pub async fn read_record<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Record> {
    let mut hdr_buf = [0u8; 8];
    reader.read_exact(&mut hdr_buf).await?;
    let header = RecordHeader::decode(&hdr_buf);

    // Validate protocol version.
    if header.version != FCGI_VERSION_1 {
        return Err(anyhow!(
            "unsupported FastCGI version: {} (expected {})",
            header.version,
            FCGI_VERSION_1
        ));
    }

    let content_len = header.content_length as usize;
    let padding_len = header.padding_length as usize;
    let total = content_len + padding_len;

    // Read directly into a BytesMut to avoid double-copy.
    // NOTE: we intentionally avoid zero-initializing the buffer for performance.
    let mut buf = BytesMut::with_capacity(total);
    if total > 0 {
        // SAFETY: `read_exact` initializes the full `total` bytes before we freeze/slice.
        unsafe {
            buf.set_len(total);
        }
        reader.read_exact(&mut buf).await?;
    }
    buf.truncate(content_len);
    let content = buf.freeze();

    Ok(Record { header, content })
}

/// Write one FastCGI record to an async writer.
pub async fn write_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    record_type: u8,
    request_id: u16,
    content: &[u8],
) -> Result<()> {
    let padding = (8 - (content.len() % 8)) % 8;
    let header = RecordHeader {
        version: FCGI_VERSION_1,
        record_type,
        request_id,
        content_length: content.len() as u16,
        padding_length: padding as u8,
    };
    writer.write_all(&header.encode()).await?;
    if !content.is_empty() {
        writer.write_all(content).await?;
    }
    if padding > 0 {
        let pad = [0u8; 8];
        writer.write_all(&pad[..padding]).await?;
    }
    Ok(())
}

/// Write FCGI_STDOUT in chunks (max 65535 bytes per record), then an empty STDOUT record.
pub async fn write_stdout_stream<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: u16,
    data: &[u8],
) -> Result<()> {
    for chunk in data.chunks(65535) {
        write_record(writer, FCGI_STDOUT, request_id, chunk).await?;
    }
    // Empty STDOUT signals end of stream.
    write_record(writer, FCGI_STDOUT, request_id, &[]).await?;
    Ok(())
}

/// Write FCGI_STDERR in chunks, then an empty STDERR record.
#[allow(dead_code)]
pub async fn write_stderr_stream<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: u16,
    data: &[u8],
) -> Result<()> {
    for chunk in data.chunks(65535) {
        write_record(writer, FCGI_STDERR, request_id, chunk).await?;
    }
    write_record(writer, FCGI_STDERR, request_id, &[]).await?;
    Ok(())
}

/// Write an FCGI_END_REQUEST record.
pub async fn write_end_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: u16,
    app_status: u32,
    protocol_status: u8,
) -> Result<()> {
    let mut body = [0u8; 8];
    body[0..4].copy_from_slice(&app_status.to_be_bytes());
    body[4] = protocol_status;
    write_record(writer, FCGI_END_REQUEST, request_id, &body).await?;
    Ok(())
}

/// Write an FCGI_UNKNOWN_TYPE management response.
async fn write_unknown_type<W: AsyncWrite + Unpin>(writer: &mut W, unknown_type: u8) -> Result<()> {
    let mut body = [0u8; 8];
    body[0] = unknown_type;
    write_record(writer, FCGI_UNKNOWN_TYPE, 0, &body).await?;
    Ok(())
}

/// Parsed FastCGI request from a client (e.g. qpxd).
#[derive(Debug)]
pub struct FcgiRequest {
    pub request_id: u16,
    pub params: HashMap<String, String>,
    pub stdin: Bytes,
}

/// Size limits for FastCGI request parsing.
pub struct RequestLimits {
    pub max_params_bytes: usize,
    pub max_stdin_bytes: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_params_bytes: 1_048_576, // 1 MiB
            max_stdin_bytes: 33_554_432, // 32 MiB
        }
    }
}

/// Read a complete FastCGI request (BEGIN_REQUEST + PARAMS + STDIN).
///
/// Management records (request_id=0) are handled inline.
/// Multiplexed requests (interleaved request_ids) are rejected.
#[allow(dead_code)]
pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<FcgiRequest> {
    read_request_with_limits(reader, &RequestLimits::default(), &mut DummyWriter).await
}

/// Read a complete FastCGI request with configurable size limits.
///
/// A writer is needed to respond to management records inline.
pub async fn read_request_with_limits<R, W>(
    reader: &mut R,
    limits: &RequestLimits,
    writer: &mut W,
) -> Result<FcgiRequest>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // 1. Read records until we get a BEGIN_REQUEST, skipping management records.
    let (request_id, role) = loop {
        let rec = read_record(reader).await?;

        if rec.header.request_id == 0 {
            handle_management_record(writer, &rec).await?;
            continue;
        }

        if rec.header.record_type != FCGI_BEGIN_REQUEST {
            return Err(anyhow!(
                "expected FCGI_BEGIN_REQUEST, got type {}",
                rec.header.record_type
            ));
        }

        if rec.content.len() < 3 {
            return Err(anyhow!("BEGIN_REQUEST body too short"));
        }
        let role = u16::from_be_bytes([rec.content[0], rec.content[1]]);
        break (rec.header.request_id, role);
    };

    // Validate role — we only support FCGI_RESPONDER.
    if role != FCGI_RESPONDER {
        write_end_request(writer, request_id, 0, FCGI_UNKNOWN_ROLE).await?;
        return Err(anyhow!("unsupported FastCGI role: {}", role));
    }

    // 2. PARAMS (one or more records, terminated by empty)
    let mut params_buf = BytesMut::new();
    loop {
        let rec = read_record(reader).await?;

        if rec.header.request_id == 0 {
            handle_management_record(writer, &rec).await?;
            continue;
        }
        if rec.header.request_id != request_id {
            return Err(anyhow!(
                "multiplexing not supported: expected request_id {}, got {}",
                request_id,
                rec.header.request_id
            ));
        }
        if rec.header.record_type == FCGI_ABORT_REQUEST {
            return Err(anyhow!("request aborted by client"));
        }
        if rec.header.record_type != FCGI_PARAMS {
            return Err(anyhow!(
                "expected FCGI_PARAMS, got type {}",
                rec.header.record_type
            ));
        }
        if rec.content.is_empty() {
            break;
        }
        if params_buf.len() + rec.content.len() > limits.max_params_bytes {
            return Err(anyhow!(
                "PARAMS exceeds size limit ({} bytes)",
                limits.max_params_bytes
            ));
        }
        params_buf.extend_from_slice(&rec.content);
    }
    let params = decode_name_values(&params_buf)?;

    // 3. STDIN (one or more records, terminated by empty)
    let mut stdin_buf = BytesMut::new();
    loop {
        let rec = read_record(reader).await?;

        if rec.header.request_id == 0 {
            handle_management_record(writer, &rec).await?;
            continue;
        }
        if rec.header.request_id != request_id {
            return Err(anyhow!(
                "multiplexing not supported: expected request_id {}, got {}",
                request_id,
                rec.header.request_id
            ));
        }
        if rec.header.record_type == FCGI_ABORT_REQUEST {
            return Err(anyhow!("request aborted by client"));
        }
        if rec.header.record_type != FCGI_STDIN {
            return Err(anyhow!(
                "expected FCGI_STDIN, got type {}",
                rec.header.record_type
            ));
        }
        if rec.content.is_empty() {
            break;
        }
        if stdin_buf.len() + rec.content.len() > limits.max_stdin_bytes {
            return Err(anyhow!(
                "STDIN exceeds size limit ({} bytes)",
                limits.max_stdin_bytes
            ));
        }
        stdin_buf.extend_from_slice(&rec.content);
    }

    Ok(FcgiRequest {
        request_id,
        params,
        stdin: stdin_buf.freeze(),
    })
}

/// Handle a management record (request_id = 0).
async fn handle_management_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    rec: &Record,
) -> Result<()> {
    match rec.header.record_type {
        FCGI_GET_VALUES => {
            // Respond with empty FCGI_GET_VALUES_RESULT (we don't advertise capabilities).
            write_record(writer, FCGI_GET_VALUES_RESULT, 0, &[]).await?;
        }
        _ => {
            write_unknown_type(writer, rec.header.record_type).await?;
        }
    }
    Ok(())
}

/// A no-op writer for the simple `read_request` that doesn't need to respond to management records.
struct DummyWriter;

impl tokio::io::AsyncWrite for DummyWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
