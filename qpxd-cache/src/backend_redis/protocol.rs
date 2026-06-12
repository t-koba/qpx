use super::{CachedBody, REDIS_CACHE_MAX_IDLE_CONNECTIONS, RedisConnection};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
use std::io::IoSlice;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{Duration, timeout};

pub fn encode_command(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(format!("*{}\r\n", parts.len()).as_bytes());
    for part in parts {
        out.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out
}

pub async fn recycle_stream(idle: Arc<AsyncMutex<Vec<RedisConnection>>>, stream: RedisConnection) {
    let mut idle = idle.lock().await;
    if idle.len() < REDIS_CACHE_MAX_IDLE_CONNECTIONS {
        idle.push(stream);
    }
}

pub async fn write_command3(
    conn: &mut RedisConnection,
    timeout_dur: Duration,
    command: &[u8],
    arg1: &[u8],
    arg2: &[u8],
) -> Result<()> {
    let command_header = format!("${}\r\n", command.len());
    let arg1_header = format!("${}\r\n", arg1.len());
    let arg2_header = format!("${}\r\n", arg2.len());
    write_all_vectored(
        conn,
        timeout_dur,
        &[
            b"*3\r\n",
            command_header.as_bytes(),
            command,
            b"\r\n",
            arg1_header.as_bytes(),
            arg1,
            b"\r\n",
            arg2_header.as_bytes(),
            arg2,
            b"\r\n",
        ],
    )
    .await?;
    Ok(())
}

async fn write_all_vectored(
    conn: &mut RedisConnection,
    timeout_dur: Duration,
    parts: &[&[u8]],
) -> Result<()> {
    const MAX_IO_SLICES: usize = 16;
    let mut part_idx = 0usize;
    let mut offset = 0usize;
    while part_idx < parts.len() {
        while part_idx < parts.len() && offset == parts[part_idx].len() {
            part_idx += 1;
            offset = 0;
        }
        if part_idx == parts.len() {
            break;
        }
        let mut slices = [IoSlice::new(&[]); MAX_IO_SLICES];
        let mut slice_count = 0usize;
        for (idx, part) in parts[part_idx..].iter().enumerate() {
            let bytes = if idx == 0 { &part[offset..] } else { part };
            if bytes.is_empty() {
                continue;
            }
            slices[slice_count] = IoSlice::new(bytes);
            slice_count += 1;
            if slice_count == slices.len() {
                break;
            }
        }
        let written = timeout(
            timeout_dur,
            conn.stream.write_vectored(&slices[..slice_count]),
        )
        .await??;
        if written == 0 {
            return Err(anyhow!("redis stream closed while writing command"));
        }
        let mut remaining = written;
        while part_idx < parts.len() {
            let available = parts[part_idx].len() - offset;
            if remaining < available {
                offset += remaining;
                break;
            }
            remaining -= available;
            part_idx += 1;
            offset = 0;
            if remaining == 0 {
                break;
            }
        }
    }
    Ok(())
}

pub async fn read_simple_ok(conn: &mut RedisConnection, timeout_dur: Duration) -> Result<()> {
    let line = read_line(conn, timeout_dur).await?;
    if line == b"+OK" {
        return Ok(());
    }
    if let Some(err) = line.strip_prefix(b"-") {
        return Err(anyhow!("redis error: {}", String::from_utf8_lossy(err)));
    }
    Err(anyhow!(
        "unexpected redis response: {}",
        String::from_utf8_lossy(&line)
    ))
}

pub async fn read_bulk_len(
    conn: &mut RedisConnection,
    timeout_dur: Duration,
    max_bytes: usize,
) -> Result<Option<usize>> {
    let line = read_line(conn, timeout_dur).await?;
    if line == b"$-1" {
        return Ok(None);
    }
    let len_str = line
        .strip_prefix(b"$")
        .ok_or_else(|| anyhow!("invalid redis bulk response"))?;
    let len: usize = std::str::from_utf8(len_str)?.parse()?;
    if len > max_bytes {
        return Err(anyhow!(
            "redis cache get payload too large: {} > {}",
            len,
            max_bytes
        ));
    }
    Ok(Some(len))
}

pub async fn read_bulk_string(
    conn: &mut RedisConnection,
    timeout_dur: Duration,
    max_bytes: usize,
) -> Result<Option<Bytes>> {
    let Some(len) = read_bulk_len(conn, timeout_dur, max_bytes).await? else {
        return Ok(None);
    };
    let mut payload = vec![0u8; len + 2];
    read_exact_buffered(conn, timeout_dur, &mut payload).await?;
    if &payload[len..] != b"\r\n" {
        return Err(anyhow!("invalid redis bulk terminator"));
    }
    payload.truncate(len);
    Ok(Some(Bytes::from(payload)))
}

pub async fn read_bulk_string_array(
    conn: &mut RedisConnection,
    timeout_dur: Duration,
    expected_len: usize,
    max_bytes: usize,
) -> Result<Vec<Option<Bytes>>> {
    let line = read_line(conn, timeout_dur).await?;
    let len = line
        .strip_prefix(b"*")
        .ok_or_else(|| anyhow!("invalid redis array response"))?;
    let len: usize = std::str::from_utf8(len)?.parse()?;
    if len != expected_len {
        return Err(anyhow!(
            "redis array length mismatch: expected {}, got {}",
            expected_len,
            len
        ));
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_bulk_string(conn, timeout_dur, max_bytes).await?);
    }
    Ok(out)
}

pub async fn read_bulk_cached_body(
    conn: &mut RedisConnection,
    timeout_dur: Duration,
    max_bytes: usize,
) -> Result<Option<CachedBody>> {
    let Some(len) = read_bulk_len(conn, timeout_dur, max_bytes).await? else {
        return Ok(None);
    };
    if len <= 64 * 1024 {
        let mut payload = vec![0u8; len + 2];
        read_exact_buffered(conn, timeout_dur, &mut payload).await?;
        if &payload[len..] != b"\r\n" {
            return Err(anyhow!("invalid redis bulk terminator"));
        }
        payload.truncate(len);
        return Ok(Some(CachedBody::from_bytes(Bytes::from(payload))));
    }

    let (file, path) = qpx_core::secure_file::create_secure_temp_file("qpx-cache-redis", ".body")?;
    let mut file = tokio::fs::File::from_std(file);
    let mut remaining = len;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len());
        read_exact_buffered(conn, timeout_dur, &mut buf[..want]).await?;
        file.write_all(&buf[..want]).await?;
        remaining -= want;
    }
    let mut terminator = [0u8; 2];
    read_exact_buffered(conn, timeout_dur, &mut terminator).await?;
    if terminator != *b"\r\n" {
        return Err(anyhow!("invalid redis bulk terminator"));
    }
    file.flush().await?;
    drop(file);
    Ok(Some(CachedBody::from_spooled_file(path, len as u64)))
}

pub async fn stream_redis_bulk_to_body(
    mut conn: RedisConnection,
    timeout_dur: Duration,
    len: usize,
    mut tx: qpx_http::body::Sender,
) -> Result<RedisConnection> {
    let mut remaining = len;
    let mut buf = BytesMut::with_capacity(64 * 1024);
    while remaining > 0 {
        let want = remaining.min(64 * 1024);
        buf.resize(want, 0);
        read_exact_buffered(&mut conn, timeout_dur, &mut buf[..want]).await?;
        let chunk = buf.split().freeze();
        if tx.send_data(chunk).await.is_err() {
            return Err(anyhow!("redis cache body consumer closed"));
        }
        remaining -= want;
    }
    let mut terminator = [0u8; 2];
    read_exact_buffered(&mut conn, timeout_dur, &mut terminator).await?;
    if terminator != *b"\r\n" {
        tx.abort();
        return Err(anyhow!("invalid redis bulk terminator"));
    }
    Ok(conn)
}

pub async fn write_set_cached_body(
    conn: &mut RedisConnection,
    timeout_dur: Duration,
    key: &[u8],
    body: &CachedBody,
    ttl_secs: u64,
) -> Result<()> {
    timeout(timeout_dur, conn.stream.write_all(b"*5\r\n$3\r\nSET\r\n")).await??;
    timeout(
        timeout_dur,
        conn.stream
            .write_all(format!("${}\r\n", key.len()).as_bytes()),
    )
    .await??;
    timeout(timeout_dur, conn.stream.write_all(key)).await??;
    timeout(timeout_dur, conn.stream.write_all(b"\r\n")).await??;
    timeout(
        timeout_dur,
        conn.stream
            .write_all(format!("${}\r\n", body.len()).as_bytes()),
    )
    .await??;
    let mut body_stream = body.to_body();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk?;
        timeout(timeout_dur, conn.stream.write_all(chunk.as_ref())).await??;
    }
    timeout(timeout_dur, conn.stream.write_all(b"\r\n$2\r\nEX\r\n")).await??;
    let ttl = ttl_secs.to_string();
    timeout(
        timeout_dur,
        conn.stream
            .write_all(format!("${}\r\n", ttl.len()).as_bytes()),
    )
    .await??;
    timeout(timeout_dur, conn.stream.write_all(ttl.as_bytes())).await??;
    timeout(timeout_dur, conn.stream.write_all(b"\r\n")).await??;
    Ok(())
}

pub async fn read_line(conn: &mut RedisConnection, timeout_dur: Duration) -> Result<Vec<u8>> {
    timeout(timeout_dur, async {
        loop {
            if let Some(pos) = conn.read_buf.windows(2).position(|w| w == b"\r\n") {
                let mut line = conn.read_buf.split_to(pos + 2);
                line.truncate(pos);
                return Ok(line.to_vec());
            }
            if conn.read_buf.len() > 8192 {
                return Err(anyhow!("redis line too long"));
            }
            let old_len = conn.read_buf.len();
            conn.read_buf.resize(old_len + 1024, 0);
            let n = conn.stream.read(&mut conn.read_buf[old_len..]).await?;
            if n == 0 {
                return Err(anyhow!("redis connection closed"));
            }
            conn.read_buf.truncate(old_len + n);
        }
    })
    .await?
}

pub async fn read_exact_buffered(
    conn: &mut RedisConnection,
    timeout_dur: Duration,
    mut dst: &mut [u8],
) -> Result<()> {
    while !dst.is_empty() {
        if !conn.read_buf.is_empty() {
            let take = dst.len().min(conn.read_buf.len());
            let bytes = conn.read_buf.split_to(take);
            dst[..take].copy_from_slice(&bytes);
            dst = &mut dst[take..];
            continue;
        }
        timeout(timeout_dur, conn.stream.read_exact(dst)).await??;
        return Ok(());
    }
    Ok(())
}

pub async fn read_integer(conn: &mut RedisConnection, timeout_dur: Duration) -> Result<i64> {
    let line = read_line(conn, timeout_dur).await?;
    if let Some(err) = line.strip_prefix(b"-") {
        return Err(anyhow!("redis error: {}", String::from_utf8_lossy(err)));
    }
    let value = line
        .strip_prefix(b":")
        .ok_or_else(|| anyhow!("invalid redis integer response"))?;
    Ok(std::str::from_utf8(value)?.parse::<i64>()?)
}

pub async fn validate_next_append_reply(
    conn: &mut RedisConnection,
    timeout_dur: Duration,
    pending_appends: &mut VecDeque<usize>,
) -> Result<()> {
    let expected = pending_appends
        .pop_front()
        .ok_or_else(|| anyhow!("missing redis APPEND pipeline expectation"))?;
    let appended = read_integer(conn, timeout_dur).await?;
    if appended < 0 || appended as usize != expected {
        return Err(anyhow!("redis APPEND returned unexpected object length"));
    }
    Ok(())
}
