use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration, Instant};

const MAX_CLIENT_HELLO_PEEK_BYTES: usize = 64 * 1024;

pub async fn read_client_hello_with_timeout<R>(
    stream: &mut R,
    timeout_dur: Duration,
) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let deadline = Instant::now() + timeout_dur;
    let mut desired = 5usize;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    loop {
        let target = desired.min(MAX_CLIENT_HELLO_PEEK_BYTES);
        while buf.len() < target {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let want = (target - buf.len()).min(tmp.len());
            let n = match timeout(remaining, stream.read(&mut tmp[..want])).await {
                Ok(Ok(n)) => n,
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "timed out while reading client hello",
                    ));
                }
            };
            if n == 0 {
                return Ok(buf);
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() >= MAX_CLIENT_HELLO_PEEK_BYTES {
                buf.truncate(MAX_CLIENT_HELLO_PEEK_BYTES);
                return Ok(buf);
            }
        }

        let next = match required_client_hello_peek_bytes(&buf) {
            Some(next) => next.min(MAX_CLIENT_HELLO_PEEK_BYTES),
            None => return Ok(buf),
        };
        if buf.len() >= next || next == MAX_CLIENT_HELLO_PEEK_BYTES {
            return Ok(buf);
        }
        desired = next;
    }
}

pub fn looks_like_tls_client_hello(buf: &[u8]) -> bool {
    buf.len() >= 6 && buf[0] == 22 && buf[5] == 1
}

pub fn extract_sni(buf: &[u8]) -> Option<String> {
    let client_hello = reassemble_client_hello_handshake(buf)?;
    parse_sni_from_client_hello(&client_hello)
}

fn required_client_hello_peek_bytes(buf: &[u8]) -> Option<usize> {
    if buf.len() < 5 {
        return Some(5);
    }
    if buf[0] != 22 {
        return None;
    }

    let mut pos = 0usize;
    let mut handshake_header = [0u8; 4];
    let mut handshake_header_len = 0usize;
    let mut handshake_bytes = 0usize;
    let mut total_handshake_bytes: Option<usize> = None;

    loop {
        if pos + 5 > buf.len() {
            return Some(pos.saturating_add(5));
        }
        if buf.get(pos)? != &22 {
            return None;
        }
        let record_len = u16::from_be_bytes([*buf.get(pos + 3)?, *buf.get(pos + 4)?]) as usize;
        let record_end = pos.saturating_add(5).saturating_add(record_len);
        if record_end > MAX_CLIENT_HELLO_PEEK_BYTES {
            return Some(MAX_CLIENT_HELLO_PEEK_BYTES);
        }
        if buf.len() < record_end {
            return Some(record_end);
        }
        let payload = &buf[pos + 5..record_end];
        handshake_bytes = handshake_bytes.saturating_add(payload.len());

        if total_handshake_bytes.is_none() && handshake_header_len < handshake_header.len() {
            let take = (handshake_header.len() - handshake_header_len).min(payload.len());
            handshake_header[handshake_header_len..handshake_header_len + take]
                .copy_from_slice(&payload[..take]);
            handshake_header_len += take;
            if handshake_header_len == handshake_header.len() {
                if handshake_header[0] != 1 {
                    return None;
                }
                let hs_len = read_u24(&handshake_header, 1)?;
                total_handshake_bytes = Some(hs_len.saturating_add(4));
            }
        }

        if let Some(total) = total_handshake_bytes {
            if handshake_bytes >= total {
                return None;
            }
        }

        pos = record_end;
        if pos >= buf.len() {
            return Some(pos.saturating_add(5));
        }
    }
}

fn reassemble_client_hello_handshake(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 5 || buf[0] != 22 {
        return None;
    }

    let mut pos = 0usize;
    let mut handshake = Vec::new();
    let mut total: Option<usize> = None;
    while pos + 5 <= buf.len() {
        if buf.get(pos)? != &22 {
            return None;
        }
        let record_len = u16::from_be_bytes([*buf.get(pos + 3)?, *buf.get(pos + 4)?]) as usize;
        let record_end = pos.checked_add(5)?.checked_add(record_len)?;
        if record_end > buf.len() {
            return None;
        }
        let payload = &buf[pos + 5..record_end];
        handshake.extend_from_slice(payload);
        if total.is_none() && handshake.len() >= 4 {
            if handshake[0] != 1 {
                return None;
            }
            let hs_len = read_u24(&handshake, 1)?;
            total = Some(hs_len.saturating_add(4));
        }
        if let Some(total) = total {
            if handshake.len() >= total {
                handshake.truncate(total);
                return Some(handshake);
            }
        }
        pos = record_end;
    }
    None
}

fn parse_sni_from_client_hello(buf: &[u8]) -> Option<String> {
    if buf.len() < 4 || buf.first()? != &1 {
        return None;
    }

    let hs_len = read_u24(buf, 1)?;
    let mut pos = 4usize;
    let hs_end = pos.checked_add(hs_len)?;
    if hs_end > buf.len() {
        return None;
    }

    pos = skip(buf, pos, 2)?; // legacy_version
    pos = skip(buf, pos, 32)?; // random

    let session_id_len = *buf.get(pos)? as usize;
    pos = skip(buf, pos + 1, session_id_len)?;

    let cipher_suites_len = read_u16(buf, pos)? as usize;
    pos = skip(buf, pos + 2, cipher_suites_len)?;

    let compression_len = *buf.get(pos)? as usize;
    pos = skip(buf, pos + 1, compression_len)?;

    let extensions_len = read_u16(buf, pos)? as usize;
    pos += 2;
    let ext_end = pos.checked_add(extensions_len)?;
    if ext_end > hs_end {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = read_u16(buf, pos)?;
        let ext_len = read_u16(buf, pos + 2)? as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            return None;
        }

        if ext_type == 0 {
            return parse_sni_extension(&buf[pos..pos + ext_len]);
        }
        pos += ext_len;
    }

    None
}

fn parse_sni_extension(ext: &[u8]) -> Option<String> {
    if ext.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    if list_len + 2 > ext.len() {
        return None;
    }

    let mut pos = 2;
    let end = 2 + list_len;
    while pos + 3 <= end {
        let name_type = ext[pos];
        let name_len = u16::from_be_bytes([ext[pos + 1], ext[pos + 2]]) as usize;
        pos += 3;
        if pos + name_len > end {
            return None;
        }
        if name_type == 0 {
            let host = std::str::from_utf8(&ext[pos..pos + name_len]).ok()?;
            return Some(host.to_ascii_lowercase());
        }
        pos += name_len;
    }

    None
}

fn read_u16(buf: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]))
}

fn read_u24(buf: &[u8], pos: usize) -> Option<usize> {
    let b0 = *buf.get(pos)? as usize;
    let b1 = *buf.get(pos + 1)? as usize;
    let b2 = *buf.get(pos + 2)? as usize;
    Some((b0 << 16) | (b1 << 8) | b2)
}

fn skip(buf: &[u8], start: usize, len: usize) -> Option<usize> {
    let end = start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some(end)
}
