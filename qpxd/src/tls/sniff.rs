use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration, Instant};

const MAX_CLIENT_HELLO_PEEK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsClientHelloInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub tls_version: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
}

pub async fn read_client_hello_with_timeout<R>(
    stream: &mut R,
    timeout_dur: Duration,
) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    read_client_hello_with_timeout_mode(stream, timeout_dur, true).await
}

pub async fn try_read_client_hello_with_timeout<R>(
    stream: &mut R,
    timeout_dur: Duration,
) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    read_client_hello_with_timeout_mode(stream, timeout_dur, false).await
}

async fn read_client_hello_with_timeout_mode<R>(
    stream: &mut R,
    timeout_dur: Duration,
    fail_on_timeout: bool,
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
                    if fail_on_timeout {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "timed out while reading client hello",
                        ));
                    }
                    return Ok(buf);
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

#[cfg(test)]
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    extract_client_hello_info(buf).and_then(|info| info.sni)
}

pub fn extract_client_hello_info(buf: &[u8]) -> Option<TlsClientHelloInfo> {
    let client_hello = reassemble_client_hello_handshake(buf)?;
    parse_client_hello_info(&client_hello)
}

pub fn extract_client_hello_info_from_handshake(buf: &[u8]) -> Option<TlsClientHelloInfo> {
    parse_client_hello_info(buf)
}

pub(crate) fn fuzz_client_hello_parser(buf: &[u8]) {
    let _ = required_client_hello_peek_bytes(buf);
    let _ = looks_like_tls_client_hello(buf);
    let _ = extract_client_hello_info(buf);
    let _ = extract_client_hello_info_from_handshake(buf);
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

fn parse_client_hello_info(buf: &[u8]) -> Option<TlsClientHelloInfo> {
    if buf.len() < 4 || buf.first()? != &1 {
        return None;
    }

    let hs_len = read_u24(buf, 1)?;
    let mut pos = 4usize;
    let hs_end = pos.checked_add(hs_len)?;
    if hs_end > buf.len() {
        return None;
    }

    let legacy_version = read_u16(buf, pos)?;
    pos = skip(buf, pos, 2)?; // legacy_version
    pos = skip(buf, pos, 32)?; // random

    let session_id_len = *buf.get(pos)? as usize;
    pos = skip(buf, pos + 1, session_id_len)?;

    let cipher_suites_len = read_u16(buf, pos)? as usize;
    let cipher_suites = parse_u16_list(buf, pos + 2, cipher_suites_len)?
        .into_iter()
        .filter(|value| !is_grease_value(*value))
        .collect::<Vec<_>>();
    pos = skip(buf, pos + 2, cipher_suites_len)?;

    let compression_len = *buf.get(pos)? as usize;
    pos = skip(buf, pos + 1, compression_len)?;

    let extensions_len = read_u16(buf, pos)? as usize;
    pos += 2;
    let ext_end = pos.checked_add(extensions_len)?;
    if ext_end > hs_end {
        return None;
    }

    let mut sni = None;
    let mut alpn = None;
    let mut supported_versions = Vec::new();
    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();

    while pos + 4 <= ext_end {
        let ext_type = read_u16(buf, pos)?;
        let ext_len = read_u16(buf, pos + 2)? as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            return None;
        }

        let ext = &buf[pos..pos + ext_len];
        if !is_grease_value(ext_type) {
            extensions.push(ext_type);
        }
        match ext_type {
            0 => {
                sni = parse_sni_extension(ext);
            }
            10 => {
                let groups_len = read_u16(ext, 0)? as usize;
                supported_groups = parse_u16_list(ext, 2, groups_len)?
                    .into_iter()
                    .filter(|value| !is_grease_value(*value))
                    .collect();
            }
            11 => {
                let points_len = *ext.first()? as usize;
                if points_len + 1 > ext.len() {
                    return None;
                }
                ec_point_formats = ext[1..1 + points_len]
                    .iter()
                    .map(|value| *value as u16)
                    .collect();
            }
            16 => {
                alpn = parse_alpn_extension(ext);
            }
            43 => {
                let versions_len = *ext.first()? as usize;
                if versions_len + 1 > ext.len() || !versions_len.is_multiple_of(2) {
                    return None;
                }
                supported_versions = parse_u16_list(ext, 1, versions_len)?
                    .into_iter()
                    .filter(|value| !is_grease_value(*value))
                    .collect();
            }
            _ => {}
        }
        pos += ext_len;
    }

    let negotiated_version = supported_versions
        .iter()
        .copied()
        .max()
        .unwrap_or(legacy_version);
    let ja3 = Some(format!(
        "{},{},{},{},{}",
        legacy_version,
        join_u16_list(&cipher_suites),
        join_u16_list(&extensions),
        join_u16_list(&supported_groups),
        join_u16_list(&ec_point_formats),
    ));

    Some(TlsClientHelloInfo {
        sni: sni.clone(),
        alpn: alpn.clone(),
        tls_version: tls_version_label(negotiated_version).map(str::to_string),
        ja3,
        ja4: Some(build_ja4_fingerprint(
            negotiated_version,
            sni.is_some(),
            alpn.as_deref(),
            cipher_suites.len(),
            extensions.len(),
            supported_groups.len(),
        )),
    })
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

fn parse_u16_list(buf: &[u8], start: usize, len: usize) -> Option<Vec<u16>> {
    if !len.is_multiple_of(2) {
        return None;
    }
    let end = start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let mut out = Vec::with_capacity(len / 2);
    let mut pos = start;
    while pos + 1 < end {
        out.push(read_u16(buf, pos)?);
        pos += 2;
    }
    Some(out)
}

fn parse_alpn_extension(ext: &[u8]) -> Option<String> {
    if ext.len() < 2 {
        return None;
    }
    let list_len = read_u16(ext, 0)? as usize;
    if list_len + 2 > ext.len() || list_len == 0 {
        return None;
    }
    let mut pos = 2usize;
    let end = 2 + list_len;
    let first_len = *ext.get(pos)? as usize;
    pos += 1;
    if pos + first_len > end {
        return None;
    }
    std::str::from_utf8(&ext[pos..pos + first_len])
        .ok()
        .map(|value| value.to_ascii_lowercase())
}

fn join_u16_list(values: &[u16]) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}

fn is_grease_value(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && ((value >> 8) as u8 == (value & 0xff) as u8)
}

fn tls_version_label(version: u16) -> Option<&'static str> {
    match version {
        0x0300 => Some("ssl3"),
        0x0301 => Some("tls1.0"),
        0x0302 => Some("tls1.1"),
        0x0303 => Some("tls1.2"),
        0x0304 => Some("tls1.3"),
        _ => None,
    }
}

fn build_ja4_fingerprint(
    version: u16,
    has_sni: bool,
    alpn: Option<&str>,
    cipher_count: usize,
    extension_count: usize,
    group_count: usize,
) -> String {
    let version_token = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni_token = if has_sni { 'd' } else { 'i' };
    let alpn_token = alpn
        .map(|value| {
            value
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .take(2)
                .collect::<String>()
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "00".to_string());
    format!(
        "t{version_token}{sni_token}{alpn_token}_{cipher_count:02}_{extension_count:02}_{group_count:02}"
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u24(out: &mut Vec<u8>, value: usize) {
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
    }

    fn push_extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
        push_u16(out, kind);
        push_u16(out, data.len() as u16);
        out.extend_from_slice(data);
    }

    fn build_client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        push_u16(&mut body, 0x0303);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);

        push_u16(&mut body, 6);
        push_u16(&mut body, 0x1301);
        push_u16(&mut body, 0x1302);
        push_u16(&mut body, 0x1303);

        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();

        let host = b"example.com";
        let mut sni = Vec::new();
        push_u16(&mut sni, (host.len() + 3) as u16);
        sni.push(0);
        push_u16(&mut sni, host.len() as u16);
        sni.extend_from_slice(host);
        push_extension(&mut extensions, 0, &sni);

        let mut groups = Vec::new();
        push_u16(&mut groups, 4);
        push_u16(&mut groups, 29);
        push_u16(&mut groups, 23);
        push_extension(&mut extensions, 10, &groups);

        let point_formats = [1u8, 0u8];
        push_extension(&mut extensions, 11, &point_formats);

        let alpn = b"h2";
        let mut alpn_ext = Vec::new();
        push_u16(&mut alpn_ext, (alpn.len() + 1) as u16);
        alpn_ext.push(alpn.len() as u8);
        alpn_ext.extend_from_slice(alpn);
        push_extension(&mut extensions, 16, &alpn_ext);

        let supported_versions = [4u8, 0x03, 0x04, 0x03, 0x03];
        push_extension(&mut extensions, 43, &supported_versions);

        push_u16(&mut body, extensions.len() as u16);
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        push_u24(&mut handshake, body.len());
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(22);
        push_u16(&mut record, 0x0301);
        push_u16(&mut record, handshake.len() as u16);
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extract_client_hello_info_parses_metadata() {
        let info = extract_client_hello_info(&build_client_hello()).expect("info");
        assert_eq!(info.sni.as_deref(), Some("example.com"));
        assert_eq!(info.alpn.as_deref(), Some("h2"));
        assert_eq!(info.tls_version.as_deref(), Some("tls1.3"));
        assert_eq!(
            info.ja3.as_deref(),
            Some("771,4865-4866-4867,0-10-11-16-43,29-23,0")
        );
        assert_eq!(info.ja4.as_deref(), Some("t13dh2_03_05_02"));
        assert_eq!(
            extract_sni(&build_client_hello()).as_deref(),
            Some("example.com")
        );
    }
}
