use crate::TlsAcceptor;
use crate::hub::ExporterHub;
use anyhow::{Result, anyhow};
use cidr::IpCidr;
use qpx_core::exporter::STREAM_PREFACE_LINE;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast};
use tokio::time::timeout;
use tracing::warn;

const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    Live,
    History,
    Follow,
}

pub(crate) struct StreamAcceptContext {
    pub(crate) hub: ExporterHub,
    pub(crate) allow: Vec<IpCidr>,
    pub(crate) token: Option<String>,
    pub(crate) tls: Option<TlsAcceptor>,
    pub(crate) tls_accept_timeout: Duration,
    pub(crate) max_control_line_bytes: usize,
    pub(crate) handshake_timeout: Duration,
    pub(crate) connections: Arc<Semaphore>,
}

pub(crate) async fn run_stream_accept_loop(
    listener: TcpListener,
    ctx: StreamAcceptContext,
) -> Result<()> {
    let StreamAcceptContext {
        hub,
        allow,
        token,
        tls,
        tls_accept_timeout,
        max_control_line_bytes,
        handshake_timeout,
        connections,
    } = ctx;
    #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
    let _ = tls_accept_timeout;
    loop {
        let permit = connections.clone().acquire_owned().await?;
        let (stream, peer) = listener.accept().await?;
        if !ip_allowed(peer.ip(), &allow) {
            continue;
        }
        let hub = hub.clone();
        let token = token.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let res = match tls {
                Some(acceptor) => {
                    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
                    {
                        match timeout(tls_accept_timeout, acceptor.accept(stream)).await {
                            Ok(Ok(tls_stream)) => {
                                handle_stream_client(
                                    tls_stream,
                                    hub,
                                    token,
                                    max_control_line_bytes,
                                    handshake_timeout,
                                )
                                .await
                            }
                            Ok(Err(err)) => Err(anyhow!("tls accept failed: {err}")),
                            Err(_) => Err(anyhow!("tls accept timed out")),
                        }
                    }
                    #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
                    {
                        let _ = acceptor;
                        drop(stream);
                        Err(anyhow!("TLS is not supported in this build"))
                    }
                }
                None => {
                    handle_stream_client(
                        stream,
                        hub,
                        token,
                        max_control_line_bytes,
                        handshake_timeout,
                    )
                    .await
                }
            };
            if let Err(err) = res {
                warn!(error = ?err, peer = %peer, "stream client disconnected");
            }
        });
    }
}

async fn handle_stream_client<S>(
    stream: S,
    hub: ExporterHub,
    token: Option<String>,
    max_control_line_bytes: usize,
    handshake_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let Some(preface) =
        read_line_limited_with_timeout(&mut reader, max_control_line_bytes, handshake_timeout)
            .await?
    else {
        return Ok(());
    };
    if preface != STREAM_PREFACE_LINE.as_bytes() {
        return Err(anyhow!("invalid stream preface"));
    }

    let mut next =
        read_line_limited_with_timeout(&mut reader, max_control_line_bytes, handshake_timeout)
            .await?;
    if let Some(line) = next.as_ref().and_then(|l| parse_auth_line(l)) {
        if let Some(expected) = token.as_deref() {
            if !constant_time_eq(line, expected) {
                return Err(anyhow!("invalid token"));
            }
        } else {
            // AUTH provided but not required: accept.
        }
        next =
            read_line_limited_with_timeout(&mut reader, max_control_line_bytes, handshake_timeout)
                .await?;
    } else if token.is_some() {
        return Err(anyhow!("missing AUTH line"));
    }

    let mode = parse_mode(next.ok_or_else(|| anyhow!("missing MODE line"))?.as_slice())?;

    // Always start the stream with a valid section header + interfaces.
    write_stream_block(&mut writer, &hub.pcap_preface).await?;

    if matches!(mode, StreamMode::History | StreamMode::Follow) {
        for block in hub.history_snapshot().await {
            write_stream_block(&mut writer, &block).await?;
        }
    }
    if matches!(mode, StreamMode::Live | StreamMode::Follow) {
        let mut rx = hub.live_tx.subscribe();
        loop {
            match rx.recv().await {
                Ok(block) => write_stream_block(&mut writer, &block).await?,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
    Ok(())
}

async fn write_stream_block<W>(writer: &mut W, block: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(STREAM_WRITE_TIMEOUT, writer.write_all(block))
        .await
        .map_err(|_| anyhow!("qpxr stream client write timed out"))??;
    Ok(())
}

async fn read_line_limited<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            if out.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if out.len() + take > max_bytes {
                return Err(anyhow!("line too long"));
            }
            out.extend_from_slice(&buf[..take]);
            reader.consume(take);
            break;
        }
        if out.len() + buf.len() > max_bytes {
            return Err(anyhow!("line too long"));
        }
        out.extend_from_slice(buf);
        let len = buf.len();
        reader.consume(len);
    }

    if out.ends_with(b"\n") {
        out.pop();
    }
    if out.ends_with(b"\r") {
        out.pop();
    }
    Ok(Some(out))
}

async fn read_line_limited_with_timeout<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
    timeout_dur: Duration,
) -> Result<Option<Vec<u8>>> {
    timeout(timeout_dur, read_line_limited(reader, max_bytes))
        .await
        .map_err(|_| anyhow!("read timed out"))?
}

fn parse_auth_line(line: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(line).ok()?;
    let text = text.trim();
    let rest = text.strip_prefix("AUTH ")?;
    Some(rest.trim())
}

fn parse_mode(line: &[u8]) -> Result<StreamMode> {
    let text = std::str::from_utf8(line).map_err(|_| anyhow!("MODE line is not utf-8"))?;
    let trimmed = text.trim();
    let body = trimmed.strip_prefix("MODE ").unwrap_or(trimmed);
    let normalized = body.trim().to_ascii_uppercase();
    Ok(match normalized.as_str() {
        "HISTORY" => StreamMode::History,
        "FOLLOW" => StreamMode::Follow,
        "LIVE" => StreamMode::Live,
        other => return Err(anyhow!("unknown mode: {}", other)),
    })
}

/// Constant-time token comparison. Both inputs are reduced to fixed-length
/// digests first so token length does not create a separate timing branch.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_digest = Sha256::digest(a.as_bytes());
    let b_digest = Sha256::digest(b.as_bytes());
    a_digest
        .iter()
        .zip(b_digest.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn ip_allowed(peer: IpAddr, allow: &[IpCidr]) -> bool {
    if allow.is_empty() {
        return true;
    }
    allow.iter().any(|cidr| cidr.contains(&peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_accepts_follow() {
        assert!(matches!(
            parse_mode(b"MODE FOLLOW").unwrap(),
            StreamMode::Follow
        ));
    }

    #[test]
    fn parse_mode_accepts_history() {
        assert!(matches!(
            parse_mode(b"MODE HISTORY").unwrap(),
            StreamMode::History
        ));
    }

    #[test]
    fn parse_mode_accepts_live() {
        assert!(matches!(
            parse_mode(b"MODE LIVE").unwrap(),
            StreamMode::Live
        ));
    }

    #[test]
    fn parse_mode_case_insensitive() {
        assert!(matches!(
            parse_mode(b"MODE follow").unwrap(),
            StreamMode::Follow
        ));
        assert!(matches!(
            parse_mode(b"MODE Live").unwrap(),
            StreamMode::Live
        ));
    }

    #[test]
    fn parse_mode_without_prefix() {
        assert!(matches!(parse_mode(b"FOLLOW").unwrap(), StreamMode::Follow));
    }

    #[test]
    fn parse_mode_rejects_unknown() {
        assert!(parse_mode(b"MODE INVALID").is_err());
    }

    #[test]
    fn parse_mode_trims_whitespace() {
        assert!(matches!(
            parse_mode(b"  MODE FOLLOW  ").unwrap(),
            StreamMode::Follow
        ));
    }

    #[test]
    fn constant_time_eq_matches_equal_strings() {
        assert!(constant_time_eq("secret", "secret"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn constant_time_eq_rejects_different_strings() {
        assert!(!constant_time_eq("secret", "Secret"));
        assert!(!constant_time_eq("abc", "abx"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq("short", "longer"));
        assert!(!constant_time_eq("a", ""));
    }
}
