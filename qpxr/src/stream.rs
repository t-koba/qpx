use crate::TlsAcceptor;
use crate::hub::{ExporterHub, FollowBoundary, HistorySnapshot, SequencedBlock};
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

    // Subscribe before reading history: publications during the transfer
    // stay in the live buffer, and the snapshot boundary below drops the
    // overlap, so nothing falls between snapshot and subscription.
    let mut live_rx = if matches!(mode, StreamMode::Live | StreamMode::Follow) {
        Some(hub.live_tx.subscribe())
    } else {
        None
    };
    let mut follow_boundary: Option<FollowBoundary> = None;
    let mut pending_live = None;
    if matches!(mode, StreamMode::History | StreamMode::Follow) {
        let snapshot = hub.history_snapshot().await;
        let max_seq = snapshot.published_seq;
        let handoff_blocks = if matches!(mode, StreamMode::Follow) {
            let (queued, pending) = live_rx
                .as_mut()
                .map(|rx| drain_live_handoff(rx, Some(max_seq), || {}))
                .unwrap_or_default();
            pending_live = pending;
            follow_handoff_blocks(&snapshot, queued)
        } else {
            snapshot.blocks()
        };
        for bytes in &handoff_blocks {
            write_stream_block(&mut writer, bytes).await?;
        }
        if matches!(mode, StreamMode::Follow) {
            follow_boundary = Some(snapshot.into_boundary());
        }
    }
    if let Some(mut rx) = live_rx {
        loop {
            let block = if let Some(block) = pending_live.take() {
                block
            } else {
                match rx.recv().await {
                    Ok(block) => block,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            };
            let clear_boundary = match &follow_boundary {
                Some(boundary) if boundary.is_already_sent(block.seq) => continue,
                Some(boundary) if boundary.is_past(block.seq) => true,
                _ => false,
            };
            if clear_boundary {
                follow_boundary = None;
            }
            write_stream_block(&mut writer, &block.bytes).await?;
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

/// Drains the buffered live handoff without waiting for new publications.
fn drain_live_handoff(
    rx: &mut broadcast::Receiver<SequencedBlock>,
    max_seq: Option<u64>,
    mut before_recv: impl FnMut(),
) -> (Vec<SequencedBlock>, Option<SequencedBlock>) {
    use broadcast::error::TryRecvError;

    let mut queued = Vec::new();
    // One extra attempt lets the loop observe the first post-snapshot block
    // after the whole in-range sequence space has been consumed.
    let mut remaining = max_seq.map(|max| max.saturating_add(2)).unwrap_or(2);
    loop {
        before_recv();
        match rx.try_recv() {
            Ok(block) => {
                // Publications made after the history snapshot belong to the
                // live stream. Keep the first one so the caller can emit it
                // after the handoff instead of dropping it from the channel.
                if max_seq.is_some_and(|max| block.seq > max) {
                    return (queued, Some(block));
                }
                queued.push(block);
                remaining = remaining.saturating_sub(1);
                if remaining == 0 {
                    break;
                }
            }
            // Lagged advances the cursor to the oldest still-buffered block;
            // those survivors belong in the ordered initial handoff too. A
            // lag still consumes budget: a busy publisher must not keep the
            // handoff from reaching replay by making every receive lag.
            Err(TryRecvError::Lagged(_)) => {
                remaining = remaining.saturating_sub(1);
                if remaining == 0 {
                    break;
                }
            }
            Err(TryRecvError::Empty | TryRecvError::Closed) => break,
        }
    }
    (queued, None)
}

/// Builds the ordered first batch for FOLLOW: live blocks older than the
/// snapshot's first block, then history, then newer live blocks. Blocks that
/// are already in the history snapshot are dropped instead of duplicated.
fn follow_handoff_blocks(
    snapshot: &HistorySnapshot,
    queued: Vec<SequencedBlock>,
) -> Vec<bytes::Bytes> {
    let mut merged = Vec::with_capacity(snapshot.entries.len() + queued.len());
    merged.extend(snapshot.entries.iter().cloned());
    merged.extend(queued);
    merged.sort_by_key(|block| block.seq);
    merged.dedup_by_key(|block| block.seq);
    merged.into_iter().map(|block| block.bytes).collect()
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
    fn follow_handoff_drain_does_not_collect_new_publications() {
        let (tx, mut rx) = broadcast::channel::<SequencedBlock>(32);
        for seq in 0..3 {
            tx.send(SequencedBlock {
                seq,
                bytes: bytes::Bytes::from_static(b"initial"),
            })
            .expect("initial publication");
        }
        let published = std::sync::atomic::AtomicUsize::new(0);
        let publisher = tx.clone();
        let (queued, pending) = drain_live_handoff(&mut rx, Some(2), || {
            let offset = published.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if offset < 4 {
                publisher
                    .send(SequencedBlock {
                        seq: 3 + offset as u64,
                        bytes: bytes::Bytes::from_static(b"during handoff"),
                    })
                    .expect("publication during handoff");
            }
        });

        assert_eq!(
            queued.iter().map(|block| block.seq).collect::<Vec<_>>(),
            vec![0, 1, 2],
            "only the pre-existing live buffer belongs in the initial handoff"
        );
        assert_eq!(
            pending.map(|block| block.seq),
            Some(3),
            "the boundary-crossing publication must stay in the live stream"
        );
    }

    #[test]
    fn follow_handoff_lag_exhausts_the_snapshot_budget() {
        let (tx, mut rx) = broadcast::channel::<SequencedBlock>(2);
        let publisher = tx.clone();
        let calls = std::cell::Cell::new(0u64);

        let (queued, pending) = drain_live_handoff(&mut rx, Some(1), || {
            let call = calls.get() + 1;
            calls.set(call);
            if call <= 8 {
                for offset in 0..3 {
                    publisher
                        .send(SequencedBlock {
                            seq: 10 + (call - 1) * 3 + offset,
                            bytes: bytes::Bytes::from_static(b"during handoff"),
                        })
                        .expect("publication during handoff");
                }
            }
        });

        assert!(
            calls.get() <= 3,
            "repeated lag must exhaust the fixed handoff budget, got {} receives",
            calls.get()
        );
        assert!(queued.is_empty(), "no in-range block survived the lag");
        assert_eq!(pending.map(|block| block.seq), None);
    }

    #[test]
    fn follow_handoff_merges_unretained_pre_snapshot_blocks() {
        let (tx, mut rx) = broadcast::channel::<SequencedBlock>(16);
        for (seq, payload) in [(41, b"A"), (42, b"B"), (43, b"C")] {
            tx.send(SequencedBlock {
                seq,
                bytes: bytes::Bytes::from_static(payload),
            })
            .expect("publication");
        }
        let snapshot = HistorySnapshot {
            entries: Vec::new(),
            published_seq: 42,
        };

        let (queued, pending) = drain_live_handoff(&mut rx, Some(snapshot.published_seq), || {});
        assert_eq!(
            queued.iter().map(|block| block.seq).collect::<Vec<_>>(),
            vec![41, 42],
            "surviving pre-snapshot live blocks must be part of the handoff"
        );
        assert_eq!(pending.map(|block| block.seq), Some(43));
        assert_eq!(
            follow_handoff_blocks(&snapshot, queued),
            vec![
                bytes::Bytes::from_static(b"A"),
                bytes::Bytes::from_static(b"B")
            ]
        );

        let boundary = snapshot.into_boundary();
        assert!(!boundary.is_already_sent(41));
        assert!(!boundary.is_past(42));
        assert!(boundary.is_past(43));
    }

    #[test]
    fn follow_handoff_blocks_preserves_evicted_block_order() {
        let snapshot = HistorySnapshot {
            published_seq: 1,
            entries: vec![SequencedBlock {
                seq: 1,
                bytes: bytes::Bytes::from_static(b"B"),
            }],
        };
        let queued = vec![
            SequencedBlock {
                seq: 0,
                bytes: bytes::Bytes::from_static(b"A"),
            },
            SequencedBlock {
                seq: 1,
                bytes: bytes::Bytes::from_static(b"B"),
            },
        ];

        assert_eq!(
            follow_handoff_blocks(&snapshot, queued),
            vec![
                bytes::Bytes::from_static(b"A"),
                bytes::Bytes::from_static(b"B")
            ],
            "handoff must stay ordered by sequence"
        );
    }

    #[test]
    fn follow_handoff_blocks_keeps_queued_block_from_history_gap() {
        let snapshot = HistorySnapshot {
            published_seq: 2,
            entries: vec![
                SequencedBlock {
                    seq: 0,
                    bytes: bytes::Bytes::from_static(b"A"),
                },
                SequencedBlock {
                    seq: 2,
                    bytes: bytes::Bytes::from_static(b"C"),
                },
            ],
        };
        let queued = vec![
            SequencedBlock {
                seq: 0,
                bytes: bytes::Bytes::from_static(b"A"),
            },
            SequencedBlock {
                seq: 1,
                bytes: bytes::Bytes::from_static(b"B"),
            },
            SequencedBlock {
                seq: 2,
                bytes: bytes::Bytes::from_static(b"C"),
            },
        ];

        assert_eq!(
            follow_handoff_blocks(&snapshot, queued),
            vec![
                bytes::Bytes::from_static(b"A"),
                bytes::Bytes::from_static(b"B"),
                bytes::Bytes::from_static(b"C")
            ],
            "a gap in timestamp-filtered history must not suppress a queued live block"
        );
    }

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

    #[test]
    fn follow_handoff_keeps_surviving_live_blocks_after_broadcast_lag() {
        let (tx, mut rx) = broadcast::channel::<SequencedBlock>(2);
        // The receiver never reads until after the buffer has overflowed.
        for seq in 0..5u64 {
            tx.send(SequencedBlock {
                seq,
                bytes: bytes::Bytes::from(vec![seq as u8]),
            })
            .expect("live publication");
        }

        let snapshot = HistorySnapshot {
            published_seq: 4,
            entries: vec![0, 2, 3, 4]
                .into_iter()
                .map(|seq| SequencedBlock {
                    seq,
                    bytes: bytes::Bytes::from(vec![seq as u8]),
                })
                .collect(),
        };
        let (queued, pending) = drain_live_handoff(&mut rx, Some(4), || {});
        assert!(
            pending.is_none(),
            "lagged survivors are inside the snapshot"
        );
        let handoff = follow_handoff_blocks(&snapshot, queued);

        let seqs: Vec<u64> = handoff.iter().map(|bytes| bytes[0] as u64).collect();
        assert_eq!(
            seqs,
            vec![0, 2, 3, 4],
            "surviving live entries must merge with gapped history in publication order"
        );
    }
}
