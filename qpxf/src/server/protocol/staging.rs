use super::*;
use tokio::fs::File;
use tokio::io::AsyncSeekExt;
use tokio::sync::mpsc;

pub(super) struct PreparedResponse {
    pub(super) meta: IpcResponseMeta,
    staged: Option<File>,
    staged_bytes: usize,
    pub(super) body_leftover: Bytes,
}

impl PreparedResponse {
    pub(super) async fn next_staged_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.staged_bytes != 0 {
            let file = self
                .staged
                .as_mut()
                .ok_or_else(|| anyhow!("missing CGI staging file"))?;
            let len = usize::try_from(file.read_u64_le().await?)?;
            if len == 0 || len > self.staged_bytes {
                return Err(anyhow!("invalid CGI staging chunk length"));
            }
            let mut buf = vec![0; len];
            file.read_exact(&mut buf).await?;
            self.staged_bytes -= len;
            return Ok(Some(Bytes::from(buf)));
        }
        self.staged = None;
        Ok(None)
    }
}

/// Keep headers uncommitted until request validation completes, without letting
/// bounded executor stdout queues stop the CGI from consuming stdin. Body bytes
/// are spooled to an anonymous file, capped by the backend's configured stdout
/// limit (not by request size), plus eight framing bytes per nonempty chunk.
/// Framing preserves executor chunk sizes, including for small SHM rings. File
/// size is thus at most nine times the stdout limit even for one-byte chunks.
/// Memory stays bounded to the header and one chunk; the anonymous file is
/// removed automatically on success, rejection, or cancellation.
/// The caller drains stderr independently throughout preparation and replay.
pub(super) async fn prepare_response(
    stdout: &mut mpsc::Receiver<Bytes>,
    mut stdin_result: oneshot::Receiver<StdinReadOutcome>,
    max_stdout_bytes: usize,
    invalid_headers_body: &'static [u8],
) -> std::result::Result<PreparedResponse, IpcPlainResponse> {
    let mut header_buf = BytesMut::new();
    let mut parsed: Option<ParsedCgiOutputHead> = None;
    let mut invalid_headers = false;
    let mut stdout_open = true;
    let mut stdin_complete = false;
    let mut staged: Option<File> = None;
    let mut staged_bytes = 0usize;
    loop {
        if stdin_complete && (parsed.is_some() || invalid_headers || !stdout_open) {
            let Some(parsed) = parsed else {
                return Err(IpcPlainResponse::new(502, invalid_headers_body));
            };
            if let Some(file) = &mut staged
                && file.rewind().await.is_err()
            {
                return Err(staging_error());
            }
            return Ok(PreparedResponse {
                meta: parsed.meta,
                staged,
                staged_bytes,
                body_leftover: parsed.body_leftover,
            });
        }
        tokio::select! {
            // Prefer a completed validation over staging more output.
            biased;
            outcome = &mut stdin_result, if !stdin_complete => {
                if let Ok(outcome) = outcome
                    && let Some((status, body)) = outcome.error_response()
                {
                    return Err(IpcPlainResponse::new(status, body));
                }
                stdin_complete = true;
            }
            chunk = stdout.recv(), if stdout_open => {
                let Some(chunk) = chunk else {
                    stdout_open = false;
                    continue;
                };
                if invalid_headers { continue; }
                let body = if parsed.is_none() {
                    match consume_cgi_stdout_header(&mut header_buf, chunk) {
                        Ok(Some(head)) => {
                            let mut head = head;
                            // If stdin is valid already, return the leftover without spooling.
                            let body = if stdin_complete {
                                Bytes::new()
                            } else {
                                std::mem::take(&mut head.body_leftover)
                            };
                            parsed = Some(head);
                            body
                        }
                        Ok(None) => continue,
                        Err(_) => {
                            // Still drain stdout so input validation cannot deadlock.
                            invalid_headers = true;
                            continue;
                        }
                    }
                } else {
                    chunk
                };
                if body.is_empty() { continue; }
                let Some(total) = staged_bytes.checked_add(body.len()) else {
                    return Err(staging_error());
                };
                if total > max_stdout_bytes {
                    return Err(staging_error());
                }
                staged_bytes = total;
                if staged.is_none() {
                    let file = tokio::task::spawn_blocking(tempfile::tempfile).await;
                    staged = Some(File::from_std(match file {
                        Ok(Ok(file)) => file,
                        _ => return Err(staging_error()),
                    }));
                }
                let file = staged.as_mut().ok_or_else(staging_error)?;
                if file.write_u64_le(body.len() as u64).await.is_err()
                    || file.write_all(&body).await.is_err()
                {
                    return Err(staging_error());
                }
            }
        }
    }
}

fn staging_error() -> IpcPlainResponse {
    warn!("CGI pre-commit output staging failed or exceeded backend stdout limit");
    IpcPlainResponse::new(502, b"bad gateway (CGI output staging failed)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn validated_input_keeps_small_leftover_without_creating_a_spool() {
        let (stdout_tx, mut stdout_rx) = mpsc::channel(1);
        let (stdin_tx, stdin_rx) = oneshot::channel();
        stdin_tx.send(StdinReadOutcome::Complete).unwrap();
        stdout_tx
            .send(Bytes::from_static(b"Status: 200\r\n\r\nready"))
            .await
            .unwrap();
        let mut prepared = prepare_response(&mut stdout_rx, stdin_rx, 5, b"invalid")
            .await
            .ok()
            .expect("prepare response");
        assert!(prepared.staged.is_none());
        assert!(prepared.next_staged_chunk().await.unwrap().is_none());
        assert_eq!(prepared.body_leftover, b"ready"[..]);
    }

    #[tokio::test]
    async fn stages_bounded_output_until_validation_then_replays_in_order() {
        let (stdout_tx, mut stdout_rx) = mpsc::channel(1);
        let (stdin_tx, stdin_rx) = oneshot::channel();
        let producer = tokio::spawn(async move {
            stdout_tx
                .send(Bytes::from_static(b"Status: 202\r\n\r\nfirst"))
                .await
                .unwrap();
            stdout_tx.send(Bytes::from_static(b"second")).await.unwrap();
            stdout_tx.send(Bytes::from_static(b"third")).await.unwrap();
            // Sending beyond channel capacity must finish before input validates.
            stdin_tx.send(StdinReadOutcome::Complete).unwrap();
        });
        let mut prepared = prepare_response(&mut stdout_rx, stdin_rx, 16, b"invalid")
            .await
            .ok()
            .expect("prepare response");
        assert_eq!(prepared.meta.status, 202);
        let mut body = Vec::new();
        while let Some(chunk) = prepared.next_staged_chunk().await.unwrap() {
            assert!(chunk.len() <= 6, "replay must not merge executor chunks");
            body.extend_from_slice(&chunk);
        }
        while let Some(chunk) = stdout_rx.recv().await {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"firstsecondthird");
        producer.await.unwrap();
    }

    #[tokio::test]
    async fn staging_limit_fails_before_commit() {
        let (stdout_tx, mut stdout_rx) = mpsc::channel(1);
        let (_stdin_tx, stdin_rx) = oneshot::channel();
        stdout_tx
            .send(Bytes::from_static(b"Status: 200\r\n\r\n1234"))
            .await
            .unwrap();
        let response = prepare_response(&mut stdout_rx, stdin_rx, 3, b"invalid")
            .await
            .err()
            .expect("staging must not exceed backend limit");
        assert_eq!(response.status, 502);
        assert_eq!(response.body, b"bad gateway (CGI output staging failed)");
    }

    #[tokio::test]
    async fn invalid_headers_still_drain_stdout_until_input_is_validated() {
        let (stdout_tx, mut stdout_rx) = mpsc::channel(1);
        let (stdin_tx, stdin_rx) = oneshot::channel();
        let producer = tokio::spawn(async move {
            stdout_tx
                .send(Bytes::from_static(b"invalid header\r\n\r\n"))
                .await
                .unwrap();
            for _ in 0..32 {
                stdout_tx
                    .send(Bytes::from_static(b"discard"))
                    .await
                    .unwrap();
            }
            stdin_tx.send(StdinReadOutcome::Truncated).unwrap();
        });
        let response = timeout(
            Duration::from_secs(2),
            prepare_response(&mut stdout_rx, stdin_rx, 8, b"invalid"),
        )
        .await
        .expect("output must not block validation")
        .err()
        .expect("input must be rejected");
        assert_eq!(response.status, 400);
        assert_eq!(response.body, b"request body truncated");
        producer.await.unwrap();
    }
}
