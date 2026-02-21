use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Duration, Instant};
use tracing::error;

use crate::executor::{CgiRequest, CgiResponse, Execution, Executor};
use crate::fastcgi::{
    decode_name_values, encode_name_value, read_record, write_end_request, write_record,
    RequestLimits, FCGI_ABORT_REQUEST, FCGI_BEGIN_REQUEST, FCGI_GET_VALUES, FCGI_GET_VALUES_RESULT,
    FCGI_OVERLOADED, FCGI_PARAMS, FCGI_REQUEST_COMPLETE, FCGI_RESPONDER, FCGI_STDERR, FCGI_STDIN,
    FCGI_STDOUT, FCGI_UNKNOWN_ROLE, FCGI_UNKNOWN_TYPE,
};
use crate::router::Router;

const FCGI_KEEP_CONN: u8 = 1;

#[derive(Debug)]
enum WriterMsg {
    Record {
        record_type: u8,
        request_id: u16,
        content: Bytes,
    },
    EndRequest {
        request_id: u16,
        app_status: u32,
        protocol_status: u8,
    },
}

struct ReqState {
    last_activity: Instant,
    params_buf: BytesMut,
    params_done: bool,
    stdin_bytes: usize,
    stdin_tx: Option<mpsc::Sender<Bytes>>,
    stdin_rx: Option<mpsc::Receiver<Bytes>>,
    abort_notify: Option<oneshot::Sender<()>>,
    exec_task: Option<tokio::task::JoinHandle<()>>,
}

struct ConnState {
    close_when_idle: bool,
    states: HashMap<u16, ReqState>,
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_connection<S>(
    stream: S,
    router: Arc<Router>,
    semaphore: Arc<Semaphore>,
    limits: Arc<RequestLimits>,
    input_idle: Duration,
    conn_idle: Duration,
    max_conns: usize,
    max_reqs_per_conn: usize,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    // Larger buffer reduces syscalls for high record rates.
    let mut reader = BufReader::with_capacity(64 * 1024, reader);

    let (writer_tx, mut writer_rx) = mpsc::channel::<WriterMsg>(1024);
    // Buffer small writes (record headers, small chunks) to reduce syscalls.
    let mut writer = BufWriter::with_capacity(64 * 1024, writer);
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = writer_rx.recv().await {
            match msg {
                WriterMsg::Record {
                    record_type,
                    request_id,
                    content,
                } => {
                    write_record(&mut writer, record_type, request_id, &content).await?;
                }
                WriterMsg::EndRequest {
                    request_id,
                    app_status,
                    protocol_status,
                } => {
                    write_end_request(&mut writer, request_id, app_status, protocol_status).await?;
                    writer.flush().await?;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let (complete_tx, mut complete_rx) = mpsc::channel::<u16>(128);
    let mut conn = ConnState {
        close_when_idle: false,
        states: HashMap::new(),
    };
    let mut last_any_activity = Instant::now();

    loop {
        let next_deadline =
            compute_next_deadline(&conn.states, last_any_activity, input_idle, conn_idle);

        tokio::select! {
            rec = read_record(&mut reader) => {
                let rec = match rec {
                    Ok(r) => r,
                    Err(e) => {
                        if is_eof_error(&e) {
                            break;
                        }
                        return Err(e);
                    }
                };
                last_any_activity = Instant::now();
                if rec.header.request_id == 0 {
                    handle_management_record(&writer_tx, &rec, max_conns, max_reqs_per_conn).await?;
                    continue;
                }
                handle_request_record(
                    &router,
                    &semaphore,
                    limits.as_ref(),
                    &writer_tx,
                    &complete_tx,
                    max_reqs_per_conn,
                    &mut conn,
                    rec,
                ).await?;
                if conn.close_when_idle && conn.states.is_empty() {
                    break;
                }
            }
            Some(done_id) = complete_rx.recv() => {
                let _ = conn.states.remove(&done_id);
                if conn.close_when_idle && conn.states.is_empty() {
                    break;
                }
            }
            _ = tokio::time::sleep_until(next_deadline) => {
                if conn.close_when_idle && conn.states.is_empty() {
                    break;
                }
                // Idle connection timeout (no in-flight requests).
                if conn.states.is_empty() && Instant::now().duration_since(last_any_activity) >= conn_idle {
                    break;
                }
                // Per-request input idle timeouts.
                let timed_out: Vec<u16> = conn.states.iter()
                    .filter_map(|(id, st)| {
                        let expecting_input = !st.params_done || st.stdin_tx.is_some();
                        if expecting_input && Instant::now().duration_since(st.last_activity) >= input_idle {
                            Some(*id)
                        } else {
                            None
                        }
                    })
                    .collect();
                for id in timed_out {
                    if let Some(mut st) = conn.states.remove(&id) {
                        if let Some(abort) = st.abort_notify.take() {
                            let _ = abort.send(());
                        }
                        if let Some(mut task) = st.exec_task.take() {
                            // Give the execution a brief window to observe abort and shut down cleanly.
                            let _ = tokio::time::timeout(Duration::from_millis(200), &mut task).await;
                            if !task.is_finished() {
                                task.abort();
                            }
                            let _ = task.await;
                        }
                        // Best-effort timeout response.
                        let _ = send_cgi_output(&writer_tx, id, CgiResponse {
                            status: 408,
                            headers: vec![("Content-Type".into(), "text/plain".into())],
                            body: Bytes::from_static(b"request timeout"),
                        }.to_cgi_output()).await;
                        let _ = writer_tx.send(WriterMsg::Record{ record_type: FCGI_STDOUT, request_id: id, content: Bytes::new()}).await;
                        let _ = writer_tx.send(WriterMsg::EndRequest{ request_id: id, app_status: 0, protocol_status: FCGI_REQUEST_COMPLETE}).await;
                    }
                }
            }
        }
    }

    // Connection is closing: abort any in-flight executions to avoid orphaned work.
    let mut exec_tasks = Vec::new();
    for (_, mut st) in conn.states.drain() {
        if let Some(abort) = st.abort_notify.take() {
            let _ = abort.send(());
        }
        // Close stdin so executors can observe EOF quickly.
        st.stdin_tx.take();
        if let Some(task) = st.exec_task.take() {
            exec_tasks.push(task);
        }
    }
    // Allow tasks a brief window to propagate abort into the executor, then hard-abort any stragglers.
    tokio::time::sleep(Duration::from_secs(1)).await;
    for task in &exec_tasks {
        if !task.is_finished() {
            task.abort();
        }
    }
    for task in exec_tasks {
        let _ = task.await;
    }

    drop(writer_tx);
    let _ = writer_task.await;
    Ok(())
}

fn is_eof_error(e: &anyhow::Error) -> bool {
    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
        return io_err.kind() == std::io::ErrorKind::UnexpectedEof;
    }
    let msg = e.to_string();
    msg.contains("unexpected eof") || msg.contains("early eof")
}

fn compute_next_deadline(
    states: &HashMap<u16, ReqState>,
    last_any_activity: Instant,
    input_idle: Duration,
    conn_idle: Duration,
) -> Instant {
    if states.is_empty() {
        return last_any_activity + conn_idle;
    }
    let mut next = Instant::now() + Duration::from_secs(3600);
    for st in states.values() {
        let expecting_input = !st.params_done || st.stdin_tx.is_some();
        if expecting_input {
            let d = st.last_activity + input_idle;
            if d < next {
                next = d;
            }
        }
    }
    next
}

async fn handle_management_record(
    writer_tx: &mpsc::Sender<WriterMsg>,
    rec: &crate::fastcgi::Record,
    max_conns: usize,
    max_reqs_per_conn: usize,
) -> Result<()> {
    match rec.header.record_type {
        FCGI_GET_VALUES => {
            let req = decode_name_values(&rec.content)?;
            let mut out = BytesMut::new();
            for k in req.keys() {
                match k.as_str() {
                    "FCGI_MAX_CONNS" => {
                        encode_name_value(&mut out, k.as_bytes(), max_conns.to_string().as_bytes());
                    }
                    "FCGI_MAX_REQS" => {
                        encode_name_value(
                            &mut out,
                            k.as_bytes(),
                            max_reqs_per_conn.to_string().as_bytes(),
                        );
                    }
                    "FCGI_MPXS_CONNS" => {
                        let value = if max_reqs_per_conn > 1 { b"1" } else { b"0" };
                        encode_name_value(&mut out, k.as_bytes(), value);
                    }
                    _ => {}
                }
            }
            writer_tx
                .send(WriterMsg::Record {
                    record_type: FCGI_GET_VALUES_RESULT,
                    request_id: 0,
                    content: out.freeze(),
                })
                .await
                .map_err(|_| anyhow!("writer closed"))?;
        }
        other => {
            let mut body = [0u8; 8];
            body[0] = other;
            writer_tx
                .send(WriterMsg::Record {
                    record_type: FCGI_UNKNOWN_TYPE,
                    request_id: 0,
                    content: Bytes::copy_from_slice(&body),
                })
                .await
                .map_err(|_| anyhow!("writer closed"))?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_request_record(
    router: &Router,
    semaphore: &Arc<Semaphore>,
    limits: &RequestLimits,
    writer_tx: &mpsc::Sender<WriterMsg>,
    complete_tx: &mpsc::Sender<u16>,
    max_reqs_per_conn: usize,
    conn: &mut ConnState,
    rec: crate::fastcgi::Record,
) -> Result<()> {
    let request_id = rec.header.request_id;
    let now = Instant::now();

    match rec.header.record_type {
        FCGI_BEGIN_REQUEST => {
            if conn.states.contains_key(&request_id) {
                return Err(anyhow!(
                    "duplicate BEGIN_REQUEST for request_id {}",
                    request_id
                ));
            }
            if conn.states.len() >= max_reqs_per_conn {
                // Too many in-flight request IDs on this connection: fail-fast (no unbounded state).
                let _ = send_cgi_output(
                    writer_tx,
                    request_id,
                    CgiResponse {
                        status: 503,
                        headers: vec![("Content-Type".into(), "text/plain".into())],
                        body: Bytes::from_static(b"overloaded"),
                    }
                    .to_cgi_output(),
                )
                .await;
                let _ = writer_tx
                    .send(WriterMsg::Record {
                        record_type: FCGI_STDOUT,
                        request_id,
                        content: Bytes::new(),
                    })
                    .await;
                let _ = writer_tx
                    .send(WriterMsg::Record {
                        record_type: FCGI_STDERR,
                        request_id,
                        content: Bytes::new(),
                    })
                    .await;
                let _ = writer_tx
                    .send(WriterMsg::EndRequest {
                        request_id,
                        app_status: 0,
                        protocol_status: FCGI_OVERLOADED,
                    })
                    .await;
                return Ok(());
            }
            if rec.content.len() < 3 {
                return Err(anyhow!("BEGIN_REQUEST body too short"));
            }
            let role = u16::from_be_bytes([rec.content[0], rec.content[1]]);
            let flags = rec.content[2];
            if role != FCGI_RESPONDER {
                writer_tx
                    .send(WriterMsg::EndRequest {
                        request_id,
                        app_status: 0,
                        protocol_status: FCGI_UNKNOWN_ROLE,
                    })
                    .await
                    .map_err(|_| anyhow!("writer closed"))?;
                return Ok(());
            }

            let (stdin_tx, stdin_rx) = mpsc::channel::<Bytes>(16);
            if (flags & FCGI_KEEP_CONN) == 0 {
                conn.close_when_idle = true;
            }
            conn.states.insert(
                request_id,
                ReqState {
                    last_activity: now,
                    params_buf: BytesMut::new(),
                    params_done: false,
                    stdin_bytes: 0,
                    stdin_tx: Some(stdin_tx),
                    stdin_rx: Some(stdin_rx),
                    abort_notify: None,
                    exec_task: None,
                },
            );
        }
        FCGI_PARAMS => {
            if !rec.content.is_empty() {
                let Some(st) = conn.states.get_mut(&request_id) else {
                    return Ok(());
                };
                st.last_activity = now;
                if st.params_done {
                    return Err(anyhow!("unexpected PARAMS after terminator"));
                }
                if st.params_buf.len() + rec.content.len() > limits.max_params_bytes {
                    return Err(anyhow!("PARAMS exceeds size limit"));
                }
                st.params_buf.extend_from_slice(&rec.content);
                return Ok(());
            }

            let parsed = {
                let Some(st) = conn.states.get_mut(&request_id) else {
                    return Ok(());
                };
                st.last_activity = now;
                if st.params_done {
                    return Err(anyhow!("unexpected PARAMS after terminator"));
                }
                st.params_done = true;
                parse_cgi_params(st.params_buf.as_ref())?
            };

            let (executor, matched_prefix) =
                match router.route(&parsed.script_name, parsed.server_name.as_deref()) {
                    Some(v) => v,
                    None => {
                        send_cgi_output(
                            writer_tx,
                            request_id,
                            CgiResponse {
                                status: 404,
                                headers: vec![("Content-Type".into(), "text/plain".into())],
                                body: Bytes::from_static(b"no handler matched"),
                            }
                            .to_cgi_output(),
                        )
                        .await?;
                        writer_tx
                            .send(WriterMsg::Record {
                                record_type: FCGI_STDOUT,
                                request_id,
                                content: Bytes::new(),
                            })
                            .await
                            .map_err(|_| anyhow!("writer closed"))?;
                        writer_tx
                            .send(WriterMsg::EndRequest {
                                request_id,
                                app_status: 0,
                                protocol_status: FCGI_REQUEST_COMPLETE,
                            })
                            .await
                            .map_err(|_| anyhow!("writer closed"))?;
                        conn.states.remove(&request_id);
                        return Ok(());
                    }
                };

            let mut cgi_req = parsed.into_cgi_request();
            if let Some(prefix) = matched_prefix {
                cgi_req.matched_prefix = Some(prefix);
            }

            // Fail-fast if no worker slot is available (avoid unbounded queues).
            let permit = match Arc::clone(semaphore).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    send_cgi_output(
                        writer_tx,
                        request_id,
                        CgiResponse {
                            status: 503,
                            headers: vec![("Content-Type".into(), "text/plain".into())],
                            body: Bytes::from_static(b"overloaded"),
                        }
                        .to_cgi_output(),
                    )
                    .await
                    .ok();
                    writer_tx
                        .send(WriterMsg::Record {
                            record_type: FCGI_STDOUT,
                            request_id,
                            content: Bytes::new(),
                        })
                        .await
                        .ok();
                    writer_tx
                        .send(WriterMsg::Record {
                            record_type: FCGI_STDERR,
                            request_id,
                            content: Bytes::new(),
                        })
                        .await
                        .ok();
                    writer_tx
                        .send(WriterMsg::EndRequest {
                            request_id,
                            app_status: 0,
                            protocol_status: FCGI_OVERLOADED,
                        })
                        .await
                        .ok();
                    conn.states.remove(&request_id);
                    return Ok(());
                }
            };

            let (stdin_rx, abort_rx) = {
                let Some(st) = conn.states.get_mut(&request_id) else {
                    return Ok(());
                };
                let stdin_rx = st
                    .stdin_rx
                    .take()
                    .ok_or_else(|| anyhow!("stdin receiver missing"))?;
                let (abort_tx, abort_rx) = oneshot::channel::<()>();
                st.abort_notify = Some(abort_tx);
                (stdin_rx, abort_rx)
            };

            let writer_tx2 = writer_tx.clone();
            let complete_tx2 = complete_tx.clone();
            let task = tokio::spawn(async move {
                if let Err(e) = run_execution(
                    request_id, executor, cgi_req, stdin_rx, abort_rx, permit, writer_tx2,
                )
                .await
                {
                    error!(request_id = request_id, error = %e, "execution failed");
                }
                let _ = complete_tx2.send(request_id).await;
            });
            if let Some(st) = conn.states.get_mut(&request_id) {
                st.exec_task = Some(task);
            }
        }
        FCGI_STDIN => {
            let Some(st) = conn.states.get_mut(&request_id) else {
                return Ok(());
            };
            st.last_activity = now;
            if !st.params_done {
                return Err(anyhow!("STDIN before PARAMS terminator"));
            }
            if rec.content.is_empty() {
                st.stdin_tx = None; // close stdin channel
            } else {
                st.stdin_bytes = st.stdin_bytes.saturating_add(rec.content.len());
                if st.stdin_bytes > limits.max_stdin_bytes {
                    return Err(anyhow!("STDIN exceeds size limit"));
                }
                if let Some(tx) = st.stdin_tx.as_ref() {
                    let _ = tx.send(rec.content.clone()).await;
                }
            }
        }
        FCGI_ABORT_REQUEST => {
            if let Some(mut st) = conn.states.remove(&request_id) {
                if let Some(abort) = st.abort_notify.take() {
                    let _ = abort.send(());
                }
                if let Some(mut task) = st.exec_task.take() {
                    let _ = tokio::time::timeout(Duration::from_millis(200), &mut task).await;
                    if !task.is_finished() {
                        task.abort();
                    }
                    let _ = task.await;
                }
                writer_tx
                    .send(WriterMsg::EndRequest {
                        request_id,
                        app_status: 0,
                        protocol_status: FCGI_REQUEST_COMPLETE,
                    })
                    .await
                    .ok();
            }
        }
        _ => {}
    }
    Ok(())
}

struct ParsedCgiParams {
    script_name: String,
    path_info: String,
    query_string: String,
    request_method: String,
    content_type: String,
    content_length: usize,
    server_protocol: Option<String>,
    server_name: Option<String>,
    server_port: u16,
    remote_addr: Option<String>,
    remote_port: Option<u16>,
    http_headers: HashMap<String, String>,
}

impl ParsedCgiParams {
    fn into_cgi_request(self) -> CgiRequest {
        CgiRequest {
            matched_prefix: None,
            script_name: self.script_name,
            path_info: self.path_info,
            query_string: self.query_string,
            request_method: self.request_method,
            content_type: self.content_type,
            content_length: self.content_length,
            server_protocol: self
                .server_protocol
                .unwrap_or_else(|| "HTTP/1.1".to_string()),
            server_name: self.server_name.unwrap_or_else(|| "localhost".to_string()),
            server_port: self.server_port,
            remote_addr: self.remote_addr,
            remote_port: self.remote_port,
            http_headers: self.http_headers,
        }
    }
}

fn parse_cgi_params(data: &[u8]) -> Result<ParsedCgiParams> {
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

    fn parse_usize_ascii(data: &[u8]) -> Option<usize> {
        if data.is_empty() {
            return None;
        }
        let mut v: usize = 0;
        for &b in data {
            if !b.is_ascii_digit() {
                return None;
            }
            v = v.checked_mul(10)?.checked_add((b - b'0') as usize)?;
        }
        Some(v)
    }

    fn parse_u16_ascii(data: &[u8]) -> Option<u16> {
        parse_usize_ascii(data).and_then(|v| u16::try_from(v).ok())
    }

    fn http_suffix_to_header_name(suffix: &[u8]) -> String {
        let mut out = String::with_capacity(suffix.len());
        for &b in suffix {
            let b = match b {
                b'_' => b'-',
                b'A'..=b'Z' => b + 32,
                _ => b,
            };
            out.push(b as char);
        }
        out
    }

    let mut rest = data;
    let mut out = ParsedCgiParams {
        script_name: String::new(),
        path_info: String::new(),
        query_string: String::new(),
        request_method: "GET".to_string(),
        content_type: String::new(),
        content_length: 0,
        server_protocol: None,
        server_name: None,
        server_port: 80,
        remote_addr: None,
        remote_port: None,
        http_headers: HashMap::new(),
    };

    while !rest.is_empty() {
        let name_len = read_nv_len(&mut rest)?;
        let value_len = read_nv_len(&mut rest)?;
        if rest.len() < name_len + value_len {
            return Err(anyhow!("truncated name-value pair"));
        }
        let (name, rest2) = rest.split_at(name_len);
        let (value, rest3) = rest2.split_at(value_len);
        rest = rest3;

        if name == b"SCRIPT_NAME" {
            out.script_name = std::str::from_utf8(value)?.to_string();
        } else if name == b"PATH_INFO" {
            out.path_info = std::str::from_utf8(value)?.to_string();
        } else if name == b"QUERY_STRING" {
            out.query_string = std::str::from_utf8(value)?.to_string();
        } else if name == b"REQUEST_METHOD" {
            out.request_method = std::str::from_utf8(value)?.to_string();
        } else if name == b"CONTENT_TYPE" {
            out.content_type = std::str::from_utf8(value)?.to_string();
        } else if name == b"CONTENT_LENGTH" {
            out.content_length = parse_usize_ascii(value).unwrap_or(0);
        } else if name == b"SERVER_NAME" {
            out.server_name = Some(std::str::from_utf8(value)?.to_string());
        } else if name == b"SERVER_PROTOCOL" {
            out.server_protocol = Some(std::str::from_utf8(value)?.to_string());
        } else if name == b"SERVER_PORT" {
            out.server_port = parse_u16_ascii(value).unwrap_or(80);
        } else if name == b"REMOTE_ADDR" {
            out.remote_addr = Some(std::str::from_utf8(value)?.to_string());
        } else if name == b"REMOTE_PORT" {
            out.remote_port = parse_u16_ascii(value);
        } else if let Some(suffix) = name.strip_prefix(b"HTTP_") {
            let key = http_suffix_to_header_name(suffix);
            let val = std::str::from_utf8(value)?.to_string();
            if let Some(existing) = out.http_headers.get_mut(&key) {
                if !existing.is_empty() {
                    existing.push_str(", ");
                }
                existing.push_str(val.as_str());
            } else {
                out.http_headers.insert(key, val);
            }
        }
    }
    Ok(out)
}

async fn run_execution(
    request_id: u16,
    executor: Arc<dyn Executor>,
    req: CgiRequest,
    mut stdin_rx: mpsc::Receiver<Bytes>,
    mut abort_rx: oneshot::Receiver<()>,
    _permit: OwnedSemaphorePermit,
    writer_tx: mpsc::Sender<WriterMsg>,
) -> Result<()> {
    let exec = match executor.start(req).await {
        Ok(exec) => exec,
        Err(e) => {
            // If the executor fails to start, return a well-formed CGI error response
            // so the client doesn't hang waiting for headers.
            let out = CgiResponse {
                status: 502,
                headers: vec![("Content-Type".into(), "text/plain".into())],
                body: Bytes::from(format!("executor start error: {}", e)),
            }
            .to_cgi_output();
            send_cgi_output(&writer_tx, request_id, out).await.ok();
            writer_tx
                .send(WriterMsg::Record {
                    record_type: FCGI_STDOUT,
                    request_id,
                    content: Bytes::new(),
                })
                .await
                .ok();
            writer_tx
                .send(WriterMsg::Record {
                    record_type: FCGI_STDERR,
                    request_id,
                    content: Bytes::new(),
                })
                .await
                .ok();
            writer_tx
                .send(WriterMsg::EndRequest {
                    request_id,
                    app_status: 1,
                    protocol_status: FCGI_REQUEST_COMPLETE,
                })
                .await
                .ok();
            return Ok(());
        }
    };
    let Execution {
        stdin: exec_stdin,
        stdout: exec_stdout,
        stderr: exec_stderr,
        abort: exec_abort,
        done: exec_done,
    } = exec;

    // Forward inbound STDIN to executor stdin.
    let exec_stdin = exec_stdin;
    let stdin_task = tokio::spawn(async move {
        while let Some(chunk) = stdin_rx.recv().await {
            if exec_stdin.send(chunk).await.is_err() {
                break;
            }
        }
    });

    // Forward executor stdout/stderr to FastCGI.
    let stdout_sent = Arc::new(AtomicBool::new(false));
    let writer_tx_stdout = writer_tx.clone();
    let mut stdout_rx = exec_stdout;
    let stdout_sent_flag = Arc::clone(&stdout_sent);
    let stdout_task = tokio::spawn(async move {
        while let Some(chunk) = stdout_rx.recv().await {
            if !chunk.is_empty() {
                stdout_sent_flag.store(true, Ordering::Relaxed);
            }
            send_record_chunks(&writer_tx_stdout, FCGI_STDOUT, request_id, chunk)
                .await
                .ok();
        }
    });

    let writer_tx_stderr = writer_tx.clone();
    let mut stderr_rx = exec_stderr;
    let stderr_task = tokio::spawn(async move {
        while let Some(chunk) = stderr_rx.recv().await {
            send_record_chunks(&writer_tx_stderr, FCGI_STDERR, request_id, chunk)
                .await
                .ok();
        }
    });

    // Wait for completion or abort.
    let mut exec_abort = Some(exec_abort);
    let mut exec_done = exec_done;
    let done = tokio::select! {
        _ = &mut abort_rx => {
            if let Some(abort) = exec_abort.take() {
                let _ = abort.send(());
            }
            Err(anyhow!("request aborted"))
        }
        res = &mut exec_done => match res {
            Ok(r) => r,
            Err(e) => Err(anyhow!("executor task join failed: {}", e)),
        }
    };

    stdin_task.abort();
    let _ = stdin_task.await;
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    // If execution failed before producing any stdout, return a minimal CGI error response.
    if done.is_err() && !stdout_sent.load(Ordering::Relaxed) {
        let out = CgiResponse {
            status: 502,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: Bytes::from_static(b"executor error"),
        }
        .to_cgi_output();
        send_cgi_output(&writer_tx, request_id, out).await.ok();
    }
    // Terminate streams and end the request (always).
    writer_tx
        .send(WriterMsg::Record {
            record_type: FCGI_STDOUT,
            request_id,
            content: Bytes::new(),
        })
        .await
        .map_err(|_| anyhow!("writer closed"))?;
    writer_tx
        .send(WriterMsg::Record {
            record_type: FCGI_STDERR,
            request_id,
            content: Bytes::new(),
        })
        .await
        .map_err(|_| anyhow!("writer closed"))?;
    writer_tx
        .send(WriterMsg::EndRequest {
            request_id,
            app_status: if done.is_ok() { 0 } else { 1 },
            protocol_status: FCGI_REQUEST_COMPLETE,
        })
        .await
        .map_err(|_| anyhow!("writer closed"))?;
    Ok(())
}

async fn send_cgi_output(
    writer_tx: &mpsc::Sender<WriterMsg>,
    request_id: u16,
    out: Bytes,
) -> Result<()> {
    send_record_chunks(writer_tx, FCGI_STDOUT, request_id, out).await
}

async fn send_record_chunks(
    writer_tx: &mpsc::Sender<WriterMsg>,
    record_type: u8,
    request_id: u16,
    data: Bytes,
) -> Result<()> {
    let mut off = 0usize;
    while off < data.len() {
        let end = std::cmp::min(off + 65535, data.len());
        let chunk = data.slice(off..end);
        writer_tx
            .send(WriterMsg::Record {
                record_type,
                request_id,
                content: chunk,
            })
            .await
            .map_err(|_| anyhow!("writer closed"))?;
        off = end;
    }
    Ok(())
}
