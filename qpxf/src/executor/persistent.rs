use super::{CgiRequest, Execution, Executor};
use crate::config::{FastCgiBackendConfig, ScgiBackendConfig};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};
use tokio::time::{Duration, timeout};

const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_ABORT_REQUEST: u8 = 2;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_RESPONDER: u16 = 1;

trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedIo = Pin<Box<dyn AsyncIo>>;

pub struct FastCgiExecutor {
    timeout: Duration,
    pool: Arc<FastCgiConnectionPool>,
    max_stdin_bytes: usize,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

impl FastCgiExecutor {
    pub fn new(config: &FastCgiBackendConfig) -> Result<Self> {
        Ok(Self {
            timeout: Duration::from_millis(config.timeout_ms),
            pool: Arc::new(FastCgiConnectionPool::new(
                config.address.clone(),
                config.pool.max_concurrency,
                config.pool.max_idle,
            )?),
            max_stdin_bytes: config.max_stdin_bytes,
            max_stdout_bytes: config.max_stdout_bytes,
            max_stderr_bytes: config.max_stderr_bytes,
        })
    }
}

#[async_trait]
impl Executor for FastCgiExecutor {
    async fn start(&self, req: CgiRequest) -> Result<Execution> {
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Bytes>(16);
        let (stdout_tx, stdout_rx) = mpsc::channel::<Bytes>(16);
        let (stderr_tx, stderr_rx) = mpsc::channel::<Bytes>(16);
        let (abort_tx, mut abort_rx) = oneshot::channel::<()>();

        let timeout_dur = self.timeout;
        let pool = self.pool.clone();
        let max_stdin = self.max_stdin_bytes;
        let max_stdout = self.max_stdout_bytes;
        let max_stderr = self.max_stderr_bytes;

        let done = tokio::spawn(async move {
            let body = tokio::select! {
                body = collect_stdin(&mut stdin_rx, max_stdin) => body?,
                _ = &mut abort_rx => return Ok(()),
            };
            let env = build_gateway_env(&req, body.len());
            let future = pool.execute(env, body, max_stdout, max_stderr);
            let (stdout, stderr) = timeout(timeout_dur, future)
                .await
                .context("fastcgi backend request timed out")??;
            if !stderr.is_empty() {
                let _ = stderr_tx.send(stderr).await;
            }
            if !stdout.is_empty() {
                let _ = stdout_tx.send(stdout).await;
            }
            Ok(())
        });

        Ok(Execution {
            stdin: stdin_tx,
            stdout: stdout_rx,
            stderr: stderr_rx,
            abort: abort_tx,
            done,
        })
    }
}

struct FastCgiConnectionPool {
    address: String,
    idle: Mutex<Vec<BoxedIo>>,
    semaphore: Arc<Semaphore>,
    max_idle: usize,
}

impl FastCgiConnectionPool {
    fn new(address: String, max_concurrency: usize, max_idle: usize) -> Result<Self> {
        if address.trim().is_empty() {
            return Err(anyhow!("fastcgi backend address must not be empty"));
        }
        Ok(Self {
            address,
            idle: Mutex::new(Vec::new()),
            semaphore: Arc::new(Semaphore::new(max_concurrency)),
            max_idle,
        })
    }

    async fn execute(
        &self,
        env: Vec<(String, String)>,
        body: Bytes,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<(Bytes, Bytes)> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| anyhow!("fastcgi backend semaphore closed"))?;
        let mut stream = self.take().await?;
        let result =
            run_fastcgi_on_stream(&mut stream, env, body, max_stdout_bytes, max_stderr_bytes).await;
        if result.is_ok() {
            self.put(stream).await;
        }
        result
    }

    async fn take(&self) -> Result<BoxedIo> {
        if let Some(stream) = self.idle.lock().await.pop() {
            return Ok(stream);
        }
        connect_backend(self.address.as_str()).await
    }

    async fn put(&self, stream: BoxedIo) {
        let mut idle = self.idle.lock().await;
        if idle.len() < self.max_idle {
            idle.push(stream);
        }
    }
}

pub struct ScgiExecutor {
    inner: PersistentExecutor,
}

impl ScgiExecutor {
    pub fn new(config: &ScgiBackendConfig) -> Result<Self> {
        Ok(Self {
            inner: PersistentExecutor::new(
                config.address.clone(),
                config.timeout_ms,
                config.max_concurrency,
                config.max_stdin_bytes,
                config.max_stdout_bytes,
                config.max_stderr_bytes,
            )?,
        })
    }
}

#[async_trait]
impl Executor for ScgiExecutor {
    async fn start(&self, req: CgiRequest) -> Result<Execution> {
        self.inner.start(req).await
    }
}

struct PersistentExecutor {
    address: String,
    timeout: Duration,
    semaphore: Arc<Semaphore>,
    max_stdin_bytes: usize,
    max_stdout_bytes: usize,
}

impl PersistentExecutor {
    fn new(
        address: String,
        timeout_ms: u64,
        max_concurrency: usize,
        max_stdin_bytes: usize,
        max_stdout_bytes: usize,
        _max_stderr_bytes: usize,
    ) -> Result<Self> {
        if address.trim().is_empty() {
            return Err(anyhow!("persistent backend address must not be empty"));
        }
        Ok(Self {
            address,
            timeout: Duration::from_millis(timeout_ms),
            semaphore: Arc::new(Semaphore::new(max_concurrency)),
            max_stdin_bytes,
            max_stdout_bytes,
        })
    }

    async fn start(&self, req: CgiRequest) -> Result<Execution> {
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Bytes>(16);
        let (stdout_tx, stdout_rx) = mpsc::channel::<Bytes>(16);
        let (stderr_tx, stderr_rx) = mpsc::channel::<Bytes>(16);
        let (abort_tx, mut abort_rx) = oneshot::channel::<()>();

        let address = self.address.clone();
        let timeout_dur = self.timeout;
        let semaphore = self.semaphore.clone();
        let max_stdin = self.max_stdin_bytes;
        let max_stdout = self.max_stdout_bytes;
        let done = tokio::spawn(async move {
            let permit = semaphore
                .acquire_owned()
                .await
                .map_err(|_| anyhow!("persistent backend semaphore closed"))?;
            let _permit = permit;
            let body = tokio::select! {
                body = collect_stdin(&mut stdin_rx, max_stdin) => body?,
                _ = &mut abort_rx => return Ok(()),
            };
            let env = build_gateway_env(&req, body.len());
            let future = run_scgi(address.as_str(), env, body, max_stdout);
            let (stdout, stderr) = timeout(timeout_dur, future)
                .await
                .context("persistent backend request timed out")??;
            if !stderr.is_empty() {
                let _ = stderr_tx.send(stderr).await;
            }
            if !stdout.is_empty() {
                let _ = stdout_tx.send(stdout).await;
            }
            Ok(())
        });

        Ok(Execution {
            stdin: stdin_tx,
            stdout: stdout_rx,
            stderr: stderr_rx,
            abort: abort_tx,
            done,
        })
    }
}

async fn collect_stdin(rx: &mut mpsc::Receiver<Bytes>, limit: usize) -> Result<Bytes> {
    let mut out = BytesMut::new();
    while let Some(chunk) = rx.recv().await {
        if out.len().saturating_add(chunk.len()) > limit {
            return Err(anyhow!("persistent backend stdin exceeds configured limit"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

async fn connect_backend(address: &str) -> Result<BoxedIo> {
    if let Some(path) = address.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            let stream = UnixStream::connect(path)
                .await
                .with_context(|| format!("failed to connect unix backend {path}"))?;
            Ok(Box::pin(stream))
        }
        #[cfg(not(unix))]
        {
            Err(anyhow!(
                "unix backend addresses are not supported on this platform: {path}"
            ))
        }
    } else {
        let stream = TcpStream::connect(address)
            .await
            .with_context(|| format!("failed to connect tcp backend {address}"))?;
        Ok(Box::pin(stream))
    }
}

async fn run_scgi(
    address: &str,
    env: Vec<(String, String)>,
    body: Bytes,
    max_stdout_bytes: usize,
) -> Result<(Bytes, Bytes)> {
    let mut stream = connect_backend(address).await?;
    let mut headers = BytesMut::new();
    for (name, value) in env {
        headers.extend_from_slice(name.as_bytes());
        headers.extend_from_slice(b"\0");
        headers.extend_from_slice(value.as_bytes());
        headers.extend_from_slice(b"\0");
    }
    let prefix = format!("{}:", headers.len());
    stream.write_all(prefix.as_bytes()).await?;
    stream.write_all(&headers).await?;
    stream.write_all(b",").await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    let stdout = read_limited(&mut stream, max_stdout_bytes).await?;
    Ok((stdout, Bytes::new()))
}

async fn run_fastcgi_on_stream(
    stream: &mut BoxedIo,
    env: Vec<(String, String)>,
    body: Bytes,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
) -> Result<(Bytes, Bytes)> {
    write_fastcgi_begin(stream).await?;
    let params = encode_fastcgi_params(env)?;
    for chunk in params.chunks(u16::MAX as usize) {
        write_fastcgi_record(stream, FCGI_PARAMS, chunk).await?;
    }
    write_fastcgi_record(stream, FCGI_PARAMS, &[]).await?;
    for chunk in body.chunks(u16::MAX as usize) {
        write_fastcgi_record(stream, FCGI_STDIN, chunk).await?;
    }
    write_fastcgi_record(stream, FCGI_STDIN, &[]).await?;

    let mut stdout = BytesMut::new();
    let mut stderr = BytesMut::new();
    loop {
        let Some((record_type, content)) = read_fastcgi_record(stream).await? else {
            return Err(anyhow!(
                "fastcgi backend closed connection before end request"
            ));
        };
        match record_type {
            FCGI_STDOUT => append_limited(&mut stdout, &content, max_stdout_bytes, "stdout")?,
            FCGI_STDERR => append_limited(&mut stderr, &content, max_stderr_bytes, "stderr")?,
            FCGI_END_REQUEST => break,
            FCGI_ABORT_REQUEST => return Err(anyhow!("fastcgi backend aborted request")),
            _ => {}
        }
    }
    Ok((stdout.freeze(), stderr.freeze()))
}

async fn write_fastcgi_begin(stream: &mut BoxedIo) -> Result<()> {
    let mut content = [0u8; 8];
    content[0..2].copy_from_slice(&FCGI_RESPONDER.to_be_bytes());
    content[2] = 1;
    write_fastcgi_record(stream, FCGI_BEGIN_REQUEST, &content).await
}

async fn write_fastcgi_record(stream: &mut BoxedIo, record_type: u8, content: &[u8]) -> Result<()> {
    let content_len = u16::try_from(content.len()).context("fastcgi record too large")?;
    let padding_len = (8 - (content.len() % 8)) % 8;
    let header = [
        1,
        record_type,
        0,
        1,
        (content_len >> 8) as u8,
        content_len as u8,
        padding_len as u8,
        0,
    ];
    stream.write_all(&header).await?;
    stream.write_all(content).await?;
    if padding_len > 0 {
        stream.write_all(&[0u8; 8][..padding_len]).await?;
    }
    Ok(())
}

async fn read_fastcgi_record(stream: &mut BoxedIo) -> Result<Option<(u8, Bytes)>> {
    let mut header = [0u8; 8];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let record_type = header[1];
    let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let padding_len = header[6] as usize;
    let mut content = vec![0u8; content_len];
    stream.read_exact(&mut content).await?;
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        stream.read_exact(&mut padding).await?;
    }
    Ok(Some((record_type, Bytes::from(content))))
}

fn encode_fastcgi_params(env: Vec<(String, String)>) -> Result<Bytes> {
    let mut out = BytesMut::new();
    for (name, value) in env {
        encode_fastcgi_len(&mut out, name.len())?;
        encode_fastcgi_len(&mut out, value.len())?;
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    Ok(out.freeze())
}

fn encode_fastcgi_len(out: &mut BytesMut, len: usize) -> Result<()> {
    if len < 128 {
        out.extend_from_slice(&[len as u8]);
    } else {
        let len = u32::try_from(len).context("fastcgi param too large")? | 0x8000_0000;
        out.extend_from_slice(&len.to_be_bytes());
    }
    Ok(())
}

async fn read_limited(stream: &mut BoxedIo, limit: usize) -> Result<Bytes> {
    let mut out = BytesMut::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        append_limited(&mut out, &buf[..read], limit, "stdout")?;
    }
    Ok(out.freeze())
}

fn append_limited(out: &mut BytesMut, chunk: &[u8], limit: usize, label: &str) -> Result<()> {
    if out.len().saturating_add(chunk.len()) > limit {
        return Err(anyhow!(
            "persistent backend {label} exceeds configured limit"
        ));
    }
    out.extend_from_slice(chunk);
    Ok(())
}

fn build_gateway_env(req: &CgiRequest, body_len: usize) -> Vec<(String, String)> {
    let mut env = Vec::new();
    push_env(&mut env, "GATEWAY_INTERFACE", "CGI/1.1".to_string());
    push_env(&mut env, "SERVER_PROTOCOL", req.server_protocol.clone());
    push_env(
        &mut env,
        "SERVER_SOFTWARE",
        concat!("qpxf/", env!("CARGO_PKG_VERSION")).to_string(),
    );
    push_env(&mut env, "REQUEST_METHOD", req.request_method.clone());
    push_env(&mut env, "QUERY_STRING", req.query_string.clone());
    push_env(&mut env, "SCRIPT_NAME", req.script_name.clone());
    push_env(&mut env, "PATH_INFO", req.path_info.clone());
    push_env(&mut env, "SERVER_NAME", req.server_name.clone());
    push_env(&mut env, "SERVER_PORT", req.server_port.to_string());
    push_env(&mut env, "CONTENT_LENGTH", body_len.to_string());
    if !req.content_type.is_empty() {
        push_env(&mut env, "CONTENT_TYPE", req.content_type.clone());
    }
    if let Some(addr) = req.remote_addr.as_ref() {
        push_env(&mut env, "REMOTE_ADDR", addr.clone());
    }
    if let Some(port) = req.remote_port {
        push_env(&mut env, "REMOTE_PORT", port.to_string());
    }

    let connection_tokens = parse_connection_tokens(&req.http_headers);
    for (key, value) in req.http_headers.iter().take(100) {
        let lower = key.to_ascii_lowercase();
        if is_hop_by_hop_header(&lower) || connection_tokens.contains(lower.as_str()) {
            continue;
        }
        push_env(
            &mut env,
            format!("HTTP_{}", key.to_uppercase().replace('-', "_")),
            value.clone(),
        );
    }
    env
}

fn push_env(env: &mut Vec<(String, String)>, name: impl Into<String>, value: String) {
    env.push((name.into(), value));
}

fn parse_connection_tokens(headers: &HashMap<String, String>) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(value) = headers.get("connection") else {
        return out;
    };
    for token in value.split(',') {
        let token = token.trim();
        if !token.is_empty() {
            out.insert(token.to_ascii_lowercase());
        }
    }
    out
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-authentication-info"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::{Duration, sleep, timeout};

    #[test]
    fn fastcgi_param_lengths_roundtrip_short_and_long() {
        let encoded = encode_fastcgi_params(vec![
            ("A".to_string(), "B".to_string()),
            ("X".repeat(130), "Y".repeat(140)),
        ])
        .expect("encode");
        let mut cursor = Cursor::new(encoded.as_ref());
        assert_eq!(read_len(&mut cursor), 1);
        assert_eq!(read_len(&mut cursor), 1);
        let mut name = vec![0; 1];
        let mut value = vec![0; 1];
        Read::read_exact(&mut cursor, &mut name).expect("name");
        Read::read_exact(&mut cursor, &mut value).expect("value");
        assert_eq!(&name, b"A");
        assert_eq!(&value, b"B");
        assert_eq!(read_len(&mut cursor), 130);
        assert_eq!(read_len(&mut cursor), 140);
    }

    fn read_len(cursor: &mut Cursor<&[u8]>) -> usize {
        let mut first = [0u8; 1];
        Read::read_exact(cursor, &mut first).expect("first");
        if first[0] & 0x80 == 0 {
            first[0] as usize
        } else {
            let mut rest = [0u8; 3];
            Read::read_exact(cursor, &mut rest).expect("rest");
            u32::from_be_bytes([first[0] & 0x7f, rest[0], rest[1], rest[2]]) as usize
        }
    }

    #[tokio::test]
    async fn fastcgi_pool_reuses_idle_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_task = accepted.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            accepted_task.fetch_add(1, Ordering::SeqCst);
            for _ in 0..2 {
                read_fastcgi_request_from_tcp(&mut stream).await;
                write_fastcgi_record_to_tcp(&mut stream, FCGI_STDOUT, b"Status: 200 OK\r\n\r\nok")
                    .await;
                write_fastcgi_record_to_tcp(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
            }
        });

        let pool = FastCgiConnectionPool::new(address, 1, 1).expect("pool");
        for _ in 0..2 {
            let (stdout, stderr) = pool
                .execute(Vec::new(), Bytes::new(), 1024, 1024)
                .await
                .expect("execute");
            assert!(stderr.is_empty());
            assert_eq!(stdout, Bytes::from_static(b"Status: 200 OK\r\n\r\nok"));
        }
        server.await.expect("server");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fastcgi_pool_discards_broken_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_task = accepted.clone();
        let server = tokio::spawn(async move {
            let (mut broken, _) = listener.accept().await.expect("accept broken");
            accepted_task.fetch_add(1, Ordering::SeqCst);
            read_fastcgi_request_from_tcp(&mut broken).await;
            drop(broken);

            let (mut stream, _) = listener.accept().await.expect("accept replacement");
            accepted_task.fetch_add(1, Ordering::SeqCst);
            read_fastcgi_request_from_tcp(&mut stream).await;
            write_fastcgi_record_to_tcp(&mut stream, FCGI_STDOUT, b"Status: 200 OK\r\n\r\nok")
                .await;
            write_fastcgi_record_to_tcp(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
        });

        let pool = FastCgiConnectionPool::new(address, 1, 1).expect("pool");
        let err = pool
            .execute(Vec::new(), Bytes::new(), 1024, 1024)
            .await
            .expect_err("broken connection should fail");
        assert!(err.to_string().contains("closed connection"));

        let (stdout, stderr) = pool
            .execute(Vec::new(), Bytes::new(), 1024, 1024)
            .await
            .expect("replacement connection");
        assert!(stderr.is_empty());
        assert_eq!(stdout, Bytes::from_static(b"Status: 200 OK\r\n\r\nok"));
        server.await.expect("server");
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn fastcgi_pool_respects_max_concurrency() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            read_fastcgi_request_from_tcp(&mut stream).await;
            release_rx.await.expect("release first request");
            write_fastcgi_record_to_tcp(&mut stream, FCGI_STDOUT, b"Status: 200 OK\r\n\r\none")
                .await;
            write_fastcgi_record_to_tcp(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
            read_fastcgi_request_from_tcp(&mut stream).await;
            write_fastcgi_record_to_tcp(&mut stream, FCGI_STDOUT, b"Status: 200 OK\r\n\r\ntwo")
                .await;
            write_fastcgi_record_to_tcp(&mut stream, FCGI_END_REQUEST, &[0; 8]).await;
        });

        let pool = Arc::new(FastCgiConnectionPool::new(address, 1, 1).expect("pool"));
        let first_pool = pool.clone();
        let first = tokio::spawn(async move {
            first_pool
                .execute(Vec::new(), Bytes::new(), 1024, 1024)
                .await
                .expect("first")
                .0
        });
        sleep(Duration::from_millis(50)).await;
        let second_pool = pool.clone();
        let mut second = tokio::spawn(async move {
            second_pool
                .execute(Vec::new(), Bytes::new(), 1024, 1024)
                .await
                .expect("second")
                .0
        });
        assert!(
            timeout(Duration::from_millis(50), &mut second)
                .await
                .is_err()
        );
        release_tx.send(()).expect("release");
        let first_stdout = first.await.expect("first join");
        assert_eq!(
            first_stdout,
            Bytes::from_static(b"Status: 200 OK\r\n\r\none")
        );
        let second_stdout = second.await.expect("second join");
        assert_eq!(
            second_stdout,
            Bytes::from_static(b"Status: 200 OK\r\n\r\ntwo")
        );
        server.await.expect("server");
    }

    #[tokio::test]
    async fn scgi_executor_respects_max_concurrency() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let (checked_tx, checked_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("accept first");
            let first_task = tokio::spawn(async move {
                read_scgi_request_from_tcp(&mut first).await;
                release_rx.await.expect("release first scgi request");
                first
                    .write_all(b"Status: 200 OK\r\n\r\none")
                    .await
                    .expect("first response");
            });
            assert!(
                timeout(Duration::from_millis(75), listener.accept())
                    .await
                    .is_err(),
                "second SCGI connection should wait for the concurrency permit"
            );
            checked_tx.send(()).expect("checked");
            first_task.await.expect("first task");
            let (mut second, _) = listener.accept().await.expect("accept second");
            read_scgi_request_from_tcp(&mut second).await;
            second
                .write_all(b"Status: 200 OK\r\n\r\ntwo")
                .await
                .expect("second response");
        });

        let executor = Arc::new(
            PersistentExecutor::new(address, 1000, 1, 1024, 1024, 1024).expect("executor"),
        );
        let first = tokio::spawn(start_persistent_request(executor.clone()));
        sleep(Duration::from_millis(25)).await;
        let second = tokio::spawn(start_persistent_request(executor.clone()));
        checked_rx.await.expect("checked concurrency");
        release_tx.send(()).expect("release");
        let first_stdout = first.await.expect("first join");
        assert_eq!(
            first_stdout,
            Bytes::from_static(b"Status: 200 OK\r\n\r\none")
        );
        let second_stdout = second.await.expect("second join");
        assert_eq!(
            second_stdout,
            Bytes::from_static(b"Status: 200 OK\r\n\r\ntwo")
        );
        server.await.expect("server");
    }

    async fn start_persistent_request(executor: Arc<PersistentExecutor>) -> Bytes {
        let mut execution = executor
            .start(test_cgi_request())
            .await
            .expect("start request");
        drop(execution.stdin);
        let mut stdout = BytesMut::new();
        while let Some(chunk) = execution.stdout.recv().await {
            stdout.extend_from_slice(&chunk);
        }
        execution.done.await.expect("join").expect("done");
        stdout.freeze()
    }

    fn test_cgi_request() -> CgiRequest {
        CgiRequest {
            script_name: "/index".to_string(),
            path_info: String::new(),
            query_string: String::new(),
            request_method: "GET".to_string(),
            content_type: String::new(),
            content_length: 0,
            server_protocol: "HTTP/1.1".to_string(),
            server_name: "localhost".to_string(),
            server_port: 80,
            remote_addr: None,
            remote_port: None,
            http_headers: HashMap::new(),
            matched_prefix: None,
        }
    }

    async fn read_fastcgi_request_from_tcp(stream: &mut TcpStream) {
        loop {
            let Some((record_type, content)) = read_fastcgi_record_from_tcp(stream).await else {
                panic!("unexpected eof");
            };
            if record_type == FCGI_STDIN && content.is_empty() {
                break;
            }
        }
    }

    async fn read_fastcgi_record_from_tcp(stream: &mut TcpStream) -> Option<(u8, Bytes)> {
        let mut header = [0u8; 8];
        if stream.read_exact(&mut header).await.is_err() {
            return None;
        }
        let record_type = header[1];
        let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
        let padding_len = header[6] as usize;
        let mut content = vec![0u8; content_len];
        stream.read_exact(&mut content).await.expect("content");
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            stream.read_exact(&mut padding).await.expect("padding");
        }
        Some((record_type, Bytes::from(content)))
    }

    async fn write_fastcgi_record_to_tcp(stream: &mut TcpStream, record_type: u8, content: &[u8]) {
        let content_len = content.len() as u16;
        let padding_len = (8 - (content.len() % 8)) % 8;
        let header = [
            1,
            record_type,
            0,
            1,
            (content_len >> 8) as u8,
            content_len as u8,
            padding_len as u8,
            0,
        ];
        stream.write_all(&header).await.expect("header");
        stream.write_all(content).await.expect("content");
        if padding_len > 0 {
            stream
                .write_all(&[0u8; 8][..padding_len])
                .await
                .expect("padding");
        }
    }

    async fn read_scgi_request_from_tcp(stream: &mut TcpStream) {
        let mut len = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream
                .read_exact(&mut byte)
                .await
                .expect("netstring length");
            if byte[0] == b':' {
                break;
            }
            len.push(byte[0]);
        }
        let len = std::str::from_utf8(&len)
            .expect("length utf8")
            .parse::<usize>()
            .expect("length");
        let mut headers = vec![0u8; len];
        stream.read_exact(&mut headers).await.expect("headers");
        let mut comma = [0u8; 1];
        stream.read_exact(&mut comma).await.expect("comma");
        assert_eq!(comma[0], b',');
    }
}
