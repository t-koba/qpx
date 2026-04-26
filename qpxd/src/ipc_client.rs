use crate::http::body::Body;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use hyper::{Request, Response};
use qpx_core::config::{IpcMode, IpcUpstreamConfig};
use qpx_core::ipc::meta::{IpcRequestMeta, IpcResponseMeta};
use qpx_core::ipc::protocol::{read_frame, write_frame};
use qpx_core::shm_ring::ShmRingBuffer;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::warn;

use url::Url;

const MAX_IDLE_CONNS_PER_BACKEND: usize = 8;
const SHM_RING_SIZE: usize = 16 * 1024 * 1024; // 16MB
const IPC_DOWNSTREAM_ABORT_POLL_INTERVAL: Duration = Duration::from_millis(250);
static IPC_SHM_LAST_CLEANUP_UNIX_SECS: AtomicU64 = AtomicU64::new(0);

fn maybe_cleanup_ipc_shm_dir(dir: &Path) {
    qpx_core::ipc::shm::maybe_cleanup_stale_ipc_shm_files(
        dir,
        &IPC_SHM_LAST_CLEANUP_UNIX_SECS,
        60,
        3600,
    );
}

struct AbortOnDrop<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
}

impl<T> AbortOnDrop<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

struct IpcShmCleanup {
    req_path: PathBuf,
    res_path: PathBuf,
    active: bool,
}

impl IpcShmCleanup {
    fn new(req_path: PathBuf, res_path: PathBuf) -> Self {
        Self {
            req_path,
            res_path,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for IpcShmCleanup {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = std::fs::remove_file(&self.req_path);
        let _ = std::fs::remove_file(&self.res_path);
    }
}

const SHM_PUSH_CHUNK_BYTES: usize = 64 * 1024;

async fn push_request_ring_bytes(
    ring: &mut ShmRingBuffer,
    bytes: &[u8],
    timeout_dur: Duration,
) -> Result<()> {
    loop {
        match ring.try_push(bytes) {
            Ok(true) => return Ok(()),
            Ok(false) => {
                timeout(timeout_dur, ring.wait_for_space(bytes.len()))
                    .await
                    .map_err(|_| anyhow!("IPC SHM request body writer timed out"))??;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn write_request_body_to_shm(
    body: &mut Body,
    mut req_ring: ShmRingBuffer,
    timeout_dur: Duration,
) -> Result<()> {
    while let Some(chunk) = timeout(timeout_dur, body.data())
        .await
        .map_err(|_| anyhow!("IPC request body read timed out"))?
    {
        let data = chunk.map_err(|err| anyhow!("IPC request body read failed: {}", err))?;
        for part in data.chunks(SHM_PUSH_CHUNK_BYTES) {
            push_request_ring_bytes(&mut req_ring, part, timeout_dur).await?;
        }
    }
    push_request_ring_bytes(&mut req_ring, &[], timeout_dur).await
}

fn finish_shm_body_writer_result(
    body_result: std::result::Result<Result<()>, tokio::sync::oneshot::error::RecvError>,
) -> Result<()> {
    match body_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(anyhow!("IPC SHM request body writer ended unexpectedly")),
    }
}

async fn read_shm_response_meta_after_body_writer<S>(
    stream: &mut S,
    mut result_rx: tokio::sync::oneshot::Receiver<Result<()>>,
) -> Result<IpcResponseMeta>
where
    S: AsyncRead + Unpin,
{
    let pending_meta = tokio::select! {
        res = read_frame(stream) => Some(res?),
        body_result = &mut result_rx => {
            finish_shm_body_writer_result(body_result)?;
            None
        }
    };

    if let Some(meta) = pending_meta {
        Ok(meta)
    } else {
        read_frame(stream).await
    }
}

async fn downstream_body_closed(sender: &mut crate::http::body::Sender) -> bool {
    sender.is_closed()
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ClientConnInfo {
    pub remote_addr: Option<std::net::SocketAddr>,
}

#[derive(Debug, Clone)]
pub(crate) struct IpcUpstream {
    mode: IpcMode,
    backend: IpcBackend,
    timeout: Duration,
}

impl IpcUpstream {
    pub(crate) fn from_config(cfg: &IpcUpstreamConfig) -> Result<Self> {
        Ok(Self {
            mode: cfg.mode.clone(),
            backend: parse_ipc_address(cfg.address.as_str())?,
            timeout: Duration::from_millis(cfg.timeout_ms),
        })
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    fn effective_timeout(&self, route_timeout: Duration) -> Duration {
        std::cmp::min(route_timeout, self.timeout)
    }
}

#[derive(Debug, Clone)]
enum IpcBackend {
    Tcp {
        host: String,
        port: u16,
    },
    #[cfg(unix)]
    Unix {
        path: PathBuf,
    },
}

impl IpcBackend {
    fn pool_key(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("tcp://{}:{}", host, port),
            #[cfg(unix)]
            Self::Unix { path } => format!("unix://{}", path.display()),
        }
    }
}

enum IpcStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl IpcStream {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.write_all(buf).await,
            #[cfg(unix)]
            Self::Unix(s) => s.write_all(buf).await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf).await,
            #[cfg(unix)]
            Self::Unix(s) => s.read(buf).await,
        }
    }
}

impl tokio::io::AsyncRead for IpcStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            Self::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for IpcStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            Self::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match &mut *self {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

type PoolMap = HashMap<String, Vec<IpcStream>>;
type Pool = Arc<Mutex<PoolMap>>;

fn ipc_pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

async fn connect_backend(backend: &IpcBackend, timeout_dur: Duration) -> Result<IpcStream> {
    match backend {
        IpcBackend::Tcp { host, port } => {
            let addr = format!("{}:{}", host, port);
            let stream = timeout(timeout_dur, TcpStream::connect(&addr))
                .await
                .map_err(|_| anyhow!("IPC connect timeout: {}", addr))??;
            let _ = stream.set_nodelay(true);
            Ok(IpcStream::Tcp(stream))
        }
        #[cfg(unix)]
        IpcBackend::Unix { path } => {
            let stream = timeout(timeout_dur, UnixStream::connect(path))
                .await
                .map_err(|_| anyhow!("IPC unix connect timeout: {}", path.display()))??;
            Ok(IpcStream::Unix(stream))
        }
    }
}

async fn checkout_stream(
    backend: &IpcBackend,
    timeout_dur: Duration,
) -> Result<(String, IpcStream)> {
    let key = backend.pool_key();
    if let Some(stream) = {
        let pool = ipc_pool();
        let mut guard = pool.lock().await;
        guard.get_mut(&key).and_then(|v| v.pop())
    } {
        return Ok((key, stream));
    }
    let stream = connect_backend(backend, timeout_dur).await?;
    Ok((key, stream))
}

async fn checkin_stream(key: String, stream: IpcStream) {
    let pool = ipc_pool();
    let mut guard = pool.lock().await;
    let entry = guard.entry(key).or_insert_with(Vec::new);
    if entry.len() >= MAX_IDLE_CONNS_PER_BACKEND {
        return;
    }
    entry.push(stream);
}

fn parse_ipc_address(raw: &str) -> Result<IpcBackend> {
    if let Some(path) = raw.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            return Ok(IpcBackend::Unix {
                path: PathBuf::from(path),
            });
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(anyhow!("unix IPC backends are not supported"));
        }
    }
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(anyhow!(
            "invalid IPC address (expected host:port or unix://path): {}",
            raw
        ));
    };
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("invalid IPC port in address: {}", raw))?;
    Ok(IpcBackend::Tcp {
        host: host.to_string(),
        port,
    })
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

fn parse_connection_tokens(headers: &hyper::HeaderMap) -> HashSet<String> {
    let mut out = HashSet::new();
    for value in headers.get_all("connection") {
        let Ok(s) = value.to_str() else {
            continue;
        };
        for token in s.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                out.insert(token.to_ascii_lowercase());
            }
        }
    }
    out
}

fn build_ipc_meta(req: &Request<Body>, conn: ClientConnInfo) -> IpcRequestMeta {
    let mut headers = Vec::new();
    let connection_tokens = parse_connection_tokens(req.headers());
    let mut has_host = false;
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        if is_hop_by_hop_header(name_str) {
            continue;
        }
        if connection_tokens.contains(name_str) {
            continue;
        }
        if let Ok(val_str) = value.to_str() {
            if name_str.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            headers.push((name_str.to_string(), val_str.to_string()));
        }
    }
    // HTTP/2 and HTTP/3 requests carry the authority in the URI/metadata rather than a Host
    // header. CGI expects HTTP_HOST, so synthesize it when missing.
    if !has_host {
        if let Some(authority) = req.uri().authority() {
            headers.push(("host".to_string(), authority.as_str().to_string()));
        }
    }

    let mut params = HashMap::new();
    if let Some(remote) = conn.remote_addr {
        params.insert("REMOTE_ADDR".to_string(), remote.ip().to_string());
        params.insert("REMOTE_PORT".to_string(), remote.port().to_string());
    }

    IpcRequestMeta {
        method: req.method().as_str().to_string(),
        uri: req.uri().to_string(),
        headers,
        params,
        req_body_shm_path: None,
        req_body_shm_size_bytes: None,
        res_body_shm_path: None,
        res_body_shm_size_bytes: None,
    }
}

pub(crate) async fn proxy_ipc(
    req: Request<Body>,
    url: &Url,
    proxy_name: &str,
) -> Result<Response<Body>> {
    let mode = IpcMode::Tcp;
    let backend = match url.scheme() {
        "ipc" => {
            let host = url.host_str().ok_or_else(|| anyhow!("missing IPC host"))?;
            let port = url.port().unwrap_or(9000);
            IpcBackend::Tcp {
                host: host.to_string(),
                port,
            }
        }
        #[cfg(unix)]
        "ipc+unix" => IpcBackend::Unix {
            path: PathBuf::from(url.path()),
        },
        _ => return Err(anyhow!("unsupported IPC url scheme: {}", url.scheme())),
    };
    proxy_ipc_backend(
        req,
        &backend,
        mode,
        proxy_name,
        ClientConnInfo::default(),
        Duration::from_secs(30),
    )
    .await
}

pub(crate) async fn proxy_ipc_upstream(
    req: Request<Body>,
    upstream: &IpcUpstream,
    proxy_name: &str,
    conn: ClientConnInfo,
    route_timeout: Duration,
) -> Result<Response<Body>> {
    let timeout_dur = upstream.effective_timeout(route_timeout);
    proxy_ipc_backend(
        req,
        &upstream.backend,
        upstream.mode.clone(),
        proxy_name,
        conn,
        timeout_dur,
    )
    .await
}

async fn proxy_ipc_backend(
    mut req: Request<Body>,
    backend: &IpcBackend,
    mode: IpcMode,
    _proxy_name: &str,
    conn: ClientConnInfo,
    timeout_dur: Duration,
) -> Result<Response<Body>> {
    let mut meta = build_ipc_meta(&req, conn);
    let uuid = uuid::Uuid::new_v4().to_string();

    let mut shm_cleanup: Option<IpcShmCleanup> = None;
    let mut req_ring = None;
    let mut res_ring = None;
    let mut res_path_fs: Option<PathBuf> = None;
    let mut body_writer_abort: Option<AbortOnDrop<()>> = None;
    let mut body_writer_result_rx = None;

    if mode == IpcMode::Shm {
        let shm_dir = qpx_core::ipc::shm::ipc_shm_dir()?;

        let req_token = format!("ipc_req_{uuid}.shm");
        let res_token = format!("ipc_res_{uuid}.shm");
        let (req_path, created_req_ring) =
            qpx_core::ipc::shm::create_or_open_ipc_ring(&req_token, "ipc_req_", SHM_RING_SIZE)?;
        let (res_path, created_res_ring) =
            qpx_core::ipc::shm::create_or_open_ipc_ring(&res_token, "ipc_res_", SHM_RING_SIZE)?;
        req_ring = Some(created_req_ring);
        res_ring = Some(created_res_ring);
        maybe_cleanup_ipc_shm_dir(&shm_dir);
        shm_cleanup = Some(IpcShmCleanup::new(req_path, res_path.clone()));
        meta.req_body_shm_path = Some(req_token);
        meta.req_body_shm_size_bytes = Some(SHM_RING_SIZE);
        meta.res_body_shm_path = Some(res_token);
        meta.res_body_shm_size_bytes = Some(SHM_RING_SIZE);
        res_path_fs = Some(res_path);
    }

    let (pool_key, mut stream) = checkout_stream(backend, timeout_dur).await?;

    write_frame(&mut stream, &meta).await?;

    if mode == IpcMode::Shm {
        // Stream req body to shm ring
        let req_ring = req_ring.unwrap();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<()>>();
        let handle = tokio::spawn(async move {
            let result = write_request_body_to_shm(req.body_mut(), req_ring, timeout_dur).await;
            if let Err(Err(err)) = result_tx.send(result) {
                warn!(error = ?err, "IPC SHM request body writer failed after response started");
            }
        });
        body_writer_abort = Some(AbortOnDrop::new(handle));
        body_writer_result_rx = Some(result_rx);
    } else {
        // Stream req body over tcp
        while let Some(chunk) = timeout(timeout_dur, req.body_mut().data())
            .await
            .map_err(|_| anyhow!("IPC TCP request body read timed out"))?
        {
            let data = chunk?;
            timeout(timeout_dur, stream.write_all(&data))
                .await
                .map_err(|_| anyhow!("IPC TCP request body write timed out"))??;
        }
        timeout(timeout_dur, stream.shutdown())
            .await
            .map_err(|_| anyhow!("IPC TCP request body shutdown timed out"))??;
    }

    let res_meta: IpcResponseMeta = if let Some(result_rx) = body_writer_result_rx.take() {
        read_shm_response_meta_after_body_writer(&mut stream, result_rx).await?
    } else {
        read_frame(&mut stream).await?
    };

    let mut builder = Response::builder().status(res_meta.status);
    for (k, v) in res_meta.headers {
        builder = builder.header(k, v);
    }

    let (mut sender, body) = Body::channel();

    if mode == IpcMode::Shm {
        let mut res_ring = res_ring.unwrap();
        let res_path = res_path_fs.unwrap();
        let body_writer_abort = body_writer_abort;
        tokio::spawn(async move {
            let mut reusable = true;
            loop {
                match res_ring.try_pop() {
                    Ok(Some(data)) => {
                        if data.is_empty() {
                            break; // EOF
                        }
                        if sender.send_data(Bytes::from(data)).await.is_err() {
                            reusable = false;
                            break;
                        }
                    }
                    Ok(None) => {
                        tokio::select! {
                            wait = res_ring.wait_for_data() => {
                                if wait.is_err() {
                                    reusable = false;
                                    break;
                                }
                            }
                            _ = tokio::time::sleep(IPC_DOWNSTREAM_ABORT_POLL_INTERVAL) => {
                                if downstream_body_closed(&mut sender).await {
                                    reusable = false;
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => {
                        reusable = false;
                        break;
                    }
                }
            }
            drop(body_writer_abort);
            drop(res_ring);
            let _ = std::fs::remove_file(res_path);
            if reusable {
                checkin_stream(pool_key, stream).await;
            }
        });
    } else {
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                let read = tokio::select! {
                    read = stream.read(&mut buf) => Some(read),
                    _ = tokio::time::sleep(IPC_DOWNSTREAM_ABORT_POLL_INTERVAL) => {
                        if downstream_body_closed(&mut sender).await {
                            None
                        } else {
                            continue;
                        }
                    }
                };
                match read {
                    None => break,
                    Some(Ok(0)) => break,
                    Some(Ok(n)) => {
                        if sender
                            .send_data(Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Some(Err(_)) => break,
                }
            }
            // Cannot checkin Tcp stream if it reached EOF on response. It must be dropped.
            // Unless qpxf somehow signals EOF without closing? TCP raw stream just closes the socket.
            // This transport is one-request-per-connection, so EOF means the socket is no longer reusable.
        });
    }

    if let Some(cleanup) = shm_cleanup.as_mut() {
        cleanup.disarm();
    }
    Ok(builder.body(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::Duration;

    fn temp_shm_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        ShmRingBuffer::default_shm_dir().join(format!("{name}-{}-{nonce}.shm", std::process::id()))
    }

    #[tokio::test]
    async fn shm_body_writer_does_not_push_eof_after_body_error() {
        let req_path = temp_shm_path("ipc-body-writer");
        let mut reader = ShmRingBuffer::create_or_open(&req_path, 64 * 1024).unwrap();
        let writer = ShmRingBuffer::create_or_open(&req_path, 64 * 1024).unwrap();

        let (mut sender, mut body) = Body::channel();
        sender.send_data(Bytes::from_static(b"abc")).await.unwrap();
        sender.abort();

        let err = write_request_body_to_shm(&mut body, writer, Duration::from_secs(1))
            .await
            .expect_err("body error should propagate");
        assert!(err.to_string().contains("request body read failed"));

        let first = reader.try_pop().unwrap().expect("payload");
        assert_eq!(first, b"abc");
        let waited = timeout(Duration::from_millis(100), reader.wait_for_data()).await;
        assert!(waited.is_err(), "unexpected clean EOF in request ring");

        let _ = std::fs::remove_file(req_path);
    }

    #[tokio::test]
    async fn shm_response_meta_returns_before_body_writer_after_fast_response() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let response_meta = IpcResponseMeta {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
        };
        let writer = tokio::spawn(async move {
            write_frame(&mut server, &response_meta)
                .await
                .expect("write response meta");
        });
        let (result_tx, result_rx) = tokio::sync::oneshot::channel::<Result<()>>();
        let read_task = tokio::spawn(async move {
            read_shm_response_meta_after_body_writer(&mut client, result_rx).await
        });

        tokio::task::yield_now().await;
        let meta = read_task
            .await
            .expect("join read task")
            .expect("read response meta");
        assert_eq!(meta.status, 200);
        assert!(
            result_tx
                .send(Err(anyhow!("body writer failed late")))
                .is_err(),
            "response metadata reader should not keep waiting on the body writer"
        );
        writer.await.expect("join writer");
    }

    #[tokio::test]
    async fn downstream_body_closed_reports_dropped_receiver() {
        let (sender, body) = Body::channel();
        drop(body);

        let mut sender = sender;
        assert!(downstream_body_closed(&mut sender).await);
        assert!(sender.is_closed());
    }
}
