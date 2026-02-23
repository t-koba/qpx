use anyhow::{anyhow, Result};
use bytes::Bytes;
use hyper::body::HttpBody as _;
use hyper::{Body, Request, Response};
use qpx_core::config::{IpcMode, IpcUpstreamConfig};
use qpx_core::ipc::meta::{IpcRequestMeta, IpcResponseMeta};
use qpx_core::ipc::protocol::{read_frame, write_frame};
use qpx_core::shm_ring::ShmRingBuffer;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

use url::Url;

const MAX_IDLE_CONNS_PER_BACKEND: usize = 8;
const SHM_RING_SIZE: usize = 16 * 1024 * 1024; // 16MB
static IPC_SHM_LAST_CLEANUP_UNIX_SECS: AtomicU64 = AtomicU64::new(0);

fn maybe_cleanup_ipc_shm_dir(dir: &PathBuf) {
    // Best-effort GC for crash/abort cases (especially important on Windows where unlink-on-open
    // semantics don't exist). This is intentionally coarse to keep per-request overhead tiny.
    const CLEANUP_INTERVAL_SECS: u64 = 60;
    const STALE_AFTER_SECS: u64 = 3600;

    let now = SystemTime::now();
    let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let last = IPC_SHM_LAST_CLEANUP_UNIX_SECS.load(Ordering::Relaxed);
    if now_secs.saturating_sub(last) < CLEANUP_INTERVAL_SECS {
        return;
    }
    if IPC_SHM_LAST_CLEANUP_UNIX_SECS
        .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("ipc_req_") && !name.starts_with("ipc_res_") {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("shm") {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let Ok(age) = now.duration_since(modified) else {
            continue;
        };
        if age.as_secs() < STALE_AFTER_SECS {
            continue;
        }
        let _ = std::fs::remove_file(path);
    }
}

struct AbortOnDrop {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl AbortOnDrop {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn disarm(&mut self) {
        // Dropping JoinHandle detaches the task; we only want to abort on cancellation/error paths.
        let _ = self.handle.take();
    }
}

impl Drop for AbortOnDrop {
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
    let mut body_writer_abort: Option<AbortOnDrop> = None;

    if mode == IpcMode::Shm {
        let shm_dir = ShmRingBuffer::default_shm_dir().join("ipc");

        let req_token = format!("ipc_req_{uuid}.shm");
        let res_token = format!("ipc_res_{uuid}.shm");
        let req_path = shm_dir.join(&req_token);
        let res_path = shm_dir.join(&res_token);
        req_ring = Some(ShmRingBuffer::create_or_open(&req_path, SHM_RING_SIZE)?);
        res_ring = Some(ShmRingBuffer::create_or_open(&res_path, SHM_RING_SIZE)?);
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
        let mut req_ring = req_ring.unwrap();
        const SHM_PUSH_CHUNK_BYTES: usize = 64 * 1024;
        let handle = tokio::spawn(async move {
            while let Some(chunk) = req.body_mut().data().await {
                if let Ok(data) = chunk {
                    for part in data.chunks(SHM_PUSH_CHUNK_BYTES) {
                        loop {
                            match req_ring.try_push(part) {
                                Ok(true) => break,
                                Ok(false) => {
                                    if req_ring.wait_for_space(part.len()).await.is_err() {
                                        return;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            }
            // push EOF
            loop {
                match req_ring.try_push(&[]) {
                    Ok(true) => break,
                    Ok(false) => {
                        if req_ring.wait_for_space(0).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        body_writer_abort = Some(AbortOnDrop::new(handle));
    } else {
        // Stream req body over tcp
        while let Some(chunk) = req.body_mut().data().await {
            let data = chunk?;
            stream.write_all(&data).await?;
        }
        stream.shutdown().await?;
    }

    let res_meta: IpcResponseMeta = read_frame(&mut stream).await?;

    let mut builder = Response::builder().status(res_meta.status);
    for (k, v) in res_meta.headers {
        builder = builder.header(k, v);
    }

    let (mut sender, body) = Body::channel();

    if mode == IpcMode::Shm {
        let mut res_ring = res_ring.unwrap();
        let res_path = res_path_fs.unwrap();
        tokio::spawn(async move {
            loop {
                match res_ring.try_pop() {
                    Ok(Some(data)) => {
                        if data.is_empty() {
                            break; // EOF
                        }
                        if sender.send_data(Bytes::from(data)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        if res_ring.wait_for_data().await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            drop(res_ring);
            let _ = std::fs::remove_file(res_path);
            checkin_stream(pool_key, stream).await; // We checkin ONLY AFTER EOF or Drop in SHM
        });
    } else {
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if sender
                            .send_data(Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // Cannot checkin Tcp stream if it reached EOF on response. It must be dropped.
            // Unless qpxf somehow signals EOF without closing? TCP raw stream just closes the socket.
            // FastCGI supported multiplexing but IPC raw stream does not. So we drop it.
        });
    }

    if let Some(abort) = body_writer_abort.as_mut() {
        abort.disarm();
    }
    if let Some(cleanup) = shm_cleanup.as_mut() {
        cleanup.disarm();
    }
    Ok(builder.body(body)?)
}
