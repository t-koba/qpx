use anyhow::{anyhow, Result};
use bytes::{BufMut, Bytes, BytesMut};
use hyper::body::HttpBody as _;
use hyper::{Body, Request, Response, StatusCode};
use qpx_core::config::FastCgiUpstreamConfig;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{timeout, Duration};
use tracing::warn;
use url::Url;

// FastCGI constants.
const FCGI_VERSION: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_RESPONDER: u16 = 1;
const FCGI_KEEP_CONN: u8 = 1;

const MAX_HTTP_HEADERS: usize = 100;
const MAX_CGI_HEADER_BYTES: usize = 64 * 1024;
const MAX_CGI_HEADER_LINES: usize = 200;
const MAX_FASTCGI_STDERR_BYTES: usize = 1024 * 1024;
const MAX_IDLE_CONNS_PER_BACKEND: usize = 8;

fn put_nv_len(buf: &mut BytesMut, len: usize) {
    if len < 128 {
        buf.put_u8(len as u8);
    } else {
        buf.put_u32((len as u32) | 0x8000_0000);
    }
}

fn put_nv_pair(buf: &mut BytesMut, name: &[u8], value: &[u8]) {
    put_nv_len(buf, name.len());
    put_nv_len(buf, value.len());
    buf.extend_from_slice(name);
    buf.extend_from_slice(value);
}

fn put_http_header_param(buf: &mut BytesMut, header_name: &str, value: &[u8]) {
    // env var key: HTTP_{HEADER_NAME}, uppercased with '-' -> '_'
    let name_bytes = header_name.as_bytes();
    let env_name_len = 5 + name_bytes.len();
    put_nv_len(buf, env_name_len);
    put_nv_len(buf, value.len());
    buf.extend_from_slice(b"HTTP_");
    for &b in name_bytes {
        let out = match b {
            b'-' => b'_',
            b'a'..=b'z' => b - 32,
            _ => b,
        };
        buf.put_u8(out);
    }
    buf.extend_from_slice(value);
}

async fn write_record(
    stream: &mut FastCgiStream,
    record_type: u8,
    request_id: u16,
    content: &[u8],
) -> Result<()> {
    if content.len() > 65535 {
        return Err(anyhow!("FastCGI record too large: {}", content.len()));
    }
    let padding = (8 - (content.len() % 8)) % 8;
    let header = [
        FCGI_VERSION,
        record_type,
        (request_id >> 8) as u8,
        (request_id & 0xff) as u8,
        (content.len() >> 8) as u8,
        (content.len() & 0xff) as u8,
        padding as u8,
        0,
    ];
    stream.write_all(&header).await?;
    if !content.is_empty() {
        stream.write_all(content).await?;
    }
    if padding > 0 {
        const PAD: [u8; 8] = [0u8; 8];
        stream.write_all(&PAD[..padding]).await?;
    }
    Ok(())
}

async fn write_begin_request(stream: &mut FastCgiStream, request_id: u16) -> Result<()> {
    let mut body = [0u8; 8];
    body[0] = (FCGI_RESPONDER >> 8) as u8;
    body[1] = (FCGI_RESPONDER & 0xff) as u8;
    body[2] = FCGI_KEEP_CONN;
    write_record(stream, FCGI_BEGIN_REQUEST, request_id, &body).await
}

/// Headers that should not be forwarded as HTTP_* to CGI/FastCGI.
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

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ClientConnInfo {
    pub remote_addr: Option<std::net::SocketAddr>,
    pub dst_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub(crate) struct FastCgiUpstream {
    backend: FastCgiBackend,
    timeout: Duration,
    params: HashMap<String, String>,
}

impl FastCgiUpstream {
    pub(crate) fn from_config(cfg: &FastCgiUpstreamConfig) -> Result<Self> {
        Ok(Self {
            backend: parse_fastcgi_address(cfg.address.as_str())?,
            timeout: Duration::from_millis(cfg.timeout_ms),
            params: cfg.params.clone(),
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
enum FastCgiBackend {
    Tcp {
        host: String,
        port: u16,
    },
    #[cfg(unix)]
    Unix {
        path: PathBuf,
    },
}

impl FastCgiBackend {
    fn pool_key(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("tcp://{}:{}", host, port),
            #[cfg(unix)]
            Self::Unix { path } => format!("unix://{}", path.display()),
        }
    }
}

enum FastCgiStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl FastCgiStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let mut off = 0usize;
        while off < buf.len() {
            let n = match self {
                Self::Tcp(s) => s.read(&mut buf[off..]).await?,
                #[cfg(unix)]
                Self::Unix(s) => s.read(&mut buf[off..]).await?,
            };
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected eof",
                ));
            }
            off += n;
        }
        Ok(())
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.write_all(buf).await,
            #[cfg(unix)]
            Self::Unix(s) => s.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush().await,
            #[cfg(unix)]
            Self::Unix(s) => s.flush().await,
        }
    }
}

type PoolMap = HashMap<String, Vec<FastCgiStream>>;
type Pool = Arc<Mutex<PoolMap>>;

fn fastcgi_pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

async fn connect_backend(backend: &FastCgiBackend, timeout_dur: Duration) -> Result<FastCgiStream> {
    match backend {
        FastCgiBackend::Tcp { host, port } => {
            let addr = format!("{}:{}", host, port);
            let stream = timeout(timeout_dur, TcpStream::connect(&addr))
                .await
                .map_err(|_| anyhow!("FastCGI connect timeout: {}", addr))??;
            let _ = stream.set_nodelay(true);
            Ok(FastCgiStream::Tcp(stream))
        }
        #[cfg(unix)]
        FastCgiBackend::Unix { path } => {
            let stream = timeout(timeout_dur, UnixStream::connect(path))
                .await
                .map_err(|_| anyhow!("FastCGI unix connect timeout: {}", path.display()))??;
            Ok(FastCgiStream::Unix(stream))
        }
    }
}

async fn checkout_stream(
    backend: &FastCgiBackend,
    timeout_dur: Duration,
) -> Result<(String, FastCgiStream)> {
    let key = backend.pool_key();
    if let Some(stream) = {
        let pool = fastcgi_pool();
        let mut guard = pool.lock().await;
        guard.get_mut(&key).and_then(|v| v.pop())
    } {
        return Ok((key, stream));
    }
    let stream = connect_backend(backend, timeout_dur).await?;
    Ok((key, stream))
}

async fn checkin_stream(key: String, stream: FastCgiStream) {
    let pool = fastcgi_pool();
    let mut guard = pool.lock().await;
    let entry = guard.entry(key).or_insert_with(Vec::new);
    if entry.len() >= MAX_IDLE_CONNS_PER_BACKEND {
        return;
    }
    entry.push(stream);
}

fn parse_fastcgi_address(raw: &str) -> Result<FastCgiBackend> {
    if let Some(path) = raw.strip_prefix("unix://") {
        #[cfg(unix)]
        {
            return Ok(FastCgiBackend::Unix {
                path: PathBuf::from(path),
            });
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(anyhow!("unix FastCGI backends are not supported"));
        }
    }
    // host:port (no scheme)
    let Some((host, port)) = raw.rsplit_once(':') else {
        return Err(anyhow!(
            "invalid FastCGI address (expected host:port or unix://path): {}",
            raw
        ));
    };
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("invalid FastCGI port in address: {}", raw))?;
    Ok(FastCgiBackend::Tcp {
        host: host.to_string(),
        port,
    })
}

fn server_protocol(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

fn build_params(
    req: &Request<Body>,
    body_len: Option<usize>,
    upstream_params: &HashMap<String, String>,
    conn: ClientConnInfo,
) -> BytesMut {
    let mut params = BytesMut::new();

    // Route/static params first; dynamic request-derived values may override them.
    for (k, v) in upstream_params {
        put_nv_pair(&mut params, k.as_bytes(), v.as_bytes());
    }

    let method = req.method().as_str();
    let path = req.uri().path();
    let query = req.uri().query().unwrap_or("");

    put_nv_pair(&mut params, b"REQUEST_METHOD", method.as_bytes());
    put_nv_pair(&mut params, b"SCRIPT_NAME", path.as_bytes());
    put_nv_pair(&mut params, b"PATH_INFO", b"");
    put_nv_pair(&mut params, b"QUERY_STRING", query.as_bytes());
    put_nv_pair(
        &mut params,
        b"SERVER_PROTOCOL",
        server_protocol(req.version()).as_bytes(),
    );

    // SERVER_NAME and SERVER_PORT from the Host header (client-facing),
    // not from the upstream URL.
    let (server_name, server_port): (&str, Cow<'_, str>) =
        if let Some(host_val) = req.headers().get("host") {
            let host_str = host_val.to_str().unwrap_or("localhost");
            // Fast path that correctly handles bracketed IPv6 host headers.
            if host_str.starts_with('[') {
                if let Some(end) = host_str.find(']') {
                    let host = &host_str[1..end];
                    let after = &host_str[end + 1..];
                    if let Some(port) = after.strip_prefix(':') {
                        (host, Cow::Borrowed(port))
                    } else {
                        (host, Cow::Owned(conn.dst_port.unwrap_or(80).to_string()))
                    }
                } else {
                    (
                        host_str,
                        Cow::Owned(conn.dst_port.unwrap_or(80).to_string()),
                    )
                }
            } else if let Some((h, p)) = host_str.rsplit_once(':') {
                (h, Cow::Borrowed(p))
            } else {
                (
                    host_str,
                    Cow::Owned(conn.dst_port.unwrap_or(80).to_string()),
                )
            }
        } else {
            (
                "localhost",
                Cow::Owned(conn.dst_port.unwrap_or(80).to_string()),
            )
        };
    put_nv_pair(&mut params, b"SERVER_NAME", server_name.as_bytes());
    put_nv_pair(&mut params, b"SERVER_PORT", server_port.as_bytes());
    put_nv_pair(&mut params, b"GATEWAY_INTERFACE", b"CGI/1.1");

    if let Some(remote) = conn.remote_addr {
        let ip = remote.ip().to_string();
        let port = remote.port().to_string();
        put_nv_pair(&mut params, b"REMOTE_ADDR", ip.as_bytes());
        put_nv_pair(&mut params, b"REMOTE_PORT", port.as_bytes());
    }

    // Content-Type from header.
    if let Some(ct) = req.headers().get("content-type") {
        put_nv_pair(&mut params, b"CONTENT_TYPE", ct.as_bytes());
    }
    if let Some(len) = body_len {
        let len = len.to_string();
        put_nv_pair(&mut params, b"CONTENT_LENGTH", len.as_bytes());
    }

    // HTTP_* headers, excluding hop-by-hop and already-mapped headers.
    let connection_tokens = parse_connection_tokens(req.headers());
    let mut header_count = 0usize;
    for (name, value) in req.headers() {
        if header_count >= MAX_HTTP_HEADERS {
            break;
        }
        let name_str = name.as_str();
        if name_str == "content-type" || name_str == "content-length" {
            continue;
        }
        if is_hop_by_hop_header(name_str) {
            continue;
        }
        if connection_tokens.contains(name_str) {
            continue;
        }
        put_http_header_param(&mut params, name_str, value.as_bytes());
        header_count += 1;
    }

    params
}

/// Proxy an HTTP request to a FastCGI backend.
pub(crate) async fn proxy_fastcgi(
    req: Request<Body>,
    url: &Url,
    proxy_name: &str,
) -> Result<Response<Body>> {
    proxy_fastcgi_url_with_timeout(
        req,
        url,
        proxy_name,
        ClientConnInfo::default(),
        Duration::from_secs(30),
    )
    .await
}

pub(crate) async fn proxy_fastcgi_upstream(
    req: Request<Body>,
    upstream: &FastCgiUpstream,
    proxy_name: &str,
    conn: ClientConnInfo,
    route_timeout: Duration,
) -> Result<Response<Body>> {
    let timeout_dur = upstream.effective_timeout(route_timeout);
    proxy_fastcgi_backend(
        req,
        &upstream.backend,
        &upstream.params,
        proxy_name,
        conn,
        timeout_dur,
    )
    .await
}

pub(crate) async fn proxy_fastcgi_url_with_timeout(
    req: Request<Body>,
    url: &Url,
    proxy_name: &str,
    conn: ClientConnInfo,
    timeout_dur: Duration,
) -> Result<Response<Body>> {
    let backend = match url.scheme() {
        "fastcgi" => {
            let host = url
                .host_str()
                .ok_or_else(|| anyhow!("missing FastCGI host"))?;
            let port = url.port().unwrap_or(9000);
            FastCgiBackend::Tcp {
                host: host.to_string(),
                port,
            }
        }
        #[cfg(unix)]
        "fastcgi+unix" => FastCgiBackend::Unix {
            path: PathBuf::from(url.path()),
        },
        _ => return Err(anyhow!("unsupported FastCGI url scheme: {}", url.scheme())),
    };
    let empty_params = HashMap::new();
    proxy_fastcgi_backend(req, &backend, &empty_params, proxy_name, conn, timeout_dur).await
}

async fn proxy_fastcgi_backend(
    mut req: Request<Body>,
    backend: &FastCgiBackend,
    upstream_params: &HashMap<String, String>,
    _proxy_name: &str,
    conn: ClientConnInfo,
    timeout_dur: Duration,
) -> Result<Response<Body>> {
    let request_id: u16 = 1;

    // Determine request body length if known.
    let body_len_hdr = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    let body_len = body_len_hdr.or_else(|| {
        req.body()
            .size_hint()
            .exact()
            .and_then(|n| usize::try_from(n).ok())
    });

    let params_data = build_params(&req, body_len, upstream_params, conn);

    let (pool_key, mut stream) = checkout_stream(backend, timeout_dur).await?;

    // 1) BEGIN_REQUEST
    write_begin_request(&mut stream, request_id).await?;

    // 2) PARAMS
    for chunk in params_data.chunks(65535) {
        write_record(&mut stream, FCGI_PARAMS, request_id, chunk).await?;
    }
    write_record(&mut stream, FCGI_PARAMS, request_id, &[]).await?;

    // 3) STDIN (streamed)
    let mut sent = 0usize;
    while let Some(next) = req.body_mut().data().await {
        let chunk = next?;
        sent = sent.saturating_add(chunk.len());
        if let Some(expected) = body_len {
            if sent > expected {
                return Err(anyhow!("request body exceeded Content-Length"));
            }
        }
        for part in chunk.chunks(65535) {
            write_record(&mut stream, FCGI_STDIN, request_id, part).await?;
        }
    }
    if let Some(expected) = body_len_hdr {
        if sent != expected {
            return Err(anyhow!("request body shorter than Content-Length"));
        }
    }
    write_record(&mut stream, FCGI_STDIN, request_id, &[]).await?;
    stream.flush().await?;

    // 4) Read response records and stream CGI body to the client.
    let (mut sender, body) = Body::channel();
    let (hdr_tx, hdr_rx) = oneshot::channel::<Result<(StatusCode, http::HeaderMap)>>();

    tokio::spawn(async move {
        if let Err(e) =
            read_fastcgi_response(&mut stream, request_id, &mut sender, hdr_tx, timeout_dur).await
        {
            // If we haven't sent headers yet, try to surface the error.
            // If the receiver is already gone, ignore.
            sender.abort();
            warn!(error = %e, "FastCGI response read failed");
            return;
        }
        checkin_stream(pool_key, stream).await;
    });

    let (status, headers) = hdr_rx
        .await
        .map_err(|_| anyhow!("FastCGI header channel dropped"))??;
    let mut builder = Response::builder().status(status);
    *builder.headers_mut().unwrap() = headers;
    Ok(builder.body(body)?)
}

async fn read_fastcgi_response(
    stream: &mut FastCgiStream,
    request_id: u16,
    body_sender: &mut hyper::body::Sender,
    hdr_tx: oneshot::Sender<Result<(StatusCode, http::HeaderMap)>>,
    timeout_dur: Duration,
) -> Result<()> {
    let mut hdr_tx = Some(hdr_tx);
    let mut header_buf: Vec<u8> = Vec::new();
    let mut headers_sent = false;
    let mut stderr_buf: BytesMut = BytesMut::new();

    loop {
        let mut hdr = [0u8; 8];
        timeout(timeout_dur, stream.read_exact(&mut hdr))
            .await
            .map_err(|_| anyhow!("FastCGI response read timeout"))??;
        let rtype = hdr[1];
        let rid = u16::from_be_bytes([hdr[2], hdr[3]]);
        if rid != request_id && rid != 0 {
            return Err(anyhow!(
                "unexpected FastCGI request_id in response: {}",
                rid
            ));
        }
        let content_len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
        let padding_len = hdr[6] as usize;

        let total = content_len + padding_len;
        let mut body = Vec::with_capacity(total);
        if total > 0 {
            // SAFETY: `read_exact` fully initializes `total` bytes.
            unsafe {
                body.set_len(total);
            }
            timeout(timeout_dur, stream.read_exact(&mut body))
                .await
                .map_err(|_| anyhow!("FastCGI response read timeout"))??;
        }
        let mut bytes = Bytes::from(body);
        let content = bytes.split_to(content_len);

        match rtype {
            FCGI_STDOUT => {
                if content.is_empty() {
                    continue;
                }
                if !headers_sent {
                    if header_buf.len() + content.len() > MAX_CGI_HEADER_BYTES {
                        if let Some(tx) = hdr_tx.take() {
                            let _ = tx.send(Err(anyhow!("CGI headers too large")));
                        }
                        return Err(anyhow!("CGI headers too large"));
                    }
                    header_buf.extend_from_slice(&content);
                    if let Some((pos, sep_len)) = find_header_boundary(&header_buf) {
                        let header_section = &header_buf[..pos];
                        let body_start = pos + sep_len;
                        let (status, headers) = parse_cgi_headers(header_section)?;
                        headers_sent = true;
                        if let Some(tx) = hdr_tx.take() {
                            let _ = tx.send(Ok((status, headers)));
                        }
                        if body_start < header_buf.len() {
                            let rest = header_buf.split_off(body_start);
                            if !rest.is_empty() {
                                body_sender.send_data(Bytes::from(rest)).await?;
                            }
                        }
                        header_buf.clear();
                    }
                } else {
                    // Zero-copy: stream record content directly into the HTTP body channel.
                    body_sender.send_data(content).await?;
                }
            }
            FCGI_STDERR => {
                if !content.is_empty() && stderr_buf.len() < MAX_FASTCGI_STDERR_BYTES {
                    let remaining = MAX_FASTCGI_STDERR_BYTES.saturating_sub(stderr_buf.len());
                    let take = std::cmp::min(remaining, content.len());
                    stderr_buf.extend_from_slice(&content[..take]);
                }
            }
            FCGI_END_REQUEST => {
                break;
            }
            _ => {}
        }
    }

    if !headers_sent {
        if let Some(tx) = hdr_tx.take() {
            let _ = tx.send(Err(anyhow!("missing CGI header boundary")));
        }
        return Err(anyhow!("missing CGI header boundary"));
    }

    if !stderr_buf.is_empty() {
        let stderr_str = String::from_utf8_lossy(&stderr_buf);
        warn!(fastcgi_stderr = %stderr_str, "FastCGI backend stderr");
    }
    Ok(())
}

fn parse_cgi_headers(data: &[u8]) -> Result<(StatusCode, http::HeaderMap)> {
    if data.len() > MAX_CGI_HEADER_BYTES {
        return Err(anyhow!("CGI headers too large"));
    }
    let header_str = std::str::from_utf8(data)?;
    let mut status = StatusCode::OK;
    let mut headers = http::HeaderMap::new();
    let mut count = 0usize;

    for line in header_str.lines() {
        if count >= MAX_CGI_HEADER_LINES {
            return Err(anyhow!("too many CGI headers"));
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if key.eq_ignore_ascii_case("Status") {
                if let Some(code_str) = value.split_whitespace().next() {
                    if let Ok(code) = code_str.parse::<u16>() {
                        status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
                    }
                }
            } else if let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes()) {
                if let Ok(val) = http::header::HeaderValue::from_str(value) {
                    headers.append(name, val);
                }
            }
            count += 1;
        }
    }
    Ok((status, headers))
}

fn find_header_boundary(data: &[u8]) -> Option<(usize, usize)> {
    for i in 0..data.len() {
        if data[i..].starts_with(b"\r\n\r\n") {
            return Some((i, 4));
        }
        if data[i..].starts_with(b"\n\n") {
            return Some((i, 2));
        }
    }
    None
}
