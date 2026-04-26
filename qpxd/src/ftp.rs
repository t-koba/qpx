use crate::http::body::Body;
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::config::FtpConfig;
use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use thiserror::Error;
use tokio::net::lookup_host;
use tokio::sync::Semaphore;
use tokio::task;
use tokio::time::timeout;
use tracing::warn;
use url::Url;

#[derive(Debug, Error)]
#[error("ftp request body exceeds configured limit: {0} bytes")]
struct RequestBodyTooLarge(usize);

#[derive(Debug, Error)]
#[error("ftp response body exceeds configured limit: {0} bytes")]
struct ResponseBodyTooLarge(usize);

#[derive(Debug, Error)]
#[error("ftp upstream operation timed out")]
struct OperationTimedOut;

#[derive(Debug, Error)]
#[error("ftp too many concurrent operations")]
struct TooManyConcurrentOperations;

const MAX_FTP_CONTROL_LINE: usize = 8 * 1024;

pub async fn handle_ftp(
    req: Request<Body>,
    limits: FtpConfig,
    unsupported_method_message: Arc<str>,
    semaphore: Arc<Semaphore>,
) -> Result<Response<Body>> {
    let method = req.method().clone();
    let uri = req.uri().to_string();
    let timeout_dur = StdDuration::from_millis(limits.timeout_ms.max(1));
    let body_bytes =
        match collect_body_limited(req.into_body(), limits.max_request_body_bytes, timeout_dur)
            .await
        {
            Ok(bytes) => bytes,
            Err(err) => return Ok(ftp_error(err)),
        };
    let url = match Url::parse(uri.as_str()).context("invalid ftp url") {
        Ok(url) => url,
        Err(err) => return Ok(ftp_error(err)),
    };
    let host = match url.host_str().map(ToOwned::to_owned) {
        Some(host) => host,
        None => return Ok(ftp_error(anyhow!("missing ftp host"))),
    };
    let port = url.port().unwrap_or(21);
    let user = if url.username().is_empty() {
        "anonymous".to_string()
    } else {
        url.username().to_string()
    };
    let pass = url.password().unwrap_or("anonymous@").to_string();
    let path = url.path().trim_start_matches('/').to_string();
    let is_dir_listing = url.path().ends_with('/');
    if let Err(err) = ensure_safe_ftp_path(if path.is_empty() {
        None
    } else {
        Some(path.as_str())
    }) {
        return Ok(ftp_error(err));
    }

    let addr = match timeout(timeout_dur, lookup_host((host.as_str(), port))).await {
        Ok(Ok(mut iter)) => match iter.next() {
            Some(addr) => addr,
            None => return Ok(ftp_error(anyhow!("unable to resolve ftp host"))),
        },
        Ok(Err(err)) => return Ok(ftp_error(err.into())),
        Err(_) => return Ok(ftp_error(anyhow::Error::new(OperationTimedOut))),
    };

    let permit = match timeout(timeout_dur, semaphore.acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(err)) => return Ok(ftp_error(err.into())),
        Err(_) => return Ok(ftp_error(anyhow::Error::new(TooManyConcurrentOperations))),
    };

    let max_download_bytes = limits.max_download_bytes;
    let deadline = FtpDeadline::new(timeout_dur);
    let unsupported_method_message = unsupported_method_message.clone();
    let response = match timeout(
        timeout_dur,
        task::spawn_blocking(move || {
            // Keep the permit until the blocking FTP work ends even if the caller times out.
            let _permit = permit;
            handle_blocking(BlockingFtpJob {
                method,
                addr,
                user,
                pass,
                path,
                is_dir_listing,
                body: body_bytes,
                max_download_bytes,
                deadline,
                unsupported_method_message,
            })
        }),
    )
    .await
    {
        Ok(joined) => joined?.unwrap_or_else(ftp_error),
        Err(_) => ftp_error(anyhow::Error::new(OperationTimedOut)),
    };
    Ok(response)
}

struct BlockingFtpJob {
    method: Method,
    addr: SocketAddr,
    user: String,
    pass: String,
    path: String,
    is_dir_listing: bool,
    body: Bytes,
    max_download_bytes: usize,
    deadline: FtpDeadline,
    unsupported_method_message: Arc<str>,
}

fn handle_blocking(job: BlockingFtpJob) -> Result<Response<Body>> {
    let BlockingFtpJob {
        method,
        addr,
        user,
        pass,
        path,
        is_dir_listing,
        body,
        max_download_bytes,
        deadline,
        unsupported_method_message,
    } = job;

    let path_opt = if path.is_empty() {
        None
    } else {
        Some(path.as_str())
    };
    let is_list = method.as_str().eq_ignore_ascii_case("LIST");

    if is_list || (method == Method::GET && is_dir_listing) {
        let body = list_with_mode_fallback(
            addr,
            user.as_str(),
            pass.as_str(),
            path_opt,
            max_download_bytes,
            deadline,
        )?;
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(body))?);
    }

    if method != Method::GET && method != Method::PUT {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from(unsupported_method_message.to_string()))?);
    }

    match method {
        Method::GET => {
            let buf = get_file_with_mode_fallback(
                addr,
                user.as_str(),
                pass.as_str(),
                path.as_str(),
                max_download_bytes,
                deadline,
            )?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(buf))?)
        }
        Method::PUT => {
            put_file_with_mode_fallback(
                addr,
                user.as_str(),
                pass.as_str(),
                path.as_str(),
                body.as_ref(),
                deadline,
            )?;
            Ok(Response::builder()
                .status(StatusCode::CREATED)
                .body(Body::empty())?)
        }
        _ => unreachable!("unsupported FTP methods are returned before connection setup"),
    }
}

fn list_with_mode_fallback(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: Option<&str>,
    max_download_bytes: usize,
    deadline: FtpDeadline,
) -> Result<Vec<u8>> {
    match list_once_passive(addr, user, pass, path, max_download_bytes, deadline) {
        Ok(list) => Ok(list),
        Err(passive_err) => list_once_active(addr, user, pass, path, max_download_bytes, deadline)
            .map_err(|active_err| {
                anyhow!(
                    "FTP LIST failed in passive and active mode: passive={}, active={}",
                    passive_err,
                    active_err
                )
            }),
    }
}

#[derive(Clone, Copy)]
struct FtpDeadline {
    expires_at: Instant,
}

impl FtpDeadline {
    fn new(duration: StdDuration) -> Self {
        Self {
            expires_at: Instant::now() + duration,
        }
    }

    fn remaining(self) -> Result<StdDuration> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| anyhow::Error::new(OperationTimedOut))
    }

    fn connect(self, addr: SocketAddr) -> Result<TcpStream> {
        let stream = TcpStream::connect_timeout(&addr, self.remaining()?)?;
        self.apply_timeouts(&stream)?;
        Ok(stream)
    }

    fn apply_timeouts(self, stream: &TcpStream) -> Result<()> {
        let remaining = self.remaining()?;
        stream.set_read_timeout(Some(remaining))?;
        stream.set_write_timeout(Some(remaining))?;
        Ok(())
    }
}

struct BasicFtpClient {
    reader: BufReader<TcpStream>,
    deadline: FtpDeadline,
}

#[derive(Debug)]
struct FtpReply {
    code: u16,
    lines: Vec<String>,
}

impl BasicFtpClient {
    fn connect(addr: SocketAddr, deadline: FtpDeadline) -> Result<Self> {
        let stream = deadline.connect(addr)?;
        let mut client = Self {
            reader: BufReader::new(stream),
            deadline,
        };
        client.expect_reply(&[220], "connect")?;
        Ok(client)
    }

    fn login(&mut self, user: &str, pass: &str) -> Result<()> {
        match self.command(format!("USER {user}"))?.code {
            230 => Ok(()),
            331 => {
                self.expect_command(format!("PASS {pass}"), &[230], "PASS")?;
                Ok(())
            }
            code => Err(anyhow!("FTP USER failed with status {code}")),
        }
    }

    fn control_stream(&self) -> &TcpStream {
        self.reader.get_ref()
    }

    fn command(&mut self, command: impl AsRef<str>) -> Result<FtpReply> {
        let command = command.as_ref();
        if command
            .as_bytes()
            .iter()
            .any(|b| matches!(b, b'\r' | b'\n'))
        {
            return Err(anyhow!("FTP command contains a line break"));
        }
        self.deadline.apply_timeouts(self.reader.get_ref())?;
        let stream = self.reader.get_mut();
        stream.write_all(command.as_bytes())?;
        stream.write_all(b"\r\n")?;
        stream.flush()?;
        self.read_reply()
    }

    fn expect_command(
        &mut self,
        command: impl AsRef<str>,
        expected: &[u16],
        context: &str,
    ) -> Result<FtpReply> {
        let reply = self.command(command)?;
        expect_ftp_reply(reply, expected, context)
    }

    fn expect_reply(&mut self, expected: &[u16], context: &str) -> Result<FtpReply> {
        let reply = self.read_reply()?;
        expect_ftp_reply(reply, expected, context)
    }

    fn read_reply(&mut self) -> Result<FtpReply> {
        const MAX_FTP_REPLY_LINES: usize = 64;
        const MAX_FTP_REPLY_BYTES: usize = 32 * 1024;

        let first = self.read_control_line()?;
        let code = parse_ftp_status_code(&first)?;
        let mut total_bytes = first.len();
        let mut lines = vec![first.clone()];
        let bytes = first.as_bytes();
        if bytes.get(3) == Some(&b'-') {
            loop {
                if lines.len() >= MAX_FTP_REPLY_LINES {
                    return Err(anyhow!("FTP multiline reply exceeded line limit"));
                }
                let line = self.read_control_line()?;
                total_bytes = total_bytes
                    .checked_add(line.len())
                    .ok_or_else(|| anyhow!("FTP multiline reply length overflow"))?;
                if total_bytes > MAX_FTP_REPLY_BYTES {
                    return Err(anyhow!("FTP multiline reply exceeded byte limit"));
                }
                let done = line.starts_with(&format!("{code:03} "));
                lines.push(line);
                if done {
                    break;
                }
            }
        }
        Ok(FtpReply { code, lines })
    }

    fn read_control_line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        loop {
            ensure_ftp_control_line_capacity(line.len())?;
            self.deadline.apply_timeouts(self.reader.get_ref())?;
            let mut byte = [0_u8; 1];
            match self.reader.read(&mut byte) {
                Ok(0) if line.is_empty() => return Err(anyhow!("FTP control connection closed")),
                Ok(0) => break,
                Ok(_) => {
                    line.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(anyhow::Error::new(OperationTimedOut));
                }
                Err(err) => return Err(err.into()),
            }
        }
        while line.ends_with(b"\n") || line.ends_with(b"\r") {
            line.pop();
        }
        Ok(String::from_utf8_lossy(&line).into_owned())
    }
}

fn ensure_ftp_control_line_capacity(current_len: usize) -> Result<()> {
    if current_len >= MAX_FTP_CONTROL_LINE {
        return Err(anyhow!("FTP control line exceeded configured parser limit"));
    }
    Ok(())
}

fn expect_ftp_reply(reply: FtpReply, expected: &[u16], context: &str) -> Result<FtpReply> {
    if expected.contains(&reply.code) {
        Ok(reply)
    } else {
        Err(anyhow!(
            "FTP {context} returned unexpected status {}: {}",
            reply.code,
            reply.lines.join(" | ")
        ))
    }
}

fn parse_ftp_status_code(line: &str) -> Result<u16> {
    let bytes = line.as_bytes();
    if bytes.len() < 4 || !bytes[..3].iter().all(u8::is_ascii_digit) {
        return Err(anyhow!("invalid FTP reply line"));
    }
    line[..3]
        .parse::<u16>()
        .map_err(|err| anyhow!("invalid FTP reply status: {err}"))
}

fn ensure_safe_ftp_path(path: Option<&str>) -> Result<()> {
    if let Some(path) = path {
        if path.as_bytes().iter().any(|b| matches!(b, b'\r' | b'\n')) {
            return Err(anyhow!("FTP path contains a line break"));
        }
    }
    Ok(())
}

fn list_once_passive(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: Option<&str>,
    max_download_bytes: usize,
    deadline: FtpDeadline,
) -> Result<Vec<u8>> {
    let mut client = BasicFtpClient::connect(addr, deadline)?;
    client.login(user, pass)?;
    let data_addr = passive_data_addr(&mut client)?;
    let mut data = deadline.connect(data_addr)?;
    client.expect_command(list_command(path), &[125, 150], "LIST")?;
    let raw = read_to_end_limited_deadline(&mut data, max_download_bytes, deadline)?;
    drop(data);
    client.expect_reply(&[226, 250], "LIST finalize")?;
    Ok(normalize_ftp_listing_body(raw))
}

fn list_once_active(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: Option<&str>,
    max_download_bytes: usize,
    deadline: FtpDeadline,
) -> Result<Vec<u8>> {
    let mut client = BasicFtpClient::connect(addr, deadline)?;
    client.login(user, pass)?;
    let listener = active_data_listener(client.control_stream())?;
    client.expect_command(port_command(listener.local_addr()?)?, &[200], "PORT")?;
    client.expect_command(list_command(path), &[125, 150], "LIST")?;
    let expected_peer = client.control_stream().peer_addr()?.ip();
    let mut data = accept_active_data(listener, expected_peer, deadline)?;
    let raw = read_to_end_limited_deadline(&mut data, max_download_bytes, deadline)?;
    drop(data);
    client.expect_reply(&[226, 250], "LIST finalize")?;
    Ok(normalize_ftp_listing_body(raw))
}

fn list_command(path: Option<&str>) -> String {
    match path {
        Some(path) if !path.is_empty() => format!("LIST {path}"),
        _ => "LIST".to_string(),
    }
}

fn passive_data_addr(client: &mut BasicFtpClient) -> Result<SocketAddr> {
    if let Ok(reply) = client.expect_command("EPSV", &[229], "EPSV") {
        let port = parse_epsv_port(&reply)?;
        let mut addr = client.control_stream().peer_addr()?;
        addr.set_port(port);
        return Ok(addr);
    }
    let reply = client.expect_command("PASV", &[227], "PASV")?;
    let addr = parse_pasv_addr(&reply)?;
    let peer_ip = client.control_stream().peer_addr()?.ip();
    validate_pasv_data_endpoint(peer_ip, addr)?;
    Ok(addr)
}

fn validate_pasv_data_endpoint(
    control_peer: std::net::IpAddr,
    data_addr: SocketAddr,
) -> Result<()> {
    if data_addr.ip() != control_peer {
        return Err(anyhow!(
            "refusing FTP PASV data endpoint {} because it differs from control peer {}",
            data_addr,
            control_peer
        ));
    }
    Ok(())
}

fn parse_epsv_port(reply: &FtpReply) -> Result<u16> {
    let text = reply.lines.join(" ");
    let start = text
        .find('(')
        .ok_or_else(|| anyhow!("EPSV reply missing tuple"))?;
    let end = text[start + 1..]
        .find(')')
        .map(|offset| start + 1 + offset)
        .ok_or_else(|| anyhow!("EPSV reply missing tuple terminator"))?;
    let tuple = &text[start + 1..end];
    let mut parts = tuple.split('|');
    let _empty = parts.next();
    let _af = parts.next();
    let _empty = parts.next();
    let port = parts
        .next()
        .ok_or_else(|| anyhow!("EPSV reply missing port"))?
        .parse::<u16>()
        .map_err(|err| anyhow!("invalid EPSV port: {err}"))?;
    Ok(port)
}

fn parse_pasv_addr(reply: &FtpReply) -> Result<SocketAddr> {
    let text = reply.lines.join(" ");
    let start = text
        .find('(')
        .ok_or_else(|| anyhow!("PASV reply missing tuple"))?;
    let end = text[start + 1..]
        .find(')')
        .map(|offset| start + 1 + offset)
        .ok_or_else(|| anyhow!("PASV reply missing tuple terminator"))?;
    let numbers = text[start + 1..end]
        .split(',')
        .map(str::trim)
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| anyhow!("invalid PASV tuple: {err}"))?;
    if numbers.len() != 6 {
        return Err(anyhow!("PASV reply must contain six numbers"));
    }
    let ip = Ipv4Addr::new(numbers[0], numbers[1], numbers[2], numbers[3]);
    let port = (u16::from(numbers[4]) << 8) | u16::from(numbers[5]);
    Ok(SocketAddr::new(ip.into(), port))
}

fn active_data_listener(control: &TcpStream) -> Result<TcpListener> {
    let local = control.local_addr()?;
    let ip = match local.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(anyhow!("FTP active LIST requires an IPv4 control socket"));
        }
    };
    let listener = TcpListener::bind(SocketAddr::new(ip.into(), 0))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| anyhow!("failed to configure active FTP listener: {err}"))?;
    Ok(listener)
}

fn port_command(addr: SocketAddr) -> Result<String> {
    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => return Err(anyhow!("FTP PORT command requires IPv4")),
    };
    let port = addr.port();
    Ok(format!(
        "PORT {},{},{},{},{},{}",
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        port / 256,
        port % 256
    ))
}

fn accept_active_data(
    listener: TcpListener,
    expected_peer: std::net::IpAddr,
    deadline: FtpDeadline,
) -> Result<TcpStream> {
    loop {
        deadline.remaining()?;
        match listener.accept() {
            Ok((stream, peer)) => {
                if !active_data_peer_allowed(expected_peer, peer.ip()) {
                    warn!(
                        expected = %expected_peer,
                        actual = %peer.ip(),
                        "rejecting FTP active-mode data connection from unexpected peer"
                    );
                    continue;
                }
                deadline.apply_timeouts(&stream)?;
                return Ok(stream);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(StdDuration::from_millis(20));
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn active_data_peer_allowed(
    expected_peer: std::net::IpAddr,
    actual_peer: std::net::IpAddr,
) -> bool {
    expected_peer == actual_peer
}

fn normalize_ftp_listing_body(raw: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    for mut line in raw.split(|byte| *byte == b'\n') {
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(b'\n');
        }
        out.extend_from_slice(line);
    }
    out
}

fn get_file_with_mode_fallback(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    max_download_bytes: usize,
    deadline: FtpDeadline,
) -> Result<Vec<u8>> {
    match get_file_once_passive(addr, user, pass, path, max_download_bytes, deadline) {
        Ok(data) => Ok(data),
        Err(passive_err) => {
            get_file_once_active(addr, user, pass, path, max_download_bytes, deadline).map_err(
                |active_err| {
                    anyhow!(
                        "FTP GET failed in passive and active mode: passive={}, active={}",
                        passive_err,
                        active_err
                    )
                },
            )
        }
    }
}

fn get_file_once_passive(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    max_download_bytes: usize,
    deadline: FtpDeadline,
) -> Result<Vec<u8>> {
    let mut client = BasicFtpClient::connect(addr, deadline)?;
    client.login(user, pass)?;
    let data_addr = passive_data_addr(&mut client)?;
    let mut data = deadline.connect(data_addr)?;
    client.expect_command(format!("RETR {path}"), &[125, 150], "RETR")?;
    let out = read_to_end_limited_deadline(&mut data, max_download_bytes, deadline)?;
    drop(data);
    client.expect_reply(&[226, 250], "RETR finalize")?;
    Ok(out)
}

fn get_file_once_active(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    max_download_bytes: usize,
    deadline: FtpDeadline,
) -> Result<Vec<u8>> {
    let mut client = BasicFtpClient::connect(addr, deadline)?;
    client.login(user, pass)?;
    let listener = active_data_listener(client.control_stream())?;
    client.expect_command(port_command(listener.local_addr()?)?, &[200], "PORT")?;
    client.expect_command(format!("RETR {path}"), &[125, 150], "RETR")?;
    let expected_peer = client.control_stream().peer_addr()?.ip();
    let mut data = accept_active_data(listener, expected_peer, deadline)?;
    let out = read_to_end_limited_deadline(&mut data, max_download_bytes, deadline)?;
    drop(data);
    client.expect_reply(&[226, 250], "RETR finalize")?;
    Ok(out)
}

fn put_file_with_mode_fallback(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    body: &[u8],
    deadline: FtpDeadline,
) -> Result<()> {
    match put_file_once_passive(addr, user, pass, path, body, deadline) {
        Ok(()) => Ok(()),
        Err(passive_err) => {
            put_file_once_active(addr, user, pass, path, body, deadline).map_err(|active_err| {
                anyhow!(
                    "FTP PUT failed in passive and active mode: passive={}, active={}",
                    passive_err,
                    active_err
                )
            })
        }
    }
}

fn put_file_once_passive(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    body: &[u8],
    deadline: FtpDeadline,
) -> Result<()> {
    let mut client = BasicFtpClient::connect(addr, deadline)?;
    client.login(user, pass)?;
    let data_addr = passive_data_addr(&mut client)?;
    let mut data = deadline.connect(data_addr)?;
    client.expect_command(format!("STOR {path}"), &[125, 150], "STOR")?;
    write_all_deadline(&mut data, body, deadline)?;
    drop(data);
    client.expect_reply(&[226, 250], "STOR finalize")?;
    Ok(())
}

fn put_file_once_active(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    body: &[u8],
    deadline: FtpDeadline,
) -> Result<()> {
    let mut client = BasicFtpClient::connect(addr, deadline)?;
    client.login(user, pass)?;
    let listener = active_data_listener(client.control_stream())?;
    client.expect_command(port_command(listener.local_addr()?)?, &[200], "PORT")?;
    client.expect_command(format!("STOR {path}"), &[125, 150], "STOR")?;
    let expected_peer = client.control_stream().peer_addr()?.ip();
    let mut data = accept_active_data(listener, expected_peer, deadline)?;
    write_all_deadline(&mut data, body, deadline)?;
    drop(data);
    client.expect_reply(&[226, 250], "STOR finalize")?;
    Ok(())
}

#[cfg(test)]
fn read_to_end_limited<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let next = out
            .len()
            .checked_add(read)
            .ok_or_else(|| anyhow!("ftp response body length overflow"))?;
        if next > max_bytes {
            return Err(anyhow::Error::new(ResponseBodyTooLarge(max_bytes)));
        }
        out.extend_from_slice(&chunk[..read]);
    }
    Ok(out)
}

fn read_to_end_limited_deadline(
    reader: &mut TcpStream,
    max_bytes: usize,
    deadline: FtpDeadline,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        deadline.apply_timeouts(reader)?;
        let read = match reader.read(&mut chunk) {
            Ok(read) => read,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(anyhow::Error::new(OperationTimedOut));
            }
            Err(err) => return Err(err.into()),
        };
        if read == 0 {
            break;
        }
        let next = out
            .len()
            .checked_add(read)
            .ok_or_else(|| anyhow!("ftp response body length overflow"))?;
        if next > max_bytes {
            return Err(anyhow::Error::new(ResponseBodyTooLarge(max_bytes)));
        }
        out.extend_from_slice(&chunk[..read]);
    }
    Ok(out)
}

fn write_all_deadline(
    writer: &mut TcpStream,
    mut body: &[u8],
    deadline: FtpDeadline,
) -> Result<()> {
    const WRITE_CHUNK: usize = 16 * 1024;
    while !body.is_empty() {
        deadline.apply_timeouts(writer)?;
        let len = body.len().min(WRITE_CHUNK);
        match writer.write(&body[..len]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()),
            Ok(written) => {
                body = &body[written..];
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(anyhow::Error::new(OperationTimedOut));
            }
            Err(err) => return Err(err.into()),
        }
    }
    deadline.apply_timeouts(writer)?;
    writer.flush()?;
    Ok(())
}

async fn collect_body_limited(
    mut body: Body,
    max_bytes: usize,
    body_read_timeout: StdDuration,
) -> Result<Bytes> {
    let mut out = BytesMut::new();
    while let Some(frame) = timeout(body_read_timeout, body.data())
        .await
        .map_err(|_| anyhow::Error::new(OperationTimedOut))?
    {
        let chunk = frame?;
        let next = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("ftp request body length overflow"))?;
        if next > max_bytes {
            return Err(anyhow::Error::new(RequestBodyTooLarge(max_bytes)));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

fn ftp_error(err: anyhow::Error) -> Response<Body> {
    warn!(error = ?err, "ftp upstream handling failed");
    let status = if err.downcast_ref::<RequestBodyTooLarge>().is_some() {
        StatusCode::PAYLOAD_TOO_LARGE
    } else if err.downcast_ref::<TooManyConcurrentOperations>().is_some() {
        StatusCode::SERVICE_UNAVAILABLE
    } else if err.downcast_ref::<OperationTimedOut>().is_some()
        || err.to_string().contains("timed out")
    {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::BAD_GATEWAY
    };
    let body = if status == StatusCode::PAYLOAD_TOO_LARGE {
        "payload too large".to_string()
    } else if status == StatusCode::SERVICE_UNAVAILABLE {
        "ftp busy".to_string()
    } else if status == StatusCode::GATEWAY_TIMEOUT {
        "ftp upstream timeout".to_string()
    } else {
        "ftp upstream failure".to_string()
    };
    Response::builder()
        .status(status)
        .body(Body::from(body))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_to_end_limited_accepts_within_limit() {
        let mut cursor = Cursor::new(vec![1_u8, 2, 3, 4]);
        let out = read_to_end_limited(&mut cursor, 4).expect("read");
        assert_eq!(out, vec![1_u8, 2, 3, 4]);
    }

    #[test]
    fn read_to_end_limited_rejects_over_limit() {
        let mut cursor = Cursor::new(vec![1_u8, 2, 3, 4, 5]);
        let err = read_to_end_limited(&mut cursor, 4).expect_err("must fail");
        assert!(err.downcast_ref::<ResponseBodyTooLarge>().is_some());
    }

    #[test]
    fn list_reader_rejects_over_limit_before_normalizing() {
        let mut cursor = Cursor::new(b"123\r\n45\r\n".to_vec());
        let err = read_to_end_limited(&mut cursor, 5).expect_err("must fail");
        assert!(err.downcast_ref::<ResponseBodyTooLarge>().is_some());
    }

    #[test]
    fn normalize_ftp_listing_body_matches_legacy_join_shape() {
        let out = normalize_ftp_listing_body(b"one\r\n\r\ntwo\n".to_vec());
        assert_eq!(out, b"one\ntwo");
    }

    #[test]
    fn pasv_endpoint_must_match_control_peer() {
        let peer = "203.0.113.10".parse().unwrap();
        let same = SocketAddr::new(peer, 49152);
        validate_pasv_data_endpoint(peer, same).expect("same peer");

        let redirected = SocketAddr::new("127.0.0.1".parse().unwrap(), 22);
        let err = validate_pasv_data_endpoint(peer, redirected).expect_err("redirect must fail");
        assert!(err.to_string().contains("refusing FTP PASV data endpoint"));
    }

    #[test]
    fn active_data_peer_must_match_control_peer() {
        let peer = "203.0.113.10".parse().unwrap();
        assert!(active_data_peer_allowed(peer, peer));
        assert!(!active_data_peer_allowed(
            peer,
            "198.51.100.20".parse().unwrap()
        ));
    }

    #[test]
    fn ftp_control_line_rejects_before_unbounded_allocation() {
        let err = ensure_ftp_control_line_capacity(MAX_FTP_CONTROL_LINE)
            .expect_err("oversized control line must fail");
        assert!(err.to_string().contains("FTP control line exceeded"));
    }

    #[tokio::test]
    async fn collect_body_limited_rejects_over_limit() {
        let body = Body::from("12345");
        let err = collect_body_limited(body, 4, StdDuration::from_secs(1))
            .await
            .expect_err("must fail");
        assert!(err.downcast_ref::<RequestBodyTooLarge>().is_some());
    }

    #[tokio::test]
    async fn collect_body_limited_times_out_idle_body() {
        let (_sender, body) = Body::channel();
        let err = collect_body_limited(body, 4, StdDuration::from_millis(10))
            .await
            .expect_err("idle body must time out");
        assert!(err.downcast_ref::<OperationTimedOut>().is_some());
    }
}
