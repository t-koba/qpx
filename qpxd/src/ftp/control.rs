use super::transfer::FtpDataTransfer;
use super::{MAX_FTP_CONTROL_LINE, MAX_FTP_DEADLINE, OperationTimedOut};
use anyhow::{Result, anyhow};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration as StdDuration, Instant};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::warn;

pub(super) async fn open_list_with_mode_fallback(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: Option<&str>,
    deadline: FtpDeadline,
) -> Result<FtpDataTransfer> {
    match open_list_once_passive(addr, user, pass, path, deadline).await {
        Ok(list) => Ok(list),
        Err(passive_err) => open_list_once_active(addr, user, pass, path, deadline)
            .await
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
pub(super) struct FtpDeadline {
    expires_at: Instant,
}

impl FtpDeadline {
    pub(super) fn new(duration: StdDuration) -> Self {
        Self {
            expires_at: crate::runtime::std_deadline_after(duration.min(MAX_FTP_DEADLINE)),
        }
    }

    pub(super) fn remaining(self) -> Result<StdDuration> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| anyhow::Error::new(OperationTimedOut))
    }

    pub(super) async fn connect(self, addr: SocketAddr) -> Result<TcpStream> {
        timeout(self.remaining()?, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow::Error::new(OperationTimedOut))?
            .map_err(Into::into)
    }
}

pub(super) struct BasicFtpClient {
    reader: BufReader<TcpStream>,
    pub(super) deadline: FtpDeadline,
}

#[derive(Debug)]
pub(super) struct FtpReply {
    code: u16,
    lines: Vec<String>,
}

impl BasicFtpClient {
    pub(super) async fn connect(addr: SocketAddr, deadline: FtpDeadline) -> Result<Self> {
        let stream = deadline.connect(addr).await?;
        let mut client = Self {
            reader: BufReader::new(stream),
            deadline,
        };
        client.expect_reply(&[220], "connect").await?;
        Ok(client)
    }

    pub(super) async fn login(&mut self, user: &str, pass: &str) -> Result<()> {
        match self.command(format!("USER {user}")).await?.code {
            230 => Ok(()),
            331 => {
                self.expect_command(format!("PASS {pass}"), &[230], "PASS")
                    .await?;
                Ok(())
            }
            code => Err(anyhow!("FTP USER failed with status {code}")),
        }
    }

    pub(super) fn control_stream(&self) -> &TcpStream {
        self.reader.get_ref()
    }

    async fn command(&mut self, command: impl AsRef<str>) -> Result<FtpReply> {
        let command = command.as_ref();
        if command
            .as_bytes()
            .iter()
            .any(|b| matches!(b, b'\r' | b'\n'))
        {
            return Err(anyhow!("FTP command contains a line break"));
        }
        let stream = self.reader.get_mut();
        timeout(
            self.deadline.remaining()?,
            stream.write_all(command.as_bytes()),
        )
        .await
        .map_err(|_| anyhow::Error::new(OperationTimedOut))??;
        timeout(self.deadline.remaining()?, stream.write_all(b"\r\n"))
            .await
            .map_err(|_| anyhow::Error::new(OperationTimedOut))??;
        timeout(self.deadline.remaining()?, stream.flush())
            .await
            .map_err(|_| anyhow::Error::new(OperationTimedOut))??;
        self.read_reply().await
    }

    pub(super) async fn expect_command(
        &mut self,
        command: impl AsRef<str>,
        expected: &[u16],
        context: &str,
    ) -> Result<FtpReply> {
        let reply = self.command(command).await?;
        expect_ftp_reply(reply, expected, context)
    }

    pub(super) async fn expect_reply(
        &mut self,
        expected: &[u16],
        context: &str,
    ) -> Result<FtpReply> {
        let reply = self.read_reply().await?;
        expect_ftp_reply(reply, expected, context)
    }

    async fn read_reply(&mut self) -> Result<FtpReply> {
        const MAX_FTP_REPLY_LINES: usize = 64;
        const MAX_FTP_REPLY_BYTES: usize = 32 * 1024;

        let first = self.read_control_line().await?;
        let code = parse_ftp_status_code(&first)?;
        let mut total_bytes = first.len();
        let mut lines = vec![first.clone()];
        let bytes = first.as_bytes();
        if bytes.get(3) == Some(&b'-') {
            loop {
                if lines.len() >= MAX_FTP_REPLY_LINES {
                    return Err(anyhow!("FTP multiline reply exceeded line limit"));
                }
                let line = self.read_control_line().await?;
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

    async fn read_control_line(&mut self) -> Result<String> {
        read_ftp_control_line(&mut self.reader, self.deadline).await
    }
}

pub(super) async fn read_ftp_control_line<R>(
    reader: &mut R,
    deadline: FtpDeadline,
) -> Result<String>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let chunk = timeout(deadline.remaining()?, reader.fill_buf())
            .await
            .map_err(|_| anyhow::Error::new(OperationTimedOut))??;
        if chunk.is_empty() && line.is_empty() {
            return Err(anyhow!("FTP control connection closed"));
        }
        if chunk.is_empty() {
            break;
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(chunk.len(), |index| index + 1);
        let next_len = line
            .len()
            .checked_add(take)
            .ok_or_else(|| anyhow!("FTP control line length overflow"))?;
        if next_len > MAX_FTP_CONTROL_LINE {
            return Err(anyhow!("FTP control line exceeded configured parser limit"));
        }
        line.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    while line.ends_with(b"\n") || line.ends_with(b"\r") {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
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

pub(super) fn ensure_safe_ftp_path(path: Option<&str>) -> Result<()> {
    if let Some(path) = path
        && path.as_bytes().iter().any(|b| matches!(b, b'\r' | b'\n'))
    {
        return Err(anyhow!("FTP path contains a line break"));
    }
    Ok(())
}

async fn open_list_once_passive(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: Option<&str>,
    deadline: FtpDeadline,
) -> Result<FtpDataTransfer> {
    let mut client = BasicFtpClient::connect(addr, deadline).await?;
    client.login(user, pass).await?;
    let data_addr = passive_data_addr(&mut client).await?;
    let data = deadline.connect(data_addr).await?;
    client
        .expect_command(list_command(path), &[125, 150], "LIST")
        .await?;
    Ok(FtpDataTransfer {
        client,
        data,
        finalize_context: "LIST finalize",
    })
}

async fn open_list_once_active(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: Option<&str>,
    deadline: FtpDeadline,
) -> Result<FtpDataTransfer> {
    let mut client = BasicFtpClient::connect(addr, deadline).await?;
    client.login(user, pass).await?;
    let listener = active_data_listener(client.control_stream()).await?;
    client
        .expect_command(port_command(listener.local_addr()?)?, &[200], "PORT")
        .await?;
    client
        .expect_command(list_command(path), &[125, 150], "LIST")
        .await?;
    let expected_peer = client.control_stream().peer_addr()?.ip();
    let data = accept_active_data(listener, expected_peer, deadline).await?;
    Ok(FtpDataTransfer {
        client,
        data,
        finalize_context: "LIST finalize",
    })
}

fn list_command(path: Option<&str>) -> String {
    match path {
        Some(path) if !path.is_empty() => format!("LIST {path}"),
        _ => "LIST".to_string(),
    }
}

pub(super) async fn passive_data_addr(client: &mut BasicFtpClient) -> Result<SocketAddr> {
    if let Ok(reply) = client.expect_command("EPSV", &[229], "EPSV").await {
        let port = parse_epsv_port(&reply)?;
        let mut addr = client.control_stream().peer_addr()?;
        addr.set_port(port);
        return Ok(addr);
    }
    let reply = client.expect_command("PASV", &[227], "PASV").await?;
    let addr = parse_pasv_addr(&reply)?;
    let peer_ip = client.control_stream().peer_addr()?.ip();
    validate_pasv_data_endpoint(peer_ip, addr)?;
    Ok(addr)
}

pub(super) fn validate_pasv_data_endpoint(
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

pub(super) async fn active_data_listener(control: &TcpStream) -> Result<TcpListener> {
    let local = control.local_addr()?;
    let ip = match local.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(anyhow!("FTP active LIST requires an IPv4 control socket"));
        }
    };
    TcpListener::bind(SocketAddr::new(ip.into(), 0))
        .await
        .map_err(Into::into)
}

pub(super) fn port_command(addr: SocketAddr) -> Result<String> {
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

pub(super) async fn accept_active_data(
    listener: TcpListener,
    expected_peer: std::net::IpAddr,
    deadline: FtpDeadline,
) -> Result<TcpStream> {
    loop {
        match timeout(deadline.remaining()?, listener.accept()).await {
            Err(_) => return Err(anyhow::Error::new(OperationTimedOut)),
            Ok(Ok((stream, peer))) => {
                if !active_data_peer_allowed(expected_peer, peer.ip()) {
                    warn!(
                        expected = %expected_peer,
                        actual = %peer.ip(),
                        "rejecting FTP active-mode data connection from unexpected peer"
                    );
                    continue;
                }
                return Ok(stream);
            }
            Ok(Err(err)) => return Err(err.into()),
        }
    }
}

pub(super) fn active_data_peer_allowed(
    expected_peer: std::net::IpAddr,
    actual_peer: std::net::IpAddr,
) -> bool {
    expected_peer == actual_peer
}
