#[cfg(test)]
use super::ResponseBodyTooLarge;
use super::control::{
    BasicFtpClient, FtpDeadline, accept_active_data, active_data_listener, passive_data_addr,
    port_command,
};
use super::transfer::FtpDataTransfer;
use super::{OperationTimedOut, RequestBodyTooLarge};
use crate::http::body::Body;
use anyhow::{Result, anyhow};
#[cfg(test)]
use std::io::Read;
use std::net::SocketAddr;
#[cfg(test)]
use std::time::Duration as StdDuration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub(super) async fn open_get_file_with_mode_fallback(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    deadline: FtpDeadline,
) -> Result<FtpDataTransfer> {
    match open_get_file_once_passive(addr, user, pass, path, deadline).await {
        Ok(data) => Ok(data),
        Err(passive_err) => open_get_file_once_active(addr, user, pass, path, deadline)
            .await
            .map_err(|active_err| {
                anyhow!(
                    "FTP GET failed in passive and active mode: passive={}, active={}",
                    passive_err,
                    active_err
                )
            }),
    }
}

async fn open_get_file_once_passive(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    deadline: FtpDeadline,
) -> Result<FtpDataTransfer> {
    let mut client = BasicFtpClient::connect(addr, deadline).await?;
    client.login(user, pass).await?;
    let data_addr = passive_data_addr(&mut client).await?;
    let data = deadline.connect(data_addr).await?;
    client
        .expect_command(format!("RETR {path}"), &[125, 150], "RETR")
        .await?;
    Ok(FtpDataTransfer {
        client,
        data,
        finalize_context: "RETR finalize",
    })
}

async fn open_get_file_once_active(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    deadline: FtpDeadline,
) -> Result<FtpDataTransfer> {
    let mut client = BasicFtpClient::connect(addr, deadline).await?;
    client.login(user, pass).await?;
    let listener = active_data_listener(client.control_stream()).await?;
    client
        .expect_command(port_command(listener.local_addr()?)?, &[200], "PORT")
        .await?;
    client
        .expect_command(format!("RETR {path}"), &[125, 150], "RETR")
        .await?;
    let expected_peer = client.control_stream().peer_addr()?.ip();
    let data = accept_active_data(listener, expected_peer, deadline).await?;
    Ok(FtpDataTransfer {
        client,
        data,
        finalize_context: "RETR finalize",
    })
}

pub(super) async fn put_file_with_mode_fallback(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    body: Body,
    max_body_bytes: usize,
    deadline: FtpDeadline,
) -> Result<()> {
    let transfer = match open_put_once_passive(addr, user, pass, path, deadline).await {
        Ok(transfer) => transfer,
        Err(passive_err) => open_put_once_active(addr, user, pass, path, deadline)
            .await
            .map_err(|active_err| {
                anyhow!(
                    "FTP PUT failed in passive and active mode: passive={}, active={}",
                    passive_err,
                    active_err
                )
            })?,
    };
    write_ftp_upload_body(transfer, body, max_body_bytes).await
}

async fn open_put_once_passive(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    deadline: FtpDeadline,
) -> Result<FtpDataTransfer> {
    let mut client = BasicFtpClient::connect(addr, deadline).await?;
    client.login(user, pass).await?;
    let data_addr = passive_data_addr(&mut client).await?;
    let data = deadline.connect(data_addr).await?;
    client
        .expect_command(format!("STOR {path}"), &[125, 150], "STOR")
        .await?;
    Ok(FtpDataTransfer {
        client,
        data,
        finalize_context: "STOR finalize",
    })
}

async fn open_put_once_active(
    addr: SocketAddr,
    user: &str,
    pass: &str,
    path: &str,
    deadline: FtpDeadline,
) -> Result<FtpDataTransfer> {
    let mut client = BasicFtpClient::connect(addr, deadline).await?;
    client.login(user, pass).await?;
    let listener = active_data_listener(client.control_stream()).await?;
    client
        .expect_command(port_command(listener.local_addr()?)?, &[200], "PORT")
        .await?;
    client
        .expect_command(format!("STOR {path}"), &[125, 150], "STOR")
        .await?;
    let expected_peer = client.control_stream().peer_addr()?.ip();
    let data = accept_active_data(listener, expected_peer, deadline).await?;
    Ok(FtpDataTransfer {
        client,
        data,
        finalize_context: "STOR finalize",
    })
}

async fn write_ftp_upload_body(
    transfer: FtpDataTransfer,
    body: Body,
    max_body_bytes: usize,
) -> Result<()> {
    let FtpDataTransfer {
        mut client,
        mut data,
        finalize_context,
    } = transfer;
    stream_ftp_upload_to_data(body, &mut data, max_body_bytes, client.deadline).await?;
    drop(data);
    client.expect_reply(&[226, 250], finalize_context).await?;
    Ok(())
}

#[cfg(test)]
pub(super) fn read_to_end_limited<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>> {
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

async fn stream_ftp_upload_to_data(
    mut body: Body,
    writer: &mut TcpStream,
    max_bytes: usize,
    deadline: FtpDeadline,
) -> Result<()> {
    let mut seen = 0usize;
    while let Some(frame) = timeout(deadline.remaining()?, body.data())
        .await
        .map_err(|_| anyhow::Error::new(OperationTimedOut))?
    {
        let chunk = match frame {
            Ok(chunk) => chunk,
            Err(err) => return Err(err.into()),
        };
        let next = seen
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("ftp request body length overflow"))?;
        if next > max_bytes {
            return Err(anyhow::Error::new(RequestBodyTooLarge(max_bytes)));
        }
        seen = next;
        timeout(deadline.remaining()?, writer.write_all(chunk.as_ref()))
            .await
            .map_err(|_| anyhow::Error::new(OperationTimedOut))??;
    }
    timeout(deadline.remaining()?, writer.shutdown())
        .await
        .map_err(|_| anyhow::Error::new(OperationTimedOut))??;
    Ok(())
}

#[cfg(test)]
pub(super) async fn stream_ftp_upload_body(
    mut body: Body,
    max_bytes: usize,
    body_read_timeout: StdDuration,
) -> Result<()> {
    let mut seen = 0usize;
    while let Some(frame) = timeout(body_read_timeout, body.data())
        .await
        .map_err(|_| anyhow::Error::new(OperationTimedOut))?
    {
        let chunk = frame.map_err(anyhow::Error::from)?;
        let next = seen
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("ftp request body length overflow"))?;
        if next > max_bytes {
            return Err(anyhow::Error::new(RequestBodyTooLarge(max_bytes)));
        }
        seen = next;
    }
    Ok(())
}
