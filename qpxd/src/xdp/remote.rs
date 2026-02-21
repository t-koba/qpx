use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::Duration;

pub async fn resolve_remote_addr_with_xdp(
    stream: TcpStream,
    remote_addr: SocketAddr,
    xdp_cfg: Option<&super::CompiledXdpConfig>,
    metadata_timeout: Duration,
) -> Result<(crate::io_prefix::PrefixedIo<TcpStream>, SocketAddr)> {
    let mut stream = stream;
    if let Some(xdp_cfg) = xdp_cfg {
        let trusted = super::peer_is_trusted(remote_addr.ip(), &xdp_cfg.trusted_peers);
        if !trusted {
            if xdp_cfg.require_metadata {
                return Err(anyhow!(
                    "proxy metadata required but peer is not trusted: {}",
                    remote_addr
                ));
            }
            return Ok((
                crate::io_prefix::PrefixedIo::new(stream, Bytes::new()),
                remote_addr,
            ));
        }
        let result =
            super::consume_proxy_metadata(&mut stream, xdp_cfg.require_metadata, metadata_timeout)
                .await?;
        let effective_remote = result.meta.and_then(|meta| meta.src).unwrap_or(remote_addr);
        return Ok((
            crate::io_prefix::PrefixedIo::new(stream, result.prefix),
            effective_remote,
        ));
    }
    Ok((
        crate::io_prefix::PrefixedIo::new(stream, Bytes::new()),
        remote_addr,
    ))
}
