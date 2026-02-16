use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn resolve_remote_addr_with_xdp(
    stream: &mut TcpStream,
    remote_addr: SocketAddr,
    xdp_cfg: Option<&super::CompiledXdpConfig>,
    metadata_timeout: Duration,
) -> Result<SocketAddr> {
    if let Some(xdp_cfg) = xdp_cfg {
        let trusted = super::peer_is_trusted(remote_addr.ip(), &xdp_cfg.trusted_peers);
        if !trusted {
            if xdp_cfg.require_metadata {
                return Err(anyhow!(
                    "proxy metadata required but peer is not trusted: {}",
                    remote_addr
                ));
            }
            return Ok(remote_addr);
        }
        let meta = match timeout(
            metadata_timeout,
            super::consume_proxy_metadata(
                stream,
                xdp_cfg.require_metadata,
                xdp_cfg.metadata_mode.clone(),
            ),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                if xdp_cfg.require_metadata {
                    return Err(anyhow!("proxy metadata read timed out"));
                }
                let mut peek = [0u8; 16];
                let n = stream.peek(&mut peek).await.unwrap_or(0);
                if n > 0
                    && super::looks_like_proxy_header_prefix(
                        xdp_cfg.metadata_mode.clone(),
                        &peek[..n],
                    )
                {
                    return Err(anyhow!("proxy metadata read timed out"));
                }
                return Ok(remote_addr);
            }
        };
        if let Some(meta) = meta {
            if let Some(src) = meta.src {
                return Ok(src);
            }
        }
    }
    Ok(remote_addr)
}
