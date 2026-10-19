use anyhow::{Result, anyhow};
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::Duration;

pub(crate) async fn resolve_remote_addr_with_xdp(
    stream: TcpStream,
    remote_addr: SocketAddr,
    xdp_cfg: Option<&super::CompiledXdpConfig>,
    metadata_timeout: Duration,
) -> Result<(
    crate::http::protocol::io_prefix::PrefixedIo<TcpStream>,
    SocketAddr,
)> {
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
                crate::http::protocol::io_prefix::PrefixedIo::new(stream, Bytes::new()),
                remote_addr,
            ));
        }
        let result =
            super::consume_proxy_metadata(&mut stream, xdp_cfg.require_metadata, metadata_timeout)
                .await?;
        let effective_remote = result.meta.and_then(|meta| meta.src).unwrap_or(remote_addr);
        return Ok((
            crate::http::protocol::io_prefix::PrefixedIo::new(stream, result.prefix),
            effective_remote,
        ));
    }
    Ok((
        crate::http::protocol::io_prefix::PrefixedIo::new(stream, Bytes::new()),
        remote_addr,
    ))
}

#[cfg(test)]
mod tests {
    use crate::xdp::remote::*;
    use cidr::IpCidr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (src, dst) else {
            panic!("test helper only supports ipv4");
        };
        let mut bytes = vec![
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
            0x00, 0x0c,
        ];
        bytes.extend_from_slice(&src.ip().octets());
        bytes.extend_from_slice(&dst.ip().octets());
        bytes.extend_from_slice(&src.port().to_be_bytes());
        bytes.extend_from_slice(&dst.port().to_be_bytes());
        bytes
    }

    #[tokio::test]
    async fn resolve_remote_addr_with_xdp_dgram_uses_unspec_fallback() {
        for require_metadata in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .expect("connect");
            let (stream, remote_addr) = listener.accept().await.expect("accept");
            let mut proxy = proxy_v2_header(
                "10.1.2.3:40123".parse().unwrap(),
                "203.0.113.7:443".parse().unwrap(),
            );
            proxy[13] = 0x12; // IPv4 DGRAM metadata on a TCP connection.
            let payload = b"GET /status HTTP/1.1\r\n\r\n";
            proxy.extend_from_slice(payload);
            client
                .write_all(&proxy)
                .await
                .expect("write frame and payload");
            client.shutdown().await.expect("shutdown write");

            let cfg = super::super::CompiledXdpConfig {
                require_metadata,
                trusted_peers: vec!["127.0.0.0/8".parse::<IpCidr>().expect("cidr")],
            };
            let result = resolve_remote_addr_with_xdp(
                stream,
                remote_addr,
                Some(&cfg),
                Duration::from_secs(1),
            )
            .await;
            if require_metadata {
                let err = result
                    .err()
                    .expect("required metadata rejects DGRAM fallback");
                assert!(err.to_string().contains("proxy metadata required"));
            } else {
                let (mut prefixed, effective_remote) = result.expect("optional metadata");
                assert_eq!(effective_remote, remote_addr);
                let mut received = Vec::new();
                prefixed
                    .read_to_end(&mut received)
                    .await
                    .expect("read payload");
                assert_eq!(received, payload);
            }
        }
    }

    #[tokio::test]
    async fn resolve_remote_addr_with_xdp_uses_proxy_source_for_trusted_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let listen_addr = listener.local_addr().expect("local addr");
        let payload = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let client_payload = payload.clone();
        let proxy = proxy_v2_header(
            "10.1.2.3:40123".parse().expect("src"),
            "203.0.113.7:443".parse().expect("dst"),
        );

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(listen_addr).await.expect("connect");
            stream.write_all(&proxy).await.expect("write proxy");
            stream
                .write_all(&client_payload)
                .await
                .expect("write payload");
        });

        let (stream, remote_addr) = listener.accept().await.expect("accept");
        let cfg = super::super::CompiledXdpConfig {
            require_metadata: true,
            trusted_peers: vec!["127.0.0.0/8".parse::<IpCidr>().expect("cidr")],
        };
        let (mut prefixed, effective_remote) =
            resolve_remote_addr_with_xdp(stream, remote_addr, Some(&cfg), Duration::from_secs(1))
                .await
                .expect("resolve");

        assert_eq!(effective_remote, "10.1.2.3:40123".parse().unwrap());
        let mut buf = vec![0u8; payload.len()];
        prefixed.read_exact(&mut buf).await.expect("read prefixed");
        assert_eq!(buf, payload);
        client.await.expect("client");
    }

    #[tokio::test]
    async fn resolve_remote_addr_with_xdp_preserves_socket_peer_for_untrusted_optional_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let listen_addr = listener.local_addr().expect("local addr");
        let payload = b"GET /status HTTP/1.1\r\n\r\n".to_vec();
        let client_payload = payload.clone();

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(listen_addr).await.expect("connect");
            stream
                .write_all(&client_payload)
                .await
                .expect("write payload");
        });

        let (stream, remote_addr) = listener.accept().await.expect("accept");
        let cfg = super::super::CompiledXdpConfig {
            require_metadata: false,
            trusted_peers: vec!["10.0.0.0/8".parse::<IpCidr>().expect("cidr")],
        };
        let (mut prefixed, effective_remote) =
            resolve_remote_addr_with_xdp(stream, remote_addr, Some(&cfg), Duration::from_secs(1))
                .await
                .expect("resolve");

        assert_eq!(effective_remote, remote_addr);
        let mut buf = vec![0u8; payload.len()];
        prefixed.read_exact(&mut buf).await.expect("read prefixed");
        assert_eq!(buf, payload);
        client.await.expect("client");
    }
}
