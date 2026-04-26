use super::*;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use qpx_core::config::{UpstreamDiscoveryConfig, UpstreamDiscoveryKind};

#[derive(Clone)]
enum TestDnsRecord {
    A {
        addr: Ipv4Addr,
        ttl_secs: u32,
    },
    Aaaa {
        addr: Ipv6Addr,
        ttl_secs: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
        ttl_secs: u32,
    },
}

async fn spawn_fake_dns_server(
    answers: HashMap<(String, u16), Vec<TestDnsRecord>>,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await?;
            let response = build_test_dns_response(&buf[..n], &answers)?;
            socket.send_to(response.as_slice(), peer).await?;
        }
    });
    Ok((addr, task))
}

fn build_test_dns_response(
    request: &[u8],
    answers: &HashMap<(String, u16), Vec<TestDnsRecord>>,
) -> Result<Vec<u8>> {
    if request.len() < 12 {
        return Err(anyhow!("dns request too short"));
    }
    let query_id = u16::from_be_bytes([request[0], request[1]]);
    let (name, next) = parse_dns_name(request, 12)?;
    if next + 4 > request.len() {
        return Err(anyhow!("dns question truncated"));
    }
    let qtype = u16::from_be_bytes([request[next], request[next + 1]]);
    let question_end = next + 4;
    let mut response = Vec::with_capacity(512);
    let records = answers
        .get(&(name.to_ascii_lowercase(), qtype))
        .cloned()
        .unwrap_or_default();

    response.extend_from_slice(&query_id.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&(records.len() as u16).to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&request[12..question_end]);

    for record in records {
        response.extend_from_slice(&0xc00cu16.to_be_bytes());
        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        match record {
            TestDnsRecord::A { addr, ttl_secs } => {
                response.extend_from_slice(&ttl_secs.to_be_bytes());
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&addr.octets());
            }
            TestDnsRecord::Aaaa { addr, ttl_secs } => {
                response.extend_from_slice(&ttl_secs.to_be_bytes());
                response.extend_from_slice(&16u16.to_be_bytes());
                response.extend_from_slice(&addr.octets());
            }
            TestDnsRecord::Srv {
                priority,
                weight,
                port,
                target,
                ttl_secs,
            } => {
                let mut rdata = Vec::with_capacity(64);
                rdata.extend_from_slice(&priority.to_be_bytes());
                rdata.extend_from_slice(&weight.to_be_bytes());
                rdata.extend_from_slice(&port.to_be_bytes());
                encode_dns_name(target.as_str(), &mut rdata)?;
                response.extend_from_slice(&ttl_secs.to_be_bytes());
                response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                response.extend_from_slice(rdata.as_slice());
            }
        }
    }

    Ok(response)
}

fn discovery_config(kind: UpstreamDiscoveryKind) -> UpstreamDiscoveryConfig {
    UpstreamDiscoveryConfig {
        kind,
        name: None,
        port: None,
        interval_ms: 30_000,
        min_ttl_ms: 1_000,
        max_ttl_ms: 30_000,
    }
}

#[tokio::test]
async fn dns_discovery_resolves_connect_authority_and_refresh_delay() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 12,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let mut config = discovery_config(UpstreamDiscoveryKind::Dns);
    config.port = Some(8443);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    let (endpoints, delay) = result?;
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].connect_authority(443)?, "127.0.0.10:8443");
    assert_eq!(
        endpoints[0].host_header_authority(443)?,
        "service.example:443"
    );
    assert_eq!(endpoints[0].tls_server_name()?, "service.example");
    assert_eq!(delay, Duration::from_secs(12));
    Ok(())
}

#[tokio::test]
async fn srv_discovery_uses_logical_sni_and_clamps_ttl() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("_https._tcp.service.example".to_string(), DNS_TYPE_SRV),
        vec![TestDnsRecord::Srv {
            priority: 10,
            weight: 5,
            port: 8443,
            target: "node1.service.example".to_string(),
            ttl_secs: 20,
        }],
    );
    answers.insert(
        ("node1.service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 11),
            ttl_secs: 2,
        }],
    );
    answers.insert(
        ("node1.service.example".to_string(), DNS_TYPE_AAAA),
        vec![TestDnsRecord::Aaaa {
            addr: Ipv6Addr::LOCALHOST,
            ttl_secs: 40,
        }],
    );
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let mut config = discovery_config(UpstreamDiscoveryKind::Srv);
    config.name = Some("_https._tcp.service.example".to_string());
    config.min_ttl_ms = 5_000;
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    let (endpoints, delay) = result?;
    assert_eq!(delay, Duration::from_secs(5));
    assert_eq!(endpoints.len(), 2);
    let authorities = endpoints
        .iter()
        .map(|endpoint| endpoint.connect_authority(443))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(authorities[0], "127.0.0.11:8443");
    assert_eq!(authorities[1], "[::1]:8443");
    for endpoint in &endpoints {
        assert_eq!(endpoint.host_header_authority(443)?, "service.example:443");
        assert_eq!(endpoint.tls_server_name()?, "service.example");
    }
    Ok(())
}
