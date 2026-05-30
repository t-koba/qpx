use super::*;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
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
    Https {
        target: Option<String>,
        alpn: Vec<&'static str>,
        port: Option<u16>,
        ipv4_hints: Vec<Ipv4Addr>,
        mandatory: Vec<u16>,
        ttl_secs: u32,
    },
    HttpsAlias {
        target: String,
        ttl_secs: u32,
    },
    HttpsRaw {
        priority: u16,
        target: Option<String>,
        params: Vec<(u16, Vec<u8>)>,
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

async fn spawn_fake_dns_rcode_server(rcode: u8) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await?;
            let mut response = build_test_dns_response(&buf[..n], &HashMap::new())?;
            response[3] = (response[3] & 0xf0) | (rcode & 0x0f);
            socket.send_to(response.as_slice(), peer).await?;
        }
    });
    Ok((addr, task))
}

async fn spawn_fake_dns_server_with_tcp_fallback(
    answers: HashMap<(String, u16), Vec<TestDnsRecord>>,
) -> Result<(SocketAddr, JoinHandle<Result<()>>, JoinHandle<Result<()>>)> {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = udp.local_addr()?;
    let tcp = TcpListener::bind(addr).await?;
    let udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, peer) = udp.recv_from(&mut buf).await?;
            let mut response = build_test_dns_response(&buf[..n], &HashMap::new())?;
            response[2] |= 0x02;
            udp.send_to(response.as_slice(), peer).await?;
        }
    });
    let tcp_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await?;
            let answers = answers.clone();
            std::mem::drop(tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                stream.read_exact(&mut len_buf).await?;
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut request = vec![0u8; len];
                stream.read_exact(request.as_mut_slice()).await?;
                let response = build_test_dns_response(request.as_slice(), &answers)?;
                let response_len = u16::try_from(response.len())?;
                stream.write_all(&response_len.to_be_bytes()).await?;
                stream.write_all(response.as_slice()).await?;
                anyhow::Ok(())
            }));
        }
    });
    Ok((addr, udp_task, tcp_task))
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
            TestDnsRecord::Https {
                target,
                alpn,
                port,
                ipv4_hints,
                mandatory,
                ttl_secs,
            } => {
                let mut rdata = Vec::with_capacity(96);
                rdata.extend_from_slice(&1u16.to_be_bytes());
                if let Some(target) = target {
                    encode_dns_name(target.as_str(), &mut rdata)?;
                } else {
                    rdata.push(0);
                }
                if !mandatory.is_empty() {
                    let mut value = Vec::with_capacity(mandatory.len() * 2);
                    for key in mandatory {
                        value.extend_from_slice(&key.to_be_bytes());
                    }
                    push_svc_param(&mut rdata, 0, value.as_slice());
                }
                let mut alpn_value = Vec::new();
                for id in alpn {
                    alpn_value.push(id.len() as u8);
                    alpn_value.extend_from_slice(id.as_bytes());
                }
                push_svc_param(&mut rdata, 1, alpn_value.as_slice());
                if let Some(port) = port {
                    push_svc_param(&mut rdata, 3, &port.to_be_bytes());
                }
                if !ipv4_hints.is_empty() {
                    let mut value = Vec::with_capacity(ipv4_hints.len() * 4);
                    for addr in ipv4_hints {
                        value.extend_from_slice(&addr.octets());
                    }
                    push_svc_param(&mut rdata, 4, value.as_slice());
                }
                response.extend_from_slice(&ttl_secs.to_be_bytes());
                response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                response.extend_from_slice(rdata.as_slice());
            }
            TestDnsRecord::HttpsAlias { target, ttl_secs } => {
                let mut rdata = Vec::with_capacity(64);
                rdata.extend_from_slice(&0u16.to_be_bytes());
                encode_dns_name(target.as_str(), &mut rdata)?;
                response.extend_from_slice(&ttl_secs.to_be_bytes());
                response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                response.extend_from_slice(rdata.as_slice());
            }
            TestDnsRecord::HttpsRaw {
                priority,
                target,
                params,
                ttl_secs,
            } => {
                let mut rdata = Vec::with_capacity(96);
                rdata.extend_from_slice(&priority.to_be_bytes());
                if let Some(target) = target {
                    encode_dns_name(target.as_str(), &mut rdata)?;
                } else {
                    rdata.push(0);
                }
                for (key, value) in params {
                    push_svc_param(&mut rdata, key, value.as_slice());
                }
                response.extend_from_slice(&ttl_secs.to_be_bytes());
                response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                response.extend_from_slice(rdata.as_slice());
            }
        }
    }

    Ok(response)
}

fn push_svc_param(out: &mut Vec<u8>, key: u16, value: &[u8]) {
    out.extend_from_slice(&key.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn build_test_dns_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut request = Vec::with_capacity(256);
    request.extend_from_slice(&id.to_be_bytes());
    request.extend_from_slice(&0x0100u16.to_be_bytes());
    request.extend_from_slice(&1u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    encode_dns_name(name, &mut request)?;
    request.extend_from_slice(&qtype.to_be_bytes());
    request.extend_from_slice(&1u16.to_be_bytes());
    Ok(request)
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

mod dns;
mod https;
mod srv;
mod validation;
