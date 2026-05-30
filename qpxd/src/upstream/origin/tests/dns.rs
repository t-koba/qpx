use super::*;

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
async fn dns_discovery_retries_truncated_udp_response_over_tcp() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 12,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    let (nameserver, udp_server, tcp_server) =
        spawn_fake_dns_server_with_tcp_fallback(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    udp_server.abort();
    tcp_server.abort();
    let _ = udp_server.await;
    let _ = tcp_server.await;

    let (endpoints, delay) = result?;
    assert_eq!(delay, Duration::from_secs(12));
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].connect_authority(443)?, "127.0.0.10:443");
    Ok(())
}

#[tokio::test]
async fn dns_discovery_falls_back_after_resolver_error_rcode() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    let (bad_nameserver, bad_server) = spawn_fake_dns_rcode_server(2).await?;
    let (good_nameserver, good_server) = spawn_fake_dns_server(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example:9443",
        &config,
        &[bad_nameserver, good_nameserver],
    )
    .await;

    bad_server.abort();
    good_server.abort();
    let _ = bad_server.await;
    let _ = good_server.await;

    let (endpoints, _) = result?;
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].connect_authority(443)?, "127.0.0.10:9443");
    Ok(())
}
