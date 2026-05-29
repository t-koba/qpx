use super::*;

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

#[tokio::test]
async fn srv_discovery_skips_target_root_unavailable_records() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("_https._tcp.service.example".to_string(), DNS_TYPE_SRV),
        vec![TestDnsRecord::Srv {
            priority: 0,
            weight: 0,
            port: 8443,
            target: ".".to_string(),
            ttl_secs: 20,
        }],
    );
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let mut config = discovery_config(UpstreamDiscoveryKind::Srv);
    config.name = Some("_https._tcp.service.example".to_string());
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    let (endpoints, _delay) = result?;
    assert!(endpoints.is_empty());
    Ok(())
}
