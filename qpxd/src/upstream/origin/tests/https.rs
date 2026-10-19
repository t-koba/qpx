use super::*;

#[tokio::test]
async fn dns_discovery_adds_https_rr_h3_endpoints() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_HTTPS),
        vec![TestDnsRecord::Https {
            target: None,
            alpn: vec!["h3", "h2"],
            port: Some(9443),
            ipv4_hints: vec![Ipv4Addr::new(127, 0, 0, 12)],
            mandatory: Vec::new(),
            ttl_secs: 5,
        }],
    );
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
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
    assert_eq!(endpoints[0].connect_authority(443)?, "127.0.0.10:443");
    assert_eq!(endpoints[1].connect_authority(443)?, "127.0.0.12:9443");
    assert_eq!(
        endpoints[1].host_header_authority(443)?,
        "service.example:443"
    );
    assert_eq!(endpoints[1].tls_server_name()?, "service.example");
    assert!(endpoints[1].label().starts_with("h3://service.example:443"));
    Ok(())
}

#[tokio::test]
async fn dns_discovery_follows_https_alias_mode_for_h3_endpoints() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_HTTPS),
        vec![TestDnsRecord::HttpsAlias {
            target: "alias.example".to_string(),
            ttl_secs: 2,
        }],
    );
    answers.insert(
        ("alias.example".to_string(), DNS_TYPE_HTTPS),
        vec![TestDnsRecord::Https {
            target: None,
            alpn: vec!["h3"],
            port: Some(9443),
            ipv4_hints: vec![Ipv4Addr::new(127, 0, 0, 12)],
            mandatory: Vec::new(),
            ttl_secs: 20,
        }],
    );
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    let (endpoints, delay) = result?;
    assert_eq!(delay, Duration::from_secs(2));
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[1].connect_authority(443)?, "127.0.0.12:9443");
    assert_eq!(endpoints[1].tls_server_name()?, "service.example");
    Ok(())
}

#[tokio::test]
async fn dns_discovery_resolves_alias_service_mode_dot_owner_without_hints() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_HTTPS),
        vec![TestDnsRecord::HttpsAlias {
            target: "alias.example".to_string(),
            ttl_secs: 2,
        }],
    );
    answers.insert(
        ("alias.example".to_string(), DNS_TYPE_HTTPS),
        vec![TestDnsRecord::Https {
            target: None,
            alpn: vec!["h3"],
            port: Some(9443),
            ipv4_hints: Vec::new(),
            mandatory: Vec::new(),
            ttl_secs: 4,
        }],
    );
    answers.insert(
        ("alias.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 13),
            ttl_secs: 30,
        }],
    );
    answers.insert(("alias.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    let (endpoints, delay) = result?;
    assert_eq!(delay, Duration::from_secs(2));
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[1].connect_authority(443)?, "127.0.0.13:9443");
    assert_eq!(endpoints[1].tls_server_name()?, "service.example");
    Ok(())
}

#[tokio::test]
async fn dns_discovery_orders_https_service_mode_by_priority() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_HTTPS),
        vec![
            TestDnsRecord::HttpsRaw {
                priority: 20,
                target: None,
                params: vec![
                    (1, vec![2, b'h', b'3']),
                    (4, Ipv4Addr::new(127, 0, 0, 20).octets().to_vec()),
                ],
                ttl_secs: 5,
            },
            TestDnsRecord::HttpsRaw {
                priority: 1,
                target: None,
                params: vec![
                    (1, vec![2, b'h', b'3']),
                    (4, Ipv4Addr::new(127, 0, 0, 11).octets().to_vec()),
                ],
                ttl_secs: 5,
            },
        ],
    );
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    let (endpoints, _delay) = result?;
    assert_eq!(endpoints.len(), 3);
    assert_eq!(endpoints[1].connect_authority(443)?, "127.0.0.11:443");
    assert_eq!(endpoints[2].connect_authority(443)?, "127.0.0.20:443");
    Ok(())
}

#[tokio::test]
async fn dns_discovery_skips_https_rr_with_unsupported_mandatory_param() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_HTTPS),
        vec![TestDnsRecord::Https {
            target: None,
            alpn: vec!["h3"],
            port: Some(9443),
            ipv4_hints: vec![Ipv4Addr::new(127, 0, 0, 12)],
            mandatory: vec![65000],
            ttl_secs: 5,
        }],
    );
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    let (endpoints, _delay) = result?;
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].connect_authority(443)?, "127.0.0.10:443");
    Ok(())
}

#[tokio::test]
async fn dns_discovery_skips_https_rr_with_missing_mandatory_param() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_HTTPS),
        vec![TestDnsRecord::Https {
            target: None,
            alpn: vec!["h3"],
            port: None,
            ipv4_hints: vec![Ipv4Addr::new(127, 0, 0, 12)],
            mandatory: vec![3],
            ttl_secs: 5,
        }],
    );
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    let (endpoints, _delay) = result?;
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].connect_authority(443)?, "127.0.0.10:443");
    Ok(())
}

#[tokio::test]
async fn dns_discovery_skips_https_rr_with_mandatory_self_reference() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    answers.insert(("service.example".to_string(), DNS_TYPE_AAAA), Vec::new());
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_HTTPS),
        vec![TestDnsRecord::Https {
            target: None,
            alpn: vec!["h3"],
            port: Some(9443),
            ipv4_hints: vec![Ipv4Addr::new(127, 0, 0, 12)],
            mandatory: vec![0],
            ttl_secs: 5,
        }],
    );
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    let (endpoints, _delay) = result?;
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].connect_authority(443)?, "127.0.0.10:443");
    Ok(())
}

#[tokio::test]
async fn dns_discovery_falls_back_to_a_and_aaaa_when_https_rrset_is_malformed() -> Result<()> {
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_AAAA),
        vec![TestDnsRecord::Aaaa {
            addr: Ipv6Addr::LOCALHOST,
            ttl_secs: 30,
        }],
    );
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_HTTPS),
        vec![
            TestDnsRecord::HttpsRaw {
                priority: 1,
                target: None,
                params: vec![
                    (1, vec![2, b'h', b'3']),
                    (4, Ipv4Addr::new(127, 0, 0, 12).octets().to_vec()),
                ],
                ttl_secs: 5,
            },
            TestDnsRecord::HttpsRaw {
                priority: 1,
                target: None,
                params: vec![(1, vec![2, b'h', b'3']), (3, vec![0x12])],
                ttl_secs: 5,
            },
        ],
    );
    let (nameserver, server) = spawn_fake_dns_server(answers).await?;

    let config = discovery_config(UpstreamDiscoveryKind::Dns);
    let result = discover_origin_endpoints_with_nameservers(
        "https://service.example",
        &config,
        &[nameserver],
    )
    .await;

    server.abort();
    let _ = server.await;

    // One malformed HTTPS record invalidates its whole RRset, preserving only
    // ordinary A/AAAA discovery and preventing the otherwise valid h3 record.
    let (endpoints, delay) = result?;
    assert_eq!(delay, Duration::from_secs(30));
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0].connect_authority(443)?, "127.0.0.10:443");
    assert_eq!(endpoints[1].connect_authority(443)?, "[::1]:443");
    Ok(())
}
