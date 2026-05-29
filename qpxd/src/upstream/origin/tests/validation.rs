use super::*;

#[test]
fn dns_response_validation_requires_matching_question_and_success_header() -> Result<()> {
    let query = build_test_dns_query(0x1234, "service.example", DNS_TYPE_A)?;
    let mut answers = HashMap::new();
    answers.insert(
        ("service.example".to_string(), DNS_TYPE_A),
        vec![TestDnsRecord::A {
            addr: Ipv4Addr::new(127, 0, 0, 10),
            ttl_secs: 30,
        }],
    );
    let response = build_test_dns_response(query.as_slice(), &answers)?;
    assert!(dns_response_matches_query(
        response.as_slice(),
        0x1234,
        "SERVICE.example.",
        DNS_TYPE_A
    )?);
    assert!(!dns_response_matches_query(
        response.as_slice(),
        0x1235,
        "service.example",
        DNS_TYPE_A
    )?);
    assert!(!dns_response_matches_query(
        response.as_slice(),
        0x1234,
        "other.example",
        DNS_TYPE_A
    )?);
    assert!(!dns_response_matches_query(
        response.as_slice(),
        0x1234,
        "service.example",
        DNS_TYPE_AAAA
    )?);

    let mut nxdomain = response.clone();
    nxdomain[3] = 0x83;
    nxdomain[6] = 0;
    nxdomain[7] = 0;
    assert!(dns_response_matches_query(
        nxdomain.as_slice(),
        0x1234,
        "service.example",
        DNS_TYPE_A
    )?);

    let mut servfail = response.clone();
    servfail[3] = 0x82;
    assert!(!dns_response_matches_query(
        servfail.as_slice(),
        0x1234,
        "service.example",
        DNS_TYPE_A
    )?);

    let mut truncated = response.clone();
    truncated[2] |= 0x02;
    assert!(!dns_response_matches_query(
        truncated.as_slice(),
        0x1234,
        "service.example",
        DNS_TYPE_A
    )?);
    Ok(())
}
