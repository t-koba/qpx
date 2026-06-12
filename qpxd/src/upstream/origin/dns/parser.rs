use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{DNS_CLASS_IN, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_HTTPS, DNS_TYPE_SRV};

#[derive(Debug, Clone)]
pub(super) struct DnsARecord {
    pub(super) addr: IpAddr,
    pub(super) ttl_secs: u32,
}

#[derive(Debug, Clone)]
pub(super) struct DnsSrvRecord {
    pub(super) priority: u16,
    pub(super) weight: u16,
    pub(super) port: u16,
    pub(super) target: String,
    pub(super) ttl_secs: u32,
}

#[derive(Debug, Clone)]
pub(super) struct DnsHttpsRecord {
    pub(super) owner_name: String,
    pub(super) priority: u16,
    pub(super) target: Option<String>,
    pub(super) alpn: Vec<String>,
    pub(super) port: Option<u16>,
    pub(super) ipv4_hints: Vec<Ipv4Addr>,
    pub(super) ipv6_hints: Vec<Ipv6Addr>,
    pub(super) mandatory: Vec<u16>,
    pub(super) svc_param_keys: HashSet<u16>,
    pub(super) ttl_secs: u32,
}

#[cfg(test)]
pub(in crate::upstream::origin) fn dns_response_matches_query(
    response: &[u8],
    expected_id: u16,
    expected_name: &str,
    expected_qtype: u16,
) -> Result<bool> {
    Ok(matches!(
        dns_response_query_status(response, expected_id, expected_name, expected_qtype)?,
        DnsResponseStatus::Success
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DnsResponseStatus {
    Mismatch,
    Success,
    ErrorRcode(u8),
}

pub(super) fn dns_response_query_status(
    response: &[u8],
    expected_id: u16,
    expected_name: &str,
    expected_qtype: u16,
) -> Result<DnsResponseStatus> {
    if response.len() < 12 {
        return Ok(DnsResponseStatus::Mismatch);
    }
    let id = u16::from_be_bytes([response[0], response[1]]);
    if id != expected_id {
        return Ok(DnsResponseStatus::Mismatch);
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 || flags & 0x0200 != 0 || flags & 0x7800 != 0 {
        return Ok(DnsResponseStatus::Mismatch);
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    if qdcount != 1 {
        return Ok(DnsResponseStatus::Mismatch);
    }
    let (question_name, next) = parse_dns_name(response, 12)?;
    if next + 4 > response.len() {
        return Ok(DnsResponseStatus::Mismatch);
    }
    let qtype = u16::from_be_bytes([response[next], response[next + 1]]);
    let qclass = u16::from_be_bytes([response[next + 2], response[next + 3]]);
    if normalize_dns_name(question_name.as_str()) != normalize_dns_name(expected_name)
        || qtype != expected_qtype
        || qclass != DNS_CLASS_IN
    {
        return Ok(DnsResponseStatus::Mismatch);
    }
    let rcode = (flags & 0x000f) as u8;
    match rcode {
        0 | 3 => Ok(DnsResponseStatus::Success),
        other => Ok(DnsResponseStatus::ErrorRcode(other)),
    }
}

pub(super) fn dns_response_is_truncated_match(
    response: &[u8],
    expected_id: u16,
    expected_name: &str,
    expected_qtype: u16,
) -> Result<bool> {
    if response.len() < 12 {
        return Ok(false);
    }
    let id = u16::from_be_bytes([response[0], response[1]]);
    if id != expected_id {
        return Ok(false);
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 || flags & 0x0200 == 0 || flags & 0x7800 != 0 {
        return Ok(false);
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    if qdcount != 1 {
        return Ok(false);
    }
    let (question_name, next) = parse_dns_name(response, 12)?;
    if next + 4 > response.len() {
        return Ok(false);
    }
    let qtype = u16::from_be_bytes([response[next], response[next + 1]]);
    let qclass = u16::from_be_bytes([response[next + 2], response[next + 3]]);
    Ok(
        normalize_dns_name(question_name.as_str()) == normalize_dns_name(expected_name)
            && qtype == expected_qtype
            && qclass == DNS_CLASS_IN,
    )
}

pub(super) fn normalize_dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

pub(super) fn parse_address_records(response: &[u8], qtype: u16) -> Result<Vec<DnsARecord>> {
    let answers = parse_answer_records(response)?;
    let mut records = Vec::new();
    for answer in answers {
        if answer.qtype != qtype || answer.class != DNS_CLASS_IN {
            continue;
        }
        match qtype {
            DNS_TYPE_A if answer.rdata.len() == 4 => records.push(DnsARecord {
                addr: IpAddr::V4(Ipv4Addr::new(
                    answer.rdata[0],
                    answer.rdata[1],
                    answer.rdata[2],
                    answer.rdata[3],
                )),
                ttl_secs: answer.ttl,
            }),
            DNS_TYPE_AAAA if answer.rdata.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(answer.rdata.as_slice());
                records.push(DnsARecord {
                    addr: IpAddr::V6(Ipv6Addr::from(octets)),
                    ttl_secs: answer.ttl,
                });
            }
            _ => {}
        }
    }
    Ok(records)
}

pub(super) fn parse_srv_records(response: &[u8]) -> Result<Vec<DnsSrvRecord>> {
    let answers = parse_answer_records(response)?;
    let mut records = Vec::new();
    for answer in answers {
        if answer.qtype != DNS_TYPE_SRV || answer.class != DNS_CLASS_IN || answer.rdata.len() < 6 {
            continue;
        }
        let priority = u16::from_be_bytes([answer.rdata[0], answer.rdata[1]]);
        let weight = u16::from_be_bytes([answer.rdata[2], answer.rdata[3]]);
        let port = u16::from_be_bytes([answer.rdata[4], answer.rdata[5]]);
        let (target, _) = parse_dns_name(answer.rdata.as_slice(), 6)?;
        if target.is_empty() {
            continue;
        }
        records.push(DnsSrvRecord {
            priority,
            weight,
            port,
            target,
            ttl_secs: answer.ttl,
        });
    }
    Ok(records)
}

pub(super) fn parse_https_records(response: &[u8]) -> Result<Vec<DnsHttpsRecord>> {
    let answers = parse_answer_records(response)?;
    let mut records = Vec::new();
    for answer in answers {
        if answer.qtype != DNS_TYPE_HTTPS || answer.class != DNS_CLASS_IN || answer.rdata.len() < 3
        {
            continue;
        }
        let (priority, mut offset) = (
            u16::from_be_bytes([answer.rdata[0], answer.rdata[1]]),
            2usize,
        );
        let (target, next) = parse_dns_name(answer.rdata.as_slice(), offset)?;
        offset = next;
        let mut record = DnsHttpsRecord {
            owner_name: answer.owner_name,
            priority,
            target: (!target.is_empty()).then_some(target),
            alpn: Vec::new(),
            port: None,
            ipv4_hints: Vec::new(),
            ipv6_hints: Vec::new(),
            mandatory: Vec::new(),
            svc_param_keys: HashSet::new(),
            ttl_secs: answer.ttl,
        };
        let mut last_key = None::<u16>;
        let mut malformed = false;
        while offset + 4 <= answer.rdata.len() {
            let key = u16::from_be_bytes([answer.rdata[offset], answer.rdata[offset + 1]]);
            if last_key.is_some_and(|last| key <= last) {
                malformed = true;
                break;
            }
            last_key = Some(key);
            let len =
                u16::from_be_bytes([answer.rdata[offset + 2], answer.rdata[offset + 3]]) as usize;
            offset += 4;
            let end = offset + len;
            if end > answer.rdata.len() {
                return Err(anyhow!("HTTPS DNS SvcParam truncated"));
            }
            parse_https_svc_param(key, &answer.rdata[offset..end], &mut record)?;
            offset = end;
        }
        if malformed {
            continue;
        }
        if record.priority == 0 {
            if record.target.is_some()
                && record.alpn.is_empty()
                && record.port.is_none()
                && record.ipv4_hints.is_empty()
                && record.ipv6_hints.is_empty()
                && record.mandatory.is_empty()
            {
                records.push(record);
            }
            continue;
        }
        if record.mandatory.iter().any(|key| {
            *key == 0 || !is_supported_https_svc_param(*key) || !record.svc_param_keys.contains(key)
        }) {
            continue;
        }
        records.push(record);
    }
    Ok(records)
}

fn parse_https_svc_param(key: u16, value: &[u8], record: &mut DnsHttpsRecord) -> Result<()> {
    record.svc_param_keys.insert(key);
    match key {
        0 => {
            if !value.len().is_multiple_of(2) {
                return Err(anyhow!("HTTPS DNS mandatory SvcParam truncated"));
            }
            record.mandatory.extend(
                value
                    .chunks_exact(2)
                    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]])),
            );
        }
        1 => {
            let mut offset = 0usize;
            while offset < value.len() {
                let len = value[offset] as usize;
                offset += 1;
                let end = offset + len;
                if end > value.len() {
                    return Err(anyhow!("HTTPS DNS alpn value truncated"));
                }
                record
                    .alpn
                    .push(std::str::from_utf8(&value[offset..end])?.to_string());
                offset = end;
            }
        }
        3 if value.len() == 2 => {
            record.port = Some(u16::from_be_bytes([value[0], value[1]]));
        }
        4 if value.len().is_multiple_of(4) => {
            for chunk in value.chunks_exact(4) {
                record
                    .ipv4_hints
                    .push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
            }
        }
        6 if value.len().is_multiple_of(16) => {
            for chunk in value.chunks_exact(16) {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(chunk);
                record.ipv6_hints.push(Ipv6Addr::from(octets));
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_supported_https_svc_param(key: u16) -> bool {
    matches!(key, 0 | 1 | 3 | 4 | 6)
}

pub(super) fn h3_upstream_for_logical_origin(logical_host: &str, logical_port: u16) -> String {
    format!(
        "h3://{}",
        qpx_http::protocol::address::format_authority_host_port(logical_host, logical_port)
    )
}

struct AnswerRecord {
    pub(super) owner_name: String,
    pub(super) qtype: u16,
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) rdata: Vec<u8>,
}

fn parse_answer_records(response: &[u8]) -> Result<Vec<AnswerRecord>> {
    if response.len() < 12 {
        return Err(anyhow!("DNS response too short"));
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..qdcount {
        let (_, next) = parse_dns_name(response, offset)?;
        if next + 4 > response.len() {
            return Err(anyhow!("DNS question truncated"));
        }
        offset = next + 4;
    }

    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (owner_name, next) = parse_dns_name(response, offset)?;
        if next + 10 > response.len() {
            return Err(anyhow!("DNS answer truncated"));
        }
        let qtype = u16::from_be_bytes([response[next], response[next + 1]]);
        let class = u16::from_be_bytes([response[next + 2], response[next + 3]]);
        let ttl = u32::from_be_bytes([
            response[next + 4],
            response[next + 5],
            response[next + 6],
            response[next + 7],
        ]);
        let rdlength = u16::from_be_bytes([response[next + 8], response[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > response.len() {
            return Err(anyhow!("DNS answer rdata truncated"));
        }
        answers.push(AnswerRecord {
            owner_name,
            qtype,
            class,
            ttl,
            rdata: response[rdata_start..rdata_end].to_vec(),
        });
        offset = rdata_end;
    }
    Ok(answers)
}

pub(in crate::upstream::origin) fn parse_dns_name(
    buf: &[u8],
    offset: usize,
) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut consumed = None::<usize>;
    let mut jumps = 0usize;

    loop {
        if pos >= buf.len() {
            return Err(anyhow!("DNS name out of bounds"));
        }
        let len = buf[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= buf.len() {
                return Err(anyhow!("DNS compression pointer truncated"));
            }
            let pointer = (((len as u16 & 0x3f) << 8) | buf[pos + 1] as u16) as usize;
            if consumed.is_none() {
                consumed = Some(pos + 2);
            }
            pos = pointer;
            jumps += 1;
            if jumps > 16 {
                return Err(anyhow!("DNS compression pointer loop"));
            }
            continue;
        }
        if len == 0 {
            let next = consumed.unwrap_or(pos + 1);
            return Ok((labels.join("."), next));
        }
        if len & 0xc0 != 0 {
            return Err(anyhow!("invalid DNS label length"));
        }
        let label_len = len as usize;
        let start = pos + 1;
        let end = start + label_len;
        if end > buf.len() {
            return Err(anyhow!("DNS label truncated"));
        }
        labels.push(std::str::from_utf8(&buf[start..end])?.to_string());
        pos = end;
    }
}

pub(in crate::upstream::origin) fn encode_dns_name(name: &str, out: &mut Vec<u8>) -> Result<()> {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(anyhow!("DNS label too long"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}
