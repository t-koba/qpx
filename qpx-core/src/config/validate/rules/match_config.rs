use anyhow::{Result, anyhow};

use crate::config::types::{
    CertificateMatchConfig, IdentityMatchConfig, MatchConfig, RpcMatchConfig,
};

use super::header::{validate_header_name, validate_non_empty_ascii};
use super::{Validate, validate_optional};

impl Validate for MatchConfig {
    fn validate(&self, context: &str) -> Result<()> {
        validate_match_fields(self, context)
    }
}

pub(crate) fn validate_match_config(raw: Option<&MatchConfig>, context: &str) -> Result<()> {
    validate_optional(raw, context)
}

fn validate_match_fields(raw: &MatchConfig, context: &str) -> Result<()> {
    validate_pattern_list(raw.query.as_slice(), &format!("{context} match.query"))?;
    validate_pattern_list(
        raw.authority.as_slice(),
        &format!("{context} match.authority"),
    )?;
    validate_pattern_list(raw.scheme.as_slice(), &format!("{context} match.scheme"))?;
    validate_pattern_list(
        raw.http_version.as_slice(),
        &format!("{context} match.http_version"),
    )?;
    validate_pattern_list(raw.alpn.as_slice(), &format!("{context} match.alpn"))?;
    validate_pattern_list(
        raw.tls_version.as_slice(),
        &format!("{context} match.tls_version"),
    )?;
    validate_pattern_list(
        raw.request_size.as_slice(),
        &format!("{context} match.request_size"),
    )?;
    validate_destination_match_config(
        raw.destination.as_ref(),
        &format!("{context} match.destination"),
    )?;
    validate_numeric_patterns(
        raw.response_status.as_slice(),
        &format!("{context} match.response_status"),
    )?;
    validate_numeric_patterns(
        raw.response_size.as_slice(),
        &format!("{context} match.response_size"),
    )?;
    if let Some(fingerprint) = raw.tls_fingerprint.as_ref() {
        validate_pattern_list(
            fingerprint.ja3.as_slice(),
            &format!("{context} match.tls_fingerprint.ja3"),
        )?;
        validate_pattern_list(
            fingerprint.ja4.as_slice(),
            &format!("{context} match.tls_fingerprint.ja4"),
        )?;
    }
    validate_certificate_match_config(
        raw.client_cert.as_ref(),
        &format!("{context} match.client_cert"),
    )?;
    validate_certificate_match_config(
        raw.upstream_cert.as_ref(),
        &format!("{context} match.upstream_cert"),
    )?;
    validate_rpc_match_config(raw.rpc.as_ref(), &format!("{context} match.rpc"))?;
    Ok(())
}

fn validate_destination_match_config(
    raw: Option<&crate::config::DestinationMatchConfig>,
    context: &str,
) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    for (label, dimension) in [
        ("category", raw.category.as_ref()),
        ("reputation", raw.reputation.as_ref()),
        ("application", raw.application.as_ref()),
    ] {
        let Some(dimension) = dimension else {
            continue;
        };
        validate_pattern_list(
            dimension.value.as_slice(),
            &format!("{context}.{label}.value"),
        )?;
        validate_pattern_list(
            dimension.source.as_slice(),
            &format!("{context}.{label}.source"),
        )?;
        validate_numeric_patterns(
            dimension.confidence.as_slice(),
            &format!("{context}.{label}.confidence"),
        )?;
        if dimension.value.is_empty()
            && dimension.source.is_empty()
            && dimension.confidence.is_empty()
        {
            return Err(anyhow!(
                "{context}.{label} must configure at least one field"
            ));
        }
    }
    Ok(())
}

fn validate_rpc_match_config(raw: Option<&RpcMatchConfig>, context: &str) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    validate_pattern_list(raw.protocol.as_slice(), &format!("{context}.protocol"))?;
    validate_pattern_list(raw.service.as_slice(), &format!("{context}.service"))?;
    validate_pattern_list(raw.method.as_slice(), &format!("{context}.method"))?;
    validate_pattern_list(raw.streaming.as_slice(), &format!("{context}.streaming"))?;
    validate_pattern_list(raw.status.as_slice(), &format!("{context}.status"))?;
    validate_numeric_patterns(
        raw.message_size.as_slice(),
        &format!("{context}.message_size"),
    )?;
    validate_pattern_list(raw.message.as_slice(), &format!("{context}.message"))?;
    for (idx, trailer) in raw.trailers.iter().enumerate() {
        validate_header_name(
            trailer.name.as_str(),
            &format!("{context}.trailers[{idx}].name"),
        )?;
        if let Some(value) = trailer.value.as_deref() {
            validate_non_empty_ascii(value, &format!("{context}.trailers[{idx}].value"))?;
        }
        if let Some(regex) = trailer.regex.as_deref() {
            validate_non_empty_ascii(regex, &format!("{context}.trailers[{idx}].regex"))?;
            regex::Regex::new(regex)
                .map_err(|err| anyhow!("{context}.trailers[{idx}].regex is invalid: {err}"))?;
        }
        if trailer.value.is_none() && trailer.regex.is_none() {
            return Err(anyhow!("{context}.trailers[{idx}] must set value or regex"));
        }
    }
    if raw.protocol.is_empty()
        && raw.service.is_empty()
        && raw.method.is_empty()
        && raw.streaming.is_empty()
        && raw.status.is_empty()
        && raw.message_size.is_empty()
        && raw.message.is_empty()
        && raw.trailers.is_empty()
    {
        return Err(anyhow!("{context} must configure at least one field"));
    }
    Ok(())
}

pub(crate) fn validate_certificate_match_config(
    raw: Option<&CertificateMatchConfig>,
    context: &str,
) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    validate_pattern_list(raw.subject.as_slice(), &format!("{context}.subject"))?;
    validate_pattern_list(raw.issuer.as_slice(), &format!("{context}.issuer"))?;
    validate_pattern_list(raw.san_dns.as_slice(), &format!("{context}.san_dns"))?;
    validate_pattern_list(raw.san_uri.as_slice(), &format!("{context}.san_uri"))?;
    validate_pattern_list(
        raw.fingerprint_sha256.as_slice(),
        &format!("{context}.fingerprint_sha256"),
    )?;
    if raw.present.is_none()
        && raw.subject.is_empty()
        && raw.issuer.is_empty()
        && raw.san_dns.is_empty()
        && raw.san_uri.is_empty()
        && raw.fingerprint_sha256.is_empty()
    {
        return Err(anyhow!("{context} must configure at least one field"));
    }
    Ok(())
}

pub(crate) fn validate_pattern_list(values: &[String], context: &str) -> Result<()> {
    for value in values {
        if value.trim().is_empty() {
            return Err(anyhow!("{context} entries must not be empty"));
        }
    }
    Ok(())
}

fn validate_numeric_patterns(values: &[String], context: &str) -> Result<()> {
    for value in values {
        parse_numeric_matcher(value)
            .map_err(|e| anyhow!("{context} has invalid matcher {value}: {e}"))?;
    }
    Ok(())
}

fn parse_numeric_matcher(raw: &str) -> Result<(Option<u64>, Option<u64>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("empty matcher"));
    }
    if let Some(rest) = raw.strip_prefix(">=") {
        return Ok((Some(parse_numeric_value(rest)?), None));
    }
    if let Some(rest) = raw.strip_prefix('>') {
        let value = parse_numeric_value(rest)?;
        return Ok((Some(value.saturating_add(1)), None));
    }
    if let Some(rest) = raw.strip_prefix("<=") {
        return Ok((None, Some(parse_numeric_value(rest)?)));
    }
    if let Some(rest) = raw.strip_prefix('<') {
        let value = parse_numeric_value(rest)?;
        return Ok((None, Some(value.saturating_sub(1))));
    }
    if let Some((start, end)) = raw.split_once('-') {
        let start = parse_numeric_value(start)?;
        let end = parse_numeric_value(end)?;
        if start > end {
            return Err(anyhow!("range start must be <= end"));
        }
        return Ok((Some(start), Some(end)));
    }
    let exact = parse_numeric_value(raw)?;
    Ok((Some(exact), Some(exact)))
}

fn parse_numeric_value(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("empty numeric value"));
    }
    let (digits, scale) = match raw.chars().last().unwrap_or_default() {
        'k' | 'K' => (&raw[..raw.len() - 1], 1024u64),
        'm' | 'M' => (&raw[..raw.len() - 1], 1024u64 * 1024),
        'g' | 'G' => (&raw[..raw.len() - 1], 1024u64 * 1024 * 1024),
        _ => (raw, 1u64),
    };
    let value = digits
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow!("must be an integer"))?;
    value
        .checked_mul(scale)
        .ok_or_else(|| anyhow!("numeric value overflow"))
}

pub(crate) fn validate_identity_match_config(
    identity: Option<&IdentityMatchConfig>,
    context: &str,
) -> Result<()> {
    let Some(identity) = identity else {
        return Ok(());
    };
    for (label, values) in [
        ("user", identity.user.as_slice()),
        ("groups", identity.groups.as_slice()),
        ("device_id", identity.device_id.as_slice()),
        ("posture", identity.posture.as_slice()),
        ("tenant", identity.tenant.as_slice()),
        ("auth_strength", identity.auth_strength.as_slice()),
        ("idp", identity.idp.as_slice()),
    ] {
        for value in values {
            if value.trim().is_empty() {
                return Err(anyhow!(
                    "{context} match.identity.{label} entries must not be empty"
                ));
            }
        }
    }
    Ok(())
}
