use anyhow::{Result, anyhow};
use std::collections::HashMap;

use crate::config::types::HeaderControl;

use super::Validate;

pub(crate) fn validate_http_token(value: &str, context: &str) -> Result<()> {
    validate_non_empty_ascii(value, context)?;
    if !value.bytes().all(is_http_token_char) {
        return Err(anyhow!("{context} must be a valid HTTP token"));
    }
    Ok(())
}

pub(crate) fn validate_non_empty_ascii(value: &str, context: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{context} must not be empty"));
    }
    if !value.is_ascii() {
        return Err(anyhow!("{context} must be ASCII"));
    }
    Ok(())
}

fn is_http_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
pub(crate) fn validate_header_name(name: &str, context: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err(anyhow!("{context} header name must not be empty"));
    }
    http::header::HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| anyhow!("{context} has invalid header name: {name}"))?;
    Ok(())
}

impl Validate for HeaderControl {
    fn validate(&self, context: &str) -> Result<()> {
        validate_header_control_fields(self, context)
    }
}

pub(crate) fn validate_header_control(control: &HeaderControl, context: &str) -> Result<()> {
    control.validate(context)
}

fn validate_header_control_fields(control: &HeaderControl, context: &str) -> Result<()> {
    validate_header_map(&control.request_set, &format!("{} request_set", context))?;
    validate_header_map(&control.request_add, &format!("{} request_add", context))?;
    validate_header_remove(
        &control.request_remove,
        &format!("{} request_remove", context),
    )?;

    for (idx, item) in control.request_regex_replace.iter().enumerate() {
        if item.header.trim().is_empty() {
            return Err(anyhow!(
                "{} request_regex_replace[{}] header must not be empty",
                context,
                idx
            ));
        }
        http::header::HeaderName::from_bytes(item.header.as_bytes()).map_err(|_| {
            anyhow!(
                "{} request_regex_replace[{}] invalid header name: {}",
                context,
                idx,
                item.header
            )
        })?;
        regex::Regex::new(item.pattern.as_str()).map_err(|err| {
            anyhow!(
                "{} request_regex_replace[{}] invalid regex {}: {}",
                context,
                idx,
                item.pattern,
                err
            )
        })?;
    }

    validate_header_map(&control.response_set, &format!("{} response_set", context))?;
    validate_header_map(&control.response_add, &format!("{} response_add", context))?;
    validate_header_remove(
        &control.response_remove,
        &format!("{} response_remove", context),
    )?;

    for (idx, item) in control.response_regex_replace.iter().enumerate() {
        if item.header.trim().is_empty() {
            return Err(anyhow!(
                "{} response_regex_replace[{}] header must not be empty",
                context,
                idx
            ));
        }
        http::header::HeaderName::from_bytes(item.header.as_bytes()).map_err(|_| {
            anyhow!(
                "{} response_regex_replace[{}] invalid header name: {}",
                context,
                idx,
                item.header
            )
        })?;
        regex::Regex::new(item.pattern.as_str()).map_err(|err| {
            anyhow!(
                "{} response_regex_replace[{}] invalid regex {}: {}",
                context,
                idx,
                item.pattern,
                err
            )
        })?;
    }
    Ok(())
}

pub(crate) fn validate_header_map(map: &HashMap<String, String>, context: &str) -> Result<()> {
    for (name, value) in map {
        if name.trim().is_empty() {
            return Err(anyhow!("{context}: header name must not be empty"));
        }
        let parsed = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow!("{context}: invalid header name: {name}"))?;
        http::HeaderValue::from_str(value.as_str())
            .map_err(|_| anyhow!("{context}: invalid header value for {parsed}"))?;
    }
    Ok(())
}

fn validate_header_remove(names: &[String], context: &str) -> Result<()> {
    for name in names {
        if name.trim().is_empty() {
            return Err(anyhow!("{context}: header name must not be empty"));
        }
        http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow!("{context}: invalid header name: {name}"))?;
    }
    Ok(())
}
