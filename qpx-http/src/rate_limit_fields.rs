//! Structured response fields from draft-ietf-httpapi-ratelimit-headers.

use anyhow::{Result, anyhow};
use http::HeaderValue;

const MAX_STRUCTURED_INTEGER: u64 = 999_999_999_999_999;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitPolicyField {
    pub name: String,
    pub quota: u64,
    pub window_seconds: u64,
    pub quota_unit: Option<String>,
    pub partition_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitField {
    pub name: String,
    pub remaining: u64,
    pub reset_seconds: Option<u64>,
    pub partition_key: Option<Vec<u8>>,
}

impl RateLimitPolicyField {
    pub fn to_header_value(&self) -> Result<HeaderValue> {
        validate_integer(self.quota, "quota")?;
        validate_integer(self.window_seconds, "window")?;
        let mut value = serialize_string(self.name.as_str())?;
        value.push_str(";q=");
        value.push_str(self.quota.to_string().as_str());
        value.push_str(";w=");
        value.push_str(self.window_seconds.to_string().as_str());
        if let Some(unit) = self.quota_unit.as_deref() {
            value.push_str(";qu=");
            value.push_str(serialize_string(unit)?.as_str());
        }
        append_partition_key(&mut value, self.partition_key.as_deref());
        HeaderValue::from_str(value.as_str()).map_err(Into::into)
    }
}

impl RateLimitField {
    pub fn to_header_value(&self) -> Result<HeaderValue> {
        validate_integer(self.remaining, "remaining quota")?;
        if let Some(reset) = self.reset_seconds {
            validate_integer(reset, "reset window")?;
        }
        let mut value = serialize_string(self.name.as_str())?;
        value.push_str(";r=");
        value.push_str(self.remaining.to_string().as_str());
        if let Some(reset) = self.reset_seconds {
            value.push_str(";t=");
            value.push_str(reset.to_string().as_str());
        }
        append_partition_key(&mut value, self.partition_key.as_deref());
        HeaderValue::from_str(value.as_str()).map_err(Into::into)
    }
}

fn validate_integer(value: u64, name: &str) -> Result<()> {
    if value > MAX_STRUCTURED_INTEGER {
        return Err(anyhow!("RateLimit {name} exceeds Structured Fields range"));
    }
    Ok(())
}

fn serialize_string(value: &str) -> Result<String> {
    if !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(anyhow!("RateLimit string must contain visible ASCII only"));
    }
    let mut serialized = String::with_capacity(value.len() + 2);
    serialized.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            serialized.push('\\');
        }
        serialized.push(character);
    }
    serialized.push('"');
    Ok(serialized)
}

fn append_partition_key(output: &mut String, partition_key: Option<&[u8]>) {
    use base64::Engine as _;
    let Some(partition_key) = partition_key else {
        return;
    };
    output.push_str(";pk=:");
    base64::engine::general_purpose::STANDARD.encode_string(partition_key, output);
    output.push(':');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_policy_field() {
        let value = RateLimitPolicyField {
            name: "per-user".to_string(),
            quota: 100,
            window_seconds: 60,
            quota_unit: Some("requests".to_string()),
            partition_key: Some(b"tenant:42".to_vec()),
        }
        .to_header_value()
        .expect("RateLimit-Policy");
        assert_eq!(
            value,
            "\"per-user\";q=100;w=60;qu=\"requests\";pk=:dGVuYW50OjQy:"
        );
    }

    #[test]
    fn serializes_current_limit_field() {
        let value = RateLimitField {
            name: "per-user".to_string(),
            remaining: 42,
            reset_seconds: Some(30),
            partition_key: None,
        }
        .to_header_value()
        .expect("RateLimit");
        assert_eq!(value, "\"per-user\";r=42;t=30");
    }

    #[test]
    fn rejects_values_outside_structured_integer_range() {
        let error = RateLimitField {
            name: "default".to_string(),
            remaining: MAX_STRUCTURED_INTEGER + 1,
            reset_seconds: None,
            partition_key: None,
        }
        .to_header_value()
        .expect_err("out of range value");
        assert!(error.to_string().contains("Structured Fields range"));
    }
}
