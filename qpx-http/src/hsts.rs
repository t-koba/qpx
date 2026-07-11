//! RFC 6797 Strict Transport Security response policy.

use http::HeaderValue;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HstsPolicy {
    pub max_age_seconds: u64,
    pub include_subdomains: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HstsError {
    #[error("HSTS max-age must be greater than zero")]
    ZeroMaxAge,
    #[error("HSTS policy cannot be represented as an HTTP field value")]
    InvalidHeaderValue,
}

impl HstsPolicy {
    pub fn to_header_value(self) -> Result<HeaderValue, HstsError> {
        if self.max_age_seconds == 0 {
            return Err(HstsError::ZeroMaxAge);
        }
        let mut value = format!("max-age={}", self.max_age_seconds);
        if self.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        HeaderValue::from_str(&value).map_err(|_| HstsError::InvalidHeaderValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_hsts_policy() {
        assert_eq!(
            HstsPolicy {
                max_age_seconds: 31_536_000,
                include_subdomains: true,
            }
            .to_header_value()
            .expect("HSTS"),
            "max-age=31536000; includeSubDomains"
        );
    }
}
