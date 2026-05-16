use anyhow::{Context, Result, anyhow};
use http::{HeaderName, HeaderValue};
use qpx_core::config::HttpModuleConfig;
use std::collections::HashMap;

pub(super) fn parse_module_settings<T>(spec: &HttpModuleConfig) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    spec.parse_settings()
        .with_context(|| format!("invalid settings for http module {}", spec.r#type))
}

pub(super) fn compile_literal_headers(
    headers: HashMap<String, String>,
) -> Result<Vec<(HeaderName, HeaderValue)>> {
    headers
        .into_iter()
        .map(|(name, value)| {
            Ok((
                parse_header_name(name)?,
                HeaderValue::from_str(value.as_str())
                    .with_context(|| format!("invalid header value for {value}"))?,
            ))
        })
        .collect()
}

pub(super) fn parse_header_name(name: impl AsRef<str>) -> Result<HeaderName> {
    HeaderName::from_bytes(name.as_ref().trim().as_bytes())
        .map_err(|_| anyhow!("invalid header name: {}", name.as_ref()))
}
