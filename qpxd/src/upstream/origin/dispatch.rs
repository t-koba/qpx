use anyhow::{anyhow, Result};

use super::OriginEndpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OriginScheme {
    Http,
    Https,
    Ws,
    Wss,
    Ipc,
    IpcUnix,
}

pub(super) fn origin_scheme(origin: &OriginEndpoint) -> Result<OriginScheme> {
    scheme_from_upstream(origin.upstream.as_str())
}

pub(super) fn scheme_from_upstream(upstream: &str) -> Result<OriginScheme> {
    if upstream.starts_with("ipc+unix://") {
        return Ok(OriginScheme::IpcUnix);
    }
    if upstream.starts_with("ipc://") {
        return Ok(OriginScheme::Ipc);
    }
    let parsed = super::parse_origin_target(upstream)?;
    match parsed.scheme.as_deref() {
        Some("http") | Some("h2c") => Ok(OriginScheme::Http),
        Some("https") | Some("h2") => Ok(OriginScheme::Https),
        Some("ws") => Ok(OriginScheme::Ws),
        Some("wss") => Ok(OriginScheme::Wss),
        Some(other) => Err(anyhow!("unsupported origin scheme: {}", other)),
        None => Err(anyhow!("origin scheme required for upstream HTTP dispatch")),
    }
}

pub(super) fn default_port_for_scheme(scheme: &str) -> u16 {
    match scheme {
        "http" | "ws" | "h2c" => 80,
        "https" | "wss" | "h2" => 443,
        _ => 443,
    }
}
