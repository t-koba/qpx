use anyhow::{Result, anyhow};
use std::sync::Arc;

mod dispatch;
mod dns;
mod http_backend;
mod ipc_backend;
mod ws_backend;

pub(crate) use dns::discover_origin_endpoints;
#[cfg(all(
    feature = "http3",
    any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        feature = "http3-backend-qpx"
    )
))]
pub(crate) use dns::resolve_upstream_socket_addr;
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) use http_backend::H3OriginPool;
pub(crate) use http_backend::{
    DirectOriginPools, proxy_http, proxy_http_with_interim_timeout, shared_reverse_https_request,
};
pub(crate) use ws_backend::proxy_websocket;

#[cfg(test)]
use dns::{
    DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_HTTPS, DNS_TYPE_SRV,
    discover_origin_endpoints_with_nameservers, dns_response_matches_query, encode_dns_name,
    parse_dns_name,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OriginEndpoint {
    pub(crate) upstream: String,
    label: Arc<str>,
    parsed: Option<ParsedOriginTarget>,
    connect_host: Option<String>,
    connect_port: Option<u16>,
    logical_host: Option<String>,
    logical_port: Option<u16>,
    tls_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ParsedOriginTarget {
    pub(super) scheme: Option<String>,
    pub(super) host: String,
    pub(super) port: Option<u16>,
}

impl OriginEndpoint {
    pub(crate) fn direct(upstream: impl Into<String>) -> Self {
        let upstream = upstream.into();
        let parsed = parse_origin_target(upstream.as_str()).ok();
        let label = Arc::<str>::from(upstream.as_str());
        Self {
            upstream,
            label,
            parsed,
            connect_host: None,
            connect_port: None,
            logical_host: None,
            logical_port: None,
            tls_name: None,
        }
    }

    pub(crate) fn discovered(
        base_upstream: &str,
        connect_host: String,
        connect_port: u16,
        logical_host: String,
        logical_port: u16,
        tls_name: String,
    ) -> Self {
        let parsed = parse_origin_target(base_upstream).ok();
        let upstream = base_upstream.to_string();
        let connect = qpx_http::protocol::address::format_authority_host_port(
            connect_host.as_str(),
            connect_port,
        );
        let logical = qpx_http::protocol::address::format_authority_host_port(
            logical_host.as_str(),
            logical_port,
        );
        let mut label = format!("{upstream} via {connect}");
        if logical != connect {
            label.push_str(" host=");
            label.push_str(logical.as_str());
        }
        if tls_name != logical && tls_name != connect {
            label.push_str(" sni=");
            label.push_str(tls_name.as_str());
        }
        let label = Arc::<str>::from(label);
        Self {
            upstream,
            label,
            parsed,
            connect_host: Some(connect_host),
            connect_port: Some(connect_port),
            logical_host: Some(logical_host),
            logical_port: Some(logical_port),
            tls_name: Some(tls_name),
        }
    }

    pub(crate) fn label(&self) -> &str {
        self.label.as_ref()
    }

    pub(crate) fn uses_connect_override(&self) -> bool {
        self.connect_host.is_some()
            || self.connect_port.is_some()
            || self.logical_host.is_some()
            || self.logical_port.is_some()
            || self.tls_name.is_some()
    }

    pub(crate) fn connect_authority(&self, default_port: u16) -> Result<String> {
        let (host, port) = self.connect_parts(default_port)?;
        Ok(qpx_http::protocol::address::format_authority_host_port(
            host.as_str(),
            port,
        ))
    }

    pub(crate) fn host_header_authority(&self, default_port: u16) -> Result<String> {
        let (host, port) = self.logical_parts(default_port)?;
        Ok(qpx_http::protocol::address::format_authority_host_port(
            host.as_str(),
            port,
        ))
    }

    pub(crate) fn tls_server_name(&self) -> Result<String> {
        if let Some(name) = self.tls_name.as_ref() {
            return Ok(name.clone());
        }
        if let Some(host) = self.logical_host.as_ref() {
            return Ok(host.clone());
        }
        Ok(self.parsed()?.host.clone())
    }

    pub(super) fn connect_parts(&self, default_port: u16) -> Result<(String, u16)> {
        let parsed = self.parsed()?;
        Ok((
            self.connect_host
                .clone()
                .unwrap_or_else(|| parsed.host.clone()),
            self.connect_port.or(parsed.port).unwrap_or(default_port),
        ))
    }

    pub(super) fn logical_parts(&self, default_port: u16) -> Result<(String, u16)> {
        let parsed = self.parsed()?;
        Ok((
            self.logical_host
                .clone()
                .unwrap_or_else(|| parsed.host.clone()),
            self.logical_port.or(parsed.port).unwrap_or(default_port),
        ))
    }

    pub(super) fn default_port_hint(&self) -> u16 {
        self.connect_port
            .or(self.logical_port)
            .or_else(|| {
                self.parsed.as_ref().and_then(|parsed| {
                    parsed.port.or_else(|| {
                        parsed
                            .scheme
                            .as_deref()
                            .map(dispatch::default_port_for_scheme)
                    })
                })
            })
            .unwrap_or(443)
    }

    fn parsed(&self) -> Result<ParsedOriginTarget> {
        self.parsed
            .clone()
            .map(Ok)
            .unwrap_or_else(|| parse_origin_target(self.upstream.as_str()))
    }
}

pub(super) fn parse_origin_target(upstream: &str) -> Result<ParsedOriginTarget> {
    if upstream.contains("://") {
        let url = url::Url::parse(upstream)?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("origin missing host: {}", upstream))?
            .to_string();
        return Ok(ParsedOriginTarget {
            scheme: Some(url.scheme().to_string()),
            host,
            port: url.port(),
        });
    }

    let (host, port) = qpx_http::protocol::address::parse_authority_host_port(upstream, 443)
        .ok_or_else(|| anyhow!("invalid upstream authority: {}", upstream))?;
    Ok(ParsedOriginTarget {
        scheme: None,
        host,
        port: Some(port),
    })
}

#[cfg(test)]
mod tests;
