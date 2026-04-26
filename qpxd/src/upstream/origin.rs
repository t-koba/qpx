use anyhow::{anyhow, Result};

#[path = "origin/dispatch.rs"]
mod dispatch;
#[path = "origin/dns.rs"]
mod dns;
#[path = "origin/http_backend.rs"]
mod http_backend;
#[path = "origin/ipc_backend.rs"]
mod ipc_backend;
#[path = "origin/ws_backend.rs"]
mod ws_backend;

pub(crate) use dns::discover_origin_endpoints;
#[cfg(all(
    feature = "http3",
    any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        all(feature = "http3-backend-qpx", not(feature = "http3-backend-h3"))
    )
))]
pub(crate) use dns::resolve_upstream_socket_addr;
pub(crate) use http_backend::{
    clear_direct_origin_connection_pools, proxy_http, proxy_http_with_interim,
    shared_reverse_http_client, shared_reverse_https_client,
};
pub(crate) use ws_backend::proxy_websocket;

#[cfg(test)]
use dns::{
    discover_origin_endpoints_with_nameservers, encode_dns_name, parse_dns_name, DNS_TYPE_A,
    DNS_TYPE_AAAA, DNS_TYPE_SRV,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OriginEndpoint {
    pub(crate) upstream: String,
    connect_host: Option<String>,
    connect_port: Option<u16>,
    logical_host: Option<String>,
    logical_port: Option<u16>,
    tls_name: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ParsedOriginTarget {
    pub(super) scheme: Option<String>,
    pub(super) host: String,
    pub(super) port: Option<u16>,
}

impl OriginEndpoint {
    pub(crate) fn direct(upstream: impl Into<String>) -> Self {
        Self {
            upstream: upstream.into(),
            connect_host: None,
            connect_port: None,
            logical_host: None,
            logical_port: None,
            tls_name: None,
        }
    }

    pub(super) fn discovered(
        base_upstream: &str,
        connect_host: String,
        connect_port: u16,
        logical_host: String,
        logical_port: u16,
        tls_name: String,
    ) -> Self {
        Self {
            upstream: base_upstream.to_string(),
            connect_host: Some(connect_host),
            connect_port: Some(connect_port),
            logical_host: Some(logical_host),
            logical_port: Some(logical_port),
            tls_name: Some(tls_name),
        }
    }

    pub(crate) fn label(&self) -> String {
        if !self.uses_connect_override() {
            return self.upstream.clone();
        }

        let default_port = self.default_port_hint();
        let connect = self
            .connect_authority(default_port)
            .unwrap_or_else(|_| self.upstream.clone());
        let logical = self
            .host_header_authority(default_port)
            .unwrap_or_else(|_| connect.clone());
        let mut label = format!("{} via {}", self.upstream, connect);
        if logical != connect {
            label.push_str(" host=");
            label.push_str(logical.as_str());
        }
        if let Ok(server_name) = self.tls_server_name() {
            if server_name != logical && server_name != connect {
                label.push_str(" sni=");
                label.push_str(server_name.as_str());
            }
        }
        label
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
        Ok(crate::http::address::format_authority_host_port(
            host.as_str(),
            port,
        ))
    }

    pub(crate) fn host_header_authority(&self, default_port: u16) -> Result<String> {
        let (host, port) = self.logical_parts(default_port)?;
        Ok(crate::http::address::format_authority_host_port(
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
        Ok(parse_origin_target(self.upstream.as_str())?.host)
    }

    pub(super) fn connect_parts(&self, default_port: u16) -> Result<(String, u16)> {
        let parsed = parse_origin_target(self.upstream.as_str())?;
        Ok((
            self.connect_host.clone().unwrap_or(parsed.host),
            self.connect_port.or(parsed.port).unwrap_or(default_port),
        ))
    }

    pub(super) fn logical_parts(&self, default_port: u16) -> Result<(String, u16)> {
        let parsed = parse_origin_target(self.upstream.as_str())?;
        Ok((
            self.logical_host.clone().unwrap_or(parsed.host),
            self.logical_port.or(parsed.port).unwrap_or(default_port),
        ))
    }

    pub(super) fn default_port_hint(&self) -> u16 {
        self.connect_port
            .or(self.logical_port)
            .or_else(|| {
                parse_origin_target(self.upstream.as_str())
                    .ok()
                    .and_then(|parsed| {
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

    let (host, port) = crate::http::address::parse_authority_host_port(upstream, 443)
        .ok_or_else(|| anyhow!("invalid upstream authority: {}", upstream))?;
    Ok(ParsedOriginTarget {
        scheme: None,
        host,
        port: Some(port),
    })
}

#[cfg(test)]
#[path = "origin_tests.rs"]
mod tests;
