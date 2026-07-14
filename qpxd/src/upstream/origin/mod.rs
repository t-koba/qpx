use anyhow::{Result, anyhow};
use std::borrow::Cow;
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
    DirectOriginPools, PreparedPlainHttp1Origin, prepare_plain_http1_origin,
    prepare_proxy_http1_request, proxy_direct_plain_http1_raw_response_with_interim,
    proxy_direct_plain_http1_with_interim, proxy_http, proxy_http_with_interim_timeout,
    proxy_prepared_plain_http1_head_raw_response_with_interim,
    shared_reverse_https_request_with_trust,
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
    connect_authority: Option<Arc<str>>,
    logical_authority: Option<Arc<str>>,
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
        let default_port = parsed.as_ref().and_then(|target| {
            target
                .scheme
                .as_deref()
                .map(dispatch::default_port_for_scheme)
                .or(target.port)
        });
        let authority = parsed.as_ref().zip(default_port).map(|(target, port)| {
            Arc::<str>::from(qpx_http::protocol::address::format_authority_host_port(
                target.host.as_str(),
                target.port.unwrap_or(port),
            ))
        });
        let label = Arc::<str>::from(upstream.as_str());
        Self {
            upstream,
            label,
            parsed,
            connect_authority: authority.clone(),
            logical_authority: authority,
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
            connect_authority: Some(Arc::from(connect)),
            logical_authority: Some(Arc::from(logical)),
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

    pub(crate) fn direct_plain_http1_authorities(&self) -> Option<(&str, &str)> {
        let parsed = self.parsed.as_ref()?;
        if !matches!(parsed.scheme.as_deref(), Some("http" | "h2c" | "ws")) {
            return None;
        }
        Some((
            self.connect_authority.as_deref()?,
            self.logical_authority.as_deref()?,
        ))
    }

    pub(crate) fn connect_authority_ref(&self, default_port: u16) -> Result<Cow<'_, str>> {
        if let Some(authority) = self.connect_authority.as_ref() {
            return Ok(Cow::Borrowed(authority.as_ref()));
        }
        let (host, port) = self.connect_parts(default_port)?;
        Ok(Cow::Owned(
            qpx_http::protocol::address::format_authority_host_port(host.as_str(), port),
        ))
    }

    pub(crate) fn connect_authority(&self, default_port: u16) -> Result<String> {
        let (host, port) = self.connect_parts(default_port)?;
        Ok(qpx_http::protocol::address::format_authority_host_port(
            host.as_str(),
            port,
        ))
    }

    pub(crate) fn host_header_authority_ref(&self, default_port: u16) -> Result<Cow<'_, str>> {
        if let Some(authority) = self.logical_authority.as_ref() {
            return Ok(Cow::Borrowed(authority.as_ref()));
        }
        let (host, port) = self.logical_parts(default_port)?;
        Ok(Cow::Owned(
            qpx_http::protocol::address::format_authority_host_port(host.as_str(), port),
        ))
    }

    pub(crate) fn host_header_authority(&self, default_port: u16) -> Result<String> {
        let (host, port) = self.logical_parts(default_port)?;
        Ok(qpx_http::protocol::address::format_authority_host_port(
            host.as_str(),
            port,
        ))
    }

    pub(crate) fn tls_server_name_ref(&self) -> Result<Cow<'_, str>> {
        if let Some(name) = self.tls_name.as_ref() {
            return Ok(Cow::Borrowed(name.as_str()));
        }
        if let Some(host) = self.logical_host.as_ref() {
            return Ok(Cow::Borrowed(host.as_str()));
        }
        match self.parsed()? {
            Cow::Borrowed(parsed) => Ok(Cow::Borrowed(parsed.host.as_str())),
            Cow::Owned(parsed) => Ok(Cow::Owned(parsed.host)),
        }
    }

    pub(crate) fn tls_server_name(&self) -> Result<String> {
        self.tls_server_name_ref().map(Cow::into_owned)
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

    fn parsed(&self) -> Result<Cow<'_, ParsedOriginTarget>> {
        match self.parsed.as_ref() {
            Some(parsed) => Ok(Cow::Borrowed(parsed)),
            None => parse_origin_target(self.upstream.as_str()).map(Cow::Owned),
        }
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
