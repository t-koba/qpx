use super::headers::parse_header_name;
use super::{HttpModuleContext, HttpModuleRequestView};
use anyhow::{Context, Result, anyhow};
use http::{HeaderName, HeaderValue};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(super) struct CompiledTemplate {
    pub(super) parts: Arc<[TemplatePart]>,
}

impl CompiledTemplate {
    pub(super) fn summary(&self) -> String {
        self.parts
            .iter()
            .map(TemplatePart::summary)
            .collect::<Vec<_>>()
            .join("")
    }
}

#[derive(Debug, Clone)]
pub(super) enum TemplatePart {
    Literal(Arc<str>),
    Placeholder {
        variable: TemplateVariable,
        modifier: TemplateModifier,
    },
}

impl TemplatePart {
    fn summary(&self) -> String {
        match self {
            TemplatePart::Literal(value) => value.to_string(),
            TemplatePart::Placeholder { variable, modifier } => {
                format!("{{{}:{}}}", variable.summary(), modifier.summary())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum TemplateVariable {
    ProxyKind,
    ProxyName,
    ScopeName,
    RouteName,
    RequestMethod,
    RequestUri,
    RequestScheme,
    RequestHost,
    RequestSni,
    RequestPath,
    RequestQuery,
    RequestQueryKey(Arc<str>),
    RequestHeader(HeaderName),
    RequestAuthority,
    RemoteIp,
    IdentityUser,
    ResponseStatus,
}

impl TemplateVariable {
    fn summary(&self) -> String {
        match self {
            TemplateVariable::ProxyKind => "proxy.kind".to_string(),
            TemplateVariable::ProxyName => "proxy.name".to_string(),
            TemplateVariable::ScopeName => "scope.name".to_string(),
            TemplateVariable::RouteName => "route.name".to_string(),
            TemplateVariable::RequestMethod => "request.method".to_string(),
            TemplateVariable::RequestUri => "request.uri".to_string(),
            TemplateVariable::RequestScheme => "request.scheme".to_string(),
            TemplateVariable::RequestHost => "request.host".to_string(),
            TemplateVariable::RequestSni => "request.sni".to_string(),
            TemplateVariable::RequestPath => "request.path".to_string(),
            TemplateVariable::RequestQuery => "request.query".to_string(),
            TemplateVariable::RequestQueryKey(key) => format!("request.query.{key}"),
            TemplateVariable::RequestHeader(name) => format!("request.header.{name}"),
            TemplateVariable::RequestAuthority => "request.authority".to_string(),
            TemplateVariable::RemoteIp => "remote.ip".to_string(),
            TemplateVariable::IdentityUser => "identity.user".to_string(),
            TemplateVariable::ResponseStatus => "response.status".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum TemplateModifier {
    UrlQuery,
    PathSegment,
    Header,
    Host,
}

impl TemplateModifier {
    fn summary(self) -> &'static str {
        match self {
            TemplateModifier::UrlQuery => "urlquery",
            TemplateModifier::PathSegment => "pathsegment",
            TemplateModifier::Header => "header",
            TemplateModifier::Host => "host",
        }
    }
}

pub(super) fn compile_template(template: &str) -> Result<CompiledTemplate> {
    let mut parts = Vec::new();
    let mut rest = template;
    loop {
        let Some(open) = rest.find('{') else {
            if !rest.is_empty() {
                parts.push(TemplatePart::Literal(Arc::from(rest)));
            }
            break;
        };
        if open > 0 {
            parts.push(TemplatePart::Literal(Arc::from(&rest[..open])));
        }
        let after_open = &rest[open + 1..];
        let close = after_open
            .find('}')
            .ok_or_else(|| anyhow!("template placeholder is missing closing '}}'"))?;
        let placeholder = &after_open[..close];
        let (variable, modifier) = parse_template_placeholder(placeholder)?;
        parts.push(TemplatePart::Placeholder { variable, modifier });
        rest = &after_open[close + 1..];
    }
    Ok(CompiledTemplate {
        parts: parts.into(),
    })
}

fn parse_template_placeholder(placeholder: &str) -> Result<(TemplateVariable, TemplateModifier)> {
    let (variable, modifier) = placeholder.split_once(':').ok_or_else(|| {
        anyhow!("template placeholder {{{placeholder}}} must include an explicit modifier")
    })?;
    let variable = match variable {
        "proxy.kind" => TemplateVariable::ProxyKind,
        "proxy.name" => TemplateVariable::ProxyName,
        "scope.name" => TemplateVariable::ScopeName,
        "route.name" => TemplateVariable::RouteName,
        "request.method" => TemplateVariable::RequestMethod,
        "request.uri" => TemplateVariable::RequestUri,
        "request.scheme" => TemplateVariable::RequestScheme,
        "request.host" => TemplateVariable::RequestHost,
        "request.sni" => TemplateVariable::RequestSni,
        "request.path" => TemplateVariable::RequestPath,
        "request.query" => TemplateVariable::RequestQuery,
        "request.authority" => TemplateVariable::RequestAuthority,
        "remote.ip" => TemplateVariable::RemoteIp,
        "identity.user" => TemplateVariable::IdentityUser,
        "response.status" => TemplateVariable::ResponseStatus,
        _ if variable.starts_with("request.header.") => {
            let Some(name) = variable.strip_prefix("request.header.") else {
                return Err(anyhow!("request.header placeholder prefix mismatch"));
            };
            TemplateVariable::RequestHeader(parse_header_name(name)?)
        }
        _ if variable.starts_with("request.query.") => {
            let Some(name) = variable.strip_prefix("request.query.") else {
                return Err(anyhow!("request.query placeholder prefix mismatch"));
            };
            if name.is_empty() {
                return Err(anyhow!("request.query placeholder key must not be empty"));
            }
            TemplateVariable::RequestQueryKey(Arc::from(name))
        }
        _ => return Err(anyhow!("unknown template placeholder variable: {variable}")),
    };
    let modifier = match modifier {
        "raw" => return Err(anyhow!("raw template expansion is not allowed")),
        "urlquery" => TemplateModifier::UrlQuery,
        "pathsegment" => TemplateModifier::PathSegment,
        "header" => TemplateModifier::Header,
        "host" => TemplateModifier::Host,
        _ => return Err(anyhow!("unknown template placeholder modifier: {modifier}")),
    };
    Ok((variable, modifier))
}

pub(super) fn render_template(
    template: &CompiledTemplate,
    request: &HttpModuleRequestView<'_>,
    ctx: &HttpModuleContext,
) -> Result<String> {
    let remote_ip = ctx.remote_ip().to_string();
    let response_status = ctx
        .response_status()
        .map(|status| status.as_str().to_string())
        .unwrap_or_default();
    let request_uri = request.uri_string();
    let mut out = String::new();
    for part in template.parts.iter() {
        match part {
            TemplatePart::Literal(value) => out.push_str(value),
            TemplatePart::Placeholder { variable, modifier } => {
                let value = match variable {
                    TemplateVariable::ProxyKind => ctx.proxy_kind(),
                    TemplateVariable::ProxyName => ctx.proxy_name(),
                    TemplateVariable::ScopeName => ctx.scope_name(),
                    TemplateVariable::RouteName => ctx.route_name().unwrap_or_default(),
                    TemplateVariable::RequestMethod => request.method().as_str(),
                    TemplateVariable::RequestUri => request_uri.as_ref(),
                    TemplateVariable::RequestScheme => request.scheme().unwrap_or_default(),
                    TemplateVariable::RequestHost => request.host().unwrap_or_default(),
                    TemplateVariable::RequestSni => ctx.sni().unwrap_or_default(),
                    TemplateVariable::RequestPath => request.path(),
                    TemplateVariable::RequestQuery => request.query().unwrap_or_default(),
                    TemplateVariable::RequestQueryKey(key) => {
                        let value = request
                            .query()
                            .and_then(|query| query_value(query, key.as_ref()))
                            .unwrap_or_default();
                        push_template_value(&mut out, value.as_ref(), *modifier)?;
                        continue;
                    }
                    TemplateVariable::RequestHeader(name) => {
                        let value = request
                            .headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default();
                        push_template_value(&mut out, value, *modifier)?;
                        continue;
                    }
                    TemplateVariable::RequestAuthority => request.authority().unwrap_or_default(),
                    TemplateVariable::RemoteIp => remote_ip.as_str(),
                    TemplateVariable::IdentityUser => ctx.identity_user().unwrap_or_default(),
                    TemplateVariable::ResponseStatus => response_status.as_str(),
                };
                push_template_value(&mut out, value, *modifier)?;
            }
        }
    }
    Ok(out)
}

fn push_template_value(out: &mut String, value: &str, modifier: TemplateModifier) -> Result<()> {
    match modifier {
        TemplateModifier::UrlQuery | TemplateModifier::PathSegment => {
            out.push_str(
                utf8_percent_encode(value, NON_ALPHANUMERIC)
                    .to_string()
                    .as_str(),
            );
        }
        TemplateModifier::Header => {
            if value.as_bytes().iter().any(|byte| byte.is_ascii_control()) {
                return Err(anyhow!(
                    "template header value contains a control character"
                ));
            }
            HeaderValue::from_str(value)
                .with_context(|| format!("invalid template header value: {value}"))?;
            out.push_str(value);
        }
        TemplateModifier::Host => {
            validate_template_host(value)?;
            out.push_str(value);
        }
    }
    Ok(())
}

fn query_value(query: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

fn validate_template_host(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(anyhow!("template host value must not be empty"));
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if value.as_bytes().iter().any(|byte| byte.is_ascii_control())
        || value.contains(['/', '?', '#', '@', ':'])
    {
        return Err(anyhow!("template host value contains invalid characters"));
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(anyhow!("template host value is not a valid host name"));
        }
    }
    Ok(())
}
