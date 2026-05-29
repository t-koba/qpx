use anyhow::{Result, anyhow};

use crate::config::types::{
    CachePurgeModuleConfig, HeaderCaptureConfig, HttpModuleConfig, ResponseCompressionModuleConfig,
    SubrequestModuleConfig,
};

use super::header::{validate_header_name, validate_http_token, validate_non_empty_ascii};

pub(crate) fn validate_http_modules(modules: &[HttpModuleConfig], context: &str) -> Result<()> {
    for (idx, module) in modules.iter().enumerate() {
        let module_context = format!("{context} http_modules[{idx}]");
        validate_non_empty_ascii(
            module.r#type.as_str(),
            format!("{module_context} type").as_str(),
        )?;
        if let Some(id) = module.id.as_deref() {
            validate_non_empty_ascii(id, format!("{module_context} id").as_str())?;
        }
        match module.r#type.as_str() {
            "response_compression" => {
                let config: ResponseCompressionModuleConfig =
                    module.parse_settings().map_err(|err| {
                        anyhow!("{module_context} response_compression config: {err}")
                    })?;
                let module_context = format!("{context} http_modules[{idx}] response_compression");
                if config.min_body_bytes == 0 {
                    return Err(anyhow!("{module_context} min_body_bytes must be >= 1"));
                }
                if config.max_body_bytes == 0 {
                    return Err(anyhow!("{module_context} max_body_bytes must be >= 1"));
                }
                if config.max_body_bytes < config.min_body_bytes {
                    return Err(anyhow!(
                        "{module_context} max_body_bytes must be >= min_body_bytes"
                    ));
                }
                if !config.gzip && !config.brotli && !config.zstd {
                    return Err(anyhow!(
                        "{module_context} must enable at least one of gzip, brotli, or zstd"
                    ));
                }
                if config.gzip_level > 9 {
                    return Err(anyhow!("{module_context} gzip_level must be <= 9"));
                }
                if config.brotli_level > 11 {
                    return Err(anyhow!("{module_context} brotli_level must be <= 11"));
                }
                if !(0..=22).contains(&config.zstd_level) {
                    return Err(anyhow!("{module_context} zstd_level must be in 0..=22"));
                }
                if !(1..=256).contains(&config.worker_count) {
                    return Err(anyhow!("{module_context} worker_count must be in 1..=256"));
                }
                for pattern in &config.content_types {
                    validate_non_empty_ascii(
                        pattern,
                        format!("{module_context} content_types[]").as_str(),
                    )?;
                }
            }
            "subrequest" => {
                let config: SubrequestModuleConfig = module
                    .parse_settings()
                    .map_err(|err| anyhow!("{module_context} subrequest config: {err}"))?;
                validate_subrequest_module(&config, module_context.as_str())?;
            }
            "cache_purge" => {
                let config: CachePurgeModuleConfig = module
                    .parse_settings()
                    .map_err(|err| anyhow!("{module_context} cache_purge config: {err}"))?;
                let module_context = format!("{context} http_modules[{idx}] cache_purge");
                if config.methods.is_empty() {
                    return Err(anyhow!("{module_context} methods must not be empty"));
                }
                for method in &config.methods {
                    validate_http_token(method, format!("{module_context} methods[]").as_str())?;
                }
                if !(200..=599).contains(&config.response_status) {
                    return Err(anyhow!(
                        "{module_context} response_status must be in 200..=599"
                    ));
                }
                for (name, value) in &config.response_headers {
                    validate_header_name(
                        name,
                        format!("{module_context} response_headers").as_str(),
                    )?;
                    http::HeaderValue::from_str(value.as_str()).map_err(|_| {
                        anyhow!(
                            "{module_context} response_headers[{name}] has invalid header value"
                        )
                    })?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn has_cache_purge_module(modules: &[HttpModuleConfig]) -> bool {
    modules.iter().any(|module| module.r#type == "cache_purge")
}

fn validate_subrequest_module(config: &SubrequestModuleConfig, context: &str) -> Result<()> {
    let module_context = format!("{context} subrequest");
    validate_non_empty_ascii(
        config.name.as_str(),
        format!("{module_context} name").as_str(),
    )?;
    validate_non_empty_ascii(
        config.url.as_str(),
        format!("{module_context} url").as_str(),
    )?;
    validate_subrequest_template(
        config.url.as_str(),
        format!("{module_context} url").as_str(),
    )?;
    if let Some(method) = config.method.as_deref() {
        validate_http_token(method, format!("{module_context} method").as_str())?;
    }
    if let Some(timeout_ms) = config.timeout_ms
        && timeout_ms == 0
    {
        return Err(anyhow!("{module_context} timeout_ms must be >= 1"));
    }
    match config.max_response_bytes {
        Some(max_response_bytes) if max_response_bytes > 0 => {}
        _ => {
            return Err(anyhow!(
                "{module_context} max_response_bytes must be explicitly set and >= 1"
            ));
        }
    }
    if config.allowed_schemes.is_empty() {
        return Err(anyhow!(
            "{module_context} allowed_schemes must not be empty"
        ));
    }
    for scheme in &config.allowed_schemes {
        validate_non_empty_ascii(
            scheme,
            format!("{module_context} allowed_schemes[]").as_str(),
        )?;
    }
    if config.allowed_hosts.is_empty() {
        return Err(anyhow!("{module_context} allowed_hosts must not be empty"));
    }
    for host in &config.allowed_hosts {
        validate_non_empty_ascii(host, format!("{module_context} allowed_hosts[]").as_str())?;
    }
    for header in &config.pass_headers {
        validate_header_name(header, format!("{module_context} pass_headers[]").as_str())?;
    }
    for (name, value) in &config.request_headers {
        validate_header_name(name, format!("{module_context} request_headers").as_str())?;
        validate_non_empty_ascii(
            value,
            format!("{module_context} request_headers[{name}]").as_str(),
        )?;
        validate_subrequest_template(
            value,
            format!("{module_context} request_headers[{name}]").as_str(),
        )?;
    }
    validate_header_captures(
        &config.copy_response_headers_to_request,
        format!("{module_context} copy_response_headers_to_request").as_str(),
    )?;
    validate_header_captures(
        &config.copy_response_headers_to_response,
        format!("{module_context} copy_response_headers_to_response").as_str(),
    )?;
    Ok(())
}

fn validate_subrequest_template(value: &str, context: &str) -> Result<()> {
    let mut rest = value;
    while let Some(start) = rest.find('{') {
        if rest[..start].contains('}') {
            return Err(anyhow!("{context} has unmatched '}}'"));
        }
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('}') else {
            return Err(anyhow!("{context} has unmatched '{{'"));
        };
        let placeholder = &after_start[..end];
        validate_subrequest_placeholder(placeholder, context)?;
        rest = &after_start[end + 1..];
    }
    if rest.contains('}') {
        return Err(anyhow!("{context} has unmatched '}}'"));
    }
    Ok(())
}

fn validate_subrequest_placeholder(placeholder: &str, context: &str) -> Result<()> {
    let (variable, modifier) = placeholder
        .split_once(':')
        .ok_or_else(|| anyhow!("{context} placeholder must be variable:modifier"))?;
    if variable.trim().is_empty() || modifier.trim().is_empty() {
        return Err(anyhow!(
            "{context} placeholder variable and modifier must not be empty"
        ));
    }
    if !matches!(modifier, "urlquery" | "pathsegment" | "header" | "host") {
        return Err(anyhow!("{context} has unsupported placeholder modifier"));
    }
    match variable {
        "proxy.kind" | "proxy.name" | "scope.name" | "route.name" | "request.method"
        | "request.uri" | "request.scheme" | "request.host" | "request.sni" | "request.path"
        | "request.query" | "request.authority" | "remote.ip" | "identity.user"
        | "response.status" => Ok(()),
        _ if variable.starts_with("request.header.") => {
            let name = &variable["request.header.".len()..];
            validate_header_name(name, context)
        }
        _ if variable.starts_with("request.query.") => {
            let name = &variable["request.query.".len()..];
            validate_non_empty_ascii(name, context)
        }
        _ => Err(anyhow!("{context} has unsupported placeholder variable")),
    }
}

fn validate_header_captures(entries: &[HeaderCaptureConfig], context: &str) -> Result<()> {
    for capture in entries {
        validate_header_name(capture.from.as_str(), format!("{context}.from").as_str())?;
        validate_header_name(capture.to.as_str(), format!("{context}.to").as_str())?;
    }
    Ok(())
}
