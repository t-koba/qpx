use crate::config::{HeaderMatch, MatchConfig, TlsPassthroughMatchConfig};
use crate::prefilter::{
    compile_text_patterns, dedup_uppercase_arc, is_ascii_uppercase_token, StringInterner,
    TextPatternMatcher,
};
use crate::rules::RuleMatchContext;
use anyhow::{anyhow, Result};
use cidr::IpCidr;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CompiledMatch {
    src_ip: Vec<IpCidr>,
    dst_port: HashSet<u16>,
    host: Option<TextPatternMatcher>,
    sni: Option<TextPatternMatcher>,
    method: HashSet<Arc<str>>,
    path: Option<TextPatternMatcher>,
    headers_fast: Vec<HeaderMatcherFast>,
    headers_regex: Vec<HeaderMatcherRegex>,
}

#[derive(Debug, Clone)]
struct HeaderMatcherFast {
    name: Arc<str>,
    mode: HeaderFastMode,
}

#[derive(Debug, Clone)]
enum HeaderFastMode {
    Present,
    Exact(Arc<str>),
}

#[derive(Debug, Clone)]
struct HeaderMatcherRegex {
    name: Arc<str>,
    regex: Regex,
}

impl CompiledMatch {
    pub fn compile(
        config: &MatchConfig,
        interner: &mut StringInterner,
    ) -> Result<(Self, crate::prefilter::MatchPrefilterHint)> {
        let src_cidrs = parse_cidrs(&config.src_ip)?;
        let dst_ports = dedup_u16(&config.dst_port);
        let method_values = dedup_uppercase_arc(&config.method, interner);

        let (host, host_hint) = compile_text_patterns(&config.host, true, true, interner)?;
        let (sni, sni_hint) = compile_text_patterns(&config.sni, true, true, interner)?;
        let (path, path_hint) = compile_text_patterns(&config.path, false, false, interner)?;
        let (headers_fast, headers_regex) = build_header_matchers(&config.headers, interner)?;

        let mut dst_port = HashSet::new();
        dst_port.extend(dst_ports.iter().copied());
        let method: HashSet<Arc<str>> = method_values.iter().cloned().collect();

        Ok((
            Self {
                src_ip: src_cidrs.clone(),
                dst_port,
                host,
                sni,
                method,
                path,
                headers_fast,
                headers_regex,
            },
            crate::prefilter::MatchPrefilterHint {
                method_values,
                dst_ports,
                src_cidrs,
                host: host_hint,
                sni: sni_hint,
                path: path_hint,
            },
        ))
    }

    pub fn compile_tls_passthrough(
        config: &TlsPassthroughMatchConfig,
        interner: &mut StringInterner,
    ) -> Result<(Self, crate::prefilter::MatchPrefilterHint)> {
        let src_cidrs = parse_cidrs(&config.src_ip)?;
        let dst_ports = dedup_u16(&config.dst_port);
        let (sni, sni_hint) = compile_text_patterns(&config.sni, true, true, interner)?;

        let mut dst_port = HashSet::new();
        dst_port.extend(dst_ports.iter().copied());
        Ok((
            Self {
                src_ip: src_cidrs.clone(),
                dst_port,
                host: None,
                sni,
                method: HashSet::new(),
                path: None,
                headers_fast: Vec::new(),
                headers_regex: Vec::new(),
            },
            crate::prefilter::MatchPrefilterHint {
                method_values: Vec::new(),
                dst_ports,
                src_cidrs,
                host: crate::prefilter::TextPrefilterHint {
                    any: true,
                    ..Default::default()
                },
                sni: sni_hint,
                path: crate::prefilter::TextPrefilterHint {
                    any: true,
                    ..Default::default()
                },
            },
        ))
    }

    pub fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        if !self.src_ip.is_empty() {
            let Some(ip) = ctx.src_ip else {
                return false;
            };
            if !self.src_ip.iter().any(|cidr| cidr.contains(&ip)) {
                return false;
            }
        }

        if !self.dst_port.is_empty() {
            let Some(port) = ctx.dst_port else {
                return false;
            };
            if !self.dst_port.contains(&port) {
                return false;
            }
        }

        if let Some(host_matcher) = &self.host {
            let host = match ctx.host {
                Some(host) => host,
                None => return false,
            };
            if !host_matcher.matches(host) {
                return false;
            }
        }

        if let Some(sni_matcher) = &self.sni {
            let sni = match ctx.sni {
                Some(sni) => sni,
                None => return false,
            };
            if !sni_matcher.matches(sni) {
                return false;
            }
        }

        if !self.method.is_empty() {
            let method = match ctx.method {
                Some(m) => m,
                None => return false,
            };
            if !self.method.contains(method) {
                if is_ascii_uppercase_token(method) {
                    return false;
                }
                let upper = method.to_ascii_uppercase();
                if !self.method.contains(upper.as_str()) {
                    return false;
                }
            }
        }

        if let Some(path_matcher) = &self.path {
            let path = match ctx.path {
                Some(path) => path,
                None => return false,
            };
            if !path_matcher.matches(path) {
                return false;
            }
        }

        if !self.headers_fast.is_empty() {
            let headers = match ctx.headers {
                Some(h) => h,
                None => return false,
            };
            for matcher in &self.headers_fast {
                let mut matched = false;
                for value in headers.get_all(matcher.name.as_ref()).iter() {
                    let Ok(v) = value.to_str() else {
                        continue;
                    };
                    match &matcher.mode {
                        HeaderFastMode::Present => {
                            matched = true;
                            break;
                        }
                        HeaderFastMode::Exact(expected) => {
                            if v == expected.as_ref() {
                                matched = true;
                                break;
                            }
                        }
                    }
                }
                if !matched {
                    return false;
                }
            }
        }

        if !self.headers_regex.is_empty() {
            let headers = match ctx.headers {
                Some(h) => h,
                None => return false,
            };
            for matcher in &self.headers_regex {
                let mut matched = false;
                for value in headers.get_all(matcher.name.as_ref()).iter() {
                    let Ok(v) = value.to_str() else {
                        continue;
                    };
                    if matcher.regex.is_match(v) {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    return false;
                }
            }
        }

        true
    }
}

fn build_header_matchers(
    items: &[HeaderMatch],
    interner: &mut StringInterner,
) -> Result<(Vec<HeaderMatcherFast>, Vec<HeaderMatcherRegex>)> {
    let mut fast = Vec::new();
    let mut regex = Vec::new();

    for item in items {
        let name = interner.intern_lower(&item.name);
        if let Some(pattern) = &item.regex {
            regex.push(HeaderMatcherRegex {
                name,
                regex: Regex::new(pattern)
                    .map_err(|e| anyhow!("invalid header regex {}: {}", pattern, e))?,
            });
            continue;
        }

        let mode = if let Some(value) = &item.value {
            HeaderFastMode::Exact(interner.intern(value))
        } else {
            HeaderFastMode::Present
        };
        fast.push(HeaderMatcherFast { name, mode });
    }

    Ok((fast, regex))
}

fn parse_cidrs(items: &[String]) -> Result<Vec<IpCidr>> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let cidr: IpCidr = item
            .parse()
            .map_err(|_| anyhow!("invalid CIDR: {}", item))?;
        out.push(cidr);
    }
    Ok(out)
}

fn dedup_u16(items: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(items.len());
    let mut seen = HashSet::new();
    for item in items {
        if seen.insert(*item) {
            out.push(*item);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MatchConfig;

    #[test]
    fn compiled_match_method_is_case_insensitive() {
        let cfg = MatchConfig {
            method: vec!["get".to_string()],
            ..Default::default()
        };
        let mut interner = StringInterner::default();
        let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
        let ctx = RuleMatchContext {
            src_ip: None,
            dst_port: None,
            host: None,
            sni: None,
            method: Some("GET"),
            path: None,
            headers: None,
            user_groups: &[],
        };
        assert!(compiled.matches(&ctx));
    }

    #[test]
    fn compiled_match_path_requires_path() {
        let cfg = MatchConfig {
            path: vec!["/foo".to_string()],
            ..Default::default()
        };
        let mut interner = StringInterner::default();
        let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
        let ctx = RuleMatchContext {
            src_ip: None,
            dst_port: None,
            host: None,
            sni: None,
            method: None,
            path: None,
            headers: None,
            user_groups: &[],
        };
        assert!(!compiled.matches(&ctx));
    }
}
