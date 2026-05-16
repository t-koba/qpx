use crate::prefilter::{TextMatchMode, TextPatternMatcher, is_ascii_uppercase_token};
use crate::rules::RuleMatchContext;

use super::CompiledMatch;
use super::headers::{trace_fast_header, trace_regex_header};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchTrace {
    pub result: bool,
    pub reasons: Vec<MatchReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchReason {
    SrcIp {
        configured: String,
        actual: Option<String>,
        result: bool,
    },
    DstPort {
        configured: u16,
        actual: Option<u16>,
        result: bool,
    },
    Sni {
        mode: MatchMode,
        configured: String,
        actual: Option<String>,
        result: bool,
    },
    Host {
        mode: MatchMode,
        configured: String,
        actual: Option<String>,
        result: bool,
    },
    Method {
        configured: String,
        actual: Option<String>,
        result: bool,
    },
    Path {
        mode: MatchMode,
        configured: String,
        actual: Option<String>,
        result: bool,
    },
    Header {
        name: String,
        configured: String,
        actual: Option<String>,
        result: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    Exact,
    Prefix,
    Suffix,
    Glob,
    Regex,
    Cidr,
    Any,
}

impl CompiledMatch {
    pub fn matches_with_trace(&self, ctx: &RuleMatchContext<'_>) -> MatchTrace {
        let mut reasons = Vec::new();
        for cidr in &self.src_ip {
            reasons.push(MatchReason::SrcIp {
                configured: cidr.to_string(),
                actual: ctx.src_ip.map(|ip| ip.to_string()),
                result: ctx.src_ip.is_some_and(|ip| cidr.contains(&ip)),
            });
        }
        for port in &self.dst_port {
            reasons.push(MatchReason::DstPort {
                configured: *port,
                actual: ctx.dst_port,
                result: ctx.dst_port == Some(*port),
            });
        }
        if let Some(host) = &self.host {
            append_text_reasons(&mut reasons, TraceTextKind::Host, host, ctx.host);
        }
        if let Some(sni) = &self.sni {
            append_text_reasons(&mut reasons, TraceTextKind::Sni, sni, ctx.sni);
        }
        for method in &self.method {
            let result = ctx.method.is_some_and(|actual| {
                actual == method.as_ref()
                    || (!is_ascii_uppercase_token(actual)
                        && actual.to_ascii_uppercase() == method.as_ref())
            });
            reasons.push(MatchReason::Method {
                configured: method.to_string(),
                actual: ctx.method.map(str::to_string),
                result,
            });
        }
        if let Some(path) = &self.path {
            append_text_reasons(&mut reasons, TraceTextKind::Path, path, ctx.path);
        }
        for matcher in &self.headers_fast {
            let (configured, actual, result) = trace_fast_header(matcher, ctx.headers);
            reasons.push(MatchReason::Header {
                name: matcher.name.to_string(),
                configured,
                actual,
                result,
            });
        }
        for matcher in &self.headers_regex {
            let (actual, result) = trace_regex_header(matcher, ctx.headers);
            reasons.push(MatchReason::Header {
                name: matcher.name.to_string(),
                configured: format!("regex:{}", matcher.regex.as_str()),
                actual,
                result,
            });
        }
        MatchTrace {
            result: self.matches(ctx),
            reasons,
        }
    }
}

enum TraceTextKind {
    Host,
    Sni,
    Path,
}

fn append_text_reasons(
    out: &mut Vec<MatchReason>,
    kind: TraceTextKind,
    matcher: &TextPatternMatcher,
    actual: Option<&str>,
) {
    for trace in matcher.trace(actual) {
        let mode = match trace.mode {
            TextMatchMode::Exact => MatchMode::Exact,
            TextMatchMode::Suffix => MatchMode::Suffix,
            TextMatchMode::Glob => pattern_mode(trace.configured.as_str()),
            TextMatchMode::Regex => MatchMode::Regex,
        };
        match kind {
            TraceTextKind::Host => out.push(MatchReason::Host {
                mode,
                configured: trace.configured,
                actual: actual.map(str::to_string),
                result: trace.result,
            }),
            TraceTextKind::Sni => out.push(MatchReason::Sni {
                mode,
                configured: trace.configured,
                actual: actual.map(str::to_string),
                result: trace.result,
            }),
            TraceTextKind::Path => out.push(MatchReason::Path {
                mode,
                configured: trace.configured,
                actual: actual.map(str::to_string),
                result: trace.result,
            }),
        }
    }
}

fn pattern_mode(pattern: &str) -> MatchMode {
    if pattern.ends_with('*') && !pattern[..pattern.len().saturating_sub(1)].contains(['*', '?']) {
        MatchMode::Prefix
    } else {
        MatchMode::Glob
    }
}
