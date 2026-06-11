use crate::config::RpcMatchConfig;
use crate::prefilter::{StringInterner, TextPatternMatcher, compile_text_patterns};
use crate::rules::RuleMatchContext;

use super::Result;
use super::headers::{
    HeaderMatcherFast, HeaderMatcherRegex, build_header_matchers, fast_headers_match,
    regex_headers_match,
};
use super::identity::match_optional_text;
use super::numeric::{CompiledNumericMatcher, compile_numeric_matchers, match_optional_numeric};

#[derive(Debug, Clone)]
pub(super) struct CompiledRpcMatch {
    protocol: Option<TextPatternMatcher>,
    service: Option<TextPatternMatcher>,
    method: Option<TextPatternMatcher>,
    streaming: Option<TextPatternMatcher>,
    status: Option<TextPatternMatcher>,
    message_size: Option<CompiledNumericMatcher>,
    message: Option<TextPatternMatcher>,
    trailers_fast: Vec<HeaderMatcherFast>,
    trailers_regex: Vec<HeaderMatcherRegex>,
}

impl CompiledRpcMatch {
    pub(super) fn compile(config: &RpcMatchConfig, interner: &mut StringInterner) -> Result<Self> {
        let (protocol, _) = compile_text_patterns(&config.protocol, true, false, interner)?;
        let (service, _) = compile_text_patterns(&config.service, true, false, interner)?;
        let (method, _) = compile_text_patterns(&config.method, true, false, interner)?;
        let (streaming, _) = compile_text_patterns(&config.streaming, true, false, interner)?;
        let (status, _) = compile_text_patterns(&config.status, true, false, interner)?;
        let message_size = compile_numeric_matchers(&config.message_size)?;
        let (message, _) = compile_text_patterns(&config.message, false, false, interner)?;
        let (trailers_fast, trailers_regex) = build_header_matchers(&config.trailers, interner)?;
        Ok(Self {
            protocol,
            service,
            method,
            streaming,
            status,
            message_size,
            message,
            trailers_fast,
            trailers_regex,
        })
    }

    pub(super) fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        match_optional_text(&self.protocol, ctx.rpc_protocol)
            && match_optional_text(&self.service, ctx.rpc_service)
            && match_optional_text(&self.method, ctx.rpc_method)
            && match_optional_text(&self.streaming, ctx.rpc_streaming)
            && match_optional_text(&self.status, ctx.rpc_status)
            && match_optional_numeric(&self.message_size, ctx.rpc_message_size)
            && match_optional_text(&self.message, ctx.rpc_message)
            && fast_headers_match(&self.trailers_fast, ctx.rpc_trailers)
            && regex_headers_match(&self.trailers_regex, ctx.rpc_trailers)
    }

    pub(super) fn matches_without_request_body_observation(
        &self,
        ctx: &RuleMatchContext<'_>,
    ) -> bool {
        match_optional_text(&self.protocol, ctx.rpc_protocol)
            && match_optional_text(&self.service, ctx.rpc_service)
            && match_optional_text(&self.method, ctx.rpc_method)
            && self.status.is_none()
            && self.message.is_none()
            && self.trailers_fast.is_empty()
            && self.trailers_regex.is_empty()
    }

    pub(super) fn matches_without_response_body_observation(
        &self,
        ctx: &RuleMatchContext<'_>,
    ) -> bool {
        match_optional_text(&self.protocol, ctx.rpc_protocol)
            && match_optional_text(&self.service, ctx.rpc_service)
            && match_optional_text(&self.method, ctx.rpc_method)
    }

    pub(super) fn matches_known_request_without_body_observation(
        &self,
        ctx: &RuleMatchContext<'_>,
    ) -> bool {
        known_optional_text_matches(&self.protocol, ctx.rpc_protocol)
            && known_optional_text_matches(&self.service, ctx.rpc_service)
            && known_optional_text_matches(&self.method, ctx.rpc_method)
    }

    pub(super) fn requires_request_body_observation(&self) -> bool {
        self.message_size.is_some() || self.streaming.is_some()
    }

    pub(super) fn requires_response_body_observation(&self) -> bool {
        self.message_size.is_some()
            || self.message.is_some()
            || !self.trailers_fast.is_empty()
            || !self.trailers_regex.is_empty()
            || self.status.is_some()
            || self.streaming.is_some()
    }

    pub(super) fn requires_response_observation(&self) -> bool {
        self.status.is_some()
            || self.message_size.is_some()
            || self.message.is_some()
            || !self.trailers_fast.is_empty()
            || !self.trailers_regex.is_empty()
            || self.streaming.is_some()
    }

    pub(super) fn requires_response_context(&self) -> bool {
        self.requires_any_response_rule_rpc_context()
    }

    pub(super) fn requires_request_context_for_response_rule(&self) -> bool {
        self.protocol.is_some()
            || self.service.is_some()
            || self.method.is_some()
            || self.streaming.is_some()
    }

    pub(super) fn requires_request_body_observation_for_response_rule(&self) -> bool {
        self.streaming.is_some()
    }

    pub(super) fn requires_any_response_rule_rpc_context(&self) -> bool {
        self.requires_request_context_for_response_rule() || self.requires_response_observation()
    }
}

fn known_optional_text_matches(matcher: &Option<TextPatternMatcher>, value: Option<&str>) -> bool {
    value.is_none_or(|value| match_optional_text(matcher, Some(value)))
}
