use anyhow::Result;

use crate::runtime;

pub(crate) struct MatchPlanRequest<'a> {
    pub(crate) edge: &'a str,
    pub(crate) ctx: qpx_core::rules::RuleMatchContext<'a>,
}

pub(crate) fn render_match_plan(
    plan: &runtime::RuntimePlan,
    request: MatchPlanRequest<'_>,
) -> Result<String> {
    let mut output = String::new();
    for compiled_edge in plan.edges.iter() {
        match compiled_edge {
            runtime::CompiledEdge::Reverse(reverse) if reverse.name.as_ref() == request.edge => {
                for route in reverse.routes.iter() {
                    if route.matches(&request.ctx) {
                        output.push_str(&format!("edge: {}\n", reverse.name));
                        output.push_str("kind: reverse\n");
                        output.push_str(&format!("route: {}\n", route.name));
                        append_match_trace(
                            &mut output,
                            &route.matcher.matches_with_trace(&request.ctx),
                        );
                        super::append_reverse_target(&mut output, "target", &route.target);
                        super::append_execution_plan(&mut output, "execution_plan", &route.plan);
                        return Ok(output);
                    }
                }
                for route in reverse.tls_passthrough_routes.iter() {
                    if route.matches(&request.ctx) {
                        output.push_str(&format!("edge: {}\n", reverse.name));
                        output.push_str("kind: reverse\n");
                        output.push_str(&format!("route: {}\n", route.name));
                        append_match_trace(
                            &mut output,
                            &route.matcher.matches_with_trace(&request.ctx),
                        );
                        super::append_reverse_target(&mut output, "target", &route.target);
                        return Ok(output);
                    }
                }
                output.push_str(&format!("edge: {}\n", reverse.name));
                output.push_str("kind: reverse\n");
                output.push_str("route: <no match>\n");
                return Ok(output);
            }
            runtime::CompiledEdge::Forward(forward) if forward.name.as_ref() == request.edge => {
                for rule in forward.rules.iter() {
                    if rule.matches(&request.ctx) {
                        output.push_str(&format!("edge: {}\n", forward.name));
                        output.push_str("kind: forward\n");
                        output.push_str(&format!("rule: {}\n", rule.name));
                        append_match_trace(
                            &mut output,
                            &rule.matcher.matches_with_trace(&request.ctx),
                        );
                        super::append_ingress_execution_plan(
                            &mut output,
                            "execution_plan",
                            &rule.action_kind,
                            &rule.plan,
                        );
                        return Ok(output);
                    }
                }
                output.push_str(&format!("edge: {}\n", forward.name));
                output.push_str("kind: forward\n");
                output.push_str("rule: <default>\n");
                super::append_ingress_execution_plan(
                    &mut output,
                    "execution_plan",
                    &forward.default_action_kind,
                    &forward.default_plan,
                );
                return Ok(output);
            }
            runtime::CompiledEdge::Transparent(transparent)
                if transparent.name.as_ref() == request.edge =>
            {
                for rule in transparent.rules.iter() {
                    if rule.matches(&request.ctx) {
                        output.push_str(&format!("edge: {}\n", transparent.name));
                        output.push_str("kind: transparent\n");
                        output.push_str(&format!("rule: {}\n", rule.name));
                        append_match_trace(
                            &mut output,
                            &rule.matcher.matches_with_trace(&request.ctx),
                        );
                        super::append_ingress_execution_plan(
                            &mut output,
                            "execution_plan",
                            &rule.action_kind,
                            &rule.plan,
                        );
                        return Ok(output);
                    }
                }
                output.push_str(&format!("edge: {}\n", transparent.name));
                output.push_str("kind: transparent\n");
                output.push_str("rule: <default>\n");
                super::append_ingress_execution_plan(
                    &mut output,
                    "execution_plan",
                    &transparent.default_action_kind,
                    &transparent.default_plan,
                );
                return Ok(output);
            }
            _ => {}
        }
    }
    anyhow::bail!("edge not found: {}", request.edge);
}

fn append_match_trace(output: &mut String, trace: &qpx_core::matchers::MatchTrace) {
    output.push_str("matched_by\n");
    if trace.reasons.is_empty() {
        output.push_str("  any: true\n");
        return;
    }
    for reason in &trace.reasons {
        match reason {
            qpx_core::matchers::MatchReason::SrcIp {
                configured,
                actual,
                result,
            } => append_match_reason(
                output,
                "src_ip",
                Some("cidr"),
                configured,
                actual.as_deref(),
                *result,
            ),
            qpx_core::matchers::MatchReason::DstPort {
                configured,
                actual,
                result,
            } => append_match_reason(
                output,
                "dst_port",
                Some("exact"),
                &configured.to_string(),
                actual.map(|value| value.to_string()).as_deref(),
                *result,
            ),
            qpx_core::matchers::MatchReason::Sni {
                mode,
                configured,
                actual,
                result,
            } => append_match_reason(
                output,
                "sni",
                Some(super::match_mode_label(*mode)),
                configured,
                actual.as_deref(),
                *result,
            ),
            qpx_core::matchers::MatchReason::Host {
                mode,
                configured,
                actual,
                result,
            } => append_match_reason(
                output,
                "host",
                Some(super::match_mode_label(*mode)),
                configured,
                actual.as_deref(),
                *result,
            ),
            qpx_core::matchers::MatchReason::Method {
                configured,
                actual,
                result,
            } => append_match_reason(
                output,
                "method",
                Some("exact"),
                configured,
                actual.as_deref(),
                *result,
            ),
            qpx_core::matchers::MatchReason::Path {
                mode,
                configured,
                actual,
                result,
            } => append_match_reason(
                output,
                "path",
                Some(super::match_mode_label(*mode)),
                configured,
                actual.as_deref(),
                *result,
            ),
            qpx_core::matchers::MatchReason::Header {
                name,
                configured,
                actual,
                result,
            } => append_match_reason(
                output,
                &format!("header.{name}"),
                None,
                configured,
                actual.as_deref(),
                *result,
            ),
        }
    }
}

fn append_match_reason(
    output: &mut String,
    name: &str,
    mode: Option<&str>,
    configured: &str,
    actual: Option<&str>,
    result: bool,
) {
    output.push_str(&format!("  {name}\n"));
    if let Some(mode) = mode {
        output.push_str(&format!("    mode: {mode}\n"));
    }
    output.push_str(&format!("    configured: {configured}\n"));
    output.push_str(&format!("    actual: {}\n", actual.unwrap_or("<missing>")));
    output.push_str(&format!("    result: {}\n", super::on_off(result)));
}
