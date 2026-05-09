use anyhow::Result;
use std::net::IpAddr;

use crate::runtime;

pub(crate) fn render_explain_plan(
    plan: &runtime::RuntimePlan,
    edge_filter: Option<&str>,
    route_filter: Option<&str>,
) -> String {
    let mut output = String::new();
    for edge in plan.edges.iter() {
        match edge {
            runtime::CompiledEdge::Forward(edge) => {
                if !edge_filter_matches(edge_filter, &edge.name) {
                    continue;
                }
                output.push_str(&format!("edge {}\n", edge.name));
                output.push_str("  kind: forward\n");
                append_plan_flags(&mut output, "  aggregate_execution_plan", edge.flags);
                append_execution_plan(&mut output, "  default_action", &edge.default_plan);
                for rule in edge.rules.iter() {
                    if route_filter_matches(route_filter, &rule.name) {
                        append_execution_plan(
                            &mut output,
                            &format!("  rule {}", rule.name),
                            &rule.plan,
                        );
                    }
                }
            }
            runtime::CompiledEdge::Transparent(edge) => {
                if !edge_filter_matches(edge_filter, &edge.name) {
                    continue;
                }
                output.push_str(&format!("edge {}\n", edge.name));
                output.push_str("  kind: transparent\n");
                append_plan_flags(&mut output, "  aggregate_execution_plan", edge.flags);
                append_execution_plan(&mut output, "  default_action", &edge.default_plan);
                for rule in edge.rules.iter() {
                    if route_filter_matches(route_filter, &rule.name) {
                        append_execution_plan(
                            &mut output,
                            &format!("  rule {}", rule.name),
                            &rule.plan,
                        );
                    }
                }
            }
            runtime::CompiledEdge::Reverse(edge) => {
                if !edge_filter_matches(edge_filter, &edge.name) {
                    continue;
                }
                output.push_str(&format!("edge {}\n", edge.name));
                output.push_str("  kind: reverse\n");
                append_plan_flags(&mut output, "  aggregate_execution_plan", edge.flags);
                for route in edge.routes.iter() {
                    if route_filter_matches(route_filter, &route.name) {
                        append_match_criteria(
                            &mut output,
                            &format!("  route {} match_criteria", route.name),
                            &route.matcher,
                        );
                        append_reverse_target(
                            &mut output,
                            &format!("  route {} target", route.name),
                            &route.target,
                        );
                        append_execution_plan(
                            &mut output,
                            &format!("  route {}", route.name),
                            &route.plan,
                        );
                    }
                }
                for route in edge.tls_passthrough_routes.iter() {
                    if route_filter_matches(route_filter, &route.name) {
                        append_match_criteria(
                            &mut output,
                            &format!("  route {} match_criteria", route.name),
                            &route.matcher,
                        );
                        append_reverse_target(
                            &mut output,
                            &format!("  route {} target", route.name),
                            &route.target,
                        );
                    }
                }
            }
        }
    }
    output
}

fn edge_filter_matches(filter: Option<&str>, name: &str) -> bool {
    filter.map(|filter| filter == name).unwrap_or(true)
}

fn route_filter_matches(filter: Option<&str>, name: &str) -> bool {
    filter.map(|filter| filter == name).unwrap_or(true)
}

fn append_execution_plan(output: &mut String, label: &str, plan: &runtime::ExecutionPlan) {
    append_plan_flags(output, label, plan.flags);
    append_execution_details(output, plan);
}

fn append_execution_details(output: &mut String, plan: &runtime::ExecutionPlan) {
    if let Some(cache) = plan.cache.as_ref() {
        output.push_str("    cache\n");
        output.push_str(&format!("      backend: {}\n", cache.backend));
        if let Some(namespace) = cache.namespace.as_ref() {
            output.push_str(&format!("      namespace: {namespace}\n"));
        }
        output.push_str(&format!(
            "      max_object_bytes: {}\n",
            cache.max_object_bytes
        ));
    }
    if plan.capture.encrypted || plan.capture.plaintext.is_some() {
        output.push_str("    capture\n");
        output.push_str(&format!(
            "      encrypted: {}\n",
            on_off(plan.capture.encrypted)
        ));
        if let Some(plaintext) = plan.capture.plaintext.as_ref() {
            output.push_str(&format!(
                "      plaintext_headers: {}\n",
                on_off(plaintext.headers)
            ));
            output.push_str(&format!(
                "      plaintext_body: {}\n",
                on_off(plaintext.body)
            ));
            if let Some(limit) = plaintext.max_body_bytes {
                output.push_str(&format!("      max_body_bytes: {limit}\n"));
            }
        }
    }
    let module_stages = plan.modules.stage_labels();
    if module_stages.iter().any(|(_, modules)| !modules.is_empty()) {
        output.push_str("    modules\n");
        for (stage, modules) in module_stages {
            if modules.is_empty() {
                continue;
            }
            output.push_str(&format!("      {stage}\n"));
            for module in modules {
                output.push_str(&format!("        - {module}\n"));
            }
        }
    }
    let module_details = plan.modules.explain_details();
    if !module_details.is_empty() {
        output.push_str("    module_details\n");
        for (module, details) in module_details {
            output.push_str(&format!("      {module}\n"));
            for detail in details {
                output.push_str(&format!("        {detail}\n"));
            }
        }
    }
    if let Some(response_rules) = plan.response_rules.as_ref() {
        output.push_str("    response_rules_detail\n");
        output.push_str(&format!("      count: {}\n", response_rules.len()));
        output.push_str(&format!(
            "      needs_body: {}\n",
            on_off(response_rules.any_rule_requires_response_body_observation())
        ));
        output.push_str(&format!(
            "      needs_size: {}\n",
            on_off(response_rules.any_rule_requires_response_size())
        ));
        output.push_str(&format!(
            "      needs_rpc: {}\n",
            on_off(response_rules.any_rule_requires_response_rpc_observation())
        ));
    }
}

fn append_reverse_target(
    output: &mut String,
    label: &str,
    target: &runtime::CompiledReverseRouteTarget,
) {
    output.push_str(label);
    output.push('\n');
    match target {
        runtime::CompiledReverseRouteTarget::Upstream { upstreams, lb } => {
            output.push_str("    type: upstream\n");
            output.push_str(&format!("    lb: {lb}\n"));
            append_list(
                output,
                "    upstreams",
                upstreams.iter().map(|value| value.as_ref() as &str),
            );
        }
        runtime::CompiledReverseRouteTarget::Weighted { backends, lb } => {
            output.push_str("    type: weighted\n");
            output.push_str(&format!("    lb: {lb}\n"));
            for backend in backends.iter() {
                output.push_str("    backend\n");
                if let Some(name) = backend.name.as_ref() {
                    output.push_str(&format!("      name: {name}\n"));
                }
                output.push_str(&format!("      weight: {}\n", backend.weight));
                append_list(
                    output,
                    "      upstreams",
                    backend.upstreams.iter().map(|value| value.as_ref() as &str),
                );
            }
        }
        runtime::CompiledReverseRouteTarget::Ipc { mode, address } => {
            output.push_str("    type: ipc\n");
            output.push_str(&format!("    mode: {mode}\n"));
            output.push_str(&format!("    address: {address}\n"));
        }
        runtime::CompiledReverseRouteTarget::LocalResponse { status } => {
            output.push_str("    type: local_response\n");
            output.push_str(&format!("    status: {status}\n"));
        }
        runtime::CompiledReverseRouteTarget::TlsPassthrough { upstreams, lb } => {
            output.push_str("    type: tls_passthrough\n");
            output.push_str(&format!("    lb: {lb}\n"));
            append_list(
                output,
                "    upstreams",
                upstreams.iter().map(|value| value.as_ref() as &str),
            );
        }
    }
}

fn append_list<'a>(output: &mut String, label: &str, values: impl Iterator<Item = &'a str>) {
    output.push_str(label);
    output.push('\n');
    for value in values {
        output.push_str(&format!("      - {value}\n"));
    }
}

fn append_plan_flags(output: &mut String, label: &str, flags: runtime::PlanFlags) {
    output.push_str(label);
    output.push('\n');
    append_flag(output, "auth", flags.contains(runtime::PlanFlags::AUTH));
    append_flag(
        output,
        "identity_sources",
        flags.contains(runtime::PlanFlags::IDENTITY_SOURCES),
    );
    append_flag(
        output,
        "ext_authz",
        flags.contains(runtime::PlanFlags::EXT_AUTHZ),
    );
    append_flag(
        output,
        "destination_intel",
        flags.contains(runtime::PlanFlags::DESTINATION_INTEL),
    );
    append_flag(
        output,
        "http_guard",
        flags.contains(runtime::PlanFlags::HTTP_GUARD),
    );
    append_flag(
        output,
        "cache_lookup",
        flags.contains(runtime::PlanFlags::CACHE_LOOKUP),
    );
    append_flag(
        output,
        "cache_store",
        flags.contains(runtime::PlanFlags::CACHE_STORE),
    );
    append_flag(
        output,
        "request_modules",
        flags.contains(runtime::PlanFlags::REQUEST_MODULES),
    );
    append_flag(
        output,
        "response_modules",
        flags.contains(runtime::PlanFlags::RESPONSE_MODULES),
    );
    append_flag(
        output,
        "response_rules",
        flags.contains(runtime::PlanFlags::RESPONSE_RULES),
    );
    append_flag(
        output,
        "capture_encrypted",
        flags.contains(runtime::PlanFlags::CAPTURE_ENCRYPTED),
    );
    append_flag(
        output,
        "capture_plaintext",
        flags.contains(runtime::PlanFlags::CAPTURE_PLAINTEXT),
    );
    append_flag(
        output,
        "capture_body",
        flags.contains(runtime::PlanFlags::CAPTURE_BODY),
    );
    append_flag(
        output,
        "retry_body_buffer",
        flags.contains(runtime::PlanFlags::RETRY_BODY_BUFFER),
    );
}

fn append_flag(output: &mut String, label: &str, value: bool) {
    output.push_str(&format!("    {label}: {}\n", on_off(value)));
}

fn on_off(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

fn append_match_criteria(
    output: &mut String,
    label: &str,
    matcher: &qpx_core::matchers::CompiledMatch,
) {
    let ctx = qpx_core::rules::RuleMatchContext::default();
    let trace = matcher.matches_with_trace(&ctx);
    output.push_str(label);
    output.push('\n');
    if trace.reasons.is_empty() {
        output.push_str("    any: true\n");
        return;
    }
    for reason in &trace.reasons {
        match reason {
            qpx_core::matchers::MatchReason::SrcIp { configured, .. } => {
                append_match_criterion(output, "src_ip", Some("cidr"), configured)
            }
            qpx_core::matchers::MatchReason::DstPort { configured, .. } => {
                append_match_criterion(output, "dst_port", Some("exact"), &configured.to_string())
            }
            qpx_core::matchers::MatchReason::Sni {
                mode, configured, ..
            } => append_match_criterion(output, "sni", Some(match_mode_label(*mode)), configured),
            qpx_core::matchers::MatchReason::Host {
                mode, configured, ..
            } => append_match_criterion(output, "host", Some(match_mode_label(*mode)), configured),
            qpx_core::matchers::MatchReason::Method { configured, .. } => {
                append_match_criterion(output, "method", Some("exact"), configured)
            }
            qpx_core::matchers::MatchReason::Path {
                mode, configured, ..
            } => append_match_criterion(output, "path", Some(match_mode_label(*mode)), configured),
            qpx_core::matchers::MatchReason::Header {
                name, configured, ..
            } => append_match_criterion(output, &format!("header.{name}"), None, configured),
        }
    }
}

fn append_match_criterion(output: &mut String, name: &str, mode: Option<&str>, configured: &str) {
    output.push_str(&format!("    {name}\n"));
    if let Some(mode) = mode {
        output.push_str(&format!("      mode: {mode}\n"));
    }
    output.push_str(&format!("      configured: {configured}\n"));
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_match_plan(
    plan: &runtime::RuntimePlan,
    edge: &str,
    src_ip: Option<IpAddr>,
    dst_port: Option<u16>,
    sni: Option<&str>,
    host: Option<&str>,
    method: Option<&str>,
    path: Option<&str>,
) -> Result<String> {
    let ctx = qpx_core::rules::RuleMatchContext {
        src_ip,
        dst_port,
        sni,
        host,
        method,
        path,
        ..Default::default()
    };
    let mut output = String::new();
    for compiled_edge in plan.edges.iter() {
        match compiled_edge {
            runtime::CompiledEdge::Reverse(reverse) if reverse.name.as_ref() == edge => {
                for route in reverse.routes.iter() {
                    if route.matches(&ctx) {
                        output.push_str(&format!("edge: {}\n", reverse.name));
                        output.push_str("kind: reverse\n");
                        output.push_str(&format!("route: {}\n", route.name));
                        append_match_trace(&mut output, &route.matcher.matches_with_trace(&ctx));
                        append_reverse_target(&mut output, "target", &route.target);
                        append_execution_plan(&mut output, "execution_plan", &route.plan);
                        return Ok(output);
                    }
                }
                for route in reverse.tls_passthrough_routes.iter() {
                    if route.matches(&ctx) {
                        output.push_str(&format!("edge: {}\n", reverse.name));
                        output.push_str("kind: reverse\n");
                        output.push_str(&format!("route: {}\n", route.name));
                        append_match_trace(&mut output, &route.matcher.matches_with_trace(&ctx));
                        append_reverse_target(&mut output, "target", &route.target);
                        return Ok(output);
                    }
                }
                output.push_str(&format!("edge: {}\n", reverse.name));
                output.push_str("kind: reverse\n");
                output.push_str("route: <no match>\n");
                return Ok(output);
            }
            runtime::CompiledEdge::Forward(forward) if forward.name.as_ref() == edge => {
                for rule in forward.rules.iter() {
                    if rule.matches(&ctx) {
                        output.push_str(&format!("edge: {}\n", forward.name));
                        output.push_str("kind: forward\n");
                        output.push_str(&format!("rule: {}\n", rule.name));
                        append_match_trace(&mut output, &rule.matcher.matches_with_trace(&ctx));
                        append_execution_plan(&mut output, "execution_plan", &rule.plan);
                        return Ok(output);
                    }
                }
                output.push_str(&format!("edge: {}\n", forward.name));
                output.push_str("kind: forward\n");
                output.push_str("rule: <default>\n");
                append_execution_plan(&mut output, "execution_plan", &forward.default_plan);
                return Ok(output);
            }
            runtime::CompiledEdge::Transparent(transparent)
                if transparent.name.as_ref() == edge =>
            {
                for rule in transparent.rules.iter() {
                    if rule.matches(&ctx) {
                        output.push_str(&format!("edge: {}\n", transparent.name));
                        output.push_str("kind: transparent\n");
                        output.push_str(&format!("rule: {}\n", rule.name));
                        append_match_trace(&mut output, &rule.matcher.matches_with_trace(&ctx));
                        append_execution_plan(&mut output, "execution_plan", &rule.plan);
                        return Ok(output);
                    }
                }
                output.push_str(&format!("edge: {}\n", transparent.name));
                output.push_str("kind: transparent\n");
                output.push_str("rule: <default>\n");
                append_execution_plan(&mut output, "execution_plan", &transparent.default_plan);
                return Ok(output);
            }
            _ => {}
        }
    }
    anyhow::bail!("edge not found: {edge}");
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
                Some(match_mode_label(*mode)),
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
                Some(match_mode_label(*mode)),
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
                Some(match_mode_label(*mode)),
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
    output.push_str(&format!("    result: {}\n", on_off(result)));
}

fn match_mode_label(mode: qpx_core::matchers::MatchMode) -> &'static str {
    match mode {
        qpx_core::matchers::MatchMode::Exact => "exact",
        qpx_core::matchers::MatchMode::Prefix => "prefix",
        qpx_core::matchers::MatchMode::Suffix => "suffix",
        qpx_core::matchers::MatchMode::Glob => "glob",
        qpx_core::matchers::MatchMode::Regex => "regex",
        qpx_core::matchers::MatchMode::Cidr => "cidr",
        qpx_core::matchers::MatchMode::Any => "any",
    }
}
