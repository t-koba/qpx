use crate::budget::{LocBudget, TotalLocBudgets};
use crate::files::{has_cfg_test, is_test_file, rust_files_under};
use crate::function_lengths::function_length_warnings;
use crate::visitors::{FinalizeVisitor, PanicVisitor, UnwrapVisitor};
use anyhow::{Context, Result, anyhow, bail};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use syn::visit::Visit;
use syn::{GenericArgument, PathArguments, ReturnType, Type, Visibility};

const LIBRARY_ANYHOW_BOUNDARY_MAX: usize = 0;
const RAW_METRIC_MACRO_MAX: usize = 0;
const TEST_HELPER_DUPLICATE_MAX: usize = 0;
const DEPENDENCY_DUPLICATE_NAME_MAX: usize = 35;
const DENY_SKIP_ENTRY_MAX: usize = 53;
const POOL_STRUCT_BASELINE_MAX: usize = 7;
const QPXD_TLS_TYPE_BASELINE_MAX: usize = 1;
const DIRECT_HEADER_MUTATION_BASELINE_MAX: usize = 0;
const DIRECT_RESPONSE_POLICY_ENGINE_BASELINE_MAX: usize = 0;
const DISPATCH_PARALLEL_FILE_BASELINES: &[(&str, usize)] = &[
    ("access.rs", 2),
    ("prepare.rs", 3),
    ("policy.rs", 2),
    ("types.rs", 3),
    ("outcome.rs", 2),
];

fn rust_workspace_crates() -> impl Iterator<Item = &'static str> {
    include_str!("../workspace-crates.txt").lines()
}

fn duplicate_test_helpers() -> impl Iterator<Item = &'static str> {
    include_str!("../duplicate-test-helpers.txt").lines()
}

fn qpx_core_tls_allowed() -> impl Iterator<Item = &'static str> {
    include_str!("../qpx-core-tls-allowed.txt").lines()
}

struct FinalizeRule {
    path: &'static str,
    allowed_functions: Vec<&'static str>,
}

fn finalize_rules() -> impl Iterator<Item = FinalizeRule> {
    include_str!("../finalize-rules.tsv")
        .lines()
        .filter_map(|line| {
            let (path, allowed) = line.split_once('\t')?;
            Some(FinalizeRule {
                path,
                allowed_functions: allowed
                    .split(',')
                    .filter(|value| !value.is_empty())
                    .collect(),
            })
        })
}

pub(crate) fn check_loc_budgets(root: &Path, budgets: &[LocBudget]) -> Result<()> {
    let mut cmd = Command::new("./scripts/measure-structure.sh");
    cmd.current_dir(root);
    for budget in budgets {
        cmd.arg(budget.path);
    }
    let output = cmd.output().context("failed to run measure-structure.sh")?;
    if !output.status.success() {
        bail!(
            "measure-structure.sh failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout).context("measure output was not utf-8")?;
    let mut values = BTreeMap::new();
    for line in stdout.lines().skip(1) {
        let mut parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }
        let Some(value) = parts.pop() else {
            continue;
        };
        let path = parts.join(" ");
        if value == "missing" {
            continue;
        }
        let parsed = value
            .parse::<usize>()
            .with_context(|| format!("invalid code_loc for {path}: {value}"))?;
        values.insert(path, parsed);
    }

    let mut notices = Vec::new();
    for budget in budgets {
        match values.get(budget.path) {
            Some(actual) if *actual > budget.max => {
                let reason = if budget.reason.trim() == "r" {
                    "tracked advisory baseline"
                } else {
                    budget.reason
                };
                notices.push(format!(
                    "{}: {} > {} ({})",
                    budget.path, actual, budget.max, reason
                ));
            }
            Some(_) => {}
            None => notices.push(format!("{}: missing from measure output", budget.path)),
        }
    }
    if !notices.is_empty() {
        eprintln!(
            "advisory structure LOC budget notices:\n{}",
            notices.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_total_loc_budgets(root: &Path, budgets: TotalLocBudgets) -> Result<()> {
    let totals = measure_total_loc(root)?;
    let notices = [
        (
            "production rust LOC",
            totals.production_rust,
            budgets.production_rust,
        ),
        ("test rust LOC", totals.test_rust, budgets.test_rust),
        (
            "docs markdown LOC",
            totals.docs_markdown,
            budgets.docs_markdown,
        ),
    ]
    .into_iter()
    .filter(|(_, actual, max)| actual > max)
    .map(|(label, actual, max)| format!("{label}: {actual} > {max}"))
    .collect::<Vec<_>>();
    if !notices.is_empty() {
        eprintln!(
            "advisory workspace total LOC budget notices:\n{}",
            notices.join("\n")
        );
    }
    eprintln!(
        "workspace LOC advisory baselines: production_rust={} / {}, test_rust={} / {}, docs_markdown={} / {}",
        totals.production_rust,
        budgets.production_rust,
        totals.test_rust,
        budgets.test_rust,
        totals.docs_markdown,
        budgets.docs_markdown
    );
    Ok(())
}

pub(crate) fn check_dependency_duplicate_baseline(root: &Path) -> Result<()> {
    let lock_path = root.join("Cargo.lock");
    let lock = fs::read_to_string(&lock_path)
        .with_context(|| format!("failed to read {}", lock_path.display()))?;
    let mut package_versions = BTreeMap::<String, BTreeSet<String>>::new();
    let mut current_name: Option<String> = None;
    for line in lock.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            current_name = None;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("name = ") {
            current_name = Some(unquote_toml_string(value)?);
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("version = ")
            && let Some(name) = current_name.as_ref()
        {
            package_versions
                .entry(name.clone())
                .or_default()
                .insert(unquote_toml_string(value)?);
        }
    }

    let duplicates = package_versions
        .values()
        .filter(|versions| versions.len() > 1)
        .count();
    if duplicates > DEPENDENCY_DUPLICATE_NAME_MAX {
        bail!(
            "dependency duplicate-name baseline exceeded: {} > {}",
            duplicates,
            DEPENDENCY_DUPLICATE_NAME_MAX
        );
    }
    eprintln!(
        "dependency duplicate-name baseline: {} / {}",
        duplicates, DEPENDENCY_DUPLICATE_NAME_MAX
    );
    Ok(())
}

pub(crate) fn check_dependency_policy_config(root: &Path) -> Result<()> {
    let deny_path = root.join("deny.toml");
    let content = fs::read_to_string(&deny_path)
        .with_context(|| format!("failed to read {}", deny_path.display()))?;
    let value: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", deny_path.display()))?;
    let violations = dependency_policy_config_violations(&value);
    if !violations.is_empty() {
        bail!(
            "dependency policy config violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_workspace_lint_posture(root: &Path) -> Result<()> {
    let cargo_path = root.join("Cargo.toml");
    let cargo_content = fs::read_to_string(&cargo_path)
        .with_context(|| format!("failed to read {}", cargo_path.display()))?;
    let cargo: toml::Value = toml::from_str(&cargo_content)
        .with_context(|| format!("failed to parse {}", cargo_path.display()))?;
    let mut violations = workspace_lint_posture_violations(&cargo);
    for (rel, required) in [
        ("qpx-acme/src/lib.rs", &["#![warn(missing_docs)]"][..]),
        (
            "qpx-auth/src/lib.rs",
            &["#![warn(missing_docs)]", "#![forbid(unsafe_code)]"][..],
        ),
        (
            "qpx-h3/src/lib.rs",
            &["#![warn(missing_docs)]", "#![forbid(unsafe_code)]"][..],
        ),
        (
            "qpx-observability/src/lib.rs",
            &["#![warn(missing_docs)]"][..],
        ),
        (
            "qpx-wasm/src/lib.rs",
            &["#![warn(missing_docs)]", "#![forbid(unsafe_code)]"][..],
        ),
        ("qpxc/src/main.rs", &["#![forbid(unsafe_code)]"][..]),
    ] {
        let content =
            fs::read_to_string(root.join(rel)).with_context(|| format!("failed to read {rel}"))?;
        for needle in required {
            if !content.contains(needle) {
                violations.push(format!("{rel} missing {needle}"));
            }
        }
    }
    if !violations.is_empty() {
        bail!(
            "workspace lint posture violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn workspace_lint_posture_violations(cargo: &toml::Value) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(workspace) = cargo.get("workspace").and_then(toml::Value::as_table) else {
        return vec!["Cargo.toml missing [workspace]".to_string()];
    };
    let rust_version = workspace
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("rust-version"))
        .and_then(toml::Value::as_str);
    if rust_version != Some("1.87") {
        violations.push("workspace.package.rust-version must be 1.87".to_string());
    }
    let Some(lints) = workspace.get("lints").and_then(toml::Value::as_table) else {
        violations.push("Cargo.toml missing [workspace.lints]".to_string());
        return violations;
    };
    let rust_lints = lints.get("rust").and_then(toml::Value::as_table);
    for lint in ["dead_code", "unsafe_op_in_unsafe_fn", "unused"] {
        if rust_lints
            .and_then(|table| table.get(lint))
            .and_then(toml::Value::as_str)
            != Some("deny")
        {
            violations.push(format!("workspace rust lint {lint} must be deny"));
        }
    }
    let clippy_lints = lints.get("clippy").and_then(toml::Value::as_table);
    if clippy_lints
        .and_then(|table| table.get("undocumented_unsafe_blocks"))
        .and_then(toml::Value::as_str)
        != Some("deny")
    {
        violations
            .push("workspace clippy lint undocumented_unsafe_blocks must be deny".to_string());
    }
    violations
}

fn dependency_policy_config_violations(value: &toml::Value) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(bans) = value.get("bans").and_then(toml::Value::as_table) else {
        return vec!["deny.toml missing [bans]".to_string()];
    };
    if bans.get("multiple-versions").and_then(toml::Value::as_str) != Some("deny") {
        violations.push("deny.toml bans.multiple-versions must be deny".to_string());
    }
    if bans.get("wildcards").and_then(toml::Value::as_str) != Some("deny") {
        violations.push("deny.toml bans.wildcards must be deny".to_string());
    }
    if bans
        .get("skip-tree")
        .and_then(toml::Value::as_array)
        .is_none_or(|skip_tree| !skip_tree.is_empty())
    {
        violations.push("deny.toml bans.skip-tree must stay empty".to_string());
    }
    let skip = bans
        .get("skip")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if skip.len() > DENY_SKIP_ENTRY_MAX {
        violations.push(format!(
            "deny.toml skip baseline exceeded: {} > {}",
            skip.len(),
            DENY_SKIP_ENTRY_MAX
        ));
    }
    for (idx, entry) in skip.iter().enumerate() {
        let Some(table) = entry.as_table() else {
            violations.push(format!("deny.toml bans.skip[{idx}] must be a table"));
            continue;
        };
        if table
            .get("crate")
            .and_then(toml::Value::as_str)
            .is_none_or(str::is_empty)
        {
            violations.push(format!("deny.toml bans.skip[{idx}] missing crate"));
        }
        if table
            .get("reason")
            .and_then(toml::Value::as_str)
            .is_none_or(str::is_empty)
        {
            violations.push(format!("deny.toml bans.skip[{idx}] missing reason"));
        }
    }
    let Some(sources) = value.get("sources").and_then(toml::Value::as_table) else {
        violations.push("deny.toml missing [sources]".to_string());
        return violations;
    };
    if sources
        .get("unknown-registry")
        .and_then(toml::Value::as_str)
        != Some("deny")
    {
        violations.push("deny.toml sources.unknown-registry must be deny".to_string());
    }
    if sources.get("unknown-git").and_then(toml::Value::as_str) != Some("deny") {
        violations.push("deny.toml sources.unknown-git must be deny".to_string());
    }
    violations
}

fn unquote_toml_string(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Ok(inner.to_string())
    } else {
        bail!("expected quoted Cargo.lock value, got {trimmed:?}")
    }
}

struct TotalLoc {
    production_rust: usize,
    test_rust: usize,
    docs_markdown: usize,
}

fn measure_total_loc(root: &Path) -> Result<TotalLoc> {
    let mut production_rust = 0usize;
    let mut test_rust = 0usize;
    for crate_dir in rust_workspace_crates() {
        let crate_root = root.join(crate_dir);
        if !crate_root.is_dir() {
            continue;
        }
        let src = crate_root.join("src");
        if src.is_dir() {
            for path in rust_files_under(&src)? {
                let content = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                if is_test_file(&path) {
                    test_rust += count_code_lines(&content);
                } else {
                    let (production, tests) = split_inline_test_code_lines(&content);
                    production_rust += production;
                    test_rust += tests;
                }
            }
        }
        let tests = crate_root.join("tests");
        if tests.is_dir() {
            for path in rust_files_under(&tests)? {
                let content = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                test_rust += count_code_lines(&content);
            }
        }
    }

    let docs_markdown = count_markdown_loc(&root.join("docs"))?
        + count_markdown_file(root.join("ARCHITECTURE.md").as_path())?
        + count_markdown_file(root.join("README.md").as_path())?;

    Ok(TotalLoc {
        production_rust,
        test_rust,
        docs_markdown,
    })
}

fn split_inline_test_code_lines(content: &str) -> (usize, usize) {
    let mut production = 0usize;
    let mut tests = 0usize;
    let mut in_test = false;
    let mut test_depth = 0isize;
    let mut pending_cfg_test = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if !in_test && trimmed.starts_with("#[cfg(test)]") {
            pending_cfg_test = true;
            continue;
        }
        if pending_cfg_test && trimmed.starts_with("mod tests") && trimmed.contains('{') {
            in_test = true;
            test_depth = brace_delta(line);
            pending_cfg_test = false;
            continue;
        }
        if pending_cfg_test {
            pending_cfg_test = false;
        }
        if is_counted_code_line(line) {
            if in_test {
                tests += 1;
            } else {
                production += 1;
            }
        }
        if in_test {
            test_depth += brace_delta(line);
            if test_depth <= 0 {
                in_test = false;
                test_depth = 0;
            }
        }
    }
    (production, tests)
}

fn count_code_lines(content: &str) -> usize {
    content
        .lines()
        .filter(|line| is_counted_code_line(line))
        .count()
}

fn is_counted_code_line(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty()
        && !trimmed.starts_with("//")
        && !trimmed.starts_with("/*")
        && !trimmed.starts_with('*')
}

fn brace_delta(line: &str) -> isize {
    let uncommented = line.split("//").next().unwrap_or(line);
    uncommented.matches('{').count() as isize - uncommented.matches('}').count() as isize
}

fn count_markdown_loc(root: &Path) -> Result<usize> {
    if !root.is_dir() {
        return Ok(0);
    }
    let mut total = 0usize;
    for entry in fs::read_dir(root).with_context(|| format!("failed to read {}", root.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", root.display()))?;
        let path = entry.path();
        if path.is_dir() {
            total += count_markdown_loc(&path)?;
        } else {
            total += count_markdown_file(&path)?;
        }
    }
    Ok(total)
}

fn count_markdown_file(path: &Path) -> Result<usize> {
    if path.extension().and_then(|value| value.to_str()) != Some("md") {
        return Ok(0);
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

fn rel_path<'a>(root: &Path, path: &'a Path) -> Cow<'a, str> {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy()
}

pub(crate) fn check_qpx_core_tls_baseline(root: &Path) -> Result<()> {
    let cargo_toml = root.join("qpx-core/Cargo.toml");
    let content = fs::read_to_string(&cargo_toml)
        .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
    let value: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", cargo_toml.display()))?;
    let dependencies = value
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| anyhow!("qpx-core/Cargo.toml is missing [dependencies]"))?;

    let allowed = qpx_core_tls_allowed().collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    for name in dependencies.keys() {
        let is_tlsish = name.contains("tls")
            || name.contains("rustls")
            || matches!(name.as_str(), "rcgen" | "webpki-roots" | "lru");
        if is_tlsish && !allowed.contains(name.as_str()) {
            violations.push(name.clone());
        }
    }
    if !violations.is_empty() {
        bail!(
            "qpx-core direct TLS dependencies exceeded baseline: {}",
            violations.join(", ")
        );
    }
    Ok(())
}

pub(crate) fn check_finalize_entrypoints(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for rule in finalize_rules() {
        let path = root.join(rule.path);
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let syntax = syn::parse_file(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let mut visitor = FinalizeVisitor::default();
        visitor.visit_file(&syntax);
        for call in visitor.calls {
            if !rule.allowed_functions.contains(&call.enclosing_fn.as_str()) {
                violations.push(format!(
                    "{}: {} called inside {}",
                    rule.path, call.callee, call.enclosing_fn
                ));
            }
        }
    }
    if !violations.is_empty() {
        bail!(
            "entrypoint finalize_response violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_documented_unsafe_blocks(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for crate_dir in rust_workspace_crates().filter(|crate_dir| *crate_dir != "xtask") {
        let src = root.join(crate_dir).join("src");
        if !src.is_dir() {
            continue;
        }
        for path in rust_files_under(&src)? {
            if is_test_file(&path) {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let lines = content.lines().collect::<Vec<_>>();
            let rel = rel_path(root, &path);
            for (idx, line) in lines.iter().enumerate() {
                if !line.contains("unsafe") || line.trim_start().starts_with("//") {
                    continue;
                }
                if line.contains("unsafe fn") || line.contains("unsafe trait") {
                    continue;
                }
                if !line.contains("unsafe {") {
                    continue;
                }
                let start = idx.saturating_sub(4);
                let has_safety = lines[start..idx]
                    .iter()
                    .any(|candidate| candidate.contains("SAFETY:"));
                if !has_safety {
                    violations.push(format!(
                        "{}:{}: unsafe block missing SAFETY comment",
                        rel,
                        idx + 1
                    ));
                }
            }
        }
    }
    if !violations.is_empty() {
        bail!(
            "undocumented unsafe block violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_production_unwraps(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    visit_production_sources(root, |rel, syntax| {
        let mut visitor = UnwrapVisitor::default();
        visitor.visit_file(&syntax);
        for call in visitor.panicking_calls {
            violations.push(format!("{rel}: {}() in {}", call.method, call.enclosing_fn));
        }
        Ok(())
    })?;
    if !violations.is_empty() {
        bail!(
            "production unwrap()/expect() violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_production_panics(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    visit_production_sources(root, |rel, syntax| {
        let mut visitor = PanicVisitor::default();
        visitor.visit_file(&syntax);
        for call in visitor.panics {
            violations.push(format!(
                "{rel}: {}!() in {}",
                call.macro_name, call.enclosing_fn
            ));
        }
        Ok(())
    })?;
    if !violations.is_empty() {
        bail!(
            "production panic/todo/unimplemented violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn visit_production_sources(
    root: &Path,
    mut visit: impl FnMut(String, syn::File) -> Result<()>,
) -> Result<()> {
    for crate_dir in rust_workspace_crates() {
        let scan_root = root.join(crate_dir).join("src");
        for path in rust_files_under(scan_root.as_path())? {
            if is_test_file(&path) {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let syntax = syn::parse_file(&content)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            visit(rel_path(root, &path).to_string(), syntax)?;
        }
    }
    Ok(())
}

pub(crate) fn check_function_lengths(root: &Path) -> Result<()> {
    const WARN_OVER_LINES: usize = 200;
    let mut warnings = Vec::new();
    for path in rust_files_under(root.join("qpxd/src").as_path())? {
        if is_test_file(&path) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let rel = rel_path(root, &path);
        warnings.extend(function_length_warnings(
            rel.as_ref(),
            content.as_str(),
            WARN_OVER_LINES,
        ));
    }
    for warning in &warnings {
        eprintln!("{warning}");
    }
    eprintln!("long function advisory count: {}", warnings.len());
    Ok(())
}

pub(crate) fn check_dispatch_dependency_direction(root: &Path) -> Result<()> {
    let dispatch_dir = root.join("qpxd/src/http/dispatch");
    if !dispatch_dir.is_dir() {
        bail!("qpxd/src/http/dispatch is missing");
    }
    let forbidden = [
        "crate::forward",
        "crate::reverse",
        "crate::transparent",
        "super::super::forward",
        "super::super::reverse",
        "super::super::transparent",
    ];
    let mut violations = Vec::new();
    for path in rust_files_under(&dispatch_dir)? {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let rel = rel_path(root, &path);
        for needle in forbidden {
            if content.contains(needle) {
                violations.push(format!("{rel}: imports mode-specific module via {needle}"));
            }
        }
    }
    if !violations.is_empty() {
        bail!(
            "http/dispatch dependency direction violations:\n{}",
            violations.join("\n")
        );
    }
    let acceptance = fs::read_to_string(root.join("scripts/check-ci-acceptance-gates.sh"))?;
    for needle in "fn policy_id(&self) -> Option<&str>;fn policy_tags(&self) -> &[String];build_dispatch_audit_context;apply_ext_authz_http_access;apply_dispatch_response_policy;dispatch_cache_collapse_continue;finalize_dispatch_collapsed_cache_decision;check_dispatch_limit_response_commonality;check_dispatch_annotated_local_response_commonality;check_response_capture_after_finalize;check_proxy_authorization_header_boundary;check_reverse_response_rules_dispatch_boundary;check_h3_origin_pool_load_semantics;check_qpxf_cgi_header_parser_zero_copy;check_qpx_h3_static_response_boundary;check_rpc_frame_boundary_tests;finalize_response_headers_common;finalize_response_with_headers_in_place;set_proxy_authorization_header;trait HeaderTransform;trait ResponseTransform;MIRROR_MAX_INFLIGHT_PER_ENDPOINT;EXT_AUTHZ_RESPONSE_BUFFERS;request_side_fail_closed;send_prefixed_datagram;validate_secure_file_handle".split(';') {
        if !acceptance.contains(needle) {
            bail!("CI acceptance gate is missing required check: {needle}");
        }
    }
    Ok(())
}

pub(crate) fn check_phase3_architecture_baselines(root: &Path) -> Result<()> {
    check_dispatch_parallel_file_baseline(root)?;
    check_connection_pool_trait_boundary(root)?;
    check_pool_struct_baseline(root)?;
    check_qpxd_tls_type_baseline(root)?;
    check_response_transform_baselines(root)?;
    check_reverse_response_rules_dispatch_boundary(root)?;
    check_proxy_authorization_header_boundary(root)?;
    check_dispatch_access_commonality_baseline(root)?;
    check_dispatch_audit_builder_commonality(root)?;
    check_canonical_config_loader_baseline(root)?;
    check_manual_session_shard_modulo_baseline(root)?;
    check_shard_initialization_helper_baseline(root)?;
    check_reverse_dispatch_no_debug_cache_keys(root)?;
    check_qpx_h3_datagram_send_boundary(root)?;
    check_h3_open_queue_backpressure_baseline(root)?;
    check_h3_origin_pool_load_semantics(root)?;
    check_reverse_mirror_spawn_backpressure(root)?;
    check_ext_authz_response_buffering(root)?;
    check_response_compression_worker_backpressure(root)?;
    check_reverse_retry_template_bounded_body(root)?;
    check_http_module_body_mode_contract(root)?;
    check_rpc_frame_boundary_tests(root)?;
    check_qpxr_capture_publish_order(root)?;
    check_qpxf_cgi_header_parser_zero_copy(root)?;
    check_qpxf_ipc_cleanup_backpressure(root)?;
    check_secure_file_write_boundaries(root)?;
    check_qpx_h3_static_response_boundary(root)?;
    check_dispatch_cache_collapse_commonality(root)?;
    check_dispatch_limit_response_commonality(root)?;
    check_http_response_body_hard_cap(root)?;
    check_dispatch_annotated_local_response_commonality(root)?;
    check_dispatch_max_forwards_response_commonality(root)?;
    check_dispatch_body_too_large_response_commonality(root)?;
    Ok(())
}

pub(crate) fn check_secret_zeroize_boundaries(root: &Path) -> Result<()> {
    let util = fs::read_to_string(root.join("qpxd/src/policy_context/util.rs"))?;
    let local = fs::read_to_string(root.join("qpx-auth/src/auth/local.rs"))?;
    let cargo = fs::read_to_string(root.join("Cargo.toml"))?;
    let violations = secret_zeroize_boundary_violations(&util, &local, &cargo);
    if !violations.is_empty() {
        bail!(
            "secret zeroize boundary violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn secret_zeroize_boundary_violations(
    policy_util: &str,
    auth_local: &str,
    cargo_toml: &str,
) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "zeroize = \"1\"",
        "use zeroize::Zeroizing;",
        "let secret = Zeroizing::new(",
        "Arc::<[u8]>::from(secret.as_slice())",
        "use zeroize::Zeroize;",
        "struct LocalPasswordDigest",
        "impl Drop for LocalPasswordDigest",
        "self.0.zeroize();",
        "struct LocalDigestHa1",
        "impl Drop for LocalDigestHa1",
    ] {
        let haystack = if required == "zeroize = \"1\"" {
            cargo_toml
        } else if required.contains("Zeroizing")
            || required.contains("Arc::<[u8]>::from(secret.as_slice())")
        {
            policy_util
        } else {
            auth_local
        };
        if !haystack.contains(required) {
            violations.push(required);
        }
    }
    violations
}

fn check_reverse_dispatch_no_debug_cache_keys(root: &Path) -> Result<()> {
    let paths = [
        "qpxd/src/reverse/transport/dispatch.rs",
        "qpxd/src/reverse/transport/dispatch/prepare.rs",
    ];
    let mut violations = Vec::new();
    for rel in paths {
        let content = fs::read_to_string(root.join(rel))?;
        for violation in reverse_debug_cache_key_violations(&content) {
            violations.push(format!("{rel}: {violation}"));
        }
    }
    if !violations.is_empty() {
        bail!(
            "reverse dispatch hot path must not allocate Debug cache keys:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn reverse_debug_cache_key_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for forbidden in ["format!(\"{:?}\"", "format!(r#\"{:?}\""] {
        if content.contains(forbidden) {
            violations.push("format!(\"{:?}\")");
        }
    }
    violations
}

fn check_dispatch_access_commonality_baseline(root: &Path) -> Result<()> {
    let paths = [
        "qpxd/src/forward/request/dispatch.rs",
        "qpxd/src/reverse/transport/dispatch/access.rs",
        "qpxd/src/transparent/http/dispatch/complete.rs",
        "qpxd/src/http/mitm/dispatch.rs",
    ];
    let mut violations = Vec::new();
    for rel in paths {
        let path = root.join(rel);
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        violations.extend(
            dispatch_access_commonality_violations(&content)
                .into_iter()
                .map(|violation| format!("{rel}: {violation}")),
        );
    }
    if !violations.is_empty() {
        bail!(
            "dispatch access commonality baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn dispatch_access_commonality_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    // The combined stage wraps audit construction and ext_authz application;
    // dispatchers may either call it or use the two shared primitives, but
    // must never hand-roll the sequence.
    let uses_combined_stage = content.contains("enforce_http_access(");
    if !uses_combined_stage && !content.contains("build_dispatch_audit_context(") {
        violations.push("missing build_dispatch_audit_context");
    }
    if !uses_combined_stage && !content.contains("apply_ext_authz_http_access(") {
        violations.push("missing apply_ext_authz_http_access");
    }
    for forbidden in [
        "DispatchAuditContext::new(",
        ".policy_id()",
        ".policy_tags()",
        "ExtAuthzEnforcement::Continue",
        "ExtAuthzEnforcement::Deny",
    ] {
        if content.contains(forbidden) {
            violations.push(forbidden);
        }
    }
    violations
}

fn check_dispatch_audit_builder_commonality(root: &Path) -> Result<()> {
    let paths = [
        ("qpxd/src/forward/request/dispatch.rs", true),
        ("qpxd/src/forward/request/dispatch/policy.rs", true),
        ("qpxd/src/http/mitm/dispatch.rs", true),
        (
            "qpxd/src/transparent/http/dispatch/prepare_helpers.rs",
            true,
        ),
        ("qpxd/src/reverse/transport/dispatch.rs", false),
    ];
    let mut violations = Vec::new();
    for (rel, require_builder) in paths {
        let content = fs::read_to_string(root.join(rel))?;
        violations.extend(
            dispatch_audit_builder_commonality_violations(&content, require_builder)
                .into_iter()
                .map(|violation| format!("{rel}: {violation}")),
        );
    }
    if !violations.is_empty() {
        bail!(
            "dispatch audit builder commonality violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn dispatch_audit_builder_commonality_violations(
    content: &str,
    require_builder: bool,
) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if require_builder && !content.contains("build_dispatch_audit_context(") {
        violations.push("missing build_dispatch_audit_context");
    }
    if content.contains("DispatchAuditContext::new(") {
        violations.push("DispatchAuditContext::new(");
    }
    violations
}

fn check_connection_pool_trait_boundary(root: &Path) -> Result<()> {
    let mod_rel = "qpxd/src/upstream/pool/mod.rs";
    let mod_content = fs::read_to_string(root.join(mod_rel))?;
    let cluster_rel = "qpxd/src/upstream/pool/cluster.rs";
    let cluster_content = fs::read_to_string(root.join(cluster_rel))?;
    let violations = connection_pool_trait_boundary_violations(&mod_content, &cluster_content);
    if !violations.is_empty() {
        bail!(
            "connection pool trait boundary violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn connection_pool_trait_boundary_violations(
    mod_content: &str,
    cluster_content: &str,
) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "trait ConnectionPool<T>",
        "type Acquire;",
        "fn acquire_connection",
    ] {
        if !mod_content.contains(required) {
            violations.push("missing ConnectionPool acquire contract");
            break;
        }
    }
    for required in [
        "impl ConnectionPool<ResolvedUpstreamProxy> for Arc<UpstreamProxyCluster>",
        "self.select()",
    ] {
        if !cluster_content.contains(required) {
            violations.push("UpstreamProxyCluster must implement ConnectionPool acquisition without changing selection semantics");
            break;
        }
    }
    violations
}

fn check_dispatch_cache_collapse_commonality(root: &Path) -> Result<()> {
    let paths = [
        "qpxd/src/forward/request/dispatch/request_dispatch_cache.rs",
        "qpxd/src/reverse/transport/dispatch/dispatch_cache.rs",
    ];
    let mut violations = Vec::new();
    for rel in paths {
        let path = root.join(rel);
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        violations.extend(
            dispatch_cache_collapse_commonality_violations(&content)
                .into_iter()
                .map(|violation| format!("{rel}: {violation}")),
        );
    }
    if !violations.is_empty() {
        bail!(
            "dispatch cache collapse commonality baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn dispatch_cache_collapse_commonality_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if !content.contains("dispatch_cache_collapse_continue(") {
        violations.push("missing dispatch_cache_collapse_continue");
    }
    if !content.contains("dispatch_cache_collapse_response(") {
        violations.push("missing dispatch_cache_collapse_response");
    }
    if !content.contains("finalize_dispatch_collapsed_cache_decision(") {
        violations.push("missing finalize_dispatch_collapsed_cache_decision");
    }
    for forbidden in [
        "DispatchOutcome::CacheCollapsedHit",
        "DispatchOutcome::CacheCollapsedStale",
    ] {
        if content.contains(forbidden) {
            violations.push(forbidden);
        }
    }
    violations
}

fn check_dispatch_limit_response_commonality(root: &Path) -> Result<()> {
    let paths = [
        "qpxd/src/forward/request/dispatch",
        "qpxd/src/reverse/transport/dispatch",
        "qpxd/src/transparent/http/dispatch",
        "qpxd/src/http/mitm",
        "qpxd/src/http/dispatch",
    ];
    let mut violations = Vec::new();
    for rel in paths {
        for path in rust_files_under(&root.join(rel))? {
            let rel_path = rel_path(root, &path);
            if rel_path == "qpxd/src/http/dispatch/limit_response.rs" {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            violations.extend(
                dispatch_limit_response_commonality_violations(&content)
                    .into_iter()
                    .map(|violation| format!("{rel_path}: {violation}")),
            );
        }
    }
    if !violations.is_empty() {
        bail!(
            "dispatch limit response commonality baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn dispatch_limit_response_commonality_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for forbidden in [
        "too_many_requests_response(",
        "DispatchOutcome::RateLimited",
        "DispatchOutcome::ConcurrencyLimited",
    ] {
        if content.contains(forbidden) {
            violations.push(forbidden);
        }
    }
    violations
}

fn check_http_response_body_hard_cap(root: &Path) -> Result<()> {
    let files = [
        "qpxd/src/http/capture/stream.rs",
        "qpxd/src/http/dispatch/cache.rs",
        "qpxd/src/http/dispatch/cache_decision.rs",
        "qpxd/src/forward/request/dispatch/request_dispatch_upstream.rs",
        "qpxd/src/forward/request/dispatch.rs",
        "qpxd/src/forward/request/dispatch/prepare.rs",
        "qpxd/src/reverse/transport/dispatch/outcome.rs",
        "qpxd/src/reverse/transport/dispatch/dispatch_http.rs",
        "qpxd/src/reverse/transport/dispatch/dispatch_ipc.rs",
        "qpxd/src/transparent/http/dispatch/complete.rs",
        "qpxd/src/transparent/http/dispatch/prepared.rs",
        "qpxd/src/http/mitm/dispatch.rs",
        "qpxd/src/http/mitm/upstream.rs",
    ];
    let mut content = String::new();
    for rel in files {
        content.push_str(&fs::read_to_string(root.join(rel)).with_context(|| rel.to_string())?);
        content.push('\n');
    }
    let violations = http_response_body_hard_cap_violations(&content);
    if !violations.is_empty() {
        bail!(
            "HTTP/1/2 response body hard-cap boundary violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_http_body_spool_failure_handling(root: &Path) -> Result<()> {
    let content = fs::read_to_string(root.join("qpxd/src/http/body/size.rs"))
        .context("qpxd/src/http/body/size.rs")?;
    let violations = http_body_spool_failure_handling_violations(&content);
    if !violations.is_empty() {
        bail!(
            "HTTP body spool failure handling violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn http_body_spool_failure_handling_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "pub(crate) enum ObservedBodySpoolError",
        "Create {",
        "operation: &'static str",
        "is_observed_body_spool_error",
        "record_body_spool_error(direction, reason, \"create\")",
        "record_body_spool_error(direction, reason, \"write\")",
        "record_body_spool_error(direction, reason, \"flush\")",
        "write_observed_body_spool(",
        "flush_observed_body_spool(",
    ] {
        if !content.contains(required) {
            violations.push(required);
        }
    }
    violations
}

fn check_rpc_frame_boundary_tests(root: &Path) -> Result<()> {
    let content = fs::read_to_string(root.join("qpxd/src/http/rpc/tests.rs"))
        .context("qpxd/src/http/rpc/tests.rs")?;
    let violations = rpc_frame_boundary_test_violations(&content);
    if !violations.is_empty() {
        bail!(
            "RPC frame boundary test coverage violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn rpc_frame_boundary_test_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "grpc_observer_parses_five_byte_header_split_one_byte_at_a_time",
        "grpc_web_text_observer_parses_base64_quantum_split_one_byte_at_a_time",
        "connect_streaming_observer_reassembles_eos_metadata_split_one_byte_at_a_time",
        "for byte in body",
        "for byte in encoded.bytes()",
    ] {
        if !content.contains(required) {
            violations.push(required);
        }
    }
    violations
}

fn http_response_body_hard_cap_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "pub(crate) fn limit_response_body_for_plan",
        "plan.streaming.max_response_body_bytes",
        "body.limit_bytes(max_bytes)",
        "emit_optional_response_for_export(response, selected_plan",
        "emit_optional_response_for_export(",
        "capture_reverse_response_outcome",
        "finalize_dispatch_cached_response",
        "plan: &'a crate::runtime::ExecutionPlan",
        "limit_response_body_for_plan(\n        response, plan,",
        "limit_response_body_for_plan(response, &selected_plan)",
        "limit_response_body_for_plan(response, selected_plan)",
        "input.selected_plan",
    ] {
        if !content.contains(required) {
            violations.push(required);
        }
    }
    violations
}

fn check_dispatch_annotated_local_response_commonality(root: &Path) -> Result<()> {
    let paths = [
        "qpxd/src/forward/request/dispatch",
        "qpxd/src/reverse/transport/dispatch",
        "qpxd/src/transparent/http/dispatch",
        "qpxd/src/http/mitm",
        "qpxd/src/http/dispatch",
    ];
    let allowed = "qpxd/src/http/dispatch/prepare/response.rs";
    let mut violations = Vec::new();
    for rel in paths {
        for path in rust_files_under(&root.join(rel))? {
            let rel_path = rel_path(root, &path);
            if rel_path == allowed {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            violations.extend(
                dispatch_annotated_local_response_commonality_violations(&content)
                    .into_iter()
                    .map(|violation| format!("{rel_path}: {violation}")),
            );
        }
    }
    if !violations.is_empty() {
        bail!(
            "dispatch annotated local response commonality baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn dispatch_annotated_local_response_commonality_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if content.contains("finalized_local_response(") {
        violations.push("finalized_local_response(");
    }
    violations
}

fn check_dispatch_max_forwards_response_commonality(root: &Path) -> Result<()> {
    let paths = [
        "qpxd/src/reverse/transport/dispatch.rs",
        "qpxd/src/transparent/http/dispatch/complete.rs",
        "qpxd/src/http/mitm/upstream.rs",
    ];
    let mut violations = Vec::new();
    for rel in paths {
        let content = fs::read_to_string(root.join(rel))?;
        violations.extend(
            dispatch_max_forwards_response_commonality_violations(&content)
                .into_iter()
                .map(|violation| format!("{rel}: {violation}")),
        );
    }
    if !violations.is_empty() {
        bail!(
            "dispatch max-forwards response commonality baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn dispatch_max_forwards_response_commonality_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if !content.contains("annotated_max_forwards_response(") {
        violations.push("missing annotated_max_forwards_response");
    }
    if content.contains("handle_max_forwards_in_place(") {
        violations.push("handle_max_forwards_in_place(");
    }
    violations
}

fn check_dispatch_body_too_large_response_commonality(root: &Path) -> Result<()> {
    let paths = [
        "qpxd/src/http/dispatch/prepare.rs",
        "qpxd/src/reverse/transport/dispatch/prepare.rs",
        "qpxd/src/http/mitm/dispatch.rs",
    ];
    let mut violations = Vec::new();
    for rel in paths {
        let content = fs::read_to_string(root.join(rel))?;
        violations.extend(
            dispatch_body_too_large_response_commonality_violations(&content)
                .into_iter()
                .map(|violation| format!("{rel}: {violation}")),
        );
    }
    if !violations.is_empty() {
        bail!(
            "dispatch body-too-large response commonality baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn dispatch_body_too_large_response_commonality_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if !content.contains("request_body_too_large_response(") {
        violations.push("missing request_body_too_large_response");
    }
    for forbidden in [
        "StatusCode::PAYLOAD_TOO_LARGE",
        "http::StatusCode::PAYLOAD_TOO_LARGE",
        "Body::from(\"request body too large\")",
    ] {
        if content.contains(forbidden) {
            violations.push(forbidden);
        }
    }
    violations
}

fn check_canonical_config_loader_baseline(root: &Path) -> Result<()> {
    let loader_path = root.join("qpx-core/src/config/types/canonical/mod.rs");
    let content = fs::read_to_string(&loader_path)
        .with_context(|| format!("failed to read {}", loader_path.display()))?;
    let forbidden = ["unreachable!(", "panic!(", "todo!(", "unimplemented!("];
    let mut violations = forbidden
        .into_iter()
        .filter(|needle| content.contains(needle))
        .map(|needle| format!("qpx-core/src/config/types/canonical/mod.rs: {needle}"))
        .collect::<Vec<_>>();
    violations.extend(single_canonical_config_schema_violations(
        root,
        [
            "qpx-core/src/config/types/canonical/mod.rs",
            "qpx-core/src/config/types/canonical/schema.rs",
            "qpxd/src/cli.rs",
            "qpxd/src/daemon.rs",
            "qpxd/src/startup.rs",
            "docs/config-schema.md",
        ],
    )?);
    let sample_path = root.join("qpx-core/src/config/tests/sample_config_tests.rs");
    let sample_content = fs::read_to_string(&sample_path)
        .with_context(|| format!("failed to read {}", sample_path.display()))?;
    violations.extend(
        canonical_sample_config_guard_violations(&sample_content)
            .into_iter()
            .map(|violation| {
                format!("qpx-core/src/config/tests/sample_config_tests.rs: {violation}")
            }),
    );
    if !violations.is_empty() {
        bail!(
            "canonical config loader baseline violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn single_canonical_config_schema_violations(
    root: &Path,
    paths: impl IntoIterator<Item = &'static str>,
) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    for rel in paths {
        let content =
            fs::read_to_string(root.join(rel)).with_context(|| format!("failed to read {rel}"))?;
        for forbidden in [
            "schema_version",
            "qpx.config/v1",
            "UpgradeConfig",
            "upgrade_config",
        ] {
            if content.contains(forbidden) {
                violations.push(format!(
                    "{rel}: canonical config must not carry schema-version compatibility marker `{forbidden}`"
                ));
            }
        }
        if content.contains("upgrade-config") {
            violations.push(format!(
                "{rel}: canonical config must not expose upgrade-config compatibility command"
            ));
        }
    }
    Ok(violations)
}

fn canonical_sample_config_guard_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "fn sample_qpxd_configs_load()",
        "collect_yaml_files(&root.join(\"config/usecases\"), &mut files)",
        "root.join(\"config/qpx.example.yaml\")",
        "is_qpxd_sample_config(path)",
        "expand_sample_env(&raw)",
        "copy_sample_fragments(&root, &dir)",
        "load_config(&config)",
    ] {
        if !content.contains(required) {
            violations.push("sample config guard must load qpx.example and qpxd usecases through the real loader");
            break;
        }
    }
    violations
}

fn check_manual_session_shard_modulo_baseline(root: &Path) -> Result<()> {
    let paths = [
        "qpxd/src/reverse/h3/passthrough/index/shared.rs",
        "qpxd/src/transparent/udp/session/index.rs",
        "qpx-h3/src/client/registry.rs",
        "qpx-h3/src/server/registry.rs",
        "qpx-h3/src/transport/datagram.rs",
        "qpxd/src/http/modules/response_compression/streaming.rs",
    ];
    let mut violations = Vec::new();
    for rel in paths {
        let path = root.join(rel);
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        for needle in manual_session_shard_modulo_needles(&content) {
            violations.push(format!("{rel}: {needle}"));
        }
    }
    if !violations.is_empty() {
        bail!(
            "manual session shard modulo baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn manual_session_shard_modulo_needles(content: &str) -> Vec<&'static str> {
    let compact = content
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    [
        (
            "(session_id as usize) % self.shards.len()",
            "(session_idasusize)%self.shards.len()",
        ),
        (
            "(stream_id as usize) % self.streams.len()",
            "(stream_idasusize)%self.streams.len()",
        ),
        (
            "session_id as usize % self.workers.len()",
            "session_idasusize%self.workers.len()",
        ),
    ]
    .into_iter()
    .filter_map(|(reported, compact_needle)| compact.contains(compact_needle).then_some(reported))
    .collect()
}

fn check_shard_initialization_helper_baseline(root: &Path) -> Result<()> {
    let helper = fs::read_to_string(root.join("qpx-http/src/sharding.rs"))?;
    let mut violations = shard_initialization_helper_violations(&helper);
    let async_map_files = [
        "qpxd/src/upstream/pool/sender_pool.rs",
        "qpxd/src/ipc_client/pool.rs",
        "qpxd/src/upstream/origin/http_backend/h3_pool/alt_svc.rs",
    ];
    for rel in async_map_files {
        let content = fs::read_to_string(root.join(rel))?;
        if !content.contains("AsyncShardMap") {
            violations.push(format!("{rel}: missing AsyncShardMap"));
        }
        violations.extend(
            async_shard_map_field_violations(&content)
                .into_iter()
                .map(|violation| format!("{rel}: {violation}")),
        );
    }
    for rel in [
        "qpxd/src/upstream/pool/sender_pool.rs",
        "qpxd/src/ipc_client/pool.rs",
        "qpxd-cache/src/types.rs",
        "qpxd/src/http3/quinn_socket/broker/rate_limiter.rs",
    ] {
        let content = fs::read_to_string(root.join(rel))?;
        violations.extend(
            shard_initialization_loop_violations(&content)
                .into_iter()
                .map(|violation| format!("{rel}: {violation}")),
        );
    }
    if !violations.is_empty() {
        bail!(
            "shard initialization helper baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn shard_initialization_helper_violations(content: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for required in [
        "fn sync_mutex_shards",
        "fn async_mutex_shards",
        "struct AsyncShardMap",
    ] {
        if !content.contains(required) {
            violations.push(format!("missing {required}"));
        }
    }
    violations
}

fn shard_initialization_loop_violations(content: &str) -> Vec<String> {
    let compact = content
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let mut violations = Vec::new();
    if compact.contains("Vec::with_capacity(shards)") {
        violations.push("manual shard Vec::with_capacity(shards)".to_string());
    }
    if compact.contains("for_in0..shards") {
        violations.push("manual shard initialization loop".to_string());
    }
    violations
}

fn async_shard_map_field_violations(content: &str) -> Vec<String> {
    let compact = content
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    if compact.contains("Vec<Mutex<HashMap") {
        vec!["manual async sharded HashMap field".to_string()]
    } else {
        Vec::new()
    }
}

fn check_qpx_h3_datagram_send_boundary(root: &Path) -> Result<()> {
    let rel = "qpx-h3/src/transport/datagram.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = qpx_h3_datagram_send_boundary_violations(&content);
    if !violations.is_empty() {
        bail!(
            "qpx-h3 datagram send boundary violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn qpx_h3_datagram_send_boundary_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "pub fn send_prefixed_datagram",
        "pub fn send_unprefixed_datagram_with_scratch",
    ] {
        if !content.contains(required) {
            violations.push("missing explicit datagram send boundary");
            break;
        }
    }
    if content.contains("pub fn send_datagram(") {
        violations.push("ambiguous unprefixed send_datagram API");
    }
    violations
}

fn check_h3_open_queue_backpressure_baseline(root: &Path) -> Result<()> {
    let rel = "qpxd/src/upstream/origin/http_backend/h3_pool.rs";
    let path = root.join(rel);
    let content =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let production = content.split("#[cfg(test)]").next().unwrap_or(&content);
    let violations = h3_open_queue_backpressure_violations(production);
    if !violations.is_empty() {
        bail!(
            "H3 origin open queue backpressure baseline exceeded:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn h3_open_queue_backpressure_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if !content.contains("request_open_tx.send(job)") {
        violations.push("missing bounded request_open_tx.send(job)");
    }
    if content.contains("request_open_tx.try_send(") || content.contains(".try_send(job)") {
        violations.push("request open queue uses try_send");
    }
    for forbidden in [
        "Mutex<H3SendRequest",
        "Mutex < H3SendRequest",
        "sender: Mutex",
    ] {
        if content.contains(forbidden) {
            violations.push("request open uses sender mutex");
            break;
        }
    }
    violations
}

fn check_h3_origin_pool_load_semantics(root: &Path) -> Result<()> {
    let rel = "qpxd/src/upstream/origin/http_backend/h3_pool/pool.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = h3_origin_pool_load_semantics_violations(&content);
    if !violations.is_empty() {
        bail!(
            "H3 origin pool load semantics violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn h3_origin_pool_load_semantics_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    let Some(load_fn) = function_body_section(content, "fn h3_connection_effective_load") else {
        return vec!["missing h3_connection_effective_load"];
    };
    if !load_fn.contains("conn.inflight_streams.load(Ordering::Relaxed)") {
        violations.push("effective load must use reserved inflight streams");
    }
    if load_fn.contains("open_queue_depth") {
        violations.push("effective load must not double count open queue depth");
    }
    let Some(capacity_fn) =
        function_body_section(content, "fn h3_connection_stream_capacity_for_limits")
    else {
        violations.push("missing h3_connection_stream_capacity_for_limits");
        return violations;
    };
    if !capacity_fn.contains("max_inflight_streams_per_connection.min(open_queue_capacity)") {
        violations.push("stream capacity must be capped by open queue capacity");
    }
    violations
}

fn function_body_section<'a>(content: &'a str, signature: &str) -> Option<&'a str> {
    let start = content.find(signature)?;
    let section = &content[start..];
    let body_start = section.find('{')?;
    let mut depth = 0isize;
    for (idx, ch) in section[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&section[..body_start + idx + 1]);
                }
            }
            _ => {}
        }
    }
    Some(section)
}

fn check_reverse_mirror_spawn_backpressure(root: &Path) -> Result<()> {
    let rel = "qpxd/src/reverse/transport/mirrors.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = reverse_mirror_spawn_backpressure_violations(&content);
    if !violations.is_empty() {
        bail!(
            "reverse mirror spawn backpressure baseline exceeded:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn reverse_mirror_spawn_backpressure_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    let permit_count = content.matches("try_acquire_mirror_permit(").count();
    let spawn_count = content.matches("tokio::spawn(async move").count();
    if permit_count < spawn_count {
        violations.push("mirror spawn count exceeds permit acquisition count");
    }
    for dispatch_fn in [
        "pub(super) fn dispatch_mirrors(",
        "pub(super) fn dispatch_streaming_mirrors(",
    ] {
        let Some(start) = content.find(dispatch_fn) else {
            violations.push("missing mirror dispatch function");
            continue;
        };
        let section = &content[start..];
        let permit_pos = section.find("try_acquire_mirror_permit(");
        let spawn_pos = section.find("tokio::spawn(async move");
        match (permit_pos, spawn_pos) {
            (Some(permit_pos), Some(spawn_pos)) if permit_pos < spawn_pos => {}
            (Some(_), Some(_)) => violations.push("mirror task spawned before permit acquisition"),
            (None, Some(_)) => violations.push("mirror task spawned without permit acquisition"),
            (Some(_), None) => {
                violations.push("mirror dispatch acquires permit but does not spawn task")
            }
            (None, None) => violations.push("mirror dispatch missing permit acquisition and spawn"),
        }
    }
    violations
}

fn check_ext_authz_response_buffering(root: &Path) -> Result<()> {
    let rel = "qpxd/src/policy_context/ext_authz.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = ext_authz_response_buffering_violations(&content);
    if !violations.is_empty() {
        bail!(
            "ext_authz response buffering baseline exceeded:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn ext_authz_response_buffering_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for needle in [
        "EXT_AUTHZ_INLINE_RESPONSE_BYTES",
        "EXT_AUTHZ_RESPONSE_BUFFERS",
        "struct ExtAuthzBodyBuffer",
        "heap: Option<Vec<u8>>",
        "collect_ext_authz_response_body(",
        "while let Some(frame) = body.frame().await",
        "out.extend(&data)?",
    ] {
        if !content.contains(needle) {
            violations.push("missing inline-first bounded ext_authz response collector");
            break;
        }
    }
    if content.contains("to_bytes_limited(") {
        violations.push("ext_authz response collector uses to_bytes_limited");
    }
    if content.contains(".collect().await") {
        violations.push("ext_authz response collector uses collect().await");
    }
    violations
}

fn check_response_compression_worker_backpressure(root: &Path) -> Result<()> {
    let rel = "qpxd/src/http/modules/response_compression/streaming.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = response_compression_worker_backpressure_violations(&content);
    if !violations.is_empty() {
        bail!(
            "response compression worker backpressure violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn response_compression_worker_backpressure_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if content.contains(".blocking_send(") {
        violations.push("compression worker must not block on async result channels");
    }
    if !content.contains("send_compression_worker_result(") {
        violations.push("compression worker results must go through nonblocking helper");
    }
    if !content.contains("mpsc::channel(COMPRESSION_PIPELINE_DEPTH.max(1))") {
        violations.push("compression result channel must remain bounded");
    }
    violations
}

fn check_reverse_retry_template_bounded_body(root: &Path) -> Result<()> {
    let template_rel = "qpxd/src/reverse/transport/request_template.rs";
    let template = fs::read_to_string(root.join(template_rel))?;
    let prepare_rel = "qpxd/src/reverse/transport/dispatch/prepare.rs";
    let prepare = fs::read_to_string(root.join(prepare_rel))?;
    let validate_rel = "qpx-core/src/config/validate/reverse.rs";
    let validate = fs::read_to_string(root.join(validate_rel))?;
    let violations = reverse_retry_template_bounded_body_violations(&template, &prepare, &validate);
    if !violations.is_empty() {
        bail!(
            "reverse retry template bounded-body baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn reverse_retry_template_bounded_body_violations(
    template: &str,
    prepare: &str,
    validate: &str,
) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for needle in [
        "content_length(req).is_some_and(|len| len <= body_threshold_bytes as u64)",
        "if req.headers().contains_key(TRANSFER_ENCODING)",
        "return None;",
        "if next > max_body_bytes",
        "create_template_spool().await?",
    ] {
        if !template.contains(needle) {
            violations.push("reverse retry template must stay explicitly bounded");
            break;
        }
    }
    if template.contains("request_may_have_body(req) ||") {
        violations.push("reverse retry template accepts unknown body length");
    }
    if template.contains("collect().await") || template.contains("to_bytes_limited(") {
        violations.push("reverse retry template uses whole-body collection helper");
    }
    if !prepare.contains("ReverseReplayRecorder::wrap_first_request(")
        || prepare.contains("ReverseRequestTemplate::from_request(")
    {
        violations.push("reverse retry prepare must stream first attempt through replay recorder");
    }
    if !validate.contains("retry.retry_body_threshold_bytes")
        || !validate.contains("> config.runtime.max_reverse_retry_template_body_bytes")
    {
        violations.push("reverse retry body threshold is not capped by runtime template limit");
    }
    violations
}

fn check_http_module_body_mode_contract(root: &Path) -> Result<()> {
    let traits_rel = "qpxd/src/http/modules/traits.rs";
    let traits = fs::read_to_string(root.join(traits_rel))?;
    let chain_rel = "qpxd/src/http/modules/chain.rs";
    let chain = fs::read_to_string(root.join(chain_rel))?;
    let streaming_rel = "qpxd/src/runtime/plan/compiler/streaming.rs";
    let streaming = fs::read_to_string(root.join(streaming_rel))?;
    let cli_rel = "qpxd/src/cli_render/mod.rs";
    let cli = fs::read_to_string(root.join(cli_rel))?;
    let violations = http_module_body_mode_contract_violations(&traits, &chain, &streaming, &cli);
    if !violations.is_empty() {
        bail!(
            "HTTP module body mode contract violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn http_module_body_mode_contract_violations(
    traits: &str,
    chain: &str,
    streaming: &str,
    cli: &str,
) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for needle in [
        "pub fn mode_label(self) -> &'static str",
        "pub fn streaming_safe(self) -> bool",
        "pub fn request_buffer_bytes(self) -> Option<usize>",
        "pub fn response_buffer_bytes(self) -> Option<usize>",
    ] {
        if !traits.contains(needle) {
            violations.push("BodyAccess must expose explicit body mode metadata");
            break;
        }
    }
    for needle in [
        "body_mode={}",
        "streaming_safe={}",
        "request_buffer_max_bytes=",
        "response_buffer_max_bytes=",
        "pub(crate) fn buffering_modules(&self) -> Vec<String>",
    ] {
        if !chain.contains(needle) {
            violations.push("compiled HTTP modules must explain body mode per module");
            break;
        }
    }
    if !streaming.contains("modules.buffering_modules()")
        || !streaming.contains("requires body buffering: {}")
    {
        violations.push("streaming requirement errors must identify buffering modules");
    }
    if !cli.contains("body_access.mode_label()") {
        violations.push("explain JSON must use canonical body mode labels");
    }
    violations
}

fn check_qpxf_cgi_header_parser_zero_copy(root: &Path) -> Result<()> {
    let rel = "qpxf/src/server/protocol.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = qpxf_cgi_header_parser_zero_copy_violations(&content);
    if !violations.is_empty() {
        bail!(
            "qpxf CGI header parser zero-copy violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn qpxf_cgi_header_parser_zero_copy_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "use memchr::memmem;",
        "body_leftover: Bytes",
        "chunk.slice(chunk_header_end..)",
        "memmem::find(chunk, b\"\\n\\n\")",
        "memmem::find(chunk, b\"\\r\\n\\r\\n\")",
    ] {
        if !content.contains(required) {
            violations.push("CGI parser must keep memmem search and Bytes-sliced body leftovers");
            break;
        }
    }
    let Some(parser_section) = function_body_section(content, "fn consume_cgi_stdout_header")
    else {
        violations.push("missing consume_cgi_stdout_header");
        return violations;
    };
    if parser_section.contains("Bytes::copy_from_slice")
        || parser_section.contains("to_vec()")
        || parser_section.contains("Vec::from")
    {
        violations.push("CGI parser must not materialize initial body leftover");
    }
    violations
}

fn check_qpxf_ipc_cleanup_backpressure(root: &Path) -> Result<()> {
    let rel = "qpxf/src/server/protocol.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = qpxf_ipc_cleanup_backpressure_violations(&content);
    if !violations.is_empty() {
        bail!(
            "qpxf IPC cleanup/backpressure violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn qpxf_ipc_cleanup_backpressure_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    let Some(drain_fn) = function_body_section(content, "async fn drain_req_ring") else {
        violations.push("missing bounded SHM request drain");
        return violations;
    };
    if !drain_fn.contains("max_drain_bytes: usize")
        || !drain_fn.contains("drained = drained.saturating_add(data.len())")
        || !drain_fn.contains("drained > max_drain_bytes")
    {
        violations.push("SHM rejected-request drain must enforce a byte ceiling");
    }
    if content.matches("drain_req_ring(").count() < 4 || !content.contains("max_stdin_bytes,") {
        violations.push("SHM rejection/overload/startup-error drains must pass max_stdin_bytes");
    }

    let Some(tcp_fn) = function_body_section(content, "pub(super) async fn handle_one_request_tcp")
    else {
        violations.push("missing TCP IPC handler");
        return violations;
    };
    if !tcp_fn.contains("drained = drained.saturating_add(n)")
        || !tcp_fn.contains("drained > max_stdin_bytes")
        || !tcp_fn.contains("IPC TCP rejected request drain exceeded limit")
    {
        violations.push("TCP rejected-request drain must enforce max_stdin_bytes");
    }
    if !tcp_fn.contains("bad gateway (no output)")
        || !tcp_fn.contains("abort_execution(exec_abort, stdin_task, exec_done).await")
    {
        violations.push("TCP incomplete CGI headers must abort executor and stdin relay");
    }

    let Some(shm_fn) = function_body_section(content, "pub(super) async fn handle_one_request_shm")
    else {
        violations.push("missing SHM IPC handler");
        return violations;
    };
    let Some(leftover_pos) = shm_fn.find("if !body_leftover.is_empty()") else {
        violations.push("SHM handler missing body_leftover write path");
        return violations;
    };
    let leftover_section = &shm_fn[leftover_pos..];
    let stdout_pos = leftover_section
        .find("let stdout_task")
        .unwrap_or(leftover_section.len());
    let leftover_section = &leftover_section[..stdout_pos];
    if !leftover_section
        .contains("push_ring_bytes(&mut res_ring, body_leftover.as_ref(), input_idle)")
        || !leftover_section.contains(".is_err()")
        || !leftover_section.contains("abort_execution(exec_abort, stdin_task, exec_done).await")
        || !leftover_section.contains("release_ipc_shm_path(&res_path, shm_reusable)")
    {
        violations
            .push("SHM body_leftover write failure must abort executor and release response ring");
    }
    violations
}

fn check_secure_file_write_boundaries(root: &Path) -> Result<()> {
    let secure_file = fs::read_to_string(root.join("qpx-core/src/secure_file.rs"))?;
    let tls_ca = fs::read_to_string(root.join("qpx-core/src/tls/ca.rs"))?;
    let acme = fs::read_to_string(root.join("qpx-acme/src/provisioner.rs"))?;
    let shm_ring = fs::read_to_string(root.join("qpx-core/src/shm_ring.rs"))?;
    let qpxr_hub = fs::read_to_string(root.join("qpxr/src/hub.rs"))?;
    let violations =
        secure_file_write_boundary_violations(&secure_file, &tls_ca, &acme, &shm_ring, &qpxr_hub);
    if !violations.is_empty() {
        bail!(
            "secure file write boundary violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn secure_file_write_boundary_violations(
    secure_file: &str,
    tls_ca: &str,
    acme: &str,
    shm_ring: &str,
    qpxr_hub: &str,
) -> Vec<&'static str> {
    let mut violations = Vec::new();

    let Some(validate_secure_file) =
        function_body_section(secure_file, "pub fn validate_secure_file_handle")
    else {
        violations.push("secure_file missing fd-based handle validation");
        return violations;
    };
    for required in [
        "meta.file_type().is_file()",
        "meta.nlink() != 1",
        "meta.uid()",
    ] {
        if !validate_secure_file.contains(required) {
            violations.push("secure_file validation must reject non-regular, hardlinked, or foreign-owned files");
            break;
        }
    }
    let Some(open_secure_options) = function_body_section(secure_file, "fn open_secure_options")
    else {
        violations.push("secure_file missing secure open helper");
        return violations;
    };
    if !open_secure_options.contains("validate_secure_file_handle(&file, path)?")
        || !open_secure_options.contains("file.set_permissions")
        || open_secure_options.contains("fs::set_permissions(path")
        || open_secure_options.contains("std::fs::set_permissions(path")
    {
        violations.push("secure output helper must validate and chmod the opened fd");
    }

    let Some(tls_write) = function_body_section(tls_ca, "fn write_text_file") else {
        violations.push("MITM CA writer missing write_text_file");
        return violations;
    };
    if !tls_write.contains("crate::secure_file::open_secure_output_file(path)")
        || !tls_write.contains("file.set_permissions")
        || tls_write.contains("fs::set_permissions(path")
    {
        violations.push("MITM CA material writes must use secure fd helper and fd chmod");
    }
    let Some(tls_key) = function_body_section(tls_ca, "fn enforce_private_key_permissions") else {
        violations.push("MITM CA key permission check missing");
        return violations;
    };
    if !tls_key.contains("validate_secure_file_handle(&file, path)")
        || !tls_key.contains("file.set_permissions")
        || tls_key.contains("fs::set_permissions(path")
    {
        violations.push("MITM CA existing key chmod must validate and chmod the opened fd");
    }

    let Some(acme_write) = function_body_section(acme, "fn write_bytes_file") else {
        violations.push("ACME writer missing write_bytes_file");
        return violations;
    };
    if !acme_write.contains("qpx_core::secure_file::open_secure_output_file(path)")
        || !acme_write.contains("file.set_permissions")
        || acme_write.contains("fs::set_permissions(path")
    {
        violations.push("ACME material writes must use secure fd helper and fd chmod");
    }

    let Some(shm_open) = function_body_section(shm_ring, "fn open_shm_file") else {
        violations.push("SHM ring missing open_shm_file");
        return violations;
    };
    let validate_pos = shm_open.find("validate_secure_shm_file(&file, path)?");
    let chmod_pos = shm_open.find("file.set_permissions");
    match (validate_pos, chmod_pos) {
        (Some(validate_pos), Some(chmod_pos)) if validate_pos < chmod_pos => {}
        _ => violations.push("SHM ring file must validate the opened fd before fd chmod"),
    }
    if shm_open.contains("fs::set_permissions(path") {
        violations.push("SHM ring file must not chmod by path after open");
    }

    let Some(qpxr_open) = function_body_section(qpxr_hub, "fn open_secure_file") else {
        violations.push("qpxr pcapng writer missing secure open helper");
        return violations;
    };
    if !qpxr_open.contains("qpx_core::secure_file::open_secure_output_file(path)")
        || qpxr_open.contains("OpenOptions::new")
        || qpxr_open.contains("fs::set_permissions(path")
    {
        violations.push("qpxr pcapng writer must use secure output helper without path chmod");
    }

    violations
}

fn check_qpx_h3_static_response_boundary(root: &Path) -> Result<()> {
    let rel = "qpxd/src/forward/h3/qpx/response.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = qpx_h3_static_response_boundary_violations(&content);
    if !violations.is_empty() {
        bail!(
            "QPX H3 static response boundary violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn qpx_h3_static_response_boundary_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    let Some(send_section) =
        function_body_section(content, "pub(super) async fn send_qpx_static_response")
    else {
        return vec!["missing send_qpx_static_response"];
    };
    if !send_section.contains("qpx_static_response(status, body)?") {
        violations.push("send_qpx_static_response must delegate response construction");
    }
    let Some(static_section) = function_body_section(content, "fn qpx_static_response") else {
        violations.push("missing qpx_static_response");
        return violations;
    };
    for required in [
        ".header(http::header::CONTENT_LENGTH, body.len().to_string())",
        "Body::from(Bytes::copy_from_slice(body))",
    ] {
        if !static_section.contains(required) {
            violations.push("qpx_static_response must set exact Content-Length and Bytes body");
            break;
        }
    }
    if static_section.contains("body.to_vec()")
        || static_section.contains("Vec::from(body)")
        || static_section.contains("Body::from(body.to_vec())")
    {
        violations.push("qpx_static_response must not materialize through Vec");
    }
    violations
}

fn check_dispatch_parallel_file_baseline(root: &Path) -> Result<()> {
    let dispatch_dirs = [
        "qpxd/src/http/dispatch",
        "qpxd/src/forward/request/dispatch",
        "qpxd/src/reverse/transport/dispatch",
        "qpxd/src/transparent/http/dispatch",
    ];
    let mut violations = Vec::new();
    for (file_name, max) in DISPATCH_PARALLEL_FILE_BASELINES {
        let count = dispatch_dirs
            .iter()
            .filter(|dir| root.join(dir).join(file_name).is_file())
            .count();
        if count > *max {
            violations.push(format!("{file_name}: {count} > {max}"));
        }
        eprintln!("dispatch parallel file baseline: {file_name} {count} / {max}");
    }
    if !violations.is_empty() {
        bail!(
            "dispatch parallel file baseline exceeded:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn check_pool_struct_baseline(root: &Path) -> Result<()> {
    let mut count = 0usize;
    for path in rust_files_under(root.join("qpxd/src").as_path())? {
        let rel = rel_path(root, &path);
        if is_test_file(&path)
            || rel.ends_with("quinn_socket/broker/packet_pool.rs")
            || rel.ends_with("http/modules/response_compression/streaming.rs")
        {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let syntax = syn::parse_file(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let mut visitor = PoolStructVisitor::default();
        visitor.visit_file(&syntax);
        count += visitor.count;
    }
    if count > POOL_STRUCT_BASELINE_MAX {
        bail!(
            "connection pool struct baseline exceeded: {} > {}",
            count,
            POOL_STRUCT_BASELINE_MAX
        );
    }
    eprintln!(
        "connection pool struct baseline: {} / {}",
        count, POOL_STRUCT_BASELINE_MAX
    );
    Ok(())
}

fn check_qpxd_tls_type_baseline(root: &Path) -> Result<()> {
    let tls_dir = root.join("qpxd/src/tls");
    let mut count = 0usize;
    for path in rust_files_under(&tls_dir)? {
        if is_test_file(&path) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let syntax = syn::parse_file(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let mut visitor = PublicOrCrateTypeVisitor::default();
        visitor.visit_file(&syntax);
        count += visitor.count;
    }
    if count > QPXD_TLS_TYPE_BASELINE_MAX {
        bail!(
            "qpxd TLS type baseline exceeded: {} > {}",
            count,
            QPXD_TLS_TYPE_BASELINE_MAX
        );
    }
    eprintln!(
        "qpxd TLS type baseline: {} / {}",
        count, QPXD_TLS_TYPE_BASELINE_MAX
    );
    Ok(())
}

#[derive(Default)]
struct PoolStructVisitor {
    count: usize,
}

impl<'ast> Visit<'ast> for PoolStructVisitor {
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let name = node.ident.to_string();
        if name == "Pool"
            || name.ends_with("Pool")
            || name.ends_with("PoolShard")
            || name.ends_with("PoolState")
            || name.ends_with("UpstreamPool")
        {
            self.count += 1;
        }
        syn::visit::visit_item_struct(self, node);
    }
}

#[derive(Default)]
struct PublicOrCrateTypeVisitor {
    count: usize,
}

impl<'ast> Visit<'ast> for PublicOrCrateTypeVisitor {
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if is_visible_outside_module(&node.vis) {
            self.count += 1;
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if is_visible_outside_module(&node.vis) {
            self.count += 1;
        }
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if is_visible_outside_module(&node.vis) {
            self.count += 1;
        }
        syn::visit::visit_item_type(self, node);
    }
}

fn is_visible_outside_module(vis: &Visibility) -> bool {
    !matches!(vis, Visibility::Inherited)
}

fn check_response_transform_baselines(root: &Path) -> Result<()> {
    check_header_transform_trait(root)?;
    check_response_transform_trait(root)?;

    let direct_header_mutations = count_direct_response_transform_files(
        root,
        &["apply_request_headers(", "apply_response_headers("],
        &[
            "qpxd/src/http/protocol/header_control.rs",
            "qpxd/src/http/protocol/l7.rs",
        ],
    )?;
    if direct_header_mutations > DIRECT_HEADER_MUTATION_BASELINE_MAX {
        bail!(
            "direct header transform baseline exceeded: {} > {}",
            direct_header_mutations,
            DIRECT_HEADER_MUTATION_BASELINE_MAX
        );
    }
    eprintln!(
        "direct header transform baseline: {} / {}",
        direct_header_mutations, DIRECT_HEADER_MUTATION_BASELINE_MAX
    );

    let direct_response_policy_engine = count_direct_response_policy_engine_files(
        root,
        &[
            "qpxd/src/http/policy/response_policy.rs",
            "qpxd/src/http/dispatch/response_policy.rs",
        ],
    )?;
    if direct_response_policy_engine > DIRECT_RESPONSE_POLICY_ENGINE_BASELINE_MAX {
        bail!(
            "direct response-policy engine baseline exceeded: {} > {}",
            direct_response_policy_engine,
            DIRECT_RESPONSE_POLICY_ENGINE_BASELINE_MAX
        );
    }
    eprintln!(
        "direct response-policy engine baseline: {} / {}",
        direct_response_policy_engine, DIRECT_RESPONSE_POLICY_ENGINE_BASELINE_MAX
    );
    Ok(())
}

fn check_response_transform_trait(root: &Path) -> Result<()> {
    let rel = "qpxd/src/http/dispatch/response_policy.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = response_transform_trait_violations(&content);
    if !violations.is_empty() {
        bail!(
            "response transform trait violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn response_transform_trait_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "trait ResponseTransform",
        "struct DispatchResponseTransformContext",
        "impl ResponseTransform for ListenerResponsePolicyDecision",
        "async fn apply_dispatch_transform(",
        ".apply_dispatch_transform(DispatchResponseTransformContext",
    ] {
        if !content.contains(required) {
            violations
                .push("ListenerResponsePolicyDecision must transform through ResponseTransform");
            break;
        }
    }
    let Some(dispatch_section) = function_body_section(
        content,
        "pub(crate) async fn apply_dispatch_response_policy",
    ) else {
        violations.push("missing apply_dispatch_response_policy");
        return violations;
    };
    if dispatch_section.contains("ListenerResponsePolicyDecision::Continue")
        || dispatch_section.contains("ListenerResponsePolicyDecision::LocalResponse")
    {
        violations
            .push("apply_dispatch_response_policy must not inline listener decision matching");
    }
    violations
}

fn check_header_transform_trait(root: &Path) -> Result<()> {
    let rel = "qpxd/src/http/protocol/header_control.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = header_transform_trait_violations(&content);
    if !violations.is_empty() {
        bail!(
            "header transform trait violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn header_transform_trait_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "trait HeaderTransform",
        "impl HeaderTransform for CompiledHeaderControl",
        "fn apply_request_transform(&self, headers: &mut http::HeaderMap)",
        "fn apply_response_transform(&self, headers: &mut http::HeaderMap)",
        "control.apply_request_transform(headers)",
        "control.apply_response_transform(headers)",
    ] {
        if !content.contains(required) {
            violations.push(
                "CompiledHeaderControl must implement HeaderTransform behind protocol entrypoints",
            );
            break;
        }
    }
    violations
}

fn count_direct_response_transform_files(
    root: &Path,
    needles: &[&str],
    allowed_paths: &[&str],
) -> Result<usize> {
    let mut count = 0usize;
    for path in rust_files_under(root.join("qpxd/src").as_path())? {
        if is_test_file(&path) {
            continue;
        }
        let rel = rel_path(root, &path);
        if allowed_paths.iter().any(|allowed| rel.as_ref() == *allowed) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if has_direct_response_transform_needle(&content, needles) {
            count += 1;
        }
    }
    Ok(count)
}

fn has_direct_response_transform_needle(content: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| content.contains(needle))
}

fn check_proxy_authorization_header_boundary(root: &Path) -> Result<()> {
    let allowed = "qpxd/src/http/protocol/header_control.rs";
    let mut violations = Vec::new();
    for path in rust_files_under(root.join("qpxd/src").as_path())? {
        if is_test_file(&path) {
            continue;
        }
        let rel = rel_path(root, &path);
        if rel.as_ref() == allowed {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        violations.extend(
            proxy_authorization_header_boundary_violations(&content)
                .into_iter()
                .map(|violation| format!("{rel}: {violation}")),
        );
    }
    if !violations.is_empty() {
        bail!(
            "proxy authorization header boundary violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn proxy_authorization_header_boundary_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for forbidden in [
        ".insert(http::header::PROXY_AUTHORIZATION",
        ".insert(::http::header::PROXY_AUTHORIZATION",
        ".remove(http::header::PROXY_AUTHORIZATION",
        ".remove(::http::header::PROXY_AUTHORIZATION",
    ] {
        if content.contains(forbidden) {
            violations.push(forbidden);
        }
    }
    violations
}

fn count_direct_response_policy_engine_files(root: &Path, allowed_paths: &[&str]) -> Result<usize> {
    let mut count = 0usize;
    for path in rust_files_under(root.join("qpxd/src").as_path())? {
        if is_test_file(&path) {
            continue;
        }
        let rel = rel_path(root, &path);
        if allowed_paths.iter().any(|allowed| rel.as_ref() == *allowed) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let syntax = syn::parse_file(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let mut visitor = DirectResponsePolicyEngineVisitor::default();
        visitor.visit_file(&syntax);
        if visitor.count > 0 {
            count += 1;
        }
    }
    Ok(count)
}

fn check_reverse_response_rules_dispatch_boundary(root: &Path) -> Result<()> {
    let rel = "qpxd/src/reverse/transport/response_rules.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = reverse_response_rules_dispatch_boundary_violations(&content);
    if !violations.is_empty() {
        bail!(
            "reverse response rules dispatch boundary violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn reverse_response_rules_dispatch_boundary_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if !content.contains("fn response_policy_parts") {
        violations.push("missing shared response_policy_parts");
    }
    if !content.contains("apply_dispatch_response_policy(DispatchResponsePolicyInput") {
        violations.push("missing dispatch response policy entrypoint");
    }
    let production = strip_cfg_test_response_policy_sections(content);
    for forbidden in [
        "apply_listener_response_policy",
        "ListenerResponsePolicyDecision",
        "response.headers().clone()",
    ] {
        if production.contains(forbidden) {
            violations.push(forbidden);
        }
    }
    violations
}

fn strip_cfg_test_response_policy_sections(content: &str) -> String {
    let mut output = String::new();
    let mut lines = content.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() == "#[cfg(test)]" {
            let Some(next) = lines.next() else {
                break;
            };
            let trimmed = next.trim_start();
            if trimmed.starts_with("use ") {
                if !next.contains(';') {
                    for line in lines.by_ref() {
                        if line.contains(';') {
                            break;
                        }
                    }
                }
                continue;
            }
            if trimmed.starts_with("pub(super) async fn apply_response_rules") {
                let mut depth = brace_delta(next);
                let mut seen_body = next.contains('{');
                for line in lines.by_ref() {
                    depth += brace_delta(line);
                    seen_body |= line.contains('{');
                    if seen_body && depth <= 0 {
                        break;
                    }
                }
                continue;
            }
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output
}

#[derive(Default)]
struct DirectResponsePolicyEngineVisitor {
    cfg_test_depth: usize,
    count: usize,
}

impl<'ast> Visit<'ast> for DirectResponsePolicyEngineVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if self.cfg_test_depth > 0 || has_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "ListenerResponsePolicyDecision" | "apply_listener_response_policy"
            )
        }) {
            self.count += 1;
        }
        syn::visit::visit_path(self, node);
    }
}

pub(crate) fn check_refactor_docs(root: &Path) -> Result<()> {
    for (path, section) in [
        ("ARCHITECTURE.md", "## Crates"),
        ("ARCHITECTURE.md", "## Quality Gates"),
        ("docs/refactor-fwd-rev.md", "## Shared Mechanics"),
        ("docs/refactor-fwd-rev.md", "## Refactor Boundary"),
        ("docs/refactor-crate-boundaries.md", "## Current Decision"),
        ("docs/refactor-crate-boundaries.md", "## Split Criteria"),
        ("docs/refactor-crate-boundaries.md", "## Non Goals"),
    ] {
        if !fs::read_to_string(root.join(path))?.contains(section) {
            bail!("{path} is missing {section}");
        }
    }
    let fwd_rev = fs::read_to_string(root.join("docs/refactor-fwd-rev.md"))?;
    let violations = forward_reverse_refactor_doc_violations(&fwd_rev);
    if !violations.is_empty() {
        bail!(
            "forward/reverse refactor spike documentation violations:\n{}",
            violations.join("\n")
        );
    }
    let crate_boundaries = fs::read_to_string(root.join("docs/refactor-crate-boundaries.md"))?;
    let violations = crate_boundary_refactor_doc_violations(&crate_boundaries);
    if !violations.is_empty() {
        bail!(
            "crate-boundary refactor documentation violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn crate_boundary_refactor_doc_violations(content: &str) -> Vec<&'static str> {
    let required = [
        "do not split qpxd solely to move LOC",
        "no feature loss",
        "no default hot-path performance regression",
        "Cargo-enforced dependency direction",
        "extract only acyclic boundaries",
        "keep qpxd as wiring",
    ];
    let mut violations = Vec::new();
    for needle in required {
        if !content.contains(needle) {
            violations.push(needle);
        }
    }
    violations
}

pub(crate) fn check_phase4_ci_acceptance_gates(root: &Path) -> Result<()> {
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
    let security = fs::read_to_string(root.join(".github/workflows/security-qa.yml"))?;
    let codeql = fs::read_to_string(root.join(".github/workflows/codeql.yml"))?;
    let structure = fs::read_to_string(root.join(".github/workflows/structure.yml"))?;
    let public_api = fs::read_to_string(root.join("scripts/check-public-api.sh"))?;
    let violations =
        phase4_ci_acceptance_violations(&ci, &security, &codeql, &structure, &public_api);
    if !violations.is_empty() {
        bail!(
            "Phase 4 CI acceptance gate violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_public_api_snapshot_script(root: &Path) -> Result<()> {
    let rel = "scripts/check-public-api.sh";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = public_api_snapshot_script_violations(&content);
    if !violations.is_empty() {
        bail!(
            "public API snapshot script violations:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_security_qa_fuzz_targets(root: &Path) -> Result<()> {
    let security_rel = ".github/workflows/security-qa.yml";
    let security = fs::read_to_string(root.join(security_rel))?;
    let mut violations = security_qa_fuzz_target_violations(&security);
    for target in PLAN_P3_FUZZ_TARGETS {
        let rel = format!("fuzz/fuzz_targets/{target}.rs");
        if !root.join(&rel).is_file() {
            violations.push(format!("missing fuzz target source {rel}"));
        }
    }
    if !violations.is_empty() {
        bail!(
            "security QA fuzz target violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

const PLAN_P3_FUZZ_TARGETS: &[&str] = &[
    "client_hello_sniff",
    "config_canonical_loader",
    "connect_frame_observer",
    "datagram_capsule_parser",
    "ftp_response_parser",
    "grpc_frame_observer",
    "grpc_web_binary_frame_observer",
    "grpc_web_text_base64_observer",
    "http1_request_head",
    "ipc_meta_frame",
    "proxy_v2_parser",
    "qpack_decoder",
    "reverse_target_input_deserializer",
    "shm_ring_ops",
    "sse_event_observer",
    "streaming_requirement_config_validator",
];

fn security_qa_fuzz_target_violations(security_workflow: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if !security_workflow.contains("cargo fuzz run \"${target}\"") {
        violations.push("security-qa workflow must run cargo fuzz for each target".to_string());
    }
    for target in PLAN_P3_FUZZ_TARGETS {
        if !security_workflow.contains(target) {
            violations.push(format!("security-qa workflow missing fuzz target {target}"));
        }
    }
    violations
}

fn public_api_snapshot_script_violations(content: &str) -> Vec<String> {
    let expected = [
        "qpx-core",
        "qpx-auth",
        "qpx-h3",
        "qpx-acme",
        "qpx-observability",
    ];
    let mut violations = Vec::new();
    let mut seen = BTreeMap::<String, String>::new();
    for line in content.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("check_crate ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let Some(crate_name) = parts.next() else {
            continue;
        };
        let Some(hash) = parts.next() else {
            violations.push(format!("check_crate {crate_name} missing expected hash"));
            continue;
        };
        if parts.next().is_some() {
            violations.push(format!(
                "check_crate {crate_name} has unexpected extra fields"
            ));
            continue;
        }
        if !is_sha256_hex(hash) {
            violations.push(format!(
                "check_crate {crate_name} expected hash must be 64 hex chars"
            ));
        }
        if seen
            .insert(crate_name.to_string(), hash.to_string())
            .is_some()
        {
            violations.push(format!("duplicate public API snapshot for {crate_name}"));
        }
    }
    for crate_name in expected {
        if !seen.contains_key(crate_name) {
            violations.push(format!("missing public API snapshot for {crate_name}"));
        }
    }
    for crate_name in seen.keys() {
        if !expected.contains(&crate_name.as_str()) {
            violations.push(format!("unexpected public API snapshot for {crate_name}"));
        }
    }
    violations
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn phase4_ci_acceptance_violations(
    ci: &str,
    security: &str,
    codeql: &str,
    structure: &str,
    public_api: &str,
) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for required in [
        "dtolnay/rust-toolchain@1.87",
        "cargo fmt --all -- --check",
        "cargo check --workspace --locked",
        "cargo build --workspace --all-targets --locked",
        "cargo test --workspace --locked -- --test-threads=1",
        "cargo doc --workspace --locked --no-deps --document-private-items",
        "cargo llvm-cov --workspace --locked --fail-under-lines 20",
        "bash ./scripts/check-public-api.sh",
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "cargo clippy -p \"${pkg}\" --locked --all-targets --no-default-features --features \"${features}\" -- -D warnings",
        "cargo audit",
        "cargo deny check",
        "bash ./scripts/e2e-control-plane.sh",
        "bash ./scripts/e2e-control-plane-soak.sh",
        "bash ./scripts/e2e-config-samples.sh",
        "bash ./scripts/e2e-local-response.sh",
        "bash ./scripts/e2e-http2.sh",
        "bash ./scripts/check-config-samples.sh",
        "bash ./scripts/audit-config-usecases.sh",
        "bash ./scripts/audit-config-behavior.sh",
        "cargo test -p qpxd --release --test perf_smoke --locked -- --nocapture",
        "cargo test -p qpxd --release --test advanced_transport_perf --locked -- --nocapture",
        "cargo bench -p qpxd --bench streaming_throughput --locked -- --sample-size 10",
        "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
    ] {
        if !ci.contains(required) {
            violations.push("ci.yml missing Phase 4 required job or command");
            break;
        }
    }
    for required in [
        "RUSTFLAGS: -Zsanitizer=address",
        "cargo test -Zbuild-std --target x86_64-unknown-linux-gnu -p qpx-core --lib shm_ring --no-default-features --features ipc-support -- --nocapture",
        "cargo test -Zbuild-std --target x86_64-unknown-linux-gnu -p qpxd ready_notifier_from_env_writes_readiness_byte -- --nocapture",
        "cargo fuzz run \"${target}\"",
        "config_canonical_loader",
        "connect_frame_observer",
        "datagram_capsule_parser",
        "grpc_frame_observer",
        "grpc_web_binary_frame_observer",
        "grpc_web_text_base64_observer",
        "reverse_target_input_deserializer",
        "sse_event_observer",
        "streaming_requirement_config_validator",
    ] {
        if !security.contains(required) {
            violations.push("security-qa.yml missing ASAN or fuzz smoke coverage");
            break;
        }
    }
    for required in [
        "github/codeql-action/init@v4",
        "github/codeql-action/analyze@v4",
    ] {
        if !codeql.contains(required) {
            violations.push("codeql.yml missing CodeQL init/analyze");
            break;
        }
    }
    for required in [
        "bash ./scripts/check-ci-acceptance-gates.sh",
        "cargo xtask structure",
        "cargo xtask budget",
    ] {
        if !structure.contains(required) {
            violations
                .push("structure.yml must run acceptance, structure, and budget gates together");
            break;
        }
    }
    for required in [
        "check_crate qpx-core",
        "check_crate qpx-auth",
        "check_crate qpx-h3",
        "check_crate qpx-acme",
        "check_crate qpx-observability",
    ] {
        if !public_api.contains(required) {
            violations.push("public API script missing library crate snapshot check");
            break;
        }
    }
    violations
}

fn forward_reverse_refactor_doc_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    let normalized = normalize_whitespace(content);
    for required in [
        "should not be fully merged",
        "shared HTTP dispatch modules own reusable policy, audit, response, cache, and limit primitives",
        "forward/reverse/transparent modules own mode-specific orchestration and upstream selection",
        "any new shared helper must remove real duplicated behavior, improve a responsibility boundary, or enforce a new mechanical gate without adding a compatibility branch",
        "the full forward/reverse request state machine",
        "route selection and body-observation ordering",
        "retry template creation and replay",
        "WebSocket/CONNECT special cases",
    ] {
        if !normalized.contains(required) {
            violations.push("missing forward/reverse commonality boundary or non-goal");
            break;
        }
    }
    violations
}

fn normalize_whitespace(content: &str) -> String {
    content.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn check_response_capture_after_finalize(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for (path, rules) in response_capture_order_rules() {
        let content = fs::read_to_string(root.join(path))?;
        for rule in rules {
            violations.extend(
                response_capture_order_violations(&content, &rule)
                    .into_iter()
                    .map(|violation| format!("{path}: {violation}")),
            );
        }
    }
    if !violations.is_empty() {
        bail!(
            "response capture after-finalization violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

struct ResponseCaptureOrderRule {
    name: &'static str,
    finalize: &'static str,
    capture: &'static str,
}

fn response_capture_order_rules() -> Vec<(&'static str, Vec<ResponseCaptureOrderRule>)> {
    vec![
        (
            "qpxd/src/forward/request/dispatch/request_dispatch_upstream.rs",
            vec![ResponseCaptureOrderRule {
                name: "forward upstream response",
                finalize: "finalize_response_with_headers_in_place(\n        request_method",
                capture: "response = emit_optional_response_for_export(response",
            }],
        ),
        (
            "qpxd/src/transparent/http/dispatch/complete.rs",
            vec![ResponseCaptureOrderRule {
                name: "transparent upstream response",
                finalize: "finalize_response_with_headers_in_place(\n        input.request_method",
                capture: "emit_optional_response_for_export(response, input.selected_plan",
            }],
        ),
        (
            "qpxd/src/reverse/transport/dispatch/dispatch_http.rs",
            vec![ResponseCaptureOrderRule {
                name: "reverse HTTP upstream response",
                finalize: "finalize_response_with_headers_in_place(\n        request_method",
                capture: "resp = crate::http::capture::stream::emit_optional_response_for_export(\n        resp",
            }],
        ),
        (
            "qpxd/src/reverse/transport/dispatch/dispatch_ipc.rs",
            vec![
                ResponseCaptureOrderRule {
                    name: "reverse IPC upstream response",
                    finalize: "finalize_response_with_headers_in_place(\n        request_method",
                    capture: "resp = crate::http::capture::stream::emit_optional_response_for_export(\n        resp",
                },
                ResponseCaptureOrderRule {
                    name: "reverse IPC upgrade response",
                    finalize: "finalize_response_with_headers_in_place(\n                request_method",
                    capture: "resp = crate::http::capture::stream::emit_optional_response_for_export(\n                resp",
                },
            ],
        ),
        (
            "qpxd/src/http/mitm/upstream.rs",
            vec![ResponseCaptureOrderRule {
                name: "MITM upstream response",
                finalize: "finalize_response_with_headers_in_place(\n        req_method",
                capture: "emit_optional_response_for_export(response, selected_plan",
            }],
        ),
    ]
}

fn response_capture_order_violations(
    content: &str,
    rule: &ResponseCaptureOrderRule,
) -> Vec<String> {
    let mut violations = Vec::new();
    let finalize_pos = content.find(rule.finalize);
    let capture_pos = content.find(rule.capture);
    if finalize_pos.is_none() {
        violations.push(format!("{} missing finalization marker", rule.name));
    }
    if capture_pos.is_none() {
        violations.push(format!("{} missing response capture marker", rule.name));
    }
    if let (Some(finalize_pos), Some(capture_pos)) = (finalize_pos, capture_pos)
        && capture_pos < finalize_pos
    {
        violations.push(format!("{} captures before finalization", rule.name));
    }
    violations
}

pub(crate) fn check_qpxr_capture_publish_order(root: &Path) -> Result<()> {
    let path = root.join("qpxr/src/hub.rs");
    let content = fs::read_to_string(&path)?;
    let violations = qpxr_capture_publish_order_violations(&content);
    if !violations.is_empty() {
        bail!(
            "qpxr capture publish order violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

fn qpxr_capture_publish_order_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    let history_pos = content.find("self.push_history_locked(");
    let live_pos = content.find("self.live_tx.send(");
    let file_try_pos = content.find("tx.try_send(");
    if history_pos.is_none() {
        violations.push("missing history publish before file sink");
    }
    if live_pos.is_none() {
        violations.push("missing live publish before file sink");
    }
    if file_try_pos.is_none() {
        violations.push("file sink must use try_send");
    }
    if let (Some(history_pos), Some(file_try_pos)) = (history_pos, file_try_pos)
        && file_try_pos < history_pos
    {
        violations.push("file sink publish occurs before history publish");
    }
    if let (Some(live_pos), Some(file_try_pos)) = (live_pos, file_try_pos)
        && file_try_pos < live_pos
    {
        violations.push("file sink publish occurs before live publish");
    }
    if content.contains("tx.send(encoded).await")
        || content.contains("tx.send(encoded.clone()).await")
    {
        violations.push("file sink must not await downstream I/O");
    }
    violations
}

pub(crate) fn check_library_anyhow_boundaries(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for crate_dir in [
        "qpx-core",
        "qpx-auth",
        "qpx-h3",
        "qpx-acme",
        "qpx-observability",
        "qpx-wasm",
    ] {
        let src = root.join(crate_dir).join("src");
        if !src.is_dir() {
            continue;
        }
        for path in rust_files_under(&src)? {
            if is_test_file(&path) {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let syntax = syn::parse_file(&content)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            let imports_anyhow_result = imports_anyhow_result(&syntax);
            let imports_anyhow_error = imports_anyhow_error(&syntax);
            let rel = rel_path(root, &path).into_owned();
            collect_public_anyhow_boundaries(
                &syntax,
                imports_anyhow_result,
                imports_anyhow_error,
                rel.as_str(),
                &mut violations,
            );
        }
    }
    if violations.len() > LIBRARY_ANYHOW_BOUNDARY_MAX {
        bail!(
            "library crate public anyhow boundary violations: {} > {}\n{}",
            violations.len(),
            LIBRARY_ANYHOW_BOUNDARY_MAX,
            violations.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_raw_metric_macro_baseline(root: &Path) -> Result<()> {
    let mut count = 0usize;
    for crate_dir in rust_workspace_crates() {
        let src = root.join(crate_dir).join("src");
        if !src.is_dir() {
            continue;
        }
        for path in rust_files_under(&src)? {
            let name = path.file_name().and_then(|value| value.to_str());
            if is_test_file(&path)
                || name.is_some_and(|name| name == "metrics.rs")
                || path.ends_with("xtask/src/checks.rs")
            {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let syntax = syn::parse_file(&content)
                .with_context(|| format!("failed to parse {}", path.display()))?;
            let mut visitor = RawMetricMacroVisitor::default();
            visitor.visit_file(&syntax);
            count += visitor.count;
        }
    }
    if count > RAW_METRIC_MACRO_MAX {
        bail!(
            "raw metric macro baseline exceeded: {} > {}",
            count,
            RAW_METRIC_MACRO_MAX
        );
    }
    eprintln!(
        "raw metric macro baseline: {} / {}",
        count, RAW_METRIC_MACRO_MAX
    );
    Ok(())
}

#[derive(Default)]
struct RawMetricMacroVisitor {
    count: usize,
}

impl<'ast> Visit<'ast> for RawMetricMacroVisitor {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "counter" | "gauge" | "histogram"
            )
        }) {
            self.count += 1;
        }
        syn::visit::visit_macro(self, node);
    }
}

pub(crate) fn check_test_helper_duplicate_baseline(root: &Path) -> Result<()> {
    let mut definitions = BTreeMap::<&'static str, Vec<String>>::new();
    let helper_names = duplicate_test_helpers().collect::<Vec<_>>();
    for crate_dir in rust_workspace_crates() {
        let tests_dir = root.join(crate_dir).join("tests");
        if tests_dir.is_dir() {
            scan_duplicate_helpers_in_tests(root, &tests_dir, &helper_names, &mut definitions)?;
        }
        let src_dir = root.join(crate_dir).join("src");
        if src_dir.is_dir() {
            scan_duplicate_helpers_in_src(root, &src_dir, &helper_names, &mut definitions)?;
        }
    }
    let duplicate_locations = definitions
        .values()
        .map(|locations| locations.len().saturating_sub(1))
        .sum::<usize>();
    if duplicate_locations > TEST_HELPER_DUPLICATE_MAX {
        bail!(
            "duplicate test helper baseline exceeded: {} > {}",
            duplicate_locations,
            TEST_HELPER_DUPLICATE_MAX
        );
    }
    eprintln!(
        "duplicate test helper baseline: {} / {}",
        duplicate_locations, TEST_HELPER_DUPLICATE_MAX
    );
    Ok(())
}

fn scan_duplicate_helpers_in_tests<'a>(
    root: &Path,
    dir: &Path,
    helper_names: &'a [&'a str],
    definitions: &mut BTreeMap<&'a str, Vec<String>>,
) -> Result<()> {
    for path in rust_files_under(dir)? {
        scan_duplicate_helpers_in_file(
            root,
            &path,
            helper_names,
            DuplicateHelperScope::AllFunctions,
            definitions,
        )?;
    }
    Ok(())
}

fn scan_duplicate_helpers_in_src<'a>(
    root: &Path,
    dir: &Path,
    helper_names: &'a [&'a str],
    definitions: &mut BTreeMap<&'a str, Vec<String>>,
) -> Result<()> {
    for path in rust_files_under(dir)? {
        let scope = if is_test_file(&path) {
            DuplicateHelperScope::AllFunctions
        } else {
            DuplicateHelperScope::CfgTestOnly
        };
        scan_duplicate_helpers_in_file(root, &path, helper_names, scope, definitions)?;
    }
    Ok(())
}

fn scan_duplicate_helpers_in_file<'a>(
    root: &Path,
    path: &Path,
    helper_names: &'a [&'a str],
    scope: DuplicateHelperScope,
    definitions: &mut BTreeMap<&'a str, Vec<String>>,
) -> Result<()> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let syntax =
        syn::parse_file(&content).with_context(|| format!("failed to parse {}", path.display()))?;
    let rel = rel_path(root, path);
    for helper_name in duplicate_helper_definitions(&syntax, helper_names, scope) {
        definitions
            .entry(helper_name)
            .or_default()
            .push(format!("{rel}:{helper_name}"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum DuplicateHelperScope {
    AllFunctions,
    CfgTestOnly,
}

fn duplicate_helper_definitions<'a>(
    syntax: &syn::File,
    helper_names: &'a [&'a str],
    scope: DuplicateHelperScope,
) -> Vec<&'a str> {
    let mut visitor = DuplicateHelperVisitor {
        helper_names,
        scope,
        cfg_test_depth: 0,
        definitions: Vec::new(),
    };
    visitor.visit_file(syntax);
    visitor.definitions
}

struct DuplicateHelperVisitor<'a> {
    helper_names: &'a [&'a str],
    scope: DuplicateHelperScope,
    cfg_test_depth: usize,
    definitions: Vec<&'a str>,
}

impl<'ast, 'a> Visit<'ast> for DuplicateHelperVisitor<'a> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if self.should_record_fn(node)
            && let Some(helper_name) = self
                .helper_names
                .iter()
                .copied()
                .find(|name| node.sig.ident == *name)
        {
            self.definitions.push(helper_name);
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let entered_cfg_test =
            matches!(self.scope, DuplicateHelperScope::CfgTestOnly) && has_cfg_test(&node.attrs);
        if entered_cfg_test {
            self.cfg_test_depth += 1;
        }
        syn::visit::visit_item_mod(self, node);
        if entered_cfg_test {
            self.cfg_test_depth -= 1;
        }
    }
}

impl DuplicateHelperVisitor<'_> {
    fn should_record_fn(&self, node: &syn::ItemFn) -> bool {
        matches!(self.scope, DuplicateHelperScope::AllFunctions)
            || self.cfg_test_depth > 0
            || has_cfg_test(&node.attrs)
    }
}

fn collect_public_anyhow_boundaries(
    syntax: &syn::File,
    imports_anyhow_result: bool,
    imports_anyhow_error: bool,
    rel: &str,
    violations: &mut Vec<String>,
) {
    collect_public_anyhow_items(
        &syntax.items,
        imports_anyhow_result,
        imports_anyhow_error,
        rel,
        "",
        violations,
    );
}

fn collect_public_anyhow_items(
    items: &[syn::Item],
    imports_anyhow_result: bool,
    imports_anyhow_error: bool,
    rel: &str,
    module_path: &str,
    violations: &mut Vec<String>,
) {
    for item in items {
        match item {
            syn::Item::Fn(item) if is_public(&item.vis) => {
                if return_type_exposes_anyhow(
                    &item.sig.output,
                    imports_anyhow_result,
                    imports_anyhow_error,
                ) {
                    violations.push(format!("{rel}: pub fn {module_path}{}", item.sig.ident));
                }
            }
            syn::Item::Type(item)
                if is_public(&item.vis)
                    && (type_path_is_anyhow_error(item.ty.as_ref(), imports_anyhow_error)
                        || type_path_is_anyhow_result(item.ty.as_ref(), imports_anyhow_result)
                        || type_contains_anyhow_error(item.ty.as_ref(), imports_anyhow_error)) =>
            {
                violations.push(format!("{rel}: pub type {module_path}{}", item.ident));
            }
            syn::Item::Struct(item) if is_public(&item.vis) => {
                for field in &item.fields {
                    if is_public(&field.vis)
                        && type_contains_anyhow_error(&field.ty, imports_anyhow_error)
                    {
                        let field_name = field
                            .ident
                            .as_ref()
                            .map_or_else(|| "<tuple-field>".to_string(), ToString::to_string);
                        violations.push(format!(
                            "{rel}: pub struct field {module_path}{}::{field_name}",
                            item.ident,
                        ));
                    }
                }
            }
            syn::Item::Enum(item)
                if is_public(&item.vis) && !item.ident.to_string().ends_with("Error") =>
            {
                for variant in &item.variants {
                    for (idx, field) in variant.fields.iter().enumerate() {
                        if type_contains_anyhow_error(&field.ty, imports_anyhow_error) {
                            let field_name = field
                                .ident
                                .as_ref()
                                .map_or_else(|| idx.to_string(), ToString::to_string);
                            violations.push(format!(
                                "{rel}: pub enum variant {module_path}{}::{}::{field_name}",
                                item.ident, variant.ident
                            ));
                        }
                    }
                }
            }
            syn::Item::Use(item) if is_public(&item.vis) => {
                if use_tree_imports_anyhow_name(&item.tree, "Result") {
                    violations.push(format!("{rel}: pub use {module_path}anyhow::Result"));
                }
                if use_tree_imports_anyhow_name(&item.tree, "Error") {
                    violations.push(format!("{rel}: pub use {module_path}anyhow::Error"));
                }
            }
            syn::Item::Impl(item) => {
                for impl_item in &item.items {
                    if let syn::ImplItem::Fn(func) = impl_item
                        && is_public(&func.vis)
                        && return_type_exposes_anyhow(
                            &func.sig.output,
                            imports_anyhow_result,
                            imports_anyhow_error,
                        )
                    {
                        violations
                            .push(format!("{rel}: pub method {module_path}{}", func.sig.ident));
                    }
                }
            }
            syn::Item::Trait(item) if is_public(&item.vis) => {
                for trait_item in &item.items {
                    match trait_item {
                        syn::TraitItem::Fn(func)
                            if return_type_exposes_anyhow(
                                &func.sig.output,
                                imports_anyhow_result,
                                imports_anyhow_error,
                            ) =>
                        {
                            violations.push(format!(
                                "{rel}: pub trait method {module_path}{}",
                                func.sig.ident
                            ));
                        }
                        syn::TraitItem::Type(assoc)
                            if assoc.default.as_ref().is_some_and(|(_, ty)| {
                                type_contains_anyhow_error(ty, imports_anyhow_error)
                            }) =>
                        {
                            violations.push(format!(
                                "{rel}: pub trait associated type {module_path}{}",
                                assoc.ident
                            ));
                        }
                        _ => {}
                    }
                }
            }
            syn::Item::Mod(item) if is_public(&item.vis) => {
                if let Some((_, items)) = &item.content {
                    let nested_module_path = format!("{module_path}{}::", item.ident);
                    collect_public_anyhow_items(
                        items,
                        imports_anyhow_result,
                        imports_anyhow_error,
                        rel,
                        &nested_module_path,
                        violations,
                    );
                }
            }
            _ => {}
        }
    }
}

fn is_public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn imports_anyhow_result(syntax: &syn::File) -> bool {
    imports_anyhow_name(syntax, "Result")
}

fn imports_anyhow_error(syntax: &syn::File) -> bool {
    imports_anyhow_name(syntax, "Error")
}

fn imports_anyhow_name(syntax: &syn::File, imported_name: &str) -> bool {
    syntax.items.iter().any(|item| {
        let syn::Item::Use(item) = item else {
            return false;
        };
        use_tree_imports_anyhow_name(&item.tree, imported_name)
    })
}

fn use_tree_imports_anyhow_name(tree: &syn::UseTree, imported_name: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) if path.ident == "anyhow" => {
            use_tree_mentions_name(path.tree.as_ref(), imported_name)
        }
        syn::UseTree::Path(path) => use_tree_imports_anyhow_name(path.tree.as_ref(), imported_name),
        _ => false,
    }
}

fn use_tree_mentions_name(tree: &syn::UseTree, imported_name: &str) -> bool {
    match tree {
        syn::UseTree::Name(name) => name.ident == imported_name,
        syn::UseTree::Rename(rename) => rename.ident == imported_name,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_mentions_name(item, imported_name)),
        syn::UseTree::Path(path) => use_tree_mentions_name(path.tree.as_ref(), imported_name),
        _ => false,
    }
}

fn type_path_is_anyhow_error(ty: &Type, imports_anyhow_error: bool) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    path_is_anyhow_name(&path.path, "Error", imports_anyhow_error)
}

fn type_path_is_anyhow_result(ty: &Type, imports_anyhow_result: bool) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    path_is_anyhow_name(&path.path, "Result", imports_anyhow_result)
}

fn return_type_exposes_anyhow(
    output: &ReturnType,
    imports_anyhow_result: bool,
    imports_anyhow_error: bool,
) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(path) = ty.as_ref() else {
        return type_contains_anyhow_error(ty.as_ref(), imports_anyhow_error);
    };
    path_is_anyhow_name(&path.path, "Result", imports_anyhow_result)
        || type_contains_anyhow_error(ty.as_ref(), imports_anyhow_error)
}

fn type_contains_anyhow_error(ty: &Type, imports_anyhow_error: bool) -> bool {
    match ty {
        Type::Path(path) => {
            path_is_anyhow_name(&path.path, "Error", imports_anyhow_error)
                || path.path.segments.iter().any(|segment| {
                    path_arguments_contain_anyhow_error(&segment.arguments, imports_anyhow_error)
                })
        }
        Type::Reference(reference) => {
            type_contains_anyhow_error(&reference.elem, imports_anyhow_error)
        }
        Type::Tuple(tuple) => tuple
            .elems
            .iter()
            .any(|elem| type_contains_anyhow_error(elem, imports_anyhow_error)),
        _ => false,
    }
}

fn path_arguments_contain_anyhow_error(
    arguments: &PathArguments,
    imports_anyhow_error: bool,
) -> bool {
    match arguments {
        PathArguments::AngleBracketed(args) => args.args.iter().any(|arg| match arg {
            GenericArgument::Type(ty) => type_contains_anyhow_error(ty, imports_anyhow_error),
            GenericArgument::AssocType(assoc) => {
                type_contains_anyhow_error(&assoc.ty, imports_anyhow_error)
            }
            _ => false,
        }),
        PathArguments::Parenthesized(args) => {
            args.inputs
                .iter()
                .any(|ty| type_contains_anyhow_error(ty, imports_anyhow_error))
                || matches!(args.output, ReturnType::Type(_, ref ty) if type_contains_anyhow_error(ty, imports_anyhow_error))
        }
        PathArguments::None => false,
    }
}

fn path_is_anyhow_name(path: &syn::Path, name: &str, imports_anyhow_name: bool) -> bool {
    let mut segments = path.segments.iter();
    match (segments.next(), path.segments.last()) {
        (Some(first), Some(last)) if first.ident == "anyhow" && last.ident == name => true,
        (Some(first), _) if imports_anyhow_name && first.ident == name => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HELPERS: &[&str] = &["spawn_qpxd", "wait_for_qpxd"];

    fn public_anyhow_violations(source: &str) -> Vec<String> {
        let syntax = syn::parse_file(source).expect("test source should parse");
        let mut violations = Vec::new();
        collect_public_anyhow_boundaries(
            &syntax,
            imports_anyhow_result(&syntax),
            imports_anyhow_error(&syntax),
            "test.rs",
            &mut violations,
        );
        violations
    }

    #[test]
    fn duplicate_helper_gate_matches_async_helpers() {
        let syntax = syn::parse_file(
            r#"
            fn spawn_qpxd() {}
            async fn spawn_qpxd() {}
            pub fn spawn_qpxd() {}
            pub async fn spawn_qpxd() {}
            pub(crate) fn spawn_qpxd() {}
            pub(crate) async fn spawn_qpxd() {}
            "#,
        )
        .expect("test source should parse");
        assert_eq!(
            duplicate_helper_definitions(&syntax, TEST_HELPERS, DuplicateHelperScope::AllFunctions),
            vec![
                "spawn_qpxd",
                "spawn_qpxd",
                "spawn_qpxd",
                "spawn_qpxd",
                "spawn_qpxd",
                "spawn_qpxd"
            ]
        );
    }

    #[test]
    fn duplicate_helper_gate_ignores_non_definitions() {
        let syntax = syn::parse_file(
            r#"
            fn unrelated() {
                let _ = spawn_qpxd();
            }
            "#,
        )
        .expect("test source should parse");
        assert!(
            duplicate_helper_definitions(&syntax, TEST_HELPERS, DuplicateHelperScope::AllFunctions)
                .is_empty()
        );
    }

    #[test]
    fn duplicate_helper_gate_scans_cfg_test_modules_in_src() {
        let syntax = syn::parse_file(
            r#"
            #[cfg(test)]
            mod tests {
                fn spawn_qpxd() {}
                async fn wait_for_qpxd() {}
            }

            mod production {
                fn spawn_qpxd() {}
            }
            "#,
        )
        .expect("test source should parse");
        assert_eq!(
            duplicate_helper_definitions(&syntax, TEST_HELPERS, DuplicateHelperScope::CfgTestOnly),
            vec!["spawn_qpxd", "wait_for_qpxd"]
        );
    }

    #[test]
    fn duplicate_helper_gate_scans_cfg_test_functions_in_src() {
        let syntax = syn::parse_file(
            r#"
            #[cfg(test)]
            fn spawn_qpxd() {}

            fn wait_for_qpxd() {}
            "#,
        )
        .expect("test source should parse");
        assert_eq!(
            duplicate_helper_definitions(&syntax, TEST_HELPERS, DuplicateHelperScope::CfgTestOnly),
            vec!["spawn_qpxd"]
        );
    }

    #[test]
    fn reverse_debug_cache_key_gate_detects_debug_format_allocation() {
        assert_eq!(
            reverse_debug_cache_key_violations(
                r#"let key = format!("{:?}", resolution_override);"#
            ),
            vec!["format!(\"{:?}\")"]
        );
        assert!(reverse_debug_cache_key_violations("cache.get(&resolution_override)").is_empty());
    }

    #[test]
    fn duplicate_helper_gate_ignores_non_test_src_modules() {
        let syntax = syn::parse_file(
            r#"
            mod production {
                pub(crate) async fn spawn_qpxd() {}
            }
            "#,
        )
        .expect("test source should parse");
        assert!(
            duplicate_helper_definitions(&syntax, TEST_HELPERS, DuplicateHelperScope::CfgTestOnly)
                .is_empty()
        );
    }

    fn raw_metric_macro_count(source: &str) -> usize {
        let syntax = syn::parse_file(source).expect("test source should parse");
        let mut visitor = RawMetricMacroVisitor::default();
        visitor.visit_file(&syntax);
        visitor.count
    }

    #[test]
    fn raw_metric_gate_counts_direct_and_qualified_macros() {
        let count = raw_metric_macro_count(
            r#"
            fn emit() {
                counter!("a").increment(1);
                metrics::gauge!("b").set(1.0);
                ::metrics::histogram!("c").record(1.0);
            }
            "#,
        );
        assert_eq!(count, 3);
    }

    #[test]
    fn raw_metric_gate_ignores_comments_and_other_macros() {
        let count = raw_metric_macro_count(
            r#"
            fn emit() {
                // counter!("commented");
                not_counter!("a");
            }
            "#,
        );
        assert_eq!(count, 0);
    }

    #[test]
    fn phase3_pool_struct_gate_counts_pool_types() {
        let syntax = syn::parse_file(
            r#"
            struct UpstreamProxyPool;
            struct H3OriginPoolShard;
            struct PacketBuffer;
            "#,
        )
        .expect("test source should parse");
        let mut visitor = PoolStructVisitor::default();
        visitor.visit_file(&syntax);
        assert_eq!(visitor.count, 2);
    }

    #[test]
    fn phase3_tls_type_gate_counts_module_visible_types() {
        let syntax = syn::parse_file(
            r#"
            pub(crate) struct CompiledUpstreamTlsTrust;
            pub type BoxTlsStream = ();
            struct InternalParser;
            enum PrivateState {}
            "#,
        )
        .expect("test source should parse");
        let mut visitor = PublicOrCrateTypeVisitor::default();
        visitor.visit_file(&syntax);
        assert_eq!(visitor.count, 2);
    }

    #[test]
    fn phase3_response_policy_gate_ignores_cfg_test_engine_use() {
        let syntax = syn::parse_file(
            r#"
            #[cfg(test)]
            fn test_only() -> ListenerResponsePolicyDecision {
                apply_listener_response_policy();
                todo!()
            }

            fn production() {
                apply_dispatch_response_policy();
            }
            "#,
        )
        .expect("test source should parse");
        let mut visitor = DirectResponsePolicyEngineVisitor::default();
        visitor.visit_file(&syntax);
        assert_eq!(visitor.count, 0);
    }

    #[test]
    fn phase3_response_policy_gate_counts_production_engine_use() {
        let syntax = syn::parse_file(
            r#"
            fn production(_: ListenerResponsePolicyDecision) {
                apply_listener_response_policy();
            }
            "#,
        )
        .expect("test source should parse");
        let mut visitor = DirectResponsePolicyEngineVisitor::default();
        visitor.visit_file(&syntax);
        assert_eq!(visitor.count, 2);
    }

    #[test]
    fn phase3_reverse_response_rules_gate_allows_cfg_test_direct_engine() {
        let content = r#"
            use crate::http::dispatch::{DispatchResponsePolicyInput, apply_dispatch_response_policy};
            #[cfg(test)]
            use crate::http::policy::response_policy::{
                ListenerResponsePolicyDecision, apply_listener_response_policy,
            };

            fn response_policy_parts() {}

            #[cfg(test)]
            pub(super) async fn apply_response_rules() -> Result<ListenerResponsePolicyDecision> {
                apply_listener_response_policy().await
            }

            pub(super) async fn apply_dispatch_response_rules() {
                apply_dispatch_response_policy(DispatchResponsePolicyInput {}).await;
            }
        "#;
        assert!(reverse_response_rules_dispatch_boundary_violations(content).is_empty());
    }

    #[test]
    fn phase3_reverse_response_rules_gate_rejects_production_direct_engine() {
        let content = r#"
            use crate::http::dispatch::{DispatchResponsePolicyInput, apply_dispatch_response_policy};
            use crate::http::policy::response_policy::ListenerResponsePolicyDecision;
            fn response_policy_parts() {}
            pub(super) async fn apply_dispatch_response_rules() -> Result<ListenerResponsePolicyDecision> {
                apply_listener_response_policy().await
            }
            fn dispatch() {
                let _ = response.headers().clone();
                apply_dispatch_response_policy(DispatchResponsePolicyInput {});
            }
        "#;
        assert_eq!(
            reverse_response_rules_dispatch_boundary_violations(content),
            [
                "apply_listener_response_policy",
                "ListenerResponsePolicyDecision",
                "response.headers().clone()",
            ]
        );
    }

    #[test]
    fn phase3_dispatch_access_gate_requires_shared_helpers() {
        assert!(
            dispatch_access_commonality_violations(
                "build_dispatch_audit_context(input); apply_ext_authz_http_access(input);"
            )
            .is_empty()
        );
        assert_eq!(
            dispatch_access_commonality_violations(
                "DispatchAuditContext::new(state); decision.policy_id(); ExtAuthzEnforcement::Deny(deny);"
            ),
            [
                "missing build_dispatch_audit_context",
                "missing apply_ext_authz_http_access",
                "DispatchAuditContext::new(",
                ".policy_id()",
                "ExtAuthzEnforcement::Deny",
            ]
        );
    }

    #[test]
    fn phase3_dispatch_audit_builder_gate_rejects_direct_context_new() {
        assert!(
            dispatch_audit_builder_commonality_violations(
                "let audit = build_dispatch_audit_context(input);",
                true,
            )
            .is_empty()
        );
        assert!(
            dispatch_audit_builder_commonality_violations("let audit = access.audit_ctx;", false,)
                .is_empty()
        );
        assert_eq!(
            dispatch_audit_builder_commonality_violations(
                "let audit = DispatchAuditContext::new(state);",
                true,
            ),
            [
                "missing build_dispatch_audit_context",
                "DispatchAuditContext::new(",
            ]
        );
        assert_eq!(
            dispatch_audit_builder_commonality_violations(
                "let audit = DispatchAuditContext::new(state);",
                false,
            ),
            ["DispatchAuditContext::new("]
        );
    }

    #[test]
    fn phase3_dispatch_cache_collapse_gate_requires_shared_helpers() {
        assert!(
            dispatch_cache_collapse_commonality_violations(
                "dispatch_cache_collapse_continue(state, guard); dispatch_cache_collapse_response(response); finalize_dispatch_collapsed_cache_decision(input);"
            )
            .is_empty()
        );
        assert_eq!(
            dispatch_cache_collapse_commonality_violations(
                "finalize_dispatch_cache_decision(DispatchCacheDecisionInput { hit_outcome: DispatchOutcome::CacheCollapsedHit, stale_outcome: DispatchOutcome::CacheCollapsedStale });"
            ),
            [
                "missing dispatch_cache_collapse_continue",
                "missing dispatch_cache_collapse_response",
                "missing finalize_dispatch_collapsed_cache_decision",
                "DispatchOutcome::CacheCollapsedHit",
                "DispatchOutcome::CacheCollapsedStale",
            ]
        );
    }

    #[test]
    fn phase3_dispatch_limit_response_gate_rejects_direct_construction() {
        assert!(
            dispatch_limit_response_commonality_violations(
                "rate_limit_response_for_parts(method, version, proxy_name, retry_after, audit); concurrency_limited_response_for_parts(method, version, proxy_name, audit);"
            )
            .is_empty()
        );
        assert_eq!(
            dispatch_limit_response_commonality_violations(
                "too_many_requests_response(retry_after); DispatchOutcome::RateLimited; DispatchOutcome::ConcurrencyLimited;"
            ),
            [
                "too_many_requests_response(",
                "DispatchOutcome::RateLimited",
                "DispatchOutcome::ConcurrencyLimited",
            ]
        );
    }

    #[test]
    fn phase3_http_response_body_hard_cap_gate_requires_downstream_cap() {
        let good = [
            "pub(crate) fn limit_response_body_for_plan",
            "plan.streaming.max_response_body_bytes",
            "body.limit_bytes(max_bytes)",
            "emit_optional_response_for_export(response, selected_plan",
            "emit_optional_response_for_export(",
            "capture_reverse_response_outcome",
            "finalize_dispatch_cached_response",
            "plan: &'a crate::runtime::ExecutionPlan",
            "limit_response_body_for_plan(\n        response, plan,",
            "limit_response_body_for_plan(response, &selected_plan)",
            "limit_response_body_for_plan(response, selected_plan)",
            "input.selected_plan",
        ]
        .join("\n");
        assert!(http_response_body_hard_cap_violations(&good).is_empty());
        assert_eq!(
            http_response_body_hard_cap_violations("pub(crate) fn limit_response_body_for_plan"),
            [
                "plan.streaming.max_response_body_bytes",
                "body.limit_bytes(max_bytes)",
                "emit_optional_response_for_export(response, selected_plan",
                "emit_optional_response_for_export(",
                "capture_reverse_response_outcome",
                "finalize_dispatch_cached_response",
                "plan: &'a crate::runtime::ExecutionPlan",
                "limit_response_body_for_plan(\n        response, plan,",
                "limit_response_body_for_plan(response, &selected_plan)",
                "limit_response_body_for_plan(response, selected_plan)",
                "input.selected_plan",
            ]
        );
    }

    #[test]
    fn phase3_body_spool_failure_gate_requires_typed_errors_and_metrics() {
        let good = [
            "pub(crate) enum ObservedBodySpoolError",
            "Create {",
            "operation: &'static str",
            "is_observed_body_spool_error",
            "record_body_spool_error(direction, reason, \"create\")",
            "record_body_spool_error(direction, reason, \"write\")",
            "record_body_spool_error(direction, reason, \"flush\")",
            "write_observed_body_spool(",
            "flush_observed_body_spool(",
        ]
        .join("\n");
        assert!(http_body_spool_failure_handling_violations(&good).is_empty());
        assert_eq!(
            http_body_spool_failure_handling_violations(
                "record_body_spool_error(direction, reason, \"create\")"
            ),
            [
                "pub(crate) enum ObservedBodySpoolError",
                "Create {",
                "operation: &'static str",
                "is_observed_body_spool_error",
                "record_body_spool_error(direction, reason, \"write\")",
                "record_body_spool_error(direction, reason, \"flush\")",
                "write_observed_body_spool(",
                "flush_observed_body_spool(",
            ]
        );
    }

    #[test]
    fn phase3_rpc_frame_boundary_gate_requires_deterministic_split_tests() {
        let good = [
            "grpc_observer_parses_five_byte_header_split_one_byte_at_a_time",
            "grpc_web_text_observer_parses_base64_quantum_split_one_byte_at_a_time",
            "connect_streaming_observer_reassembles_eos_metadata_split_one_byte_at_a_time",
            "for byte in body",
            "for byte in encoded.bytes()",
        ]
        .join("\n");
        assert!(rpc_frame_boundary_test_violations(&good).is_empty());
        assert_eq!(
            rpc_frame_boundary_test_violations(
                "grpc_observer_parses_five_byte_header_split_one_byte_at_a_time"
            ),
            [
                "grpc_web_text_observer_parses_base64_quantum_split_one_byte_at_a_time",
                "connect_streaming_observer_reassembles_eos_metadata_split_one_byte_at_a_time",
                "for byte in body",
                "for byte in encoded.bytes()",
            ]
        );
    }

    #[test]
    fn phase3_annotated_local_response_gate_rejects_direct_finalized_local_response() {
        assert!(
            dispatch_annotated_local_response_commonality_violations(
                "annotated_local_response(method, version, proxy_name, local, headers, audit, DispatchOutcome::Respond)?;"
            )
            .is_empty()
        );
        assert_eq!(
            dispatch_annotated_local_response_commonality_violations(
                "let mut response = finalized_local_response(method, version, proxy_name, local, headers)?; annotate_dispatch_response(&mut response, audit, DispatchOutcome::Respond, &[]);"
            ),
            ["finalized_local_response("]
        );
    }

    #[test]
    fn phase3_max_forwards_gate_rejects_direct_handler() {
        assert!(
            dispatch_max_forwards_response_commonality_violations(
                "if let Some(response) = annotated_max_forwards_response(req, proxy_name, trace, max, timeout, audit).await {}"
            )
            .is_empty()
        );
        assert_eq!(
            dispatch_max_forwards_response_commonality_violations(
                "let mut response = handle_max_forwards_in_place(req, proxy_name, trace, max, timeout).await?; annotate_dispatch_response(&mut response, audit, DispatchOutcome::MaxForwards, &[]);"
            ),
            [
                "missing annotated_max_forwards_response",
                "handle_max_forwards_in_place(",
            ]
        );
    }

    #[test]
    fn phase3_body_too_large_gate_rejects_direct_payload_response() {
        assert!(
            dispatch_body_too_large_response_commonality_violations(
                "return Ok(request_body_too_large_response(method, version, proxy_name, Some(audit))?);"
            )
            .is_empty()
        );
        assert_eq!(
            dispatch_body_too_large_response_commonality_violations(
                "Response::builder().status(StatusCode::PAYLOAD_TOO_LARGE).body(Body::from(\"request body too large\"))?;"
            ),
            [
                "missing request_body_too_large_response",
                "StatusCode::PAYLOAD_TOO_LARGE",
                "Body::from(\"request body too large\")",
            ]
        );
    }

    #[test]
    fn phase3_header_transform_gate_counts_request_and_response_entrypoints() {
        let needles = &["apply_request_headers(", "apply_response_headers("];

        assert!(has_direct_response_transform_needle(
            "apply_request_headers(request.headers_mut(), headers);",
            needles
        ));
        assert!(has_direct_response_transform_needle(
            "apply_response_headers(response.headers_mut(), headers);",
            needles
        ));
        assert!(!has_direct_response_transform_needle(
            "self.apply_subrequest_response_headers(&subresponse, ctx, &mut response);",
            needles
        ));
    }

    #[test]
    fn phase3_header_transform_trait_gate_requires_protocol_trait_boundary() {
        assert!(
            header_transform_trait_violations(
                r#"
                trait HeaderTransform {
                    fn apply_request_transform(&self, headers: &mut http::HeaderMap);
                    fn apply_response_transform(&self, headers: &mut http::HeaderMap);
                }
                impl HeaderTransform for CompiledHeaderControl {
                    fn apply_request_transform(&self, headers: &mut http::HeaderMap) {}
                    fn apply_response_transform(&self, headers: &mut http::HeaderMap) {}
                }
                fn apply_request_headers(headers: &mut http::HeaderMap, control: Option<&CompiledHeaderControl>) {
                    control.apply_request_transform(headers)
                }
                fn apply_response_headers(headers: &mut http::HeaderMap, control: Option<&CompiledHeaderControl>) {
                    control.apply_response_transform(headers)
                }
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            header_transform_trait_violations(
                r#"
                fn apply_request_headers(headers: &mut http::HeaderMap, control: Option<&CompiledHeaderControl>) {
                    apply_header_mutations(headers, control.request_set(), control.request_add(), control.request_remove(), control.request_regex_replace())
                }
                "#,
            ),
            ["CompiledHeaderControl must implement HeaderTransform behind protocol entrypoints"]
        );
    }

    #[test]
    fn phase3_response_transform_trait_gate_rejects_inline_decision_matching() {
        assert!(
            response_transform_trait_violations(
                r#"
                struct DispatchResponseTransformContext<'a> {
                    audit: &'a DispatchAuditContext,
                }
                trait ResponseTransform {
                    async fn apply_dispatch_transform(self, ctx: DispatchResponseTransformContext<'_>) -> Result<DispatchResponsePolicyOutcome>;
                }
                impl ResponseTransform for ListenerResponsePolicyDecision {
                    async fn apply_dispatch_transform(self, ctx: DispatchResponseTransformContext<'_>) -> Result<DispatchResponsePolicyOutcome> {
                        Ok(DispatchResponsePolicyOutcome::Response(response))
                    }
                }
                pub(crate) async fn apply_dispatch_response_policy(input: DispatchResponsePolicyInput<'_>) -> Result<DispatchResponsePolicyOutcome> {
                    decision.apply_dispatch_transform(DispatchResponseTransformContext { audit }).await
                }
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            response_transform_trait_violations(
                r#"
                pub(crate) async fn apply_dispatch_response_policy(input: DispatchResponsePolicyInput<'_>) -> Result<DispatchResponsePolicyOutcome> {
                    match apply_listener_response_policy().await? {
                        ListenerResponsePolicyDecision::Continue { response, .. } => Ok(DispatchResponsePolicyOutcome::Continue { response }),
                        ListenerResponsePolicyDecision::LocalResponse { response, .. } => Ok(DispatchResponsePolicyOutcome::Response(response)),
                    }
                }
                "#,
            ),
            [
                "ListenerResponsePolicyDecision must transform through ResponseTransform",
                "apply_dispatch_response_policy must not inline listener decision matching",
            ]
        );
    }

    #[test]
    fn phase3_proxy_authorization_header_gate_rejects_direct_mutation() {
        assert!(
            proxy_authorization_header_boundary_violations(
                "set_proxy_authorization_header(req.headers_mut(), endpoint.proxy_authorization.as_ref());"
            )
            .is_empty()
        );
        assert_eq!(
            proxy_authorization_header_boundary_violations(
                "headers.remove(http::header::PROXY_AUTHORIZATION); headers.insert(::http::header::PROXY_AUTHORIZATION, value);"
            ),
            [
                ".insert(::http::header::PROXY_AUTHORIZATION",
                ".remove(http::header::PROXY_AUTHORIZATION",
            ]
        );
    }

    #[test]
    fn phase3_manual_session_shard_modulo_gate_counts_only_session_patterns() {
        assert_eq!(
            manual_session_shard_modulo_needles(
                "&self.shards[(session_id as usize) % self.shards.len()]"
            ),
            ["(session_id as usize) % self.shards.len()"]
        );
        assert_eq!(
            manual_session_shard_modulo_needles(
                "&self.streams[(stream_id as usize) % self.streams.len()]"
            ),
            ["(stream_id as usize) % self.streams.len()"]
        );
        assert_eq!(
            manual_session_shard_modulo_needles(
                "&self.shards[(session_id as usize)\n    % self.shards.len()]"
            ),
            ["(session_id as usize) % self.shards.len()"]
        );
        assert!(
            manual_session_shard_modulo_needles(
                "let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();"
            )
            .is_empty()
        );
        assert_eq!(
            manual_session_shard_modulo_needles(
                "let worker_idx = session_id as usize % self.workers.len();"
            ),
            ["session_id as usize % self.workers.len()"]
        );
    }

    #[test]
    fn phase3_qpx_h3_datagram_send_gate_rejects_ambiguous_api() {
        assert!(
            qpx_h3_datagram_send_boundary_violations(
                r#"
                pub fn send_prefixed_datagram(&mut self, datagram: Bytes, payload_len: usize) -> Result<()> { Ok(()) }
                pub fn send_unprefixed_datagram_with_scratch(&mut self, payload: Bytes, scratch: &mut BytesMut) -> Result<()> { Ok(()) }
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            qpx_h3_datagram_send_boundary_violations(
                r#"
                pub fn send_prefixed_datagram(&mut self, datagram: Bytes, payload_len: usize) -> Result<()> { Ok(()) }
                pub fn send_datagram(&mut self, payload: Bytes) -> Result<()> { Ok(()) }
                "#,
            ),
            [
                "missing explicit datagram send boundary",
                "ambiguous unprefixed send_datagram API",
            ]
        );
    }

    #[test]
    fn phase3_shard_initialization_gate_requires_shared_helpers() {
        assert!(
            shard_initialization_helper_violations(
                "fn sync_mutex_shards() {} fn async_mutex_shards() {} struct AsyncShardMap;"
            )
            .is_empty()
        );
        assert_eq!(
            shard_initialization_helper_violations("fn sync_mutex_shards() {}"),
            [
                "missing fn async_mutex_shards",
                "missing struct AsyncShardMap",
            ]
        );
        assert!(
            shard_initialization_loop_violations(
                "shards: crate::sharding::AsyncShardMap<String, Slot>"
            )
            .is_empty()
        );
        assert_eq!(
            shard_initialization_loop_violations(
                "let mut out = Vec::with_capacity(shards); for _ in 0..shards { out.push(Mutex::new(HashMap::new())); }"
            ),
            [
                "manual shard Vec::with_capacity(shards)",
                "manual shard initialization loop",
            ]
        );
        assert_eq!(
            async_shard_map_field_violations(
                "struct Pool { shards: Vec<Mutex<HashMap<String, Slot>>> }"
            ),
            ["manual async sharded HashMap field"]
        );
    }

    #[test]
    fn phase3_canonical_sample_config_gate_requires_real_loader_coverage() {
        assert!(
            canonical_sample_config_guard_violations(
                r#"
                fn sample_qpxd_configs_load() {
                    let root = workspace_root();
                    let mut files = vec![root.join("config/qpx.example.yaml")];
                    collect_yaml_files(&root.join("config/usecases"), &mut files);
                    files.retain(|path| is_qpxd_sample_config(path));
                    let expanded = expand_sample_env(&raw)?;
                    copy_sample_fragments(&root, &dir);
                    load_config(&config)?;
                }
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            canonical_sample_config_guard_violations(
                r#"
                fn sample_qpxd_configs_load() {
                    Config::default();
                }
                "#,
            ),
            ["sample config guard must load qpx.example and qpxd usecases through the real loader"]
        );
    }

    #[test]
    fn phase3_canonical_config_gate_rejects_version_compatibility_branch() {
        let root = std::env::temp_dir().join(format!(
            "qpx-xtask-config-schema-version-{}",
            std::process::id()
        ));
        let file = root.join("qpxd/src/cli.rs");
        std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &file,
            "enum Command { UpgradeConfig } const V: &str = \"qpx.config/v1\";",
        )
        .expect("write marker file");

        let violations = single_canonical_config_schema_violations(&root, ["qpxd/src/cli.rs"])
            .expect("scan marker file");

        std::fs::remove_dir_all(&root).expect("cleanup");
        assert_eq!(
            violations,
            [
                "qpxd/src/cli.rs: canonical config must not carry schema-version compatibility marker `qpx.config/v1`",
                "qpxd/src/cli.rs: canonical config must not carry schema-version compatibility marker `UpgradeConfig`",
            ]
        );
    }

    #[test]
    fn phase3_h3_open_queue_gate_requires_bounded_send() {
        assert!(
            h3_open_queue_backpressure_violations(
                "match timeout(timeout_dur, request_open_tx.send(job)).await { Ok(Ok(())) => Ok(()) }"
            )
            .is_empty()
        );
        assert_eq!(
            h3_open_queue_backpressure_violations("request_open_tx.try_send(job)?;"),
            [
                "missing bounded request_open_tx.send(job)",
                "request open queue uses try_send"
            ]
        );
        assert_eq!(
            h3_open_queue_backpressure_violations("fn open() {}"),
            ["missing bounded request_open_tx.send(job)"]
        );
        assert_eq!(
            h3_open_queue_backpressure_violations(
                "struct H3PooledConnection { sender: Mutex<H3SendRequest> }"
            ),
            [
                "missing bounded request_open_tx.send(job)",
                "request open uses sender mutex",
            ]
        );
    }

    #[test]
    fn phase3_connection_pool_trait_gate_requires_acquire_release_health_contract() {
        assert!(
            connection_pool_trait_boundary_violations(
                r#"
                trait ConnectionPool<T> {
                    type Acquire;
                    fn acquire_connection(&self, request: Self::Acquire) -> Result<T>;
                }
                "#,
                r#"
                impl ConnectionPool<ResolvedUpstreamProxy> for Arc<UpstreamProxyCluster> {
                    fn acquire_connection(&self, (): Self::Acquire) -> Result<ResolvedUpstreamProxy> {
                        self.select()
                    }
                }
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            connection_pool_trait_boundary_violations(
                "trait ConnectionPool<T> { async fn acquire_connection(&self); }",
                "impl UpstreamProxyCluster {}",
            ),
            [
                "missing ConnectionPool acquire contract",
                "UpstreamProxyCluster must implement ConnectionPool acquisition without changing selection semantics",
            ]
        );
    }

    #[test]
    fn phase3_h3_pool_load_gate_rejects_open_queue_double_counting() {
        let good = r#"
            fn h3_connection_effective_load(conn: &H3PooledConnection) -> usize {
                conn.inflight_streams.load(Ordering::Relaxed)
            }
            fn h3_connection_stream_capacity_for_limits(
                max_inflight_streams_per_connection: usize,
                open_queue_capacity: usize,
            ) -> usize {
                max_inflight_streams_per_connection.min(open_queue_capacity)
            }
        "#;
        assert!(h3_origin_pool_load_semantics_violations(good).is_empty());

        let bad = r#"
            fn h3_connection_effective_load(conn: &H3PooledConnection) -> usize {
                conn.inflight_streams.load(Ordering::Relaxed)
                    + conn.open_queue_depth.load(Ordering::Relaxed)
            }
            fn h3_connection_stream_capacity_for_limits(
                max_inflight_streams_per_connection: usize,
                open_queue_capacity: usize,
            ) -> usize {
                max_inflight_streams_per_connection
            }
        "#;
        assert_eq!(
            h3_origin_pool_load_semantics_violations(bad),
            [
                "effective load must not double count open queue depth",
                "stream capacity must be capped by open queue capacity",
            ]
        );
    }

    #[test]
    fn phase3_reverse_mirror_gate_requires_permit_before_spawn() {
        assert!(
            reverse_mirror_spawn_backpressure_violations(
                r#"
                pub(super) fn dispatch_mirrors() {
                    let Some(_mirror_permit) = try_acquire_mirror_permit(upstream.as_ref()) else { return; };
                    tokio::spawn(async move {});
                }
                pub(super) fn dispatch_streaming_mirrors() {
                    let Some(_mirror_permit) = try_acquire_mirror_permit(upstream.as_ref()) else { return; };
                    tokio::spawn(async move {});
                }
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            reverse_mirror_spawn_backpressure_violations(
                r#"
                pub(super) fn dispatch_mirrors() {
                    tokio::spawn(async move {});
                    let _permit = try_acquire_mirror_permit(upstream.as_ref());
                }
                pub(super) fn dispatch_streaming_mirrors() {
                    tokio::spawn(async move {});
                }
                "#,
            ),
            [
                "mirror spawn count exceeds permit acquisition count",
                "mirror task spawned before permit acquisition",
                "mirror task spawned without permit acquisition",
            ]
        );
    }

    #[test]
    fn phase3_ext_authz_gate_rejects_collecting_response_body() {
        assert!(
            ext_authz_response_buffering_violations(
                r#"
                const EXT_AUTHZ_INLINE_RESPONSE_BYTES: usize = 4096;
                static EXT_AUTHZ_RESPONSE_BUFFERS: LazyLock<Mutex<Vec<Vec<u8>>>> = LazyLock::new(|| Mutex::new(Vec::new()));
                struct ExtAuthzBodyBuffer { inline: [u8; EXT_AUTHZ_INLINE_RESPONSE_BYTES], inline_len: usize, heap: Option<Vec<u8>> }
                async fn collect_ext_authz_response_body(mut body: Body) -> Result<ExtAuthzBodyBuffer> {
                    let mut out = ExtAuthzBodyBuffer::new();
                    while let Some(frame) = body.frame().await {
                        let data = frame?.into_data().unwrap();
                        out.extend(&data)?;
                    }
                    Ok(out)
                }
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            ext_authz_response_buffering_violations(
                r#"
                async fn collect_ext_authz_response_body(body: Body) -> Result<Bytes> {
                    crate::http::body::to_bytes_limited(body, 1024).await
                }
                "#,
            ),
            [
                "missing inline-first bounded ext_authz response collector",
                "ext_authz response collector uses to_bytes_limited",
            ]
        );
        assert_eq!(
            ext_authz_response_buffering_violations(
                r#"
                const EXT_AUTHZ_INLINE_RESPONSE_BYTES: usize = 4096;
                static EXT_AUTHZ_RESPONSE_BUFFERS: LazyLock<Mutex<Vec<Vec<u8>>>> = LazyLock::new(|| Mutex::new(Vec::new()));
                struct ExtAuthzBodyBuffer { inline: [u8; EXT_AUTHZ_INLINE_RESPONSE_BYTES], inline_len: usize, heap: Option<Vec<u8>> }
                async fn collect_ext_authz_response_body(mut body: Body) -> Result<ExtAuthzBodyBuffer> {
                    let bytes = body.collect().await?.to_bytes();
                    let mut out = ExtAuthzBodyBuffer::new();
                    while let Some(frame) = body.frame().await {
                        let data = frame?.into_data().unwrap();
                        out.extend(&data)?;
                    }
                    Ok(out)
                }
                "#,
            ),
            ["ext_authz response collector uses collect().await"]
        );
    }

    #[test]
    fn phase3_response_compression_worker_gate_rejects_blocking_result_send() {
        assert!(
            response_compression_worker_backpressure_violations(
                "let (result_tx, result_rx) = mpsc::channel(COMPRESSION_PIPELINE_DEPTH.max(1)); send_compression_worker_result(&result_tx, result);"
            )
            .is_empty()
        );
        assert_eq!(
            response_compression_worker_backpressure_violations("result_tx.blocking_send(result);"),
            [
                "compression worker must not block on async result channels",
                "compression worker results must go through nonblocking helper",
                "compression result channel must remain bounded",
            ]
        );
    }

    #[test]
    fn phase3_reverse_retry_template_gate_requires_bounded_known_length_body() {
        let good_template = r#"
            fn request_is_retryable(req: &Request<Body>, body_threshold_bytes: usize) -> bool {
                !request_may_have_body(req)
                    || content_length(req).is_some_and(|len| len <= body_threshold_bytes as u64)
            }
            fn content_length(req: &Request<Body>) -> Option<u64> {
                if req.headers().contains_key(TRANSFER_ENCODING) {
                    return None;
                }
                return None;
            }
            async fn collect_body_template() -> Result<()> {
                if next > max_body_bytes {
                    return Err(anyhow!("too large"));
                }
                create_template_spool().await?;
                Ok(())
            }
        "#;
        let good_validate = r#"
            if retry.retry_body_threshold_bytes
                > config.runtime.max_reverse_retry_template_body_bytes
            {
                return Err(anyhow!("retry_body_threshold_bytes too large"));
            }
        "#;
        let good_prepare = "ReverseReplayRecorder::wrap_first_request(req, max, timeout, cap);";
        assert!(
            reverse_retry_template_bounded_body_violations(
                good_template,
                good_prepare,
                good_validate
            )
            .is_empty()
        );
        assert_eq!(
            reverse_retry_template_bounded_body_violations(
                "fn request_is_retryable(req: &Request<Body>) -> bool { request_may_have_body(req) || true }",
                good_prepare,
                good_validate,
            ),
            [
                "reverse retry template must stay explicitly bounded",
                "reverse retry template accepts unknown body length",
            ]
        );
        assert_eq!(
            reverse_retry_template_bounded_body_violations(
                "fn request_is_retryable(req: &Request<Body>) -> bool { content_length(req).is_some_and(|len| len <= body_threshold_bytes as u64) } async fn collect_body_template(body: Body) { body.collect().await; }",
                "ReverseRequestTemplate::from_request(req, max, timeout).await;",
                "",
            ),
            [
                "reverse retry template must stay explicitly bounded",
                "reverse retry template uses whole-body collection helper",
                "reverse retry prepare must stream first attempt through replay recorder",
                "reverse retry body threshold is not capped by runtime template limit",
            ]
        );
    }

    #[test]
    fn phase3_http_module_body_mode_gate_requires_explainable_modes() {
        let traits = r#"
            impl BodyAccess {
                pub fn mode_label(self) -> &'static str { "headers_only" }
                pub fn streaming_safe(self) -> bool { true }
                pub fn request_buffer_bytes(self) -> Option<usize> { None }
                pub fn response_buffer_bytes(self) -> Option<usize> { None }
            }
        "#;
        let chain = r#"
            format!("body_mode={}", capabilities.body_access.mode_label());
            format!("streaming_safe={}", capabilities.body_access.streaming_safe());
            format!("request_buffer_max_bytes={max_bytes}");
            format!("response_buffer_max_bytes={max_bytes}");
            pub(crate) fn buffering_modules(&self) -> Vec<String> { Vec::new() }
        "#;
        let streaming = r#"
            let modules = modules.buffering_modules();
            "requires body buffering: {}";
        "#;
        let cli = "body_access.mode_label()";
        assert!(
            http_module_body_mode_contract_violations(traits, chain, streaming, cli).is_empty()
        );
        assert_eq!(
            http_module_body_mode_contract_violations("", "", "", ""),
            [
                "BodyAccess must expose explicit body mode metadata",
                "compiled HTTP modules must explain body mode per module",
                "streaming requirement errors must identify buffering modules",
                "explain JSON must use canonical body mode labels",
            ]
        );
    }

    #[test]
    fn phase3_qpxf_cgi_header_parser_gate_rejects_leftover_materialization() {
        let good = r#"
            use memchr::memmem;
            struct ParsedCgiOutputHead {
                body_leftover: Bytes,
            }
            fn consume_cgi_stdout_header(header_buf: &mut BytesMut, chunk: Bytes) {
                ParsedCgiOutputHead {
                    body_leftover: chunk.slice(chunk_header_end..),
                };
            }
            fn find_cgi_header_terminator(chunk: &[u8]) {
                memmem::find(chunk, b"\n\n");
                memmem::find(chunk, b"\r\n\r\n");
            }
        "#;
        assert!(qpxf_cgi_header_parser_zero_copy_violations(good).is_empty());
        assert_eq!(
            qpxf_cgi_header_parser_zero_copy_violations(
                r#"
                use memchr::memmem;
                struct ParsedCgiOutputHead {
                    body_leftover: Bytes,
                }
                fn consume_cgi_stdout_header(header_buf: &mut BytesMut, chunk: Bytes) {
                    ParsedCgiOutputHead {
                        body_leftover: Bytes::copy_from_slice(&chunk[chunk_header_end..]),
                    };
                }
                fn find_cgi_header_terminator(chunk: &[u8]) {
                    memmem::find(chunk, b"\n\n");
                    memmem::find(chunk, b"\r\n\r\n");
                }
                "#
            ),
            [
                "CGI parser must keep memmem search and Bytes-sliced body leftovers",
                "CGI parser must not materialize initial body leftover",
            ]
        );
    }

    #[test]
    fn phase3_qpxf_ipc_cleanup_gate_rejects_unbounded_or_unclean_error_paths() {
        let good = r#"
            async fn drain_req_ring(max_drain_bytes: usize) {
                drained = drained.saturating_add(data.len());
                if drained > max_drain_bytes {}
            }
            pub(super) async fn handle_one_request_shm() {
                drain_req_ring(input_idle, shm_reusable, max_stdin_bytes,).await;
                drain_req_ring(input_idle, shm_reusable, max_stdin_bytes,).await;
                drain_req_ring(input_idle, shm_reusable, max_stdin_bytes,).await;
                if !body_leftover.is_empty()
                    && push_ring_bytes(&mut res_ring, body_leftover.as_ref(), input_idle).await.is_err()
                {
                    abort_execution(exec_abort, stdin_task, exec_done).await;
                    release_ipc_shm_path(&res_path, shm_reusable);
                    return Ok(());
                }
                let stdout_task = tokio::spawn(async move {});
            }
            pub(super) async fn handle_one_request_tcp() {
                drained = drained.saturating_add(n);
                if drained > max_stdin_bytes {
                    warn!("IPC TCP rejected request drain exceeded limit");
                }
                if parsed_res.is_none() {
                    write_all_with_timeout(&mut tx, b"bad gateway (no output)", output_idle).await?;
                    abort_execution(exec_abort, stdin_task, exec_done).await;
                }
            }
        "#;
        assert!(qpxf_ipc_cleanup_backpressure_violations(good).is_empty());

        let bad = r#"
            async fn drain_req_ring() {
                while ring.try_pop_into(&mut data)? {}
            }
            pub(super) async fn handle_one_request_shm() {
                drain_req_ring(input_idle, shm_reusable).await;
                if !body_leftover.is_empty() {
                    let _ = push_ring_bytes(&mut res_ring, body_leftover.as_ref(), input_idle).await;
                }
                let stdout_task = tokio::spawn(async move {});
            }
            pub(super) async fn handle_one_request_tcp() {
                loop {
                    let n = stream.read(&mut buf).await?;
                    drained = drained.saturating_add(n);
                }
                if parsed_res.is_none() {
                    write_all_with_timeout(&mut tx, b"bad gateway (no output)", output_idle).await?;
                    return Ok(());
                }
            }
        "#;
        assert_eq!(
            qpxf_ipc_cleanup_backpressure_violations(bad),
            [
                "SHM rejected-request drain must enforce a byte ceiling",
                "SHM rejection/overload/startup-error drains must pass max_stdin_bytes",
                "TCP rejected-request drain must enforce max_stdin_bytes",
                "TCP incomplete CGI headers must abort executor and stdin relay",
                "SHM body_leftover write failure must abort executor and release response ring",
            ]
        );
    }

    #[test]
    fn phase3_secure_file_gate_rejects_path_chmod_and_missing_fd_validation() {
        let secure_file = r#"
            fn open_secure_options() {
                validate_secure_file_handle(&file, path)?;
                file.set_permissions(mode)?;
            }
            pub fn validate_secure_file_handle() {
                meta.file_type().is_file();
                if meta.nlink() != 1 {}
                meta.uid();
            }
        "#;
        let tls_ca = r#"
            fn write_text_file() {
                crate::secure_file::open_secure_output_file(path)?;
                file.set_permissions(mode)?;
            }
            fn enforce_private_key_permissions() {
                validate_secure_file_handle(&file, path)?;
                file.set_permissions(mode)?;
            }
        "#;
        let acme = r#"
            fn write_bytes_file() {
                qpx_core::secure_file::open_secure_output_file(path)?;
                file.set_permissions(mode)?;
            }
        "#;
        let shm = r#"
            fn open_shm_file() {
                validate_secure_shm_file(&file, path)?;
                file.set_permissions(mode)?;
            }
        "#;
        let qpxr = r#"
            fn open_secure_file() {
                qpx_core::secure_file::open_secure_output_file(path)?;
            }
        "#;
        assert!(
            secure_file_write_boundary_violations(secure_file, tls_ca, acme, shm, qpxr).is_empty()
        );

        let bad_secure_file = r#"
            fn open_secure_options() {
                validate_secure_file_handle(&file, path)?;
                fs::set_permissions(path, mode)?;
            }
            pub fn validate_secure_file_handle() {
                meta.file_type().is_file();
            }
        "#;
        let bad_tls_ca = r#"
            fn write_text_file() {
                crate::secure_file::open_secure_output_file(path)?;
                fs::set_permissions(path, mode)?;
            }
            fn enforce_private_key_permissions() {
                fs::set_permissions(path, mode)?;
            }
        "#;
        let bad_acme = r#"
            fn write_bytes_file() {
                qpx_core::secure_file::open_secure_output_file(path)?;
                fs::set_permissions(path, mode)?;
            }
        "#;
        let bad_shm = r#"
            fn open_shm_file() {
                file.set_permissions(mode)?;
                validate_secure_shm_file(&file, path)?;
            }
        "#;
        let bad_qpxr = r#"
            fn open_secure_file() {
                OpenOptions::new().create(true).truncate(true).open(path)?;
                fs::set_permissions(path, mode)?;
            }
        "#;
        assert_eq!(
            secure_file_write_boundary_violations(
                bad_secure_file,
                bad_tls_ca,
                bad_acme,
                bad_shm,
                bad_qpxr,
            ),
            [
                "secure_file validation must reject non-regular, hardlinked, or foreign-owned files",
                "secure output helper must validate and chmod the opened fd",
                "MITM CA material writes must use secure fd helper and fd chmod",
                "MITM CA existing key chmod must validate and chmod the opened fd",
                "ACME material writes must use secure fd helper and fd chmod",
                "SHM ring file must validate the opened fd before fd chmod",
                "qpxr pcapng writer must use secure output helper without path chmod",
            ]
        );
    }

    #[test]
    fn phase3_qpx_h3_static_response_gate_rejects_vec_materialization() {
        let good = r#"
            pub(super) async fn send_qpx_static_response() -> Result<()> {
                let response = qpx_static_response(status, body)?;
                Ok(())
            }
            fn qpx_static_response(status: StatusCode, body: &[u8]) -> Result<Response<Body>> {
                Ok(Response::builder()
                    .status(status)
                    .header(http::header::CONTENT_LENGTH, body.len().to_string())
                    .body(Body::from(Bytes::copy_from_slice(body)))?)
            }
        "#;
        assert!(qpx_h3_static_response_boundary_violations(good).is_empty());
        assert_eq!(
            qpx_h3_static_response_boundary_violations(
                r#"
                pub(super) async fn send_qpx_static_response() -> Result<()> {
                    let response = Response::builder().body(Body::from(body.to_vec()))?;
                    Ok(())
                }
                fn qpx_static_response(status: StatusCode, body: &[u8]) -> Result<Response<Body>> {
                    Ok(Response::builder()
                        .status(status)
                        .body(Body::from(body.to_vec()))?)
                }
                "#
            ),
            [
                "send_qpx_static_response must delegate response construction",
                "qpx_static_response must set exact Content-Length and Bytes body",
                "qpx_static_response must not materialize through Vec",
            ]
        );
    }

    #[test]
    fn phase3_qpxr_capture_publish_gate_requires_live_before_file_try_send() {
        assert!(
            qpxr_capture_publish_order_violations(
                "self.push_history_locked(&mut history, ts, encoded.clone()); self.live_tx.send(encoded.clone()); tx.try_send(encoded);"
            )
            .is_empty()
        );
        assert_eq!(
            qpxr_capture_publish_order_violations(
                "tx.send(encoded.clone()).await; self.push_history_locked(&mut history, ts, encoded.clone()); self.live_tx.send(encoded.clone());"
            ),
            [
                "file sink must use try_send",
                "file sink must not await downstream I/O",
            ]
        );
        assert_eq!(
            qpxr_capture_publish_order_violations(
                "tx.try_send(encoded); self.push_history_locked(&mut history, ts, encoded.clone()); self.live_tx.send(encoded.clone());"
            ),
            [
                "file sink publish occurs before history publish",
                "file sink publish occurs before live publish",
            ]
        );
    }

    #[test]
    fn phase3_response_capture_gate_requires_finalize_before_capture() {
        let rule = ResponseCaptureOrderRule {
            name: "test response",
            finalize: "finalize_response_with_headers_in_place(",
            capture: "emit_optional_response_for_export(response",
        };
        assert!(
            response_capture_order_violations(
                "finalize_response_with_headers_in_place(...); emit_optional_response_for_export(response);",
                &rule,
            )
            .is_empty()
        );
        assert_eq!(
            response_capture_order_violations(
                "emit_optional_response_for_export(response); finalize_response_with_headers_in_place(...);",
                &rule,
            ),
            ["test response captures before finalization"]
        );
        assert_eq!(
            response_capture_order_violations(
                "finalize_response_with_headers_in_place(...);",
                &rule
            ),
            ["test response missing response capture marker"]
        );
    }

    #[test]
    fn phase4_ci_acceptance_gate_rejects_missing_required_workflow_commands() {
        let ci = r#"
            dtolnay/rust-toolchain@1.87
            cargo fmt --all -- --check
            cargo check --workspace --locked
            cargo build --workspace --all-targets --locked
            cargo test --workspace --locked -- --test-threads=1
            cargo doc --workspace --locked --no-deps --document-private-items
            cargo llvm-cov --workspace --locked --fail-under-lines 20
            bash ./scripts/check-public-api.sh
            cargo clippy --workspace --all-targets --locked -- -D warnings
            cargo clippy -p "${pkg}" --locked --all-targets --no-default-features --features "${features}" -- -D warnings
            cargo audit
            cargo deny check
            bash ./scripts/e2e-control-plane.sh
            bash ./scripts/e2e-control-plane-soak.sh
            bash ./scripts/e2e-config-samples.sh
            bash ./scripts/e2e-local-response.sh
            bash ./scripts/e2e-http2.sh
            bash ./scripts/check-config-samples.sh
            bash ./scripts/audit-config-usecases.sh
            bash ./scripts/audit-config-behavior.sh
            cargo test -p qpxd --release --test perf_smoke --locked -- --nocapture
            cargo test -p qpxd --release --test advanced_transport_perf --locked -- --nocapture
            cargo bench -p qpxd --bench streaming_throughput --locked -- --sample-size 10
            github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
        "#;
        let security = r#"
            RUSTFLAGS: -Zsanitizer=address
            cargo test -Zbuild-std --target x86_64-unknown-linux-gnu -p qpx-core --lib shm_ring --no-default-features --features ipc-support -- --nocapture
            cargo test -Zbuild-std --target x86_64-unknown-linux-gnu -p qpxd ready_notifier_from_env_writes_readiness_byte -- --nocapture
            cargo fuzz run "${target}"
            config_canonical_loader
            connect_frame_observer
            datagram_capsule_parser
            grpc_frame_observer
            grpc_web_binary_frame_observer
            grpc_web_text_base64_observer
            reverse_target_input_deserializer
            sse_event_observer
            streaming_requirement_config_validator
        "#;
        let codeql = "github/codeql-action/init@v4\ngithub/codeql-action/analyze@v4";
        let structure = "bash ./scripts/check-ci-acceptance-gates.sh\ncargo xtask structure\ncargo xtask budget";
        let public_api = "check_crate qpx-core\ncheck_crate qpx-auth\ncheck_crate qpx-h3\ncheck_crate qpx-acme\ncheck_crate qpx-observability";
        assert!(
            phase4_ci_acceptance_violations(ci, security, codeql, structure, public_api).is_empty()
        );

        assert_eq!(
            phase4_ci_acceptance_violations(
                "cargo fmt --all -- --check",
                "cargo fuzz run \"${target}\"",
                "github/codeql-action/init@v4",
                "cargo xtask structure",
                "check_crate qpx-core",
            ),
            [
                "ci.yml missing Phase 4 required job or command",
                "security-qa.yml missing ASAN or fuzz smoke coverage",
                "codeql.yml missing CodeQL init/analyze",
                "structure.yml must run acceptance, structure, and budget gates together",
                "public API script missing library crate snapshot check",
            ]
        );
    }

    #[test]
    fn public_api_snapshot_gate_requires_expected_crates_and_hashes() {
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let good = format!(
            "\
            check_crate qpx-core {hash}\n\
            check_crate qpx-auth {hash}\n\
            check_crate qpx-h3 {hash}\n\
            check_crate qpx-acme {hash}\n\
            check_crate qpx-observability {hash}\n"
        );
        assert!(public_api_snapshot_script_violations(&good).is_empty());

        let bad = format!(
            "\
            check_crate qpx-core {hash}\n\
            check_crate qpx-auth short\n\
            check_crate qpx-h3\n\
            check_crate qpx-acme {hash} extra\n\
            check_crate qpx-extra {hash}\n"
        );
        assert_eq!(
            public_api_snapshot_script_violations(&bad),
            [
                "check_crate qpx-auth expected hash must be 64 hex chars",
                "check_crate qpx-h3 missing expected hash",
                "check_crate qpx-acme has unexpected extra fields",
                "missing public API snapshot for qpx-h3",
                "missing public API snapshot for qpx-acme",
                "missing public API snapshot for qpx-observability",
                "unexpected public API snapshot for qpx-extra",
            ]
        );
    }

    #[test]
    fn security_qa_fuzz_target_gate_requires_workflow_entries() {
        let good = format!(
            "cargo fuzz run \"${{target}}\"\n{}",
            PLAN_P3_FUZZ_TARGETS.join("\n")
        );
        assert!(security_qa_fuzz_target_violations(&good).is_empty());

        assert_eq!(
            security_qa_fuzz_target_violations("config_canonical_loader"),
            [
                "security-qa workflow must run cargo fuzz for each target",
                "security-qa workflow missing fuzz target client_hello_sniff",
                "security-qa workflow missing fuzz target connect_frame_observer",
                "security-qa workflow missing fuzz target datagram_capsule_parser",
                "security-qa workflow missing fuzz target ftp_response_parser",
                "security-qa workflow missing fuzz target grpc_frame_observer",
                "security-qa workflow missing fuzz target grpc_web_binary_frame_observer",
                "security-qa workflow missing fuzz target grpc_web_text_base64_observer",
                "security-qa workflow missing fuzz target http1_request_head",
                "security-qa workflow missing fuzz target ipc_meta_frame",
                "security-qa workflow missing fuzz target proxy_v2_parser",
                "security-qa workflow missing fuzz target qpack_decoder",
                "security-qa workflow missing fuzz target reverse_target_input_deserializer",
                "security-qa workflow missing fuzz target shm_ring_ops",
                "security-qa workflow missing fuzz target sse_event_observer",
                "security-qa workflow missing fuzz target streaming_requirement_config_validator",
            ]
        );
    }

    #[test]
    fn secret_zeroize_gate_requires_hmac_and_auth_digest_zeroization() {
        let util = r#"
            use zeroize::Zeroizing;
            fn load() {
                let secret = Zeroizing::new(std::env::var("K").unwrap().into_bytes());
                let _ = Arc::<[u8]>::from(secret.as_slice());
            }
        "#;
        let local = r#"
            use zeroize::Zeroize;
            struct LocalPasswordDigest([u8; 32]);
            impl Drop for LocalPasswordDigest {
                fn drop(&mut self) { self.0.zeroize(); }
            }
            struct LocalDigestHa1(String);
            impl Drop for LocalDigestHa1 {
                fn drop(&mut self) { self.0.zeroize(); }
            }
        "#;
        let cargo = r#"zeroize = "1""#;
        assert!(secret_zeroize_boundary_violations(util, local, cargo).is_empty());

        assert_eq!(
            secret_zeroize_boundary_violations("", "", ""),
            [
                "zeroize = \"1\"",
                "use zeroize::Zeroizing;",
                "let secret = Zeroizing::new(",
                "Arc::<[u8]>::from(secret.as_slice())",
                "use zeroize::Zeroize;",
                "struct LocalPasswordDigest",
                "impl Drop for LocalPasswordDigest",
                "self.0.zeroize();",
                "struct LocalDigestHa1",
                "impl Drop for LocalDigestHa1",
            ]
        );
    }

    #[test]
    fn dependency_policy_gate_rejects_weak_deny_config() {
        let good: toml::Value = toml::from_str(
            r#"
            [bans]
            multiple-versions = "deny"
            wildcards = "deny"
            skip = [
              { crate = "legacy@1.0.0", reason = "documented transitive holdback" },
            ]
            skip-tree = []

            [sources]
            unknown-registry = "deny"
            unknown-git = "deny"
            "#,
        )
        .expect("parse good deny config");
        assert!(dependency_policy_config_violations(&good).is_empty());

        let bad: toml::Value = toml::from_str(
            r#"
            [bans]
            multiple-versions = "warn"
            wildcards = "allow"
            skip = [
              { crate = "legacy@1.0.0" },
            ]
            skip-tree = [
              { crate = "legacy@1.0.0" },
            ]

            [sources]
            unknown-registry = "warn"
            unknown-git = "allow"
            "#,
        )
        .expect("parse bad deny config");
        assert_eq!(
            dependency_policy_config_violations(&bad),
            [
                "deny.toml bans.multiple-versions must be deny",
                "deny.toml bans.wildcards must be deny",
                "deny.toml bans.skip-tree must stay empty",
                "deny.toml bans.skip[0] missing reason",
                "deny.toml sources.unknown-registry must be deny",
                "deny.toml sources.unknown-git must be deny",
            ]
        );
    }

    #[test]
    fn workspace_lint_posture_gate_rejects_weakened_lints() {
        let good: toml::Value = toml::from_str(
            r#"
            [workspace.package]
            rust-version = "1.87"

            [workspace.lints.rust]
            dead_code = "deny"
            unsafe_op_in_unsafe_fn = "deny"
            unused = "deny"

            [workspace.lints.clippy]
            undocumented_unsafe_blocks = "deny"
            "#,
        )
        .expect("parse good workspace lint config");
        assert!(workspace_lint_posture_violations(&good).is_empty());

        let bad: toml::Value = toml::from_str(
            r#"
            [workspace.package]
            rust-version = "1.88"

            [workspace.lints.rust]
            dead_code = "warn"
            unsafe_op_in_unsafe_fn = "allow"

            [workspace.lints.clippy]
            undocumented_unsafe_blocks = "warn"
            "#,
        )
        .expect("parse bad workspace lint config");
        assert_eq!(
            workspace_lint_posture_violations(&bad),
            [
                "workspace.package.rust-version must be 1.87",
                "workspace rust lint dead_code must be deny",
                "workspace rust lint unsafe_op_in_unsafe_fn must be deny",
                "workspace rust lint unused must be deny",
                "workspace clippy lint undocumented_unsafe_blocks must be deny",
            ]
        );
    }

    #[test]
    fn long_function_length_check_is_advisory() {
        let root = std::env::temp_dir().join(format!(
            "qpx-xtask-long-function-advisory-{}",
            std::process::id()
        ));
        let src = root.join("qpxd/src");
        std::fs::create_dir_all(&src).expect("create temp qpxd/src");
        let mut content = String::from("pub fn intentionally_long_for_advisory() {\n");
        for _ in 0..220 {
            content.push_str("    let _value = 1;\n");
        }
        content.push_str("}\n");
        std::fs::write(src.join("lib.rs"), content).expect("write temp source");

        let result = check_function_lengths(&root);

        std::fs::remove_dir_all(&root).expect("remove temp root");
        assert!(result.is_ok());
    }

    #[test]
    fn refactor_docs_gate_requires_forward_reverse_boundaries_and_non_goals() {
        assert!(
            forward_reverse_refactor_doc_violations(
                r#"
                forward and reverse should not be fully merged.
                shared HTTP dispatch modules own reusable policy, audit, response, cache, and limit primitives.
                forward/reverse/transparent modules own mode-specific orchestration and upstream selection.
                any new shared helper must remove real duplicated behavior, improve a responsibility boundary, or enforce a new mechanical gate without adding a compatibility branch.
                The following are not extraction targets:
                the full forward/reverse request state machine;
                route selection and body-observation ordering;
                retry template creation and replay;
                WebSocket/CONNECT special cases.
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            forward_reverse_refactor_doc_violations(
                "forward and reverse share a generic RequestDispatch facade"
            ),
            ["missing forward/reverse commonality boundary or non-goal"]
        );
    }

    #[test]
    fn refactor_docs_gate_requires_crate_boundary_decision() {
        assert!(
            crate_boundary_refactor_doc_violations(
                r#"
                do not split qpxd solely to move LOC.
                no feature loss.
                no default hot-path performance regression.
                Cargo-enforced dependency direction.
                extract only acyclic boundaries.
                keep qpxd as wiring.
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            crate_boundary_refactor_doc_violations("split qpxd to reduce line count"),
            [
                "do not split qpxd solely to move LOC",
                "no feature loss",
                "no default hot-path performance regression",
                "Cargo-enforced dependency direction",
                "extract only acyclic boundaries",
                "keep qpxd as wiring",
            ]
        );
    }

    #[test]
    fn library_anyhow_gate_rejects_public_result_aliases() {
        let violations = public_anyhow_violations(
            r#"
            pub type BadAlias<T> = anyhow::Result<T>;
            "#,
        );
        assert_eq!(violations, ["test.rs: pub type BadAlias"]);
    }

    #[test]
    fn library_anyhow_gate_rejects_imported_public_result_aliases() {
        let violations = public_anyhow_violations(
            r#"
            use anyhow::Result;
            pub type BadAlias<T> = Result<T>;
            "#,
        );
        assert_eq!(violations, ["test.rs: pub type BadAlias"]);
    }

    #[test]
    fn library_anyhow_gate_rejects_public_anyhow_reexports() {
        let violations = public_anyhow_violations(
            r#"
            pub use anyhow::{Error, Result};
            "#,
        );
        assert_eq!(
            violations,
            [
                "test.rs: pub use anyhow::Result",
                "test.rs: pub use anyhow::Error"
            ]
        );
    }

    #[test]
    fn library_anyhow_gate_rejects_public_result_with_anyhow_error() {
        let violations = public_anyhow_violations(
            r#"
            pub fn bad() -> std::result::Result<(), anyhow::Error> {
                Ok(())
            }
            "#,
        );
        assert_eq!(violations, ["test.rs: pub fn bad"]);
    }

    #[test]
    fn library_anyhow_gate_rejects_public_trait_methods_with_anyhow() {
        let violations = public_anyhow_violations(
            r#"
            pub trait Bad {
                fn bad(&self) -> anyhow::Result<()>;
            }
            "#,
        );
        assert_eq!(violations, ["test.rs: pub trait method bad"]);
    }

    #[test]
    fn library_anyhow_gate_rejects_public_trait_associated_types_with_anyhow() {
        let violations = public_anyhow_violations(
            r#"
            pub trait Bad {
                type Error = anyhow::Error;
            }
            "#,
        );
        assert_eq!(violations, ["test.rs: pub trait associated type Error"]);
    }

    #[test]
    fn library_anyhow_gate_rejects_inline_public_module_items() {
        let violations = public_anyhow_violations(
            r#"
            pub mod api {
                pub fn bad() -> anyhow::Result<()> {
                    Ok(())
                }
            }
            "#,
        );
        assert_eq!(violations, ["test.rs: pub fn api::bad"]);
    }

    #[test]
    fn library_anyhow_gate_rejects_inline_public_module_reexports() {
        let violations = public_anyhow_violations(
            r#"
            pub mod api {
                pub use anyhow::Error;
            }
            "#,
        );
        assert_eq!(violations, ["test.rs: pub use api::anyhow::Error"]);
    }

    #[test]
    fn library_anyhow_gate_allows_inline_private_module_items() {
        let violations = public_anyhow_violations(
            r#"
            mod internal {
                pub fn bad() -> anyhow::Result<()> {
                    Ok(())
                }
            }
            "#,
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn library_anyhow_gate_rejects_public_struct_fields_with_anyhow() {
        let violations = public_anyhow_violations(
            r#"
            pub struct Bad {
                pub error: Option<anyhow::Error>,
            }
            "#,
        );
        assert_eq!(violations, ["test.rs: pub struct field Bad::error"]);
    }

    #[test]
    fn library_anyhow_gate_allows_private_struct_fields_with_anyhow() {
        let violations = public_anyhow_violations(
            r#"
            pub struct Wrapper {
                error: anyhow::Error,
            }
            "#,
        );
        assert!(violations.is_empty());
    }

    #[test]
    fn library_anyhow_gate_rejects_public_enum_variants_with_anyhow() {
        let violations = public_anyhow_violations(
            r#"
            pub enum Bad {
                Backend(anyhow::Error),
            }
            "#,
        );
        assert_eq!(violations, ["test.rs: pub enum variant Bad::Backend::0"]);
    }

    #[test]
    fn library_anyhow_gate_allows_crate_specific_results() {
        let violations = public_anyhow_violations(
            r#"
            pub enum LocalError {
                Backend(#[from] anyhow::Error),
            }
            pub type LocalResult<T> = std::result::Result<T, LocalError>;
            pub fn ok() -> LocalResult<()> {
                Ok(())
            }
            "#,
        );
        assert!(violations.is_empty());
    }
}
