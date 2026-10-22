use crate::budget::{LocBudget, TotalLocBudgets};
use crate::files::{has_cfg_test, is_test_file, rust_files_under};
use crate::visitors::{FinalizeVisitor, PanicVisitor, UnwrapVisitor};
use anyhow::{Context, Result, anyhow, bail};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use syn::parse::Parser;
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
    let mut violations = dependency_policy_config_violations(&value);
    let cargo_path = root.join("Cargo.toml");
    let cargo_content = fs::read_to_string(&cargo_path)
        .with_context(|| format!("failed to read {}", cargo_path.display()))?;
    let cargo: toml::Value = toml::from_str(&cargo_content)
        .with_context(|| format!("failed to parse {}", cargo_path.display()))?;
    violations.extend(external_wildcard_dependency_violations(root, &cargo)?);
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
    if rust_version != Some("1.96") {
        violations.push("workspace.package.rust-version must be 1.96".to_string());
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
    if bans.get("wildcards").and_then(toml::Value::as_str) != Some("allow") {
        violations.push(
            "deny.toml bans.wildcards must be allow; xtask rejects external wildcard dependencies"
                .to_string(),
        );
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

fn external_wildcard_dependency_violations(
    root: &Path,
    cargo: &toml::Value,
) -> Result<Vec<String>> {
    let Some(members) = cargo
        .get("workspace")
        .and_then(toml::Value::as_table)
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
    else {
        return Ok(vec!["Cargo.toml missing workspace.members".to_string()]);
    };

    let mut violations = Vec::new();
    for member in members.iter().filter_map(toml::Value::as_str) {
        if member.contains('*') {
            continue;
        }
        let manifest_path = root.join(member).join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let content = fs::read_to_string(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;
        let manifest: toml::Value = toml::from_str(&content)
            .with_context(|| format!("failed to parse {}", manifest_path.display()))?;
        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            let Some(deps) = manifest.get(section).and_then(toml::Value::as_table) else {
                continue;
            };
            for (name, dep) in deps {
                if dependency_is_external_wildcard(dep) {
                    violations.push(format!(
                        "{member}/Cargo.toml {section}.{name} must use workspace, path, or an explicit version"
                    ));
                }
            }
        }
    }
    Ok(violations)
}

fn dependency_is_external_wildcard(dep: &toml::Value) -> bool {
    match dep {
        toml::Value::String(version) => version.trim() == "*",
        toml::Value::Table(table) => {
            !table.contains_key("workspace")
                && !table.contains_key("path")
                && table.get("version").is_none_or(|version| {
                    version.as_str().is_none_or(|version| version.trim() == "*")
                })
        }
        _ => false,
    }
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
    for needle in "fn policy_id(&self) -> Option<&str>;fn policy_tags(&self) -> &[String];build_dispatch_audit_context;apply_decision_service_http_access;apply_dispatch_response_policy;dispatch_cache_collapse_continue;finalize_dispatch_collapsed_cache_decision;check_dispatch_limit_response_commonality;check_http_token_vocabulary_single_owner;check_content_length_single_owner;check_dispatch_annotated_local_response_commonality;check_response_capture_after_finalize;check_proxy_authorization_header_boundary;check_reverse_response_rules_dispatch_boundary;check_h3_origin_pool_load_semantics;check_qpxf_cgi_header_parser_zero_copy;check_qpx_h3_static_response_boundary;check_rpc_frame_boundary_tests;finalize_response_headers_common;finalize_response_with_headers_in_place;set_proxy_authorization_header;trait HeaderTransform;trait ResponseTransform;MIRROR_MAX_INFLIGHT_PER_ENDPOINT;collect_decision_service_response_body;request_side_fail_closed;send_prefixed_datagram;validate_secure_file_handle".split(';') {
        if !acceptance.contains(needle) {
            bail!("CI acceptance gate is missing required check: {needle}");
        }
    }
    Ok(())
}

pub(crate) fn check_architecture_baselines(root: &Path) -> Result<()> {
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
    check_decision_service_response_buffering(root)?;
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
    check_http_token_vocabulary_single_owner(root)?;
    check_content_length_single_owner(root)?;
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
    // The combined stage wraps audit construction and decision_service application;
    // dispatchers may either call it or use the two shared primitives, but
    // must never hand-roll the sequence.
    let uses_combined_stage = content.contains("enforce_http_access(");
    if !uses_combined_stage && !content.contains("build_dispatch_audit_context(") {
        violations.push("missing build_dispatch_audit_context");
    }
    if !uses_combined_stage && !content.contains("apply_decision_service_http_access(") {
        violations.push("missing apply_decision_service_http_access");
    }
    for forbidden in [
        "DispatchAuditContext::new(",
        ".policy_id()",
        ".policy_tags()",
        "DecisionServiceEnforcement::Continue",
        "DecisionServiceEnforcement::Deny",
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

/// The HTTP token grammar and the comma-separated header token search have
/// one owner: `qpx-core::http_token`.
///
/// The owner sits below the crates that use it - the configuration
/// validation, the DPoP claim validation and the HTTP runtime - so a single
/// implementation can serve all of them. A copy in any of them would let the
/// Forwarded element names, the WebSocket subprotocol names, the Connection
/// tokens, the configuration's header names and the DPoP method claim drift
/// apart, and the DPoP copy already had.
///
/// The gate covers the whole workspace, not one crate. No other file may
/// define a token grammar predicate or a header token search under one of the
/// names the workspace has used, and no other file may spell the search the
/// way the owner spells it: a comma split on a comma literal, in either
/// literal spelling, whose members are compared case-insensitively after
/// trimming, within 240 bytes of the split.
///
/// The other token vocabularies are not the owner's: the structured field
/// token, the media type token and the HTTP method name each have their own
/// rules.
///
/// What the text match cannot see is stated here rather than implied: a copy
/// that renames the predicate and spells the character set differently, a
/// copy that trims its members another way, and a copy whose comparison
/// stands further from its split. The owner below its users is what keeps
/// those from mattering.
fn check_http_token_vocabulary_single_owner(root: &Path) -> Result<()> {
    const OWNER: &str = "qpx-core/src/http_token.rs";
    const OWNER_FUNCTIONS: [&str; 2] = [
        "pub fn is_http_token(",
        "pub fn header_values_contain_token(",
    ];
    let mut violations = Vec::new();
    let owner = fs::read_to_string(root.join(OWNER))
        .with_context(|| format!("the HTTP token vocabulary owner {OWNER} is missing"))?;
    for required in OWNER_FUNCTIONS {
        if !owner.contains(required) {
            violations.push(format!("{OWNER}: the owner does not define `{required}`"));
        }
    }
    for crate_dir in workspace_member_crates(root)? {
        // The gate's own crate names the vocabulary it looks for.
        if crate_dir == "xtask" {
            continue;
        }
        let crate_root = root.join(&crate_dir);
        for dir in ["src", "tests"] {
            let scan_root = crate_root.join(dir);
            if !scan_root.is_dir() {
                continue;
            }
            for path in rust_files_under(&scan_root)? {
                let rel_path = rel_path(root, &path);
                if rel_path == OWNER {
                    continue;
                }
                let content = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                violations.extend(
                    http_token_vocabulary_violations(&content)
                        .into_iter()
                        .map(|violation| format!("{rel_path}: {violation}")),
                );
            }
        }
    }
    if !violations.is_empty() {
        bail!(
            "the HTTP token vocabulary must have one owner ({OWNER}):\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

/// The owner of a header set's declared Content-Length.
const CONTENT_LENGTH_OWNER: &str = "qpx-core/src/http_content_length.rs";

/// The names the workspace has used for a function that reads a header set's
/// declared Content-Length.
const CONTENT_LENGTH_READER_NAMES: [&str; 15] = [
    "fn content_length(",
    "fn parse_content_length(",
    "fn parse_declared_content_length(",
    "fn parse_content_length_fields(",
    "fn expected_body_length(",
    "fn declared_content_length(",
    "fn request_is_templateable(",
    "fn request_has_body_or_expect(",
    "fn stored_content_length(",
    "fn cacheable_content_length(",
    "fn declared_response_length(",
    "fn parse_header_u64(",
    "fn declared_response_bytes(",
    "fn response_exceeds_max_response_bytes(",
    "fn declared_request_length(",
];

/// The qualified call a site that folds the declaration into the owner uses.
///
/// The owner has three entry points, one for a header map, one for the
/// field's values and one for a sequence of named header values, so the
/// call is matched by its name: a site that reads the declaration through
/// any of them has folded it.
const CONTENT_LENGTH_OWNER_CALL: &str = "::declared_content_length";

/// The declared Content-Length has one owner, and the owner names the sites
/// that still read the declaration themselves.
///
/// A site that reads the declaration through a helper either calls the owner
/// or is named in the owner's own list, so a new reader cannot appear
/// without the owner saying what it does differently. The list may be empty:
/// an empty list says that every site that reads the declaration through a
/// helper calls the owner, and a reader that does not call the owner is a
/// violation whether or not the owner names a site. The gate reads the
/// names the workspace has used for such a helper, so a reader under a name
/// it has not seen before is beyond that rule; a reader that reads the
/// declaration inline is not beyond the gate, because the gate looks inside
/// a function's body as well and asks whether the body reads the field's
/// value and turns text into a number. Such a body must reach the owner
/// alone: a function that calls the owner and still reads the field on its
/// own is a violation as well.
///
/// The gate also asks a question that does not depend on the name of a
/// helper at all: in the shipped code, does any function read the field's
/// value? The owner reads it, and no other shipped site does, so a read of
/// the value is a violation on its own. That catches the readers the
/// naming rule cannot see: a site that reads the value and hands it to
/// another function, and a site whose helper has a name the workspace has
/// never used. Test code is not part of that rule: a test observes the
/// value to assert on what the proxy put on the wire, and it does not
/// decide what the proxy does.
///
/// A read of the value has two shapes. The first is a read of the field
/// through a header map, which the gate sees by the name the site reads
/// the field with. The second is a value taken out of the field's own
/// entry in a list of header entries: a site that compares a header's
/// name with the field's name and, in the same body, takes the value of
/// a header entry finds that entry itself, and a second reading of the
/// field is what this owner removes. The second shape is seen however
/// the entry's value is taken: by a closure that receives the entry as
/// a pair and uses its second element, by the second element of the
/// pair, and by the `value` member of the entry whose name the
/// comparison found.
/// The gate follows the entry itself as well, so the value is seen
/// however the entry travels: a binding of the entry holds it under a
/// name of its own, a closure that receives it from the search that
/// found it holds it under the name the closure binds, a pattern that
/// binds the search's result holds it as well, and a helper that
/// found it hands it to its caller, which binds the result. The
/// helper may stand in another file: the gate reads the files of the
/// workspace together, so the helpers that found the field's own entry
/// are known before the files that call them are read. A caller that
/// takes the value out of the result the helper hands it reads the
/// value as well, whether it destructures the pair or a closure
/// receives it.
///
/// The gate follows a binding of the field's name as well: a site that
/// binds the field's name to a name of its own and reads the field
/// through that binding reads the declaration, so the binding names the
/// field, and a comparison under the binding is a comparison of a
/// header's name with the field's name. It follows a constant or a
/// static that holds the field's name as well, so a site that keeps the
/// field's name in a constant of its own and reads the field through
/// that constant reads the declaration, and a comparison under the
/// constant is a comparison of a header's name with the field's name.
/// The gate follows an import as well: a site that imports the field's
/// name under a name of its own reads the declaration through that
/// name, so the gate reads the imports of the file and follows the name
/// the import gives the field's name, whether the import renames the
/// name or imports it under the name it is spelled with. The imports
/// of a nested module are the file's imports too, so they are read as
/// well, the way the constants of a nested module are read. An import
/// inside a function body is not one of them: it is a name that one
/// function holds, not a name the file holds. The name an import
/// brings the field's name under is followed for the whole file, so a
/// nested module that uses that name for something else is read as a
/// reader of the declaration; the gate errs towards seeing a read.
/// The gate follows a binding of a header entry's name as well: a site
/// that binds the entry's name to a name of its own and compares that
/// name with the field's name compares the entry's name, so the
/// comparison finds that entry and the value the site takes is that
/// entry's value. A site that copies the entry's name into a name of
/// its own holds that name as well, so the copy names the entry too,
/// and a site that copies the field's name holds the field's name, so
/// the copy names the field. A copy of a name the site holds is that
/// name, so a copy of a binding of the field's name and a copy of a
/// constant the site keeps the field's name in name the field as well.
/// The gate reads a comparison that stands in a condition of its own as
/// deciding about the field when the branch it guards skips the entry:
/// the site moved on, so the comparison did not find the entry. A
/// condition that holds more than the comparison cannot be read that
/// way, because the gate cannot say which part of it skips the entry,
/// so a comparison inside such a condition still finds the field's own
/// entry: the code after the branch may hold it.
///
/// The gate follows a name the site builds at runtime as well: a site
/// that builds the field's name with a constructor or with a macro and
/// finds the field's own entry with the built name reads the
/// declaration, so the gate reads the text the site writes out and
/// follows it back to the field. The text the site writes out may stand
/// under a name of its own: a site that binds a piece of the field's
/// name and builds the name from that piece reads the declaration, so
/// the gate reads the text a binding holds as well, whether the name is
/// built by a macro that takes the piece by its name or by adding the
/// piece to another piece.
/// The gate follows the member the value is held under as well: a
/// header entry holds its name and its value under members of its own,
/// so a site that finds the field's own entry and takes a member of it
/// that is not the member holding the name reads the declaration's
/// value. The member the comparison used is the name, so a site that
/// takes that member takes the name and not the value.
/// What the gate cannot see is a site that finds the field's entry by a
/// name it builds at runtime from text the site did not write out - a
/// piece that arrives at runtime - and a site that takes the value under
/// a member of an entry the comparison did not find. A constant of
/// another file of the workspace that holds the field's name is
/// followed: the gate reads the constants of the workspace's files, so a
/// site that imports such a constant holds the field's name under the
/// name the import gives it, and the import may rename it. The import
/// that brings such a constant in is read the way the field's own
/// imports are read, so an import in a nested module is followed too.
/// The gate
/// matches that constant by its name and not by the path the import
/// takes, so a constant of a crate outside the workspace is not
/// followed, a name one file holds the field's name under and another
/// file holds another value under is not followed either, and a
/// constant an import reaches through a glob is not followed. A helper
/// of another file that found the entry is seen when the caller calls it
/// by the name it is defined with; a call through another name is not
/// seen. A member that holds the entry's name under a name the gate does
/// not know is read as the value, because the gate cannot tell that
/// member from the member the value is held under.
fn check_content_length_single_owner(root: &Path) -> Result<()> {
    let owner_path = root.join(CONTENT_LENGTH_OWNER);
    let owner = fs::read_to_string(&owner_path)
        .with_context(|| format!("the Content-Length owner {CONTENT_LENGTH_OWNER} is missing"))?;
    let mut files = Vec::new();
    for crate_dir in workspace_member_crates(root)? {
        // The gate's own crate names the vocabulary it looks for.
        if crate_dir == "xtask" {
            continue;
        }
        let crate_root = root.join(&crate_dir);
        for dir in ["src", "tests"] {
            let scan_root = crate_root.join(dir);
            if !scan_root.is_dir() {
                continue;
            }
            for path in rust_files_under(&scan_root)? {
                let rel = rel_path(root, &path).into_owned();
                if rel == CONTENT_LENGTH_OWNER {
                    continue;
                }
                let content = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                files.push((rel, content));
            }
        }
    }
    let listed = content_length_listed_sites(&owner);
    let mut violations = content_length_single_owner_violations(&owner, &files);
    violations.extend(content_length_workspace_violations(&files, &listed)?);
    if !violations.is_empty() {
        bail!(
            "the declared Content-Length must have one owner ({CONTENT_LENGTH_OWNER}):\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

/// The violations of the declared Content-Length's single owner.
fn content_length_single_owner_violations(owner: &str, files: &[(String, String)]) -> Vec<String> {
    let listed = content_length_listed_sites(owner);
    let mut violations = Vec::new();
    let mut readers = Vec::new();
    for (path, content) in files {
        if !CONTENT_LENGTH_READER_NAMES
            .iter()
            .any(|name| content.contains(name))
        {
            continue;
        }
        readers.push(path.clone());
        if content.contains(CONTENT_LENGTH_OWNER_CALL) {
            continue;
        }
        if listed.iter().any(|site| site == path) {
            continue;
        }
        violations.push(format!(
            "{path} reads the declared Content-Length through its own helper and the owner does not name it"
        ));
    }
    for site in &listed {
        if !readers.iter().any(|reader| reader == site) {
            violations.push(format!(
                "{site} is named by the owner but does not read the declared Content-Length"
            ));
        }
    }
    violations
}

/// The sites the owner names as the ones that read the declaration
/// themselves, read from the list items of its own comment.
fn content_length_listed_sites(owner: &str) -> Vec<String> {
    let mut sites = Vec::new();
    for line in owner.lines() {
        let Some(text) = line.trim().strip_prefix("///") else {
            continue;
        };
        let Some(item) = text.trim().strip_prefix('-') else {
            continue;
        };
        let mut rest = item;
        while let Some(start) = rest.find('`') {
            rest = &rest[start + 1..];
            let Some(end) = rest.find('`') else {
                break;
            };
            let candidate = &rest[..end];
            if candidate.contains('/') && candidate.ends_with(".rs") {
                sites.push(candidate.to_string());
            }
            rest = &rest[end + 1..];
        }
    }
    sites
}

/// The methods that read a header's value.
const CONTENT_LENGTH_READ_METHODS: [&str; 3] = ["get", "get_all", "contains_key"];

/// The methods that copy a header entry's name into a name of their own.
///
/// A site that copies the name of the entry it holds holds that entry's
/// name, so the gate follows the copy back to the entry the name came
/// from.
const CONTENT_LENGTH_NAME_COPY_METHODS: [&str; 7] = [
    "to_string",
    "to_owned",
    "clone",
    "to_ascii_lowercase",
    "to_ascii_uppercase",
    "to_lowercase",
    "to_uppercase",
];

/// The constructors that build a name at runtime from text.
///
/// A site that builds the field's name at runtime and finds the field's
/// own entry with the built name reads the declaration, so the gate
/// follows the built name back to the text it was built from. The
/// constructors are named by the type and the method, so a constructor
/// of another type is not one of them.
const CONTENT_LENGTH_NAME_BUILDERS: [&str; 5] = [
    "String::from",
    "HeaderName::from_bytes",
    "HeaderName::from_lowercase",
    "HeaderName::try_from",
    "Cow::Borrowed",
];

/// The field's name, as a header spells it.
const CONTENT_LENGTH_FIELD: &str = "content-length";

/// The name the field's name is spelled with where a header crate keeps
/// it.
///
/// A path whose last segment is this name names the field, so an import
/// of such a path brings the field's name into the file under the name
/// the import gives it.
const CONTENT_LENGTH_CONSTANT: &str = "CONTENT_LENGTH";

/// The module the owner is reached through.
const CONTENT_LENGTH_OWNER_MODULE: &str = "http_content_length";

/// The entry points the owner has.
const CONTENT_LENGTH_OWNER_ENTRIES: [&str; 2] = [
    "declared_content_length",
    "declared_content_length_in_named_values",
];

/// The violations of a site that reads the declared Content-Length inline.
///
/// The rule above sees a reader that has a helper of its own, because it
/// looks for the names the workspace has used for such a helper. A reader
/// that reads the declaration in the body of a function has no helper to
/// name, so the gate looks inside the functions as well: a function that
/// reads the field's value and turns text into a number in the same body
/// reads the declaration itself, and must reach the owner alone.
///
/// The rule is what it says and no more. It sees a read of the field
/// through `get`, `get_all` and `contains_key`, a read of the field
/// through an index, and it sees a comparison of a header name with the
/// field's name. It sees the field named through a reference, through the
/// constant's text, through a name built from the text, through a copy
/// the site made of the text, through a name the site builds at
/// runtime from that text and through a name the site imported the
/// field's name under. It sees a parse whose type is written and a
/// parse whose type is inferred, because the field's value is a length
/// either way. It does not see a reader that lives outside a function
/// body, it does not see a name the site builds at runtime from text the
/// site did not write out, and it reads a function's body as one whole
/// rather than tying a parse to the read it belongs to. Read on its own
/// it does not see a constant of another file that holds the field's
/// name, because it reads one file; the gate itself reads the
/// workspace's files together and does see that constant.
#[cfg(test)]
fn content_length_inline_reader_violations(path: &str, content: &str) -> Result<Vec<String>> {
    let syntax = syn::parse_file(content)
        .with_context(|| format!("failed to parse {path} for the Content-Length gate"))?;
    Ok(content_length_inline_reader_facts_violations(
        path,
        &content_length_reader_facts_with(path, &syntax, &[]),
    ))
}

/// The violations of a site that reads the declared Content-Length inline,
/// from the facts of its functions.
fn content_length_inline_reader_facts_violations(
    path: &str,
    facts: &ContentLengthFileFacts,
) -> Vec<String> {
    let mut violations = Vec::new();
    for (name, facts) in facts {
        if !facts.reads_field || !facts.parses_integer {
            continue;
        }
        let detail = if facts.calls_owner {
            "as well as calling the owner; it must read the declaration through the owner alone"
        } else {
            "inline; it must call the owner"
        };
        violations.push(format!(
            "{path}: the function {name} reads the declared Content-Length {detail}"
        ));
    }
    violations
}

/// The violations of a shipped site that reads the declared Content-Length's
/// value.
///
/// The field's value is read in one place: the owner. A site that reads the
/// value itself interprets the declaration on its own, whether it turns the
/// value into a number in the same body or hands the value to another
/// function that does, so the rule sees the read and not the parse that may
/// follow it. The value is read either through a header map or out of the
/// entry the site found by the field's name, and both are reads of the
/// declaration's value. A read of the value is therefore a violation on
/// its own, and a site that reads the value and calls the owner as well
/// is a violation too, because the owner is the only reader.
///
/// The value is taken out of the entry in more than one way, and the rule
/// sees them all: by a closure that receives the entry as a pair and uses
/// its second element, by the second element of the pair, and by the
/// `value` member of the entry whose name the comparison found. It sees
/// the value under any other member of that entry as well: a header
/// entry holds its name and its value under members of its own, so the
/// member the comparison used is the name and every other member of the
/// entry is the value. The value
/// is the field's value when the site selects the field's own entry, and
/// a comparison of a header's name with the field's name is what selects
/// it. The value has to come from the entry the comparison found: the
/// rule reads a member of the entry only when the site takes it under the
/// name it compared or under a name the entry travels to, so a site
/// that compares the field's name and takes another entry's value is
/// not a reader either. The entry travels: a binding of the entry
/// holds it under a name of its own, a closure that receives it from
/// the search that found it holds it under the name the closure binds,
/// a pattern that binds the search's result holds it as well, and a
/// helper that found it hands it to its caller, which binds the result,
/// so the value the site takes under any of those names is the field's
/// value. The helper may stand in another file, because the rule reads
/// the files of the workspace together. A comparison that decides about
/// the field instead does not select it: a comparison whose branch skips
/// the entry decides about the field, so a site that skips the field
/// and takes another header's value is not a reader. A comparison that
/// is not equal reads the other way round when the branch skips the
/// entry, because the entry that reaches the code after the branch is
/// the field's own. A comparison that stands in a condition that holds
/// more than the comparison is not read as deciding about the field at
/// all: the rule cannot say which part of the condition skips the
/// entry, so the comparison finds the field's own entry, and the code
/// after the branch may hold it.
///
/// The rule follows a binding of a header entry's name as well: a site
/// that binds the entry's name to a name of its own and compares that
/// name with the field's name compares the entry's name, so the binding
/// stands for the entry the name came from, and the value the site
/// takes is that entry's value. A site that copies the entry's name
/// into a name of its own holds that name as well, so the copy names
/// the entry too, and a site that copies the field's name holds the
/// field's name, so the copy names the field. A copy of a name the site
/// holds is that name, so a copy of a binding of the field's name and a
/// copy of a constant the site keeps the field's name in name the field
/// as well.
///
/// The rule follows the name the site holds for the field: the field's
/// name itself, a name the site binds the field's name to, a name the
/// site keeps the field's name in a constant or a static of its own, and
/// a name the site imports the field's name under. The
/// name is followed wherever the path spells it, so a reader cannot hide
/// behind a binding, a constant or an import of its own.
///
/// The rule follows a name the site builds at runtime as well: a site
/// that builds the field's name with a constructor or with a macro and
/// finds the field's own entry with the built name reads the
/// declaration, so the rule reads the text the site writes out and
/// follows it back to the field. The text the site writes out may stand
/// under a name of its own, so the rule reads the text a binding holds
/// as well and follows a name the site builds from that piece.
///
/// What the rule cannot see is a site that finds the field's entry by a
/// name it builds at runtime from text the site did not write out - a
/// piece that arrives at runtime - and a site that takes the value under
/// a member of an entry the comparison did not find. Read on its own it
/// does not see a constant of another file that holds the field's name,
/// because it reads one file; the gate itself reads the workspace's
/// files together and does see that constant, so a site that imports
/// such a constant holds the field's name under the name the import
/// gives it, and the import may rename it. The gate matches that
/// constant by its name and not by the path the import takes, so a
/// constant of a crate outside the workspace is not followed, a name
/// one file holds the field's name under and another file holds another
/// value under is not followed either, and a constant an import reaches
/// through a glob is not followed. A helper of
/// another file that found the entry is seen when the caller calls it by
/// the name it is defined with; a call through another name is not seen.
/// A member that holds the entry's name under a name the rule does not
/// know is read as the value, because the rule cannot tell that member
/// from the member the value is held under.
///
/// The rule covers the shipped code. Test code observes the field's value to
/// assert on what the proxy put on the wire, and it does not decide what the
/// proxy does, so a test that observes the value is not a violation here; a
/// test that interprets the declaration is still a violation, because the
/// inline rule sees a body that reads the value and turns it into a number.
///
/// The owner names the sites that read the declaration themselves, so a site
/// the owner names is not a violation.
#[cfg(test)]
fn content_length_production_value_reader_violations(
    path: &str,
    content: &str,
    listed: &[String],
) -> Result<Vec<String>> {
    if listed.iter().any(|site| site == path) {
        return Ok(Vec::new());
    }
    let syntax = syn::parse_file(content)
        .with_context(|| format!("failed to parse {path} for the Content-Length gate"))?;
    Ok(content_length_production_value_reader_facts_violations(
        path,
        &content_length_reader_facts_with(path, &syntax, &[]),
        listed,
    ))
}

/// The violations of a shipped site that reads the declared Content-Length's
/// value, from the facts of its functions.
fn content_length_production_value_reader_facts_violations(
    path: &str,
    facts: &ContentLengthFileFacts,
    listed: &[String],
) -> Vec<String> {
    if listed.iter().any(|site| site == path) {
        return Vec::new();
    }
    let mut violations = Vec::new();
    for (name, facts) in facts {
        if !facts.reads_value || facts.test_code {
            continue;
        }
        let detail = if facts.calls_owner {
            "as well as calling the owner; it must read the declaration through the owner alone"
        } else {
            "itself; it must call the owner"
        };
        violations.push(format!(
            "{path}: the function {name} reads the declared Content-Length's value {detail}"
        ));
    }
    violations
}

/// The facts of the functions of a file.
///
/// Every function of the file is recorded on its own, so a reader in a
/// function is named by that function rather than by the one it sits in.
type ContentLengthFileFacts = Vec<(String, ContentLengthReaderFacts)>;

/// The facts of every file of the workspace.
type ContentLengthWorkspaceFacts = Vec<(String, ContentLengthFileFacts)>;

/// The functions of a file and what each of them says about the declared
/// Content-Length, with the names a constant of another file brings into
/// the file.
///
/// A constant of another file that holds the field's name names the field
/// in the file that imports it, so a read through that name reads the
/// declaration.
fn content_length_reader_facts_with(
    path: &str,
    syntax: &syn::File,
    imported_constants: &[String],
) -> ContentLengthFileFacts {
    let mut collector = ContentLengthFunctionCollector {
        test_file: is_test_file(Path::new(path)),
        field_name_constants: content_length_field_name_constants(syntax),
        field_name_imports: content_length_imported_names(syntax),
        imported_constants: imported_constants.to_vec(),
        ..ContentLengthFunctionCollector::default()
    };
    collector.visit_file(syntax);
    // The entry the comparison found travels: a helper that found it
    // hands it to its caller, which binds the result.
    content_length_follow_the_entry_across_functions(&mut collector.facts);
    for (_, facts) in collector.facts.iter_mut() {
        facts.finish();
    }
    collector.facts
}

/// The names that hold the entry a helper of the same file found.
///
/// A helper that finds the field's own entry hands that entry to its
/// caller, so a binding of the helper's result holds the entry the
/// comparison found, and the value the caller takes under that name is
/// the field's value. A helper of another file is found by the
/// workspace pass, which reads the files of the workspace together.
fn content_length_follow_the_entry_across_functions(
    facts: &mut [(String, ContentLengthReaderFacts)],
) {
    let finders: Vec<String> = facts
        .iter()
        .filter(|(_, facts)| facts.selects_field)
        .map(|(name, _)| name.clone())
        .collect();
    if finders.is_empty() {
        return;
    }
    for (_, facts) in facts.iter_mut() {
        for (binding, callee) in facts.finder_calls.clone() {
            if finders.contains(&callee) && !facts.field_entry_names.contains(&binding) {
                facts.field_entry_names.push(binding);
            }
        }
        for (value, callee) in facts.finder_value_calls.clone() {
            if finders.contains(&callee) && facts.used_names.contains(&value) {
                facts.reads_value = true;
            }
        }
        for callee in facts.finder_value_closures.clone() {
            if finders.contains(&callee) {
                facts.reads_value = true;
            }
        }
    }
}

/// The facts of every file of the workspace.
///
/// The rule reads one file at a time, but the entry the comparison found
/// travels between files: a helper of another file that found the field's
/// own entry hands it to its caller, so the caller binds the entry under
/// a name of its own and the value it takes under that name is the
/// field's value. The facts of the workspace are therefore taken
/// together, so the helpers that found the field's own entry are known
/// before the files that call them are read.
///
/// A helper in test code is not one of them: test code observes the
/// field's value to assert on what the proxy put on the wire, and it
/// does not decide what the proxy does, so a helper of test code does
/// not hand the field's entry to the shipped code.
fn content_length_workspace_facts(
    files: &[(String, String)],
) -> Result<ContentLengthWorkspaceFacts> {
    let mut syntaxes = Vec::new();
    for (path, content) in files {
        let syntax = syn::parse_file(content)
            .with_context(|| format!("failed to parse {path} for the Content-Length gate"))?;
        syntaxes.push((path.clone(), syntax));
    }
    // A constant of another file that holds the field's name names the
    // field in the file that imports it, so the constants of the
    // workspace are read before the files that import them.
    let workspace_constants = content_length_workspace_field_constants(&syntaxes);
    let crate_names = content_length_crate_names(&syntaxes);
    let mut parsed = Vec::new();
    for (path, syntax) in &syntaxes {
        let imported =
            content_length_imported_field_constants(syntax, &workspace_constants, &crate_names);
        parsed.push((
            path.clone(),
            content_length_reader_facts_with(path, syntax, &imported),
        ));
    }
    // The helpers that found the field's own entry in the shipped code.
    // A helper that compares a header's name with the field's name found
    // that entry, so a call to the helper hands the entry to the caller.
    // The helper is followed by the name it is defined with, so a call
    // through another name does not hand the entry over.
    let mut finders: Vec<String> = Vec::new();
    for (_, facts) in &parsed {
        for (name, facts) in facts {
            if facts.selects_field && !facts.test_code && !finders.contains(name) {
                finders.push(name.clone());
            }
        }
    }
    if finders.is_empty() {
        return Ok(parsed);
    }
    // A helper that found the field's own entry hands it to its caller,
    // wherever the helper stands, so the caller's binding of the result
    // holds the entry.
    for (_, facts) in parsed.iter_mut() {
        for (_, facts) in facts.iter_mut() {
            for (binding, callee) in facts.finder_calls.clone() {
                if finders.contains(&callee) && !facts.field_entry_names.contains(&binding) {
                    facts.field_entry_names.push(binding);
                }
            }
            for (value, callee) in facts.finder_value_calls.clone() {
                if finders.contains(&callee) && facts.used_names.contains(&value) {
                    facts.reads_value = true;
                }
            }
            for callee in facts.finder_value_closures.clone() {
                if finders.contains(&callee) {
                    facts.reads_value = true;
                }
            }
            facts.finish();
        }
    }
    Ok(parsed)
}

/// The violations of the whole workspace.
///
/// The files are read together, because the entry the comparison found
/// travels from the file that found it to the file that calls the
/// helper that found it.
fn content_length_workspace_violations(
    files: &[(String, String)],
    listed: &[String],
) -> Result<Vec<String>> {
    let workspace = content_length_workspace_facts(files)?;
    let mut violations = Vec::new();
    for (path, facts) in &workspace {
        violations.extend(content_length_inline_reader_facts_violations(path, facts));
        violations.extend(content_length_production_value_reader_facts_violations(
            path, facts, listed,
        ));
    }
    Ok(violations)
}

/// The names a file imports the field's name under.
///
/// A site that imports the field's name under a name of its own reads
/// the declaration through that name, so the gate reads the imports of
/// the file and follows the name the import gives the field's name.
///
/// The imports of a nested module are the file's imports too, so they
/// are read as well, the way the rule reads the constants of a nested
/// module. An import inside a function body is not one of them: it is a
/// name that one function holds, not a name the file holds.
fn content_length_imported_names(syntax: &syn::File) -> Vec<String> {
    let mut names = Vec::new();
    collect_imported_names_of_items(&syntax.items, &mut names);
    names
}

/// The names the imports of a list of items bring the field's name under.
///
/// A module's own imports and the imports of the modules inside it are
/// read, so a nested module's import is followed as well.
fn collect_imported_names_of_items(items: &[syn::Item], names: &mut Vec<String>) {
    for item in items {
        match item {
            syn::Item::Use(item) => collect_imported_names(&item.tree, names),
            syn::Item::Mod(item) => {
                if let Some((_, items)) = &item.content {
                    collect_imported_names_of_items(items, names);
                }
            }
            _ => {}
        }
    }
}

/// The names one import brings the field's name under.
///
/// An import of the field's name brings it under the name the import
/// gives it: the name it is renamed to when the import renames it, and
/// the name it is spelled with otherwise. An import of a group is read
/// part by part, and an import of a prefix is read through to the name
/// it ends in.
fn collect_imported_names(tree: &syn::UseTree, names: &mut Vec<String>) {
    match tree {
        syn::UseTree::Path(path) => collect_imported_names(&path.tree, names),
        syn::UseTree::Name(name) => {
            if name.ident == CONTENT_LENGTH_CONSTANT {
                names.push(name.ident.to_string());
            }
        }
        syn::UseTree::Rename(rename) => {
            if rename.ident == CONTENT_LENGTH_CONSTANT {
                names.push(rename.rename.to_string());
            }
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_imported_names(tree, names);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

/// The names the constants of the workspace hold the field's name under.
///
/// A constant of another file that holds the field's name names the field
/// in the file that imports it, so the gate reads the constants of every
/// file of the workspace. A name that two files define is not followed:
/// one of the two holds another value, so the gate cannot say which one
/// an import names.
fn content_length_workspace_field_constants(files: &[(String, syn::File)]) -> Vec<String> {
    let mut holding = Vec::new();
    let mut other = Vec::new();
    for (_, syntax) in files {
        for (name, holds) in content_length_constants(syntax) {
            if holds {
                if !holding.contains(&name) {
                    holding.push(name);
                }
            } else if !other.contains(&name) {
                other.push(name);
            }
        }
    }
    holding
        .into_iter()
        .filter(|name| !other.contains(name))
        .collect()
}

/// The names the crates of the workspace are known by in a path.
///
/// A crate of the workspace is named by its directory with the dashes
/// spelled as underscores, so an import that starts with one of these
/// names names something of the workspace.
fn content_length_crate_names(files: &[(String, syn::File)]) -> Vec<String> {
    let mut names = Vec::new();
    for (path, _) in files {
        let Some((crate_dir, _)) = path.split_once('/') else {
            continue;
        };
        let name = crate_dir.replace('-', "_");
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// The names a file imports a constant of the workspace under.
///
/// A constant of another file that holds the field's name names the field
/// in the file that imports it, so the name the import gives the constant
/// is a name of the field.
///
/// An import of a crate outside the workspace is not followed: the crate
/// is not part of the workspace the gate reads, so the gate cannot say
/// what its constant holds.
fn content_length_imported_field_constants(
    syntax: &syn::File,
    workspace_constants: &[String],
    crate_names: &[String],
) -> Vec<String> {
    let mut names = Vec::new();
    for imported in content_length_imported_constants(syntax) {
        if !content_length_import_is_internal(&imported.root, crate_names) {
            continue;
        }
        if !workspace_constants.contains(&imported.source) {
            continue;
        }
        if !names.contains(&imported.local) {
            names.push(imported.local);
        }
    }
    names
}

/// Whether an import names something of the workspace.
///
/// An import that starts with `crate`, `self` or `super` names something
/// of the crate the file belongs to, and an import that starts with the
/// name of a crate of the workspace names something of that crate.
fn content_length_import_is_internal(root: &str, crate_names: &[String]) -> bool {
    matches!(root, "crate" | "self" | "super") || crate_names.iter().any(|name| name == root)
}

/// A constant a file imports.
struct ImportedConstant {
    /// The name the import gives the constant in this file.
    local: String,
    /// The name the constant is defined with.
    source: String,
    /// The first segment of the path the import names.
    root: String,
}

/// The constants a file imports.
fn content_length_imported_constants(syntax: &syn::File) -> Vec<ImportedConstant> {
    let mut names = Vec::new();
    collect_imported_constants_of_items(&syntax.items, &mut names);
    names
}

/// The constants the imports of a list of items bring into the file.
///
/// A module's own imports and the imports of the modules inside it are
/// read, so a nested module's import is followed as well.
fn collect_imported_constants_of_items(items: &[syn::Item], names: &mut Vec<ImportedConstant>) {
    for item in items {
        match item {
            syn::Item::Use(item) => {
                let mut prefix = Vec::new();
                collect_imported_constants(&item.tree, &mut prefix, names);
            }
            syn::Item::Mod(item) => {
                if let Some((_, items)) = &item.content {
                    collect_imported_constants_of_items(items, names);
                }
            }
            _ => {}
        }
    }
}

/// The constants one import brings into the file.
///
/// The path the import names is read segment by segment, so the first
/// segment says whether the import names something of the workspace and
/// the last segment says which constant is imported. An import that
/// renames the constant brings it in under the name it is renamed to.
fn collect_imported_constants(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    names: &mut Vec<ImportedConstant>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_imported_constants(&path.tree, prefix, names);
            prefix.pop();
        }
        syn::UseTree::Name(name) => names.push(ImportedConstant {
            local: name.ident.to_string(),
            source: name.ident.to_string(),
            root: prefix.first().cloned().unwrap_or_default(),
        }),
        syn::UseTree::Rename(rename) => names.push(ImportedConstant {
            local: rename.rename.to_string(),
            source: rename.ident.to_string(),
            root: prefix.first().cloned().unwrap_or_default(),
        }),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                let mut item_prefix = prefix.clone();
                collect_imported_constants(tree, &mut item_prefix, names);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

/// The names a file holds the field's name under in a constant or a static.
///
/// A site that keeps the field's name in a constant of its own and reads
/// the field through that constant reads the declaration, so the gate
/// follows the name the constant is held under the way it follows a local
/// binding of the field's name.
fn content_length_field_name_constants(syntax: &syn::File) -> Vec<String> {
    content_length_constants(syntax)
        .into_iter()
        .filter(|(_, holds)| *holds)
        .map(|(name, _)| name)
        .collect()
}

/// The names the constants and the statics of a file are defined with, and
/// whether each of them holds the field's name.
fn content_length_constants(syntax: &syn::File) -> Vec<(String, bool)> {
    let mut names = Vec::new();
    for item in &syntax.items {
        collect_constants(item, &mut names);
    }
    names
}

/// The names the constants and the statics of an item are defined with, and
/// whether each of them holds the field's name.
///
/// A constant or a static whose value is the field's name names the field,
/// so the gate follows the name it is held under. A constant whose value is
/// something else names something else, so the gate knows that the name is
/// not the field's when another file defines it as well.
fn collect_constants(item: &syn::Item, names: &mut Vec<(String, bool)>) {
    let (ident, value) = match item {
        syn::Item::Const(item) => (&item.ident, &item.expr),
        syn::Item::Static(item) => (&item.ident, &item.expr),
        syn::Item::Mod(item) => {
            if let Some((_, items)) = &item.content {
                for inner in items {
                    collect_constants(inner, names);
                }
            }
            return;
        }
        _ => return,
    };
    names.push((ident.to_string(), names_content_length_field(value)));
}

/// What a function says about the declared Content-Length.
#[derive(Default)]
struct ContentLengthReaderFacts {
    /// The function reads the field's value.
    reads_field: bool,
    /// The function reads the field's value through a header map.
    ///
    /// This is the read itself, without the parse that may follow it: a
    /// site that reads the value and hands it to another function reads
    /// the declaration on its own just as a site that parses it does.
    reads_value: bool,
    /// The function selects the field's own entry.
    ///
    /// A comparison of a header's name with the field's name is what
    /// finds the field's own entry in a list of header entries, so it is
    /// the first half of a read of the value. A comparison that decides
    /// about the field instead does not find the entry: a comparison
    /// that is not equal, and a comparison whose branch skips the
    /// entry, decide about the field.
    selects_field: bool,
    /// The function takes the value of a header entry.
    ///
    /// A header entry is a pair of a name and a value, so a closure that
    /// receives such a pair and uses its second element takes that
    /// entry's value.
    takes_entry_value: bool,
    /// The function takes the second element of a pair.
    ///
    /// A header entry that is a pair holds its value as the pair's
    /// second element, so taking that element takes the entry's value.
    takes_pair_element: bool,
    /// The names a header's name is compared under, in a comparison that
    /// selects the field's own entry.
    ///
    /// The name a site compares with the field's name is the name of the
    /// entry it found, and the entry's value is taken under a name of its
    /// own, so the two names tell whether the value belongs to the entry
    /// the site found.
    selected_bases: Vec<String>,
    /// The names a `value` member is taken under.
    ///
    /// A header entry that is a struct holds its value under `value`, so
    /// a site that takes that member takes the entry's value.
    value_bases: Vec<String>,
    /// The members the function reads of a header entry.
    ///
    /// A header entry that is a struct holds its name and its value
    /// under members of its own, so the member the function reads tells
    /// whether it reads the entry's name or its value. The member is
    /// read under the name of the entry it belongs to.
    member_reads: Vec<(String, String)>,
    /// The members the field's own entry holds its name under.
    ///
    /// The name of the entry the comparison found is held under a
    /// member of its own, so the member tells which member of the entry
    /// is the name and which members are the value.
    name_members: Vec<String>,
    /// The names the field's own entry is held under.
    ///
    /// The entry the comparison found travels: a binding of it holds it
    /// under a name of its own, a closure that receives it from the
    /// search that found it holds it under the name the closure binds,
    /// and a helper that found it hands it to its caller, which binds
    /// the result. The value the site takes under one of these names is
    /// the field's value, so the rule follows the entry rather than the
    /// name the site happened to give it.
    field_entry_names: Vec<String>,
    /// The names a binding holds an entry under, and the entry it holds.
    ///
    /// A binding of the entry the comparison found holds that entry
    /// under a name of its own, so the names tell whether the value the
    /// site takes is the field's value.
    entry_copies: Vec<(String, String)>,
    /// The names a call's result is bound under, and the helper the call
    /// names.
    ///
    /// A helper that finds the field's own entry hands that entry to its
    /// caller, so the names tell whether a binding holds the entry the
    /// comparison found.
    finder_calls: Vec<(String, String)>,
    /// The names a call takes the entry's value under, and the helper the
    /// call names.
    ///
    /// A helper that finds the field's own entry hands that entry to its
    /// caller, so a caller that takes the value out of the result - by
    /// destructuring the pair - takes the field's value.
    finder_value_calls: Vec<(String, String)>,
    /// The helpers whose result a closure takes the entry's value of.
    ///
    /// A helper that finds the field's own entry hands that entry to its
    /// caller, so a closure that receives the result and takes the value
    /// out of it takes the field's value.
    finder_value_closures: Vec<String>,
    /// The names a pair's second element is taken under.
    ///
    /// A header entry that is a pair holds its value as the pair's
    /// second element, so the names tell whether the element that is
    /// taken is the field's own.
    pair_element_bases: Vec<String>,
    /// The function takes the value of an entry it bound by a pattern.
    ///
    /// A header entry is a pair of a name and a value, so a pattern that
    /// binds the pair's two elements binds the entry's name and the
    /// entry's value. The scope that binds them decides whether the
    /// value is the field's own: the name the scope compares with the
    /// field's name must be the name the pattern bound, and the value
    /// the pattern bound must be used in that scope.
    takes_pattern_entry_value: bool,
    /// The names the function's expressions use.
    ///
    /// A name that appears as an expression is a name the function
    /// reads, so the names tell whether a name a pattern bound is used.
    used_names: Vec<String>,
    /// The names a header entry's value is bound under.
    ///
    /// A pattern that binds an entry's pair binds its value under a name
    /// of its own, so the names tell whether a branch that skips the
    /// entry takes the value it guards.
    bound_value_names: Vec<String>,
    /// Whether a comparison in the current condition skips the entry.
    ///
    /// A comparison that guards a branch that skips the entry decides
    /// about the field rather than finding its entry, so the comparison
    /// reads the other way round: an equal comparison excludes the entry
    /// and a comparison that is not equal selects it.
    skipping_condition: bool,
    /// Whether the current condition holds more than the comparison.
    ///
    /// The rule reads a branch as skipping the entry only when the
    /// condition holds nothing but the comparison, so a comparison that
    /// stands inside a condition that holds more cannot be read as
    /// deciding about the field: the code after the branch may still
    /// hold the field's own entry, so the comparison finds it.
    compound_condition: bool,
    /// The function turns text into a number.
    parses_integer: bool,
    /// The function calls the owner.
    calls_owner: bool,
    /// The function is test code.
    ///
    /// Test code observes the field's value to assert on what the proxy
    /// put on the wire; it does not decide what the proxy does.
    test_code: bool,
    /// The names the function binds the field's name to, and the pieces
    /// of text it binds to a name of its own.
    ///
    /// A site that binds the field's name to a name of its own and reads
    /// the field through that name reads the declaration, so the gate
    /// follows the binding. A site that binds a piece of text it wrote
    /// out holds that text, so a name built from that piece is a name
    /// the gate can read.
    field_names: FieldNames,
    /// The names a header entry's name is bound under, and the entry each
    /// of them stands for.
    ///
    /// A site that binds a header entry's name to a name of its own and
    /// compares that name with the field's name compares the entry's
    /// name, so the binding stands for the entry the name came from.
    entry_name_aliases: Vec<(String, String)>,
    /// The names a loop binds a header entry's name to.
    ///
    /// A loop that walks a list of header entries binds the entry's name
    /// to a name of its own, so a binding of that name stands for the
    /// entry's name as well.
    entry_names: Vec<String>,
}

/// The names a function binds the field's name to, and the pieces of
/// text it binds to a name of its own.
///
/// A binding of the field's name stands for the field itself. A binding
/// of a piece of text holds that text, and the site wrote it out, so a
/// name the site builds from that piece is a name the gate can read.
#[derive(Default, Clone)]
struct FieldNames {
    /// The names that stand for the field's name.
    aliases: Vec<String>,
    /// The names that stand for a piece of text, and the text each of
    /// them holds.
    texts: Vec<(String, String)>,
}

impl FieldNames {
    /// The text a name holds, when the name stands for a piece of text
    /// the site wrote out.
    fn text_of(&self, name: &str) -> Option<&str> {
        self.texts
            .iter()
            .find(|(bound, _)| bound == name)
            .map(|(_, text)| text.as_str())
    }
}

/// The collector of the functions of a file.
///
/// Every function of the file is recorded on its own, so a reader in a
/// function is named by that function rather than by the one it sits in.
#[derive(Default)]
struct ContentLengthFunctionCollector {
    facts: Vec<(String, ContentLengthReaderFacts)>,
    /// How many `#[cfg(test)]` modules the collector is inside.
    test_depth: usize,
    /// Whether the file itself holds test code.
    test_file: bool,
    /// The names the file holds the field's name under in a constant or a
    /// static.
    field_name_constants: Vec<String>,
    /// The names the file imports the field's name under.
    field_name_imports: Vec<String>,
    /// The names the file imports a constant of another file under.
    ///
    /// A constant of another file that holds the field's name names the
    /// field in the file that imports it, so the name the import gives it
    /// is a name of the field.
    imported_constants: Vec<String>,
}

impl Visit<'_> for ContentLengthFunctionCollector {
    fn visit_item_fn(&mut self, node: &syn::ItemFn) {
        self.record(node.sig.ident.to_string(), &node.block);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &syn::ImplItemFn) {
        self.record(node.sig.ident.to_string(), &node.block);
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_trait_item_fn(&mut self, node: &syn::TraitItemFn) {
        if let Some(block) = &node.default {
            self.record(node.sig.ident.to_string(), block);
        }
        syn::visit::visit_trait_item_fn(self, node);
    }

    fn visit_item_mod(&mut self, node: &syn::ItemMod) {
        // A module marked `#[cfg(test)]` holds test code, so the
        // functions in it are test code as well.
        if has_cfg_test(&node.attrs) {
            self.test_depth += 1;
            syn::visit::visit_item_mod(self, node);
            self.test_depth -= 1;
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }
}

impl ContentLengthFunctionCollector {
    /// The facts of one function, taken from its body.
    fn record(&mut self, name: String, block: &syn::Block) {
        let mut aliases = self.field_name_constants.clone();
        aliases.extend(self.field_name_imports.iter().cloned());
        aliases.extend(self.imported_constants.iter().cloned());
        let mut facts = ContentLengthReaderFacts {
            test_code: self.test_file || self.test_depth > 0,
            field_names: FieldNames {
                aliases,
                ..FieldNames::default()
            },
            ..ContentLengthReaderFacts::default()
        };
        facts.visit_block(block);
        // A closure that receives the entry a search found holds that
        // entry, so the value the site takes under the name the closure
        // binds is the field's value.
        let mut chains = ContentLengthEntryChainCollector {
            field_names: facts.field_names.clone(),
            ..ContentLengthEntryChainCollector::default()
        };
        chains.visit_block(block);
        for entry_name in chains.names {
            if !facts.field_entry_names.contains(&entry_name) {
                facts.field_entry_names.push(entry_name);
            }
        }
        self.facts.push((name, facts));
    }
}

impl Visit<'_> for ContentLengthReaderFacts {
    fn visit_local(&mut self, node: &syn::Local) {
        // A binding of the field's name to a name of its own names the
        // field as well, so a site that reads the field through the
        // binding reads the declaration.
        if let Some(initializer) = &node.init
            && names_content_length_field_or_alias(&initializer.expr, &self.field_names)
            && let syn::Pat::Ident(binding) = &node.pat
            && binding.subpat.is_none()
        {
            self.field_names.aliases.push(binding.ident.to_string());
        }
        // A binding of a piece of text the site wrote out holds that
        // text, so a name the site builds from it is a name the gate
        // can read.
        if let Some(initializer) = &node.init
            && let syn::Pat::Ident(binding) = &node.pat
            && binding.subpat.is_none()
            && let Some(text) = built_text_of(&initializer.expr, &self.field_names)
        {
            self.field_names
                .texts
                .push((binding.ident.to_string(), text));
        }
        // A binding of the entry the comparison found holds that entry
        // under a name of its own, so the value the site takes under
        // that name is the field's value.
        if let Some(initializer) = &node.init
            && let syn::Pat::Ident(binding) = &node.pat
            && binding.subpat.is_none()
            && let Some(base) = expression_base_name(&initializer.expr)
        {
            self.entry_copies.push((binding.ident.to_string(), base));
        }
        // A binding of the entry a search found holds that entry under a
        // name of its own as well, so the value the site takes under
        // that name is the field's value.
        if let Some(initializer) = &node.init
            && search_entry_name(&initializer.expr, &self.field_names).is_some()
        {
            let names = pattern_binding_names(&node.pat);
            if names.len() == 1 {
                self.field_entry_names.push(names[0].clone());
            }
        }
        // A call that names a helper hands the helper's result to the
        // binding, so a helper that finds the field's own entry hands
        // that entry over.
        if let Some(initializer) = &node.init
            && let syn::Pat::Ident(binding) = &node.pat
            && binding.subpat.is_none()
            && let syn::Expr::Call(call) = unwrapped_expr(&initializer.expr)
            && let syn::Expr::Path(path) = &*call.func
            && path.qself.is_none()
            && let Some(callee) = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
        {
            self.finder_calls.push((binding.ident.to_string(), callee));
        }
        // A caller that takes the value out of the result the helper
        // hands it takes the entry's value, so the name the value is
        // bound under is recorded with the helper the call names.
        if let Some(initializer) = &node.init
            && let syn::Pat::Tuple(tuple) = &node.pat
            && tuple.elems.len() == 2
            && let syn::Pat::Ident(value) = &tuple.elems[1]
            && value.subpat.is_none()
            && let syn::Expr::Call(call) = unwrapped_expr(&initializer.expr)
            && let syn::Expr::Path(path) = &*call.func
            && path.qself.is_none()
            && let Some(callee) = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
        {
            self.finder_value_calls
                .push((value.ident.to_string(), callee));
        }
        // A binding of a header entry's name stands for the entry the
        // name came from, so a comparison under the binding compares
        // that entry's name and finds that entry.
        if let Some(initializer) = &node.init
            && let syn::Pat::Ident(binding) = &node.pat
            && binding.subpat.is_none()
            && let Some(target) = entry_name_alias_target(
                &initializer.expr,
                &self.entry_names,
                &self.entry_name_aliases,
            )
        {
            self.entry_name_aliases
                .push((binding.ident.to_string(), target));
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &syn::ExprMethodCall) {
        // A closure that receives the result of a call to a helper and
        // takes the value out of it takes the entry's value the helper
        // found, so the helper is recorded.
        if let Some(callee) = call_helper_name(&node.receiver)
            && node.args.iter().any(|argument| match argument {
                syn::Expr::Closure(closure) => closure_takes_entry_value(closure),
                _ => false,
            })
        {
            self.finder_value_closures.push(callee);
        }
        let method = node.method.to_string();
        let names_field = node
            .args
            .iter()
            .any(|argument| names_content_length_field_or_alias(argument, &self.field_names));
        if (CONTENT_LENGTH_READ_METHODS.contains(&method.as_str()) || method.starts_with("eq"))
            && names_field
        {
            self.reads_field = true;
        }
        // A comparison of a header's name with the field's name finds the
        // field's own entry, whether the field is named by the argument or
        // by the receiver.
        if method.starts_with("eq")
            && (names_field
                || names_content_length_field_or_alias(&node.receiver, &self.field_names))
        {
            // The name of the entry the site found is the other side of
            // the comparison.
            let compared = if names_field {
                &node.receiver
            } else {
                node.args.first().unwrap_or(&node.receiver)
            };
            self.record_selection(true, compared);
        }
        // A read of the field's value through the header map is the read
        // itself: whether the value is turned into a number here or
        // handed to another function, the site reads the declaration.
        if CONTENT_LENGTH_READ_METHODS.contains(&method.as_str()) && names_field {
            self.reads_value = true;
        }
        if method == "parse" {
            match &node.turbofish {
                // A parse that names its type turns text into a number when
                // the type is an integer.
                Some(turbofish) if names_integer_type(&turbofish.args) => {
                    self.parses_integer = true;
                }
                // A parse that leaves its type to be inferred turns text into
                // a number as well. The gate cannot tell what the number
                // is, and the field's value is a length, so it reads the
                // parse as a length.
                None => self.parses_integer = true,
                _ => {}
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            let segments = &path.path.segments;
            if let Some(last) = segments.last() {
                let names_integer = match &last.arguments {
                    PathArguments::AngleBracketed(arguments) => {
                        last.ident == "parse" && names_integer_type(&arguments.args)
                    }
                    _ => false,
                };
                let from_integer = last.ident == "from_str"
                    && segments
                        .iter()
                        .rev()
                        .nth(1)
                        .is_some_and(|segment| is_integer_type(&segment.ident.to_string()));
                if names_integer || from_integer {
                    self.parses_integer = true;
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_index(&mut self, node: &syn::ExprIndex) {
        // An indexed read of the field's value is a read of it as well.
        if names_content_length_field_or_alias(&node.index, &self.field_names) {
            self.reads_field = true;
            self.reads_value = true;
        }
        syn::visit::visit_expr_index(self, node);
    }

    fn visit_expr_binary(&mut self, node: &syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_))
            && (names_content_length_field_or_alias(&node.left, &self.field_names)
                || names_content_length_field_or_alias(&node.right, &self.field_names))
        {
            self.reads_field = true;
            // The name of the entry the site found is the other side of
            // the comparison.
            let compared = if names_content_length_field_or_alias(&node.left, &self.field_names) {
                &node.right
            } else {
                &node.left
            };
            self.record_selection(matches!(node.op, syn::BinOp::Eq(_)), compared);
        }
        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_expr_path(&mut self, node: &syn::ExprPath) {
        if is_content_length_owner_call(&node.path) {
            self.calls_owner = true;
        }
        // A single-segment path is a name the expression reads.
        if node.path.segments.len() == 1 {
            self.used_names
                .push(node.path.segments[0].ident.to_string());
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_if(&mut self, node: &syn::ExprIf) {
        // A comparison that guards a branch that skips the entry decides
        // about the field rather than finding its entry, so the
        // comparison in the condition reads the other way round. A
        // condition that holds more than the comparison cannot be read
        // that way: the rule cannot say which part of it skips the
        // entry, so the comparison in it still finds the field's own
        // entry, and the code after the branch may hold it.
        let comparison_only = is_field_comparison(&node.cond, &self.field_names);
        let skipping = comparison_only && self.branch_skips_the_entry(&node.then_branch);
        let saved = self.skipping_condition;
        let saved_compound = self.compound_condition;
        self.skipping_condition = saved || skipping;
        self.compound_condition = !comparison_only;
        self.visit_expr(&node.cond);
        self.skipping_condition = saved;
        self.compound_condition = saved_compound;
        self.visit_block(&node.then_branch);
        if let Some((_, else_branch)) = &node.else_branch {
            self.visit_expr(else_branch);
        }
    }

    fn visit_expr_for_loop(&mut self, node: &syn::ExprForLoop) {
        // A loop that walks a list of header entries and binds an
        // entry's pair reads the field's value when it compares the
        // name it bound with the field's name and uses the value it
        // bound.
        if let Some((name, value)) = pair_binding_names(&node.pat) {
            let mut scope = ContentLengthReaderFacts {
                test_code: self.test_code,
                bound_value_names: vec![value.clone()],
                field_names: self.field_names.clone(),
                entry_names: vec![name.clone()],
                ..ContentLengthReaderFacts::default()
            };
            scope.visit_block(&node.body);
            let selects_its_own = scope.selected_bases.contains(&name);
            let uses_its_own = scope.used_names.contains(&value);
            if selects_its_own && uses_its_own {
                self.takes_pattern_entry_value = true;
            }
            // The name the pattern bound the value under is a name the
            // function reads, so a branch that takes it reads the value
            // and does not skip the entry.
            self.bound_value_names.push(value);
        }
        syn::visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_closure(&mut self, node: &syn::ExprClosure) {
        if closure_takes_entry_value(node) {
            self.takes_entry_value = true;
        }
        syn::visit::visit_expr_closure(self, node);
    }

    fn visit_expr_field(&mut self, node: &syn::ExprField) {
        // The value of a header entry is held under a member: a struct
        // entry holds it under `value`, and a pair holds it as its second
        // element.
        match &node.member {
            syn::Member::Named(ident) => {
                if let Some(base) = expression_base_name(&node.base) {
                    // A member of the entry the comparison found is the
                    // entry's value unless it is the member that holds
                    // the name, so the gate reads every member of the
                    // entry and not only the one it knows by name.
                    self.member_reads.push((base.clone(), ident.to_string()));
                    if ident == "value" {
                        self.value_bases.push(base);
                    }
                }
            }
            syn::Member::Unnamed(index) if index.index == 1 => {
                self.takes_pair_element = true;
                if let Some(base) = expression_base_name(&node.base) {
                    self.pair_element_bases.push(base);
                }
            }
            _ => {}
        }
        syn::visit::visit_expr_field(self, node);
    }

    fn visit_item_fn(&mut self, _node: &syn::ItemFn) {
        // A function inside a function is recorded on its own, so the
        // enclosing function is not charged with its body.
    }

    fn visit_impl_item_fn(&mut self, _node: &syn::ImplItemFn) {}

    fn visit_trait_item_fn(&mut self, _node: &syn::TraitItemFn) {}
}

/// The facts of a function, and what they add up to.
impl ContentLengthReaderFacts {
    /// The read of the field's value the facts add up to.
    ///
    /// A site that finds the field's own entry by comparing a header's
    /// name with the field's name and then takes that entry's value
    /// reads the declaration's value: the owner is the only reader.
    /// The value is taken by a closure that receives the entry as a
    /// pair, by the second element of the pair, by the `value` member
    /// of the entry the comparison found, or by a pattern that binds the
    /// entry's pair. A comparison that decides about the field rather
    /// than finding its entry does not find the value either, so a site
    /// that skips the field and takes another header's value is not a
    /// reader.
    ///
    /// The entry travels, so the value may be taken under another name
    /// than the one the comparison used: a binding of the entry, a
    /// closure that receives it from the search that found it, and a
    /// helper that found it and hands it to its caller all hold the
    /// field's own entry. The value the site takes under one of those
    /// names is the field's value, so the rule follows the entry rather
    /// than the name the site happened to give it.
    fn finish(&mut self) {
        self.follow_the_entry();
        let same_entry = self
            .selected_bases
            .iter()
            .any(|base| self.value_bases.iter().any(|value| value == base));
        let from_the_entry = self.field_entry_names.iter().any(|name| {
            self.value_bases.iter().any(|value| value == name)
                || self.pair_element_bases.iter().any(|value| value == name)
        });
        // A member of the entry the comparison found is the entry's
        // value unless it is the member that holds the name, so a site
        // that takes the value under a member the gate has not seen
        // before reads the declaration's value as well.
        let from_a_member = self.member_reads.iter().any(|(base, member)| {
            !self.member_is_the_name(member)
                && (self.selected_bases.contains(base) || self.field_entry_names.contains(base))
        });
        if (self.selects_field
            && (self.takes_entry_value
                || self.takes_pair_element
                || same_entry
                || self.takes_pattern_entry_value))
            || from_the_entry
            || from_a_member
        {
            self.reads_value = true;
        }
    }

    /// Whether a member of a header entry holds its name rather than its
    /// value.
    ///
    /// A header entry holds its name under a member of its own, and the
    /// comparison that finds the entry reads that member, so the member
    /// the comparison used is the name. The workspace holds a header
    /// entry's name under a member named `name`, so that member is the
    /// name as well.
    fn member_is_the_name(&self, member: &str) -> bool {
        member == "name" || self.name_members.iter().any(|name| name == member)
    }

    /// The names the entry the comparison found travels under.
    ///
    /// A binding of the entry holds it under a name of its own, so the
    /// value the site takes under that name is the field's value.
    fn follow_the_entry(&mut self) {
        let mut changed = true;
        while changed {
            changed = false;
            for (alias, base) in self.entry_copies.clone() {
                let known =
                    self.selected_bases.contains(&base) || self.field_entry_names.contains(&base);
                if known && !self.field_entry_names.contains(&alias) {
                    self.field_entry_names.push(alias);
                    changed = true;
                }
            }
        }
    }

    /// Records a comparison of a header's name with the field's name.
    ///
    /// A comparison finds the field's own entry, so it selects it. A
    /// comparison that guards a branch that skips the entry decides
    /// about the field instead, and the two comparisons read the other
    /// way round: an equal comparison excludes the entry, and a
    /// comparison that is not equal selects it.
    fn record_selection(&mut self, is_equal: bool, compared: &syn::Expr) {
        if self.compound_condition || is_equal != self.skipping_condition {
            self.selects_field = true;
            if let Some(base) = compared_entry_base(compared) {
                self.selected_bases.push(self.resolve_entry_alias(&base));
            }
            // The name of the entry the comparison found is held under a
            // member of its own, so the member tells which member of the
            // entry is the name and which members are the value.
            if let Some(member) = compared_name_member(compared)
                && !self.name_members.contains(&member)
            {
                self.name_members.push(member);
            }
        }
    }

    /// The entry a compared name stands for.
    ///
    /// A site that binds a header entry's name to a name of its own
    /// compares that name, so the comparison finds the entry the name
    /// came from and the value the site takes is that entry's value.
    fn resolve_entry_alias(&self, base: &str) -> String {
        resolve_alias_chain(base, &self.entry_name_aliases)
    }

    /// Whether a branch skips the entry it guards.
    ///
    /// A branch that leaves the iteration without taking the value skips
    /// the entry: the site decided about the field and moves on. A branch
    /// that takes the value reads it, so it does not skip.
    fn branch_skips_the_entry(&self, block: &syn::Block) -> bool {
        if !block_skips_entry(block) {
            return false;
        }
        !self.branch_takes_the_value(block)
    }

    /// Whether a branch takes the value of the entry it guards.
    fn branch_takes_the_value(&self, block: &syn::Block) -> bool {
        let mut scope = ContentLengthReaderFacts {
            test_code: self.test_code,
            field_names: self.field_names.clone(),
            ..ContentLengthReaderFacts::default()
        };
        scope.visit_block(block);
        if !scope.value_bases.is_empty() || scope.takes_pair_element || scope.takes_entry_value {
            return true;
        }
        scope
            .used_names
            .iter()
            .any(|name| self.bound_value_names.contains(name))
    }
}

/// The collector of the closures that receive the field's own entry.
///
/// A search compares a header's name with the field's name, so the
/// entry it finds is the field's own entry, and a closure that receives
/// the entry from that search receives the field's own entry. The value
/// such a closure takes is the field's value.
#[derive(Default)]
struct ContentLengthEntryChainCollector {
    /// The names the file holds the field's name under.
    field_names: FieldNames,
    /// The names the entry is held under.
    names: Vec<String>,
}

impl Visit<'_> for ContentLengthEntryChainCollector {
    fn visit_expr_method_call(&mut self, node: &syn::ExprMethodCall) {
        // A closure that receives the entry a search found holds that
        // entry, so the value it takes is the field's value.
        if let Some(param) = closure_param_name(node.args.first())
            && search_entry_name(&node.receiver, &self.field_names).is_some()
        {
            self.names.push(param);
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// The expression a `?` or a parenthesis stands for.
///
/// A call that a site writes with a `?` is the call itself, so the rule
/// sees the helper it names.
fn unwrapped_expr(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Try(try_expr) => unwrapped_expr(&try_expr.expr),
        syn::Expr::Paren(paren) => unwrapped_expr(&paren.expr),
        syn::Expr::Group(group) => unwrapped_expr(&group.expr),
        _ => expr,
    }
}

/// The name a closure binds, when the closure takes one thing.
fn closure_param_name(argument: Option<&syn::Expr>) -> Option<String> {
    let Some(syn::Expr::Closure(closure)) = argument else {
        return None;
    };
    if closure.inputs.len() != 1 {
        return None;
    }
    let syn::Pat::Ident(binding) = &closure.inputs[0] else {
        return None;
    };
    if binding.subpat.is_some() {
        return None;
    }
    Some(binding.ident.to_string())
}

/// The name a search binds the entry it finds to.
///
/// A search compares a header's name with the field's name, so the
/// entry it finds is the field's own entry, and the closure the search
/// takes binds that entry under a name of its own.
fn search_entry_name(expr: &syn::Expr, names: &FieldNames) -> Option<String> {
    let syn::Expr::MethodCall(call) = unwrapped_expr(expr) else {
        return None;
    };
    if !matches!(call.method.to_string().as_str(), "find" | "find_map") {
        return None;
    }
    let argument = call.args.first()?;
    let syn::Expr::Closure(closure) = argument else {
        return None;
    };
    let name = closure_param_name(Some(argument))?;
    let mut scope = ContentLengthReaderFacts {
        field_names: names.clone(),
        ..ContentLengthReaderFacts::default()
    };
    scope.visit_expr(&closure.body);
    scope.selects_field.then_some(name)
}

/// The names a pattern binds.
fn pattern_binding_names(pat: &syn::Pat) -> Vec<String> {
    let mut names = Vec::new();
    collect_pattern_binding_names(pat, &mut names);
    names
}

/// The names a pattern binds, collected.
fn collect_pattern_binding_names(pat: &syn::Pat, names: &mut Vec<String>) {
    match pat {
        syn::Pat::Ident(binding) => {
            if binding.subpat.is_none() {
                names.push(binding.ident.to_string());
            }
        }
        syn::Pat::Tuple(tuple) => {
            for element in &tuple.elems {
                collect_pattern_binding_names(element, names);
            }
        }
        syn::Pat::TupleStruct(tuple) => {
            for element in &tuple.elems {
                collect_pattern_binding_names(element, names);
            }
        }
        syn::Pat::Struct(structure) => {
            for field in &structure.fields {
                collect_pattern_binding_names(&field.pat, names);
            }
        }
        syn::Pat::Reference(reference) => collect_pattern_binding_names(&reference.pat, names),
        _ => {}
    }
}

/// The names a header entry's pair is bound under.
///
/// A header entry is a pair of a name and a value, so a pattern that
/// binds the pair's two elements binds the entry's name and the entry's
/// value. The first element is the name and the second is the value,
/// because that is the order a header entry is written in.
fn pair_binding_names(pat: &syn::Pat) -> Option<(String, String)> {
    let syn::Pat::Tuple(tuple) = pat else {
        return None;
    };
    if tuple.elems.len() != 2 {
        return None;
    }
    let syn::Pat::Ident(name) = &tuple.elems[0] else {
        return None;
    };
    let syn::Pat::Ident(value) = &tuple.elems[1] else {
        return None;
    };
    if name.subpat.is_some() || value.subpat.is_some() {
        return None;
    }
    Some((name.ident.to_string(), value.ident.to_string()))
}

/// Whether a condition is a comparison of a header's name with the
/// field's name.
///
/// The rule reads the comparison in a condition the other way round when
/// the branch it guards skips the entry, and it can only say that about a
/// condition that holds the comparison and nothing else.
fn is_field_comparison(expr: &syn::Expr, names: &FieldNames) -> bool {
    match expr {
        syn::Expr::Paren(paren) => is_field_comparison(&paren.expr, names),
        syn::Expr::Binary(binary) => {
            matches!(binary.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_))
                && (names_content_length_field_or_alias(&binary.left, names)
                    || names_content_length_field_or_alias(&binary.right, names))
        }
        syn::Expr::MethodCall(call) => {
            call.method.to_string().starts_with("eq")
                && (call
                    .args
                    .iter()
                    .any(|argument| names_content_length_field_or_alias(argument, names))
                    || names_content_length_field_or_alias(&call.receiver, names))
        }
        _ => false,
    }
}

/// Whether a block leaves the iteration it guards.
///
/// A `continue` or a `break` leaves the iteration. A `continue` or a
/// `break` of a loop inside the block belongs to that loop, so the
/// search does not enter a nested loop or a closure.
fn block_skips_entry(block: &syn::Block) -> bool {
    let mut finder = SkipFinder { skips: false };
    finder.visit_block(block);
    finder.skips
}

/// The search for a block that leaves its iteration.
struct SkipFinder {
    /// Whether the block leaves the iteration.
    skips: bool,
}

impl Visit<'_> for SkipFinder {
    fn visit_expr_break(&mut self, _node: &syn::ExprBreak) {
        self.skips = true;
    }

    fn visit_expr_continue(&mut self, _node: &syn::ExprContinue) {
        self.skips = true;
    }

    fn visit_expr_closure(&mut self, _node: &syn::ExprClosure) {}

    fn visit_expr_for_loop(&mut self, _node: &syn::ExprForLoop) {}

    fn visit_expr_while(&mut self, _node: &syn::ExprWhile) {}

    fn visit_expr_loop(&mut self, _node: &syn::ExprLoop) {}
}

/// Whether an expression names the Content-Length field.
///
/// The field is named by the constant the http crate spells it with and
/// by the field's name as text. A site may reach either of those through
/// a reference, through the constant's text or through a name built from
/// the text, so the question asks about the expression the site reads the
/// field with and not only about the two spellings themselves: a read of
/// the field through `&CONTENT_LENGTH`, through `CONTENT_LENGTH.as_str()`
/// or through a name built from `"content-length"` names the field as
/// well.
///
/// A name the site builds at runtime from the field's text names the
/// field as well: the gate reads the text the site writes out, so a name
/// built by a constructor or by a macro from the field's own text names
/// the field.
fn names_content_length_field(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == CONTENT_LENGTH_CONSTANT),
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Str(value) => value.value().eq_ignore_ascii_case(CONTENT_LENGTH_FIELD),
            syn::Lit::ByteStr(value) => value
                .value()
                .eq_ignore_ascii_case(CONTENT_LENGTH_FIELD.as_bytes()),
            _ => false,
        },
        // A reference to the field's name names the field.
        syn::Expr::Reference(reference) => names_content_length_field(&reference.expr),
        // The constant's text names the field.
        syn::Expr::MethodCall(call) => {
            (call.method == "as_str"
                || CONTENT_LENGTH_NAME_COPY_METHODS.contains(&call.method.to_string().as_str()))
                && names_content_length_field(&call.receiver)
        }
        // A name built from the field's text names the field.
        syn::Expr::Call(call) => {
            let builds_a_name = builds_a_name_at_runtime(call);
            builds_a_name && call.args.first().is_some_and(names_content_length_field)
        }
        // A name the site builds at runtime from the field's text names
        // the field as well.
        syn::Expr::Macro(mac) => macro_builds_content_length_field(&mac.mac),
        _ => false,
    }
}

/// Whether a call builds a name at runtime from text.
///
/// A name built by `from_static` is a name whatever the type is, and the
/// constructors the workspace can reach are named by their type and
/// their method, so a constructor of another type is not one of them.
fn builds_a_name_at_runtime(call: &syn::ExprCall) -> bool {
    let syn::Expr::Path(path) = &*call.func else {
        return false;
    };
    let idents: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    if idents.last().is_some_and(|last| last == "from_static") {
        return true;
    }
    let Some(first) = idents.len().checked_sub(2) else {
        return false;
    };
    let callee = format!(
        "{type_name}::{method}",
        type_name = idents[first],
        method = idents[first + 1]
    );
    CONTENT_LENGTH_NAME_BUILDERS.contains(&callee.as_str())
}

/// Whether a macro builds the field's name at runtime.
///
/// A site that builds the field's name with a macro and finds the field's
/// own entry with the built name reads the declaration, so the gate reads
/// the text the macro builds when the site writes that text out.
fn macro_builds_content_length_field(mac: &syn::Macro) -> bool {
    macro_built_text(mac, &FieldNames::default())
        .is_some_and(|text| text.eq_ignore_ascii_case(CONTENT_LENGTH_FIELD))
}

/// The text a macro builds, when the site wrote that text out.
///
/// The macro is named by its own name, so a macro that builds something
/// else is not one of them.
fn macro_built_text(mac: &syn::Macro, names: &FieldNames) -> Option<String> {
    let name = mac.path.segments.last()?.ident.to_string();
    let arguments = macro_arguments(mac)?;
    match name.as_str() {
        "concat" => concat_built_text(&arguments),
        "format" => format_built_text(&arguments, names),
        _ => None,
    }
}

/// The arguments a macro call holds.
fn macro_arguments(mac: &syn::Macro) -> Option<Vec<syn::Expr>> {
    let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
    let parsed = parser.parse2(mac.tokens.clone()).ok()?;
    Some(parsed.into_iter().collect())
}

/// The text a `concat!` builds, when the site writes that text out.
fn concat_built_text(arguments: &[syn::Expr]) -> Option<String> {
    let mut built = String::new();
    for argument in arguments {
        let syn::Expr::Lit(literal) = argument else {
            return None;
        };
        let syn::Lit::Str(text) = &literal.lit else {
            return None;
        };
        built.push_str(&text.value());
    }
    Some(built)
}

/// The text a `format!` builds, when the site writes that text out.
///
/// A format string that holds a placeholder takes the text of the
/// argument that fills it, so the built text is known when the argument
/// is written out as well. A placeholder that names a piece of text
/// takes the text of the binding it names, so a site that writes the
/// name out in pieces and binds those pieces names the field as well.
/// An argument that is not written out is known only when it names the
/// field itself, because then the built text is the field's name.
fn format_built_text(arguments: &[syn::Expr], names: &FieldNames) -> Option<String> {
    let syn::Expr::Lit(literal) = arguments.first()? else {
        return None;
    };
    let syn::Lit::Str(format) = &literal.lit else {
        return None;
    };
    let format = format.value();
    // The arguments the site writes out: the positional ones in the
    // order they are written and the named ones under their names.
    let mut positional: Vec<&syn::Expr> = Vec::new();
    let mut named: Vec<(String, &syn::Expr)> = Vec::new();
    for argument in arguments.get(1..)? {
        match argument {
            syn::Expr::Assign(assign) => {
                let syn::Expr::Path(path) = &*assign.left else {
                    return None;
                };
                let name = path.path.segments.last()?.ident.to_string();
                named.push((name, &assign.right));
            }
            argument => positional.push(argument),
        }
    }
    let mut filled = vec![false; positional.len()];
    let mut built = String::new();
    let mut characters = format.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            // A doubled brace is a brace the site wrote out.
            '{' if characters.peek() == Some(&'{') => {
                characters.next();
                built.push('{');
            }
            '}' if characters.peek() == Some(&'}') => {
                characters.next();
                built.push('}');
            }
            // A placeholder takes the text of the argument that fills
            // it.
            '{' => {
                let mut placeholder = String::new();
                for character in characters.by_ref() {
                    if character == '}' {
                        break;
                    }
                    placeholder.push(character);
                }
                let placeholder = placeholder
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let text = if placeholder.is_empty() {
                    let index = filled.iter().position(|filled| !*filled)?;
                    filled[index] = true;
                    argument_text(positional[index], names)?
                } else if let Ok(index) = placeholder.parse::<usize>() {
                    let argument = positional.get(index)?;
                    filled[index] = true;
                    argument_text(argument, names)?
                } else {
                    match named.iter().find(|(name, _)| *name == placeholder) {
                        Some((_, argument)) => argument_text(argument, names)?,
                        None => name_text(&placeholder, names)?,
                    }
                };
                built.push_str(&text);
            }
            character => built.push(character),
        }
    }
    // Every argument the site wrote out has to fill a placeholder, or
    // the built text is not the text the site writes out.
    if filled.iter().any(|filled| !*filled) {
        return None;
    }
    Some(built)
}

/// The text an argument of a format string holds.
///
/// An argument the site wrote out holds the text it was written out
/// as. An argument that is not written out holds the field's name when
/// it names the field, because then the built text is the field's name.
fn argument_text(argument: &syn::Expr, names: &FieldNames) -> Option<String> {
    if let Some(text) = built_text_of(argument, names) {
        return Some(text);
    }
    if names_content_length_field_or_alias(argument, names) {
        return Some(CONTENT_LENGTH_FIELD.to_string());
    }
    None
}

/// The text a name holds, when the name stands for a piece of text the
/// site wrote out or for the field's name.
fn name_text(name: &str, names: &FieldNames) -> Option<String> {
    if let Some(text) = names.text_of(name) {
        return Some(text.to_string());
    }
    names
        .aliases
        .iter()
        .any(|alias| alias == name)
        .then(|| CONTENT_LENGTH_FIELD.to_string())
}

/// The text an expression builds, when the site wrote that text out.
///
/// A piece of text the site wrote out stands under a name of its own
/// when the site binds it, so the gate reads a binding's text as well
/// as a literal's, and a name built from those pieces is a name the
/// gate can read.
fn built_text_of(expr: &syn::Expr, names: &FieldNames) -> Option<String> {
    match expr {
        syn::Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Str(text) => Some(text.value()),
            syn::Lit::ByteStr(text) => Some(String::from_utf8_lossy(&text.value()).into_owned()),
            _ => None,
        },
        // A reference to the text is the text.
        syn::Expr::Reference(reference) => built_text_of(&reference.expr, names),
        // A binding of the text holds it.
        syn::Expr::Path(path) => {
            let name = path.path.segments.last()?.ident.to_string();
            names.text_of(&name).map(str::to_string)
        }
        // A copy of the text is the text, and a copy that changes the
        // case holds the same letters.
        syn::Expr::MethodCall(call) => {
            let text = built_text_of(&call.receiver, names)?;
            match call.method.to_string().as_str() {
                "to_ascii_lowercase" => Some(text.to_ascii_lowercase()),
                "to_ascii_uppercase" => Some(text.to_ascii_uppercase()),
                "to_lowercase" => Some(text.to_lowercase()),
                "to_uppercase" => Some(text.to_uppercase()),
                method if CONTENT_LENGTH_NAME_COPY_METHODS.contains(&method) => Some(text),
                _ => None,
            }
        }
        // A name built by a constructor holds the text it was built
        // from.
        syn::Expr::Call(call) => {
            if !builds_a_name_at_runtime(call) {
                return None;
            }
            built_text_of(call.args.first()?, names)
        }
        // A name built by a macro holds the text the macro built.
        syn::Expr::Macro(mac) => macro_built_text(&mac.mac, names),
        // Two texts added together are one text.
        syn::Expr::Binary(binary) if matches!(binary.op, syn::BinOp::Add(_)) => {
            let left = built_text_of(&binary.left, names)?;
            let right = built_text_of(&binary.right, names)?;
            Some(left + &right)
        }
        _ => None,
    }
}

/// Whether an expression names the field, directly or through a binding
/// the function made of the field's name.
///
/// A site that binds the field's name to a name of its own and reads the
/// field through that name reads the declaration, so the binding names
/// the field as well.
fn names_content_length_field_or_alias(expr: &syn::Expr, names: &FieldNames) -> bool {
    names_content_length_field(expr)
        || alias_base_name(expr, names).is_some()
        || field_name_copy_base_name(expr, names).is_some()
        || built_text_of(expr, names)
            .is_some_and(|text| text.eq_ignore_ascii_case(CONTENT_LENGTH_FIELD))
}

/// The name a copy of a name the site holds stands under.
///
/// A site that copies a name it holds holds that name, so a copy of a
/// binding of the field's name names the field, and a read through the
/// copy reads the declaration. The copy is taken by a method that copies
/// text, the same methods the field's own rule follows, so a copy taken
/// another way is not a copy the gate reads.
fn field_name_copy_base_name(expr: &syn::Expr, names: &FieldNames) -> Option<String> {
    let syn::Expr::MethodCall(call) = expr else {
        return None;
    };
    let method = call.method.to_string();
    if method != "as_str" && !CONTENT_LENGTH_NAME_COPY_METHODS.contains(&method.as_str()) {
        return None;
    }
    alias_base_name(&call.receiver, names)
}

/// The name a binding of the field's name is used under.
///
/// A binding is a plain name the function bound the field's name to, so
/// the name is the one the binding introduced. The binding is followed
/// for the rest of the function, and a binding made in a block of its own
/// is followed outside that block as well, so the gate errs towards
/// seeing a read of the field.
fn alias_base_name(expr: &syn::Expr, names: &FieldNames) -> Option<String> {
    match expr {
        syn::Expr::Path(path) if path.qself.is_none() => {
            let name = path.path.segments.last()?.ident.to_string();
            names.aliases.contains(&name).then_some(name)
        }
        syn::Expr::Reference(reference) => alias_base_name(&reference.expr, names),
        _ => None,
    }
}

/// The name a header entry is held under is the name the entry's own
/// expression stands under, so the name of `header.name` is `header` and
/// the name of `header` is `header`.
fn expression_base_name(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => {
            if path.qself.is_none() && path.path.segments.len() == 1 {
                Some(path.path.segments[0].ident.to_string())
            } else {
                None
            }
        }
        syn::Expr::Field(field) => expression_base_name(&field.base),
        syn::Expr::Reference(reference) => expression_base_name(&reference.expr),
        _ => None,
    }
}

/// The entry a binding of a header entry's name stands for.
///
/// A header entry holds its name under a member of its own, so a binding
/// of that member stands for the entry, and a loop that walks a list of
/// header entries binds the entry's name to a name of its own, so a
/// binding of that name stands for the entry's name.
fn entry_name_alias_target(
    expr: &syn::Expr,
    entry_names: &[String],
    entry_name_aliases: &[(String, String)],
) -> Option<String> {
    match expr {
        syn::Expr::Field(field) => match &field.member {
            syn::Member::Named(ident) if ident == "name" => expression_base_name(&field.base),
            _ => None,
        },
        syn::Expr::Path(path) => {
            if path.qself.is_none() && path.path.segments.len() == 1 {
                let name = path.path.segments[0].ident.to_string();
                if entry_names.contains(&name) {
                    return Some(name);
                }
                // A name that already stands for an entry stands for the
                // same entry when it is copied.
                let resolved = resolve_alias_chain(&name, entry_name_aliases);
                (resolved != name).then_some(resolved)
            } else {
                None
            }
        }
        syn::Expr::Reference(reference) => {
            entry_name_alias_target(&reference.expr, entry_names, entry_name_aliases)
        }
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => {
            entry_name_alias_target(&unary.expr, entry_names, entry_name_aliases)
        }
        // A copy of the name holds the name it was made from, so the
        // entry the copy came from is the entry the copy stands for.
        syn::Expr::MethodCall(call)
            if CONTENT_LENGTH_NAME_COPY_METHODS.contains(&call.method.to_string().as_str()) =>
        {
            entry_name_alias_target(&call.receiver, entry_names, entry_name_aliases)
        }
        _ => None,
    }
}

/// The entry a compared name stands for.
///
/// The name a site compares with the field's name is the name of the
/// entry it found, and the site may hold that name in a copy of its own,
/// so the entry is found through the copy as well.
fn compared_entry_base(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::MethodCall(call)
            if CONTENT_LENGTH_NAME_COPY_METHODS.contains(&call.method.to_string().as_str()) =>
        {
            compared_entry_base(&call.receiver)
        }
        _ => expression_base_name(expr),
    }
}

/// The member a compared name is held under.
///
/// The name of the entry the comparison found is held under a member of
/// its own, so the member tells which member of the entry is the name
/// and which members are the value. A name the site holds in a copy of
/// its own is read through the copy, so the member is the member of the
/// name the copy was made from.
fn compared_name_member(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::MethodCall(call)
            if CONTENT_LENGTH_NAME_COPY_METHODS.contains(&call.method.to_string().as_str()) =>
        {
            compared_name_member(&call.receiver)
        }
        syn::Expr::Field(field) => match &field.member {
            syn::Member::Named(ident) => Some(ident.to_string()),
            _ => None,
        },
        syn::Expr::Reference(reference) => compared_name_member(&reference.expr),
        _ => None,
    }
}

/// The entry a name stands for, through the names it was bound under.
///
/// A name the site bound stands for the entry it came from, and a name
/// bound to that name stands for the same entry, so the chain is
/// followed to the entry at its end.
fn resolve_alias_chain(base: &str, aliases: &[(String, String)]) -> String {
    let mut resolved = base.to_string();
    for _ in 0..8 {
        let Some(target) = aliases
            .iter()
            .find(|(alias, _)| alias == &resolved)
            .map(|(_, target)| target.clone())
        else {
            break;
        };
        resolved = target;
    }
    resolved
}

/// The helper a call names, when the call is a call of a name.
///
/// A call to a helper hands the helper's result to the caller, so the
/// name of the helper is what tells whether the result is the entry the
/// helper found.
fn call_helper_name(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Call(call) = unwrapped_expr(expr) else {
        return None;
    };
    let syn::Expr::Path(path) = &*call.func else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

/// Whether a closure takes the value of a header entry.
///
/// A header entry is a pair of a name and a value, so a closure that
/// receives such a pair and uses its second element takes that entry's
/// value. A closure that receives the pair but leaves the value unused
/// looks at the name alone. A closure that receives one thing does not
/// take the pair apart, but the value may still be taken out of the entry
/// by a member, which the rule sees in its own right.
fn closure_takes_entry_value(closure: &syn::ExprClosure) -> bool {
    if closure.inputs.len() != 1 {
        return false;
    }
    let syn::Pat::Tuple(tuple) = &closure.inputs[0] else {
        return false;
    };
    if tuple.elems.len() != 2 {
        return false;
    }
    let syn::Pat::Ident(binding) = &tuple.elems[1] else {
        return false;
    };
    if binding.subpat.is_some() {
        return false;
    }
    let name = binding.ident.to_string();
    let mut uses = BindingUse {
        name: &name,
        used: false,
    };
    uses.visit_expr(&closure.body);
    uses.used
}

/// Whether a body uses a name.
struct BindingUse<'a> {
    /// The name the closure binds.
    name: &'a str,
    /// Whether the body uses it.
    used: bool,
}

impl Visit<'_> for BindingUse<'_> {
    fn visit_expr_path(&mut self, node: &syn::ExprPath) {
        if node.path.is_ident(self.name) {
            self.used = true;
        }
        syn::visit::visit_expr_path(self, node);
    }
}

/// Whether a generic argument list names an integer type.
fn names_integer_type(args: &syn::punctuated::Punctuated<GenericArgument, syn::Token![,]>) -> bool {
    args.iter().any(|arg| match arg {
        GenericArgument::Type(Type::Path(path)) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| is_integer_type(&segment.ident.to_string())),
        _ => false,
    })
}

/// Whether a type name is an integer type a length may be parsed into.
fn is_integer_type(name: &str) -> bool {
    matches!(
        name,
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
    )
}

/// Whether a path reaches the owner.
///
/// The owner is reached through its module, or through a name the site
/// imported from it, so both spellings count.
fn is_content_length_owner_call(path: &syn::Path) -> bool {
    let segments = &path.segments;
    let Some(last) = segments.last() else {
        return false;
    };
    if !CONTENT_LENGTH_OWNER_ENTRIES.contains(&last.ident.to_string().as_str()) {
        return false;
    }
    match segments.iter().rev().nth(1) {
        None => true,
        Some(segment) => segment.ident == CONTENT_LENGTH_OWNER_MODULE,
    }
}

/// The workspace's member crates, read from the root manifest.
///
/// The gate covers every member, so it reads the manifest rather than a
/// hand-written list that can fall behind a new crate.
fn workspace_member_crates(root: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(root.join("Cargo.toml"))
        .with_context(|| "failed to read the workspace manifest".to_string())?;
    let manifest: toml::Value = toml::from_str(&content)
        .with_context(|| "failed to parse the workspace manifest".to_string())?;
    let members = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("the workspace manifest has no members list"))?
        .iter()
        .filter_map(|member| member.as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    if members.is_empty() {
        bail!("the workspace manifest has no members list");
    }
    Ok(members)
}

/// The names the workspace has used for the token grammar and the header
/// token search.
const HTTP_TOKEN_VOCABULARY_NAMES: [&str; 7] = [
    "fn is_http_token(",
    "fn is_http_token_char(",
    "fn is_forwarded_token(",
    "fn has_connection_token(",
    "fn header_values_contain_token(",
    "fn is_token_char(",
    "fn is_token(",
];

fn http_token_vocabulary_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for forbidden in HTTP_TOKEN_VOCABULARY_NAMES {
        if content.contains(forbidden) {
            violations.push(forbidden);
        }
    }
    if contains_token_search_idiom(content) {
        violations
            .push("the header token search idiom (a comma split compared case-insensitively)");
    }
    violations
}

/// The owner's spelling of the header token search: a comma split on a
/// comma literal whose members are compared case-insensitively after
/// trimming.
///
/// The comma literal is matched in either Rust spelling, so a copy that
/// splits on `","` is caught like one that splits on `','`.
fn contains_token_search_idiom(content: &str) -> bool {
    const COMPARE: &str = "trim().eq_ignore_ascii_case(";
    const WINDOW: usize = 240;
    let mut rest = content;
    while let Some(index) = rest.find("split") {
        let after = &rest[index + "split".len()..];
        let window = after.get(..WINDOW).unwrap_or(after);
        let split = window.find("','").or_else(|| window.find("\",\""));
        if let Some(split) = split
            && window[split..].contains(COMPARE)
        {
            return true;
        }
        rest = after;
    }
    false
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

fn check_decision_service_response_buffering(root: &Path) -> Result<()> {
    let rel = "qpxd/src/policy_context/decision_service/mod.rs";
    let content = fs::read_to_string(root.join(rel))?;
    let violations = decision_service_response_buffering_violations(&content);
    if !violations.is_empty() {
        bail!(
            "decision_service response buffering baseline exceeded:\n{}",
            violations
                .into_iter()
                .map(|violation| format!("{rel}: {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn decision_service_response_buffering_violations(content: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for needle in [
        "collect_decision_service_response_body(",
        "Result<Vec<u8>>",
        "let mut out = Vec::new();",
        "while let Some(frame) = body.frame().await",
        ".checked_add(data.len())",
        "next > max_bytes",
        "out.extend_from_slice(&data);",
    ] {
        if !content.contains(needle) {
            violations.push("missing cancellable bounded decision_service response collector");
            break;
        }
    }
    if content.contains("to_bytes_limited(") {
        violations.push("decision_service response collector uses to_bytes_limited");
    }
    if content.contains(".collect().await") {
        violations.push("decision_service response collector uses collect().await");
    }
    if content.contains("spawn_blocking") || content.contains("SyncIoBridge") {
        violations.push("decision_service response collector uses non-cancellable blocking parser");
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
    let dispatch_dir = root.join("qpxd/src/reverse/transport/dispatch");
    let mut prepare = String::new();
    let mut names: Vec<String> = Vec::new();
    for entry in fs::read_dir(&dispatch_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("prepare") && name.ends_with(".rs") {
            names.push(name);
        }
    }
    names.sort();
    for name in &names {
        prepare.push_str(&fs::read_to_string(dispatch_dir.join(name))?);
        prepare.push('\n');
    }
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
    let Some(forwarding_start) = shm_fn.find("let forwarding_result: Result<()> = async {") else {
        violations.push("SHM handler missing body_leftover write path");
        return violations;
    };
    let forwarding_tail = &shm_fn[forwarding_start..];
    let Some(forwarding_end) = forwarding_tail.find(".await;") else {
        violations.push("SHM handler missing body_leftover write path");
        return violations;
    };
    let forwarding = &forwarding_tail[..forwarding_end];
    if !forwarding.contains("if !prepared.body_leftover.is_empty()")
        || !forwarding
            .contains("push_ring_bytes(&mut res_ring, &prepared.body_leftover, input_idle).await?")
    {
        violations.push("SHM body_leftover push failures must propagate to forwarding cleanup");
    }

    let cleanup = &forwarding_tail[forwarding_end..];
    let Some(error_check) = cleanup.find("if forwarding_result.is_err()") else {
        violations
            .push("SHM body_leftover push failures must abort execution and release response ring");
        return violations;
    };
    let error_handling = &cleanup[error_check..];
    let Some(success_branch) = error_handling.find("} else {") else {
        violations
            .push("SHM body_leftover push failures must abort execution and release response ring");
        return violations;
    };
    let error_branch = &error_handling[..success_branch];
    let success_branch = &error_handling[success_branch..];
    let drop_ring = cleanup.find("drop(res_ring);");
    let release_path = cleanup.find("release_ipc_shm_path(&res_path, shm_reusable)");
    if !error_branch.contains("abort_execution(exec_abort, stdin_task, exec_done).await")
        || error_branch.contains("exec_done.await")
        || !success_branch.contains("exec_done.await")
        || drop_ring.is_none()
        || release_path.is_none()
        || drop_ring >= release_path
    {
        violations
            .push("SHM body_leftover push failures must abort execution and release response ring");
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

pub(crate) fn check_ci_acceptance_gates(root: &Path) -> Result<()> {
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
    let security = fs::read_to_string(root.join(".github/workflows/security-qa.yml"))?;
    let codeql = fs::read_to_string(root.join(".github/workflows/codeql.yml"))?;
    let structure = fs::read_to_string(root.join(".github/workflows/structure.yml"))?;
    let release = fs::read_to_string(root.join(".github/workflows/release.yml"))?;
    let about = fs::read_to_string(root.join("about.toml"))?;
    let public_api = fs::read_to_string(root.join("scripts/check-public-api.sh"))?;
    let violations = ci_acceptance_violations(
        &ci,
        &security,
        &codeql,
        &structure,
        &release,
        &about,
        &public_api,
    );
    if !violations.is_empty() {
        bail!("CI acceptance gate violations:\n{}", violations.join("\n"));
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
    "auth_credential_parser",
    "cache_key",
    "client_hello_sniff",
    "config_canonical_loader",
    "connect_frame_observer",
    "datagram_capsule_parser",
    "dispatch_policy_match",
    "ftp_response_parser",
    "grpc_frame_observer",
    "grpc_web_binary_frame_observer",
    "grpc_web_text_base64_observer",
    "h3_content_length_state",
    "h3_trailer_sanitizer",
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
    let hash_vars = public_api_hash_variables(content);
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
        if !is_sha256_hex(hash) && !is_valid_public_api_hash_var(hash, &hash_vars) {
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

fn public_api_hash_variables(content: &str) -> BTreeMap<String, bool> {
    let mut vars = BTreeMap::new();
    for line in content.lines().map(str::trim) {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if !is_shell_identifier(name) {
            continue;
        }
        let valid = is_sha256_hex(value);
        vars.entry(name.to_string())
            .and_modify(|current| *current &= valid)
            .or_insert(valid);
    }
    vars
}

fn is_valid_public_api_hash_var(hash: &str, vars: &BTreeMap<String, bool>) -> bool {
    let Some(name) = hash
        .strip_prefix('"')
        .and_then(|hash| hash.strip_suffix('"'))
    else {
        return false;
    };
    let Some(name) = name.strip_prefix('$') else {
        return false;
    };
    vars.get(name).copied().unwrap_or(false)
}

fn is_shell_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn ci_acceptance_violations(
    ci: &str,
    security: &str,
    codeql: &str,
    structure: &str,
    release: &str,
    about: &str,
    public_api: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    for required in [
        "dtolnay/rust-toolchain@1.96",
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
        "cargo test -p qpxd --release --test advanced_transport_perf --locked --features http3-backend-qpx,mitm -- --nocapture",
        "stage perf smoke compatibility artifact",
        "target/perf/perf-smoke.jsonl",
        "target/perf/advanced-transport-perf.jsonl",
        "qpx-perf-smoke-jsonl",
        "qpx-perf-audit-jsonl-qpx",
        "- perf_audit_qpx",
        "cargo bench -p qpxd --bench streaming_throughput --locked -- --sample-size 10",
        "target/perf/perf-audit-protocol-h3-crate-perf.jsonl",
        "target/perf/perf-audit-protocol-qpx-h3-perf.jsonl",
        "target/perf/perf-audit-advanced-transport-perf.jsonl",
        "cargo test -p qpxd --release --test perf_smoke --locked --features http3-backend-h3 -- --nocapture",
        "cargo test -p qpxd --release --test perf_smoke --locked --features http3-backend-qpx -- --nocapture",
        "runs-on: ubuntu-latest",
        "scripts/check-perf-runner.sh",
        "target/perf/runner.jsonl",
        "sudo apt-get install -y apache2 apache2-utils iproute2 lighttpd nginx nghttp2-client openssl squid valgrind wrk",
        "cargo build -p qpxd --release --locked",
        "python3 scripts/test-perf-policy.py",
        "python3 scripts/test-streaming-reference-comparison.py",
        "checkout pinned previous release",
        "d67a148e7ccbbd272750415213601005af0f38c5",
        "python3 scripts/perf-audit-policy.py run proxy",
        "${{ runner.temp }}/qpx-perf-policy/proxy/**",
        "python3 scripts/perf-audit-policy.py run http2",
        "${{ runner.temp }}/qpx-perf-policy/http2/**",
        "QPX_PERF_ASSESSMENT: shared",
        "target/perf/http2-compare-logs/**",
        "scripts/perf-audit-streaming-compare.sh \"$QPX_STREAMING_COMPARE_JSON\"",
        "target/perf/perf-audit-streaming-compare.jsonl",
        "target/perf/streaming-compare-logs/**",
        "scripts/perf-audit-allocation-profile.sh",
        "target/perf/perf-audit-allocation-profile.jsonl",
        "target/perf/allocations/**",
        "scripts/check-allocation-budget.sh target/perf/perf-audit-allocation-profile.jsonl perf/allocation-budget.json",
        "scripts/perf-audit-netem-compare.sh \"$QPX_NETEM_COMPARE_JSON\"",
        "target/perf/perf-audit-netem-proxy-compare.jsonl",
        "target/perf/perf-audit-netem-profile.jsonl",
        "target/perf/netem-proxy-compare-logs/**",
        "scripts/h3-interop/run.sh all",
        "target/perf/qpx-h3-interop-matrix.json",
        "target/perf/proxy-compare-logs/**",
        "scripts/perf-audit-profile.sh",
        "target/perf/perf-audit-profile-summary.jsonl",
        "target/perf/perf-audit-profile-events.jsonl",
        "target/perf/profiles/**",
        "CARGO_PROFILE_RELEASE_DEBUG: \"1\"",
        "CARGO_PROFILE_RELEASE_STRIP: \"none\"",
        "workflow_dispatch:",
        "release:",
        "types: [published]",
        "tags:",
        "\"v*\"",
        "scripts/ci-runner-minutes.py collect",
        "scripts/ci-runner-minutes.py report",
    ] {
        if !ci.contains(required) {
            violations.push(format!(
                "ci.yml missing required job or command: {required}"
            ));
            break;
        }
    }
    if ci.lines().any(|line| line == "  perf_smoke:") {
        violations.push(
            "ci.yml must not contain a separate perf_smoke job (covered by perf_audit_qpx)"
                .to_string(),
        );
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
        "h3_content_length_state",
        "h3_trailer_sanitizer",
        "reverse_target_input_deserializer",
        "sse_event_observer",
        "streaming_requirement_config_validator",
    ] {
        if !security.contains(required) {
            violations.push("security-qa.yml missing ASAN or fuzz smoke coverage".to_string());
            break;
        }
    }
    for required in [
        "github/codeql-action/init@v4",
        "github/codeql-action/analyze@v4",
    ] {
        if !codeql.contains(required) {
            violations.push("codeql.yml missing CodeQL init/analyze".to_string());
            break;
        }
    }
    for required in [
        "bash ./scripts/check-ci-acceptance-gates.sh",
        "cargo xtask structure",
        "cargo xtask budget",
    ] {
        if !structure.contains(required) {
            violations.push(
                "structure.yml must run acceptance, structure, and budget gates together"
                    .to_string(),
            );
            break;
        }
    }
    for required in [
        "workflow_dispatch:",
        "tags:",
        "v*",
        "dtolnay/rust-toolchain@1.96",
        "tool: cargo-about",
        "cross build --workspace --release --locked --target ${{ matrix.target }} --features \"${QPXD_SAMPLE_RUSTLS_FEATURES}\"",
        "cargo build --workspace --release --locked --target ${{ matrix.target }} --features \"${QPXD_SAMPLE_RUSTLS_FEATURES}\"",
        "cargo about generate --fail --config about.toml --workspace --locked licenses/about.hbs > THIRDPARTY.md",
        "softprops/action-gh-release@v3",
        "id-token: write",
        "attestations: write",
        "actions/attest-build-provenance@v4.1.1",
        "subject-path: ${{ env.ASSET }}",
        "ASSET_SHA256=",
        "files: |",
        "${{ env.ASSET_SHA256 }}",
    ] {
        if !release.contains(required) {
            violations
                .push("release.yml missing release build, package, or publish gate".to_string());
            break;
        }
    }
    if !about.contains("\"MIT-0\"") {
        violations.push("about.toml missing MIT-0 license allowance".to_string());
    }
    for required in [
        "check_crate qpx-core",
        "check_crate qpx-auth",
        "check_crate qpx-h3",
        "check_crate qpx-acme",
        "check_crate qpx-observability",
    ] {
        if !public_api.contains(required) {
            violations.push("public API script missing library crate snapshot check".to_string());
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
            "qpxd/src/reverse/transport/dispatch/finalize.rs",
            vec![ResponseCaptureOrderRule {
                name: "reverse shared finalizer",
                finalize: "finalize_response_with_headers_in_place(\n        request_method",
                capture: "emit_optional_response_for_export(\n        resp",
            }],
        ),
        (
            "qpxd/src/reverse/transport/dispatch/dispatch_http.rs",
            vec![ResponseCaptureOrderRule {
                name: "reverse HTTP shared finalizer call",
                finalize: "finalize_reverse_dispatch_response(ReverseFinalizeResponseInput",
                capture: "Box::new((interim, resp))",
            }],
        ),
        (
            "qpxd/src/reverse/transport/dispatch/dispatch_ipc.rs",
            vec![
                ResponseCaptureOrderRule {
                    name: "reverse IPC shared finalizer call",
                    finalize: "finalize_reverse_dispatch_response(ReverseFinalizeResponseInput",
                    capture: "empty_interim_response(resp)",
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

const METRIC_CARDINALITY_FORBIDDEN_LABELS: &[&str] = &[
    "path",
    "full_path",
    "authority",
    "peer_ip",
    "user_id",
    "user",
    "grpc_service",
    "grpc_method",
    "connect_procedure",
    "header",
    "header_value",
];

fn metric_cardinality_policy_violations_for_file(path: &Path, content: &str) -> Vec<String> {
    METRIC_CARDINALITY_FORBIDDEN_LABELS
        .iter()
        .filter_map(|label| {
            let needle = format!("\"{label}\" =>");
            content
                .contains(&needle)
                .then(|| format!("{} uses forbidden metric label {label}", path.display()))
        })
        .collect()
}

pub(crate) fn check_metric_cardinality_policy(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for crate_dir in rust_workspace_crates() {
        let src = root.join(crate_dir).join("src");
        if !src.is_dir() {
            continue;
        }
        for path in rust_files_under(&src)? {
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name != "metrics.rs" {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            violations.extend(metric_cardinality_policy_violations_for_file(
                &path, &content,
            ));
        }
    }
    if !violations.is_empty() {
        bail!(
            "metrics cardinality policy violations:\n{}",
            violations.join("\n")
        );
    }
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

    #[test]
    fn http_token_vocabulary_violations_flag_a_local_definition() {
        assert_eq!(
            http_token_vocabulary_violations("fn is_http_token(value: &str) -> bool {"),
            vec!["fn is_http_token("]
        );
        assert_eq!(
            http_token_vocabulary_violations("fn is_token(value: &str) -> bool {"),
            vec!["fn is_token("]
        );
        assert_eq!(
            http_token_vocabulary_violations(
                "fn has_connection_token(headers: &HeaderMap) -> bool {"
            ),
            vec!["fn has_connection_token("]
        );
    }

    #[test]
    fn http_token_vocabulary_violations_flag_the_search_idiom_under_any_name() {
        assert_eq!(
            http_token_vocabulary_violations(
                "let present = values\n    .split(',')\n    .any(|part| part.trim().eq_ignore_ascii_case(\"100-continue\"));\n"
            ),
            vec!["the header token search idiom (a comma split compared case-insensitively)"]
        );
    }

    #[test]
    fn http_token_vocabulary_violations_flag_the_search_idiom_in_either_spelling() {
        assert_eq!(
            http_token_vocabulary_violations(
                "let present = values\n    .split(\",\")\n    .any(|part| part.trim().eq_ignore_ascii_case(\"100-continue\"));\n"
            ),
            vec!["the header token search idiom (a comma split compared case-insensitively)"]
        );
    }

    #[test]
    fn http_token_vocabulary_violations_accept_the_shared_owner() {
        assert!(
            http_token_vocabulary_violations(
                "use qpx_core::http_token::{header_values_contain_token, is_http_token};"
            )
            .is_empty()
        );
        assert!(
            http_token_vocabulary_violations(
                "let upgrade = qpx_core::http_token::header_values_contain_token(headers, CONNECTION, \"upgrade\");"
            )
            .is_empty()
        );
    }

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
    fn metric_cardinality_policy_flags_forbidden_labels() {
        let path = Path::new("qpxd/src/metrics.rs");
        assert_eq!(
            metric_cardinality_policy_violations_for_file(
                path,
                r#"
                match label {
                    "route" => allowed,
                    "grpc_method" => forbidden,
                    "header_value" => forbidden,
                }
                "grpc_method" // documentation alone is ignored
                "#,
            ),
            [
                "qpxd/src/metrics.rs uses forbidden metric label grpc_method",
                "qpxd/src/metrics.rs uses forbidden metric label header_value",
            ]
        );
        assert!(
            metric_cardinality_policy_violations_for_file(
                path,
                r#""listener" => a, "route" => b, "protocol" => c, "stage" => d"#
            )
            .is_empty()
        );
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
                "build_dispatch_audit_context(input); apply_decision_service_http_access(input);"
            )
            .is_empty()
        );
        assert_eq!(
            dispatch_access_commonality_violations(
                "DispatchAuditContext::new(state); decision.policy_id(); DecisionServiceEnforcement::Deny(deny);"
            ),
            [
                "missing build_dispatch_audit_context",
                "missing apply_decision_service_http_access",
                "DispatchAuditContext::new(",
                ".policy_id()",
                "DecisionServiceEnforcement::Deny",
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
    fn the_content_length_gate_sees_a_reader_that_reads_the_field_inline() {
        // A reader that reads the field's value and turns it into a number
        // in the same body reads the declaration itself.
        let inline = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn observed_size(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&inline.0, &inline.1).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function observed_size reads the declared Content-Length inline; it must call the owner"
            ]
        );

        // The same reader written as a comparison of a header name with the
        // field's name is seen as well.
        let compared = (
            "qpxd/tests/http_rfc/mod.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> usize {
    headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&compared.0, &compared.1).unwrap(),
            [
                "qpxd/tests/http_rfc/mod.rs: the function declared_length reads the declared Content-Length inline; it must call the owner"
            ]
        );

        // A reader whose parse leaves the type to be inferred is seen as
        // well: the gate cannot tell what the number is, and the field's
        // value is a length.
        let inferred = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn observed_size(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&inferred.0, &inferred.1).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function observed_size reads the declared Content-Length inline; it must call the owner"
            ]
        );

        // A parse that names a type that is not a number is not a reader:
        // the gate reads a written type as it is written.
        let not_a_number = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_text(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.parse::<String>().unwrap_or_default())
}
"#
            .to_string(),
        );
        assert!(
            content_length_inline_reader_violations(&not_a_number.0, &not_a_number.1)
                .unwrap()
                .is_empty(),
            "a parse that names a type that is not a number is not a reader"
        );

        // A reader that calls the owner is not a violation.
        let folded = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn observed_size(headers: &HeaderMap) -> Option<u64> {
    qpx_core::http_content_length::declared_content_length(headers).ok().flatten()
}
"#
            .to_string(),
        );
        assert!(
            content_length_inline_reader_violations(&folded.0, &folded.1)
                .unwrap()
                .is_empty(),
            "a reader that calls the owner is not a violation"
        );

        // A reader that calls the owner's named-value entry point is not a
        // violation either.
        let folded_lines = (
            "qpxd/src/reverse/transport/raw_http1.rs".to_string(),
            r#"
fn raw_declared_content_length(lines: &[(&str, &str)]) -> Option<u64> {
    qpx_core::http_content_length::declared_content_length_in_named_values(lines)
        .ok()
        .flatten()
}
"#
            .to_string(),
        );
        assert!(
            content_length_inline_reader_violations(&folded_lines.0, &folded_lines.1)
                .unwrap()
                .is_empty(),
            "a reader that calls the owner's named-value entry point is not a violation"
        );

        // A reader that calls the owner's named-value entry point and still
        // reads the field on its own is a violation as well.
        let half_folded_lines = (
            "qpxd/src/reverse/transport/raw_http1.rs".to_string(),
            r#"
fn raw_declared_content_length(headers: &HeaderMap, lines: &[(&str, &str)]) -> Option<u64> {
    let own = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let owner = qpx_core::http_content_length::declared_content_length_in_named_values(lines)
        .ok()
        .flatten();
    own.or(owner)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&half_folded_lines.0, &half_folded_lines.1)
                .unwrap(),
            [
                "qpxd/src/reverse/transport/raw_http1.rs: the function raw_declared_content_length reads the declared Content-Length as well as calling the owner; it must read the declaration through the owner alone"
            ]
        );

        // A function that turns text into a number without naming the
        // field reads no declaration.
        let unrelated = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn observed_size(port: &str) -> Option<u16> {
    port.parse::<u16>().ok()
}
"#
            .to_string(),
        );
        assert!(
            content_length_inline_reader_violations(&unrelated.0, &unrelated.1)
                .unwrap()
                .is_empty(),
            "a number that is not the field's length is not a reader"
        );

        // A function that calls the owner and still reads the field on its
        // own is a violation as well: the fold is not complete while an
        // inline read remains.
        let half_folded = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn observed_size(headers: &HeaderMap) -> Option<u64> {
    let declared = qpx_core::http_content_length::declared_content_length(headers).ok().flatten();
    let inline = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    declared.or(inline)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&half_folded.0, &half_folded.1).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function observed_size reads the declared Content-Length as well as calling the owner; it must read the declaration through the owner alone"
            ]
        );

        // A reader in a trait's default method is seen as well.
        let in_trait = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
trait Observed {
    fn observed_size(&self, headers: &HeaderMap) -> Option<u64> {
        headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
    }
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&in_trait.0, &in_trait.1).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function observed_size reads the declared Content-Length inline; it must call the owner"
            ]
        );

        // A function that writes the field and reads another number is not
        // a reader either.
        let writer = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn set_length(headers: &mut HeaderMap, body: &[u8]) {
    headers.insert(CONTENT_LENGTH, body.len().to_string().parse().unwrap());
}
"#
            .to_string(),
        );
        assert!(
            content_length_inline_reader_violations(&writer.0, &writer.1)
                .unwrap()
                .is_empty(),
            "a function that writes the field is not a reader"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_shipped_site_that_reads_the_field_value() {
        // A site that reads the field's value and hands it to another
        // function reads the declaration itself, and the naming rule
        // cannot see it: no body both reads the value and turns it into
        // a number.
        let split = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    field_text(headers).and_then(|value| value.parse().ok())
}

fn field_text(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
}
"#
            .to_string(),
        );
        assert!(
            content_length_inline_reader_violations(&split.0, &split.1)
                .unwrap()
                .is_empty(),
            "the naming rule cannot see a reader that splits the read and the parse"
        );
        assert_eq!(
            content_length_production_value_reader_violations(&split.0, &split.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function field_text reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A site that calls the owner and reads the value as well is a
        // violation too: the owner is the only reader.
        let half_folded = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn observed_size(headers: &HeaderMap) -> Option<u64> {
    let declared = qpx_core::http_content_length::declared_content_length(headers).ok().flatten();
    let own = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok());
    declared.or(own.and_then(|value| value.parse().ok()))
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&half_folded.0, &half_folded.1, &[])
                .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function observed_size reads the declared Content-Length's value as well as calling the owner; it must read the declaration through the owner alone"
            ]
        );

        // An indexed read of the field's value is a read of it as well.
        let indexed = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers[CONTENT_LENGTH].to_str().ok()?.parse().ok()
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&indexed.0, &indexed.1).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length inline; it must call the owner"
            ]
        );
        assert_eq!(
            content_length_production_value_reader_violations(&indexed.0, &indexed.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // Test code observes the field's value to assert on what the
        // proxy put on the wire, so it is not a violation.
        let in_test_file = (
            "qpxd/src/http/body/size/tests.rs".to_string(),
            split.1.clone(),
        );
        assert!(
            content_length_production_value_reader_violations(
                &in_test_file.0,
                &in_test_file.1,
                &[]
            )
            .unwrap()
            .is_empty(),
            "test code may observe the field's value"
        );

        // A test module inside a shipped file is test code as well.
        let in_test_module = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn observed_size(headers: &HeaderMap) -> Option<u64> {
    qpx_core::http_content_length::declared_content_length(headers).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared_length(headers: &HeaderMap) -> Option<u64> {
        headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
    }
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(
                &in_test_module.0,
                &in_test_module.1,
                &[]
            )
            .unwrap()
            .is_empty(),
            "a test module inside a shipped file is test code"
        );

        // A site the owner names is not a violation: the owner says what
        // that site does differently.
        let listed = vec!["qpxd/src/http/body/size/io.rs".to_string()];
        assert!(
            content_length_production_value_reader_violations(&split.0, &split.1, &listed)
                .unwrap()
                .is_empty(),
            "a site the owner names may read the declaration"
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_field_named_in_another_spelling() {
        // A read of the field through a reference to the constant names
        // the field.
        let by_reference = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<&HeaderValue> {
    headers.get(&CONTENT_LENGTH)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &by_reference.0,
                &by_reference.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The constant's text names the field.
        let by_text = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<&HeaderValue> {
    headers.get(CONTENT_LENGTH.as_str())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&by_text.0, &by_text.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A name built from the field's text names the field.
        let by_built_name = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<&HeaderValue> {
    headers.get(&HeaderName::from_static("content-length"))
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &by_built_name.0,
                &by_built_name.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // Another field's name is not the field.
        let other_field = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_type(headers: &HeaderMap) -> Option<&HeaderValue> {
    headers.get(&CONTENT_TYPE)
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other_field.0, &other_field.1, &[])
                .unwrap()
                .is_empty(),
            "another field's name is not the field"
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_field_through_a_binding_of_its_name() {
        // A site that binds the field's name to a name of its own and
        // reads the field through the binding reads the declaration.
        let by_binding = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<&HeaderValue> {
    let name = CONTENT_LENGTH;
    headers.get(name)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&by_binding.0, &by_binding.1, &[])
                .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A binding of the field's text names the field as well, so a
        // site that finds the field's own entry under the binding and
        // takes that entry's value reads the declaration.
        let by_bound_text = (
            "qpxd-cache/src/entry.rs".to_string(),
            r#"
fn stored_content_length(envelope: &CachedResponseEnvelope) -> Option<u64> {
    let field = "content-length";
    let values = envelope
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(field))
        .map(|(_, value)| value.as_str());
    values.next().and_then(|value| value.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &by_bound_text.0,
                &by_bound_text.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd-cache/src/entry.rs: the function stored_content_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A site that skips the field under the binding and takes another
        // header's value decides about the field rather than reading it.
        let skipping = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn other_length(headers: &[(&str, &str)]) -> Option<&str> {
    let field = "content-length";
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(field) {
            continue;
        }
        return Some(value);
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&skipping.0, &skipping.1, &[])
                .unwrap()
                .is_empty(),
            "a site that skips the field under the binding and takes another header's value is not a reader"
        );

        // A binding of another field's name is not the field.
        let other_field = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_type(headers: &HeaderMap) -> Option<&HeaderValue> {
    let name = CONTENT_TYPE;
    headers.get(name)
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other_field.0, &other_field.1, &[])
                .unwrap()
                .is_empty(),
            "a binding of another field's name is not the field"
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_field_through_a_constant_of_its_name() {
        // A site that keeps the field's name in a constant of its own and
        // reads the field through that constant reads the declaration.
        let by_constant = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
const LENGTH_FIELD: &str = "content-length";

fn declared_length(headers: &HeaderMap) -> Option<&HeaderValue> {
    headers.get(LENGTH_FIELD)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&by_constant.0, &by_constant.1, &[])
                .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A constant that holds the field's constant names the field as
        // well, so a site that reads the field through that constant reads
        // the declaration.
        let by_constant_of_the_constant = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
const LENGTH_FIELD: &str = CONTENT_LENGTH.as_str();

fn declared_length(headers: &HeaderMap) -> Option<&HeaderValue> {
    headers.get(LENGTH_FIELD)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &by_constant_of_the_constant.0,
                &by_constant_of_the_constant.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A constant that holds another field's name is not the field.
        let other_constant = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
const TYPE_FIELD: &str = "content-type";

fn declared_type(headers: &HeaderMap) -> Option<&HeaderValue> {
    headers.get(TYPE_FIELD)
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(
                &other_constant.0,
                &other_constant.1,
                &[]
            )
            .unwrap()
            .is_empty(),
            "a constant that holds another field's name is not the field"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_site_that_takes_the_field_value_by_name() {
        // A site that finds the field's own entry by comparing a header's
        // name with the field's name and then takes that entry's value
        // reads the declaration's value: the owner is the only reader.
        let selected = (
            "qpxd-cache/src/entry.rs".to_string(),
            r#"
fn stored_content_length(envelope: &CachedResponseEnvelope) -> Option<u64> {
    let values = envelope
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        .map(|(_, value)| value.as_str());
    let _ = values.next();
    qpx_core::http_content_length::declared_content_length_in_named_values(
        envelope.headers.iter().map(|(name, value)| (name, value)),
    )
        .ok()
        .flatten()
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&selected.0, &selected.1, &[])
                .unwrap(),
            [
                "qpxd-cache/src/entry.rs: the function stored_content_length reads the declared Content-Length's value as well as calling the owner; it must read the declaration through the owner alone"
            ]
        );

        // A site that hands the named values to the owner does not select
        // the field's values itself, so it is not a reader.
        let folded = (
            "qpxd-cache/src/entry.rs".to_string(),
            r#"
fn stored_content_length(envelope: &CachedResponseEnvelope) -> Option<u64> {
    let named = envelope.headers.iter().map(|(name, value)| (name, value));
    qpx_core::http_content_length::declared_content_length_in_named_values(named)
        .ok()
        .flatten()
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&folded.0, &folded.1, &[])
                .unwrap()
                .is_empty(),
            "a site that hands the named values to the owner is not a reader"
        );

        // A site that compares the field's name and leaves the value alone
        // decides about the field rather than reading its value.
        let name_only = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn strips_the_field(headers: &[Header<'_>]) -> bool {
    headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case(b"content-length"))
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&name_only.0, &name_only.1, &[])
                .unwrap()
                .is_empty(),
            "a site that compares the field's name and leaves the value alone is not a reader"
        );

        // Another field's name is not the field.
        let other_field = (
            "qpxd-cache/src/entry.rs".to_string(),
            r#"
fn stored_type(envelope: &CachedResponseEnvelope) -> Option<&str> {
    let mut values = envelope
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(CONTENT_TYPE.as_str()))
        .map(|(_, value)| value.as_str());
    values.next()
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other_field.0, &other_field.1, &[])
                .unwrap()
                .is_empty(),
            "another field's name is not the field"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_site_that_takes_the_entry_value_by_a_member() {
        // A site that finds the field's own entry and takes the entry's
        // `value` member reads the declaration's value: the owner is the
        // only reader.
        let member = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        .map(|header| header.value)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&member.0, &member.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/raw_head.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when a loop binds the entry's pair.
        let bound = (
            "qpxd/src/upstream/raw_http1/response.rs".to_string(),
            r#"
fn declared_length(headers: &[(&str, &str)]) -> Option<&str> {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()) {
            return Some(value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&bound.0, &bound.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/response.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the entry is a pair and the value is its
        // second element.
        let pair = (
            "qpxd/src/reverse/transport/raw_http1.rs".to_string(),
            r#"
fn declared_length(headers: &[(&str, &str)]) -> Option<&str> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        .map(|entry| entry.1)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&pair.0, &pair.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/raw_http1.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A member of another name is not the value.
        let other_member = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_name(headers: &[Header<'_>]) -> Option<&str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        .map(|header| header.name)
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(
                &other_member.0,
                &other_member.1,
                &[]
            )
            .unwrap()
            .is_empty(),
            "a member of another name is not the value"
        );

        // The value has to come from the entry the comparison found: a
        // site that compares the field's name and takes another entry's
        // value does not read the declaration.
        let another_entry = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn other_value(headers: &[Header<'_>], other: &Header<'_>) -> Option<&str> {
    if headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
    {
        return Some(other.value);
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(
                &another_entry.0,
                &another_entry.1,
                &[]
            )
            .unwrap()
            .is_empty(),
            "a site that compares the field's name and takes another entry's value is not a reader"
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_value_under_a_member_of_another_name() {
        // A site that finds the field's own entry and takes a member of
        // it that is not the member holding the name reads the
        // declaration's value: the owner is the only reader.
        let member = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        .map(|header| header.bytes)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&member.0, &member.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/raw_head.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when a closure receives the entry from the
        // search that found it, under a name of its own.
        let closure = (
            "qpxd/src/reverse/transport/raw_http1.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|entry| entry.bytes)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&closure.0, &closure.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/raw_http1.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when a binding holds the entry under a name of
        // its own.
        let bound = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let entry = header;
            return Some(entry.bytes);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&bound.0, &bound.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/raw_head.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The member the comparison used holds the name, so taking that
        // member takes the name and not the value.
        let name_member = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_name(headers: &[Header<'_>]) -> Option<&str> {
    headers
        .iter()
        .find(|header| header.key.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        .map(|header| header.key)
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&name_member.0, &name_member.1, &[])
                .unwrap()
                .is_empty(),
            "the member the comparison used holds the name, not the value"
        );

        // Another field's entry is not the field's entry, so a member of
        // it is not the field's value.
        let other_field = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn other_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
        .map(|header| header.bytes)
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other_field.0, &other_field.1, &[])
                .unwrap()
                .is_empty(),
            "another field's entry is not the field's entry"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_site_that_binds_the_entry_name() {
        // A site that binds a header entry's name to a name of its own
        // and compares that name with the field's name compares the
        // entry's name, so the value it takes is the field's value.
        let bound = (
            "qpxd/src/reverse/transport/raw_http1.rs".to_string(),
            r#"
fn declared_length(headers: &[(&str, &str)]) -> Option<&str> {
    for (name, value) in headers {
        let entry_name = *name;
        if entry_name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()) {
            return Some(value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&bound.0, &bound.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/raw_http1.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the value is the entry's `value` member.
        let member = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    for header in headers {
        let entry_name = header.name;
        if entry_name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()) {
            return Some(header.value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&member.0, &member.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/raw_head.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A binding of the entry's name that is compared with another
        // header's name is not a comparison with the field's name, so the
        // value it takes is another header's value.
        let other_name = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn other_header_value(headers: &[Header<'_>]) -> Option<&[u8]> {
    for header in headers {
        let entry_name = header.name;
        if entry_name.eq_ignore_ascii_case("content-type") {
            return Some(header.value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other_name.0, &other_name.1, &[])
                .unwrap()
                .is_empty(),
            "a comparison with another header's name does not find the field's entry"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_site_that_skips_the_field() {
        // A site that compares the field's name to skip it and takes
        // another header's pair value does not read the field's value:
        // the comparison decides about the field, it does not find the
        // field's own entry.
        let skipping = (
            "qpxd/src/upstream/raw_http1/response.rs".to_string(),
            r#"
fn other_header_value(headers: &HeaderMap) -> Option<String> {
    let mut found: Option<String> = None;
    for (name, value) in headers.iter() {
        if name == CONTENT_LENGTH {
            continue;
        }
        let pair = (name, value);
        found = Some(pair.1.to_str().ok()?.to_string());
    }
    found
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&skipping.0, &skipping.1, &[])
                .unwrap()
                .is_empty(),
            "a site that skips the field and takes another header's value is not a reader"
        );

        // The same site when it takes the field's own entry's value is a
        // reader.
        let own = (
            "qpxd/src/upstream/raw_http1/response.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<String> {
    for (name, value) in headers.iter() {
        if name == CONTENT_LENGTH {
            let pair = (name, value);
            return Some(pair.1.to_str().ok()?.to_string());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&own.0, &own.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/response.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A comparison that is not equal and skips the entry selects it,
        // because the entry that reaches the code is the field's own.
        let not_equal = (
            "qpxd/src/upstream/raw_http1/response.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<String> {
    for (name, value) in headers.iter() {
        if name != CONTENT_LENGTH {
            continue;
        }
        return Some(value.to_str().ok()?.to_string());
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&not_equal.0, &not_equal.1, &[])
                .unwrap(),
            [
                "qpxd/src/upstream/raw_http1/response.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A comparison that is not equal and does not skip the entry
        // decides about the field, so the value it takes is another
        // header's value.
        let excludes = (
            "qpxd/src/upstream/raw_http1/response.rs".to_string(),
            r#"
fn other_header_value(headers: &HeaderMap) -> Option<String> {
    for (name, value) in headers.iter() {
        if name != CONTENT_LENGTH {
            return Some(value.to_str().ok()?.to_string());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&excludes.0, &excludes.1, &[])
                .unwrap()
                .is_empty(),
            "a comparison that is not equal and does not skip the entry decides about the field"
        );
    }

    #[test]
    fn the_content_length_owner_names_the_sites_that_read_the_declaration() {
        let owner = r#"
/// The sites that still read the declaration themselves are named here:
///
/// - `qpxd/src/reverse/transport/mirrors.rs` parses every value as a plain
///   integer.
pub fn declared_content_length(headers: &HeaderMap) -> Result<Option<u64>, ContentLengthError> {
    Ok(None)
}
"#;
        let named = (
            "qpxd/src/reverse/transport/mirrors.rs".to_string(),
            "fn request_is_templateable() {}\n".to_string(),
        );
        assert!(
            content_length_single_owner_violations(owner, std::slice::from_ref(&named)).is_empty()
        );

        // A reader the owner does not name is a new copy of the reading.
        let unlisted = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            "fn parse_content_length() {}\n".to_string(),
        );
        assert_eq!(
            content_length_single_owner_violations(owner, &[named.clone(), unlisted]),
            [
                "qpxd/src/http/body/size/io.rs reads the declared Content-Length through its own helper and the owner does not name it"
            ]
        );

        // A site the owner names that no longer reads the declaration is a
        // stale entry.
        assert_eq!(
            content_length_single_owner_violations(owner, &[]),
            [
                "qpxd/src/reverse/transport/mirrors.rs is named by the owner but does not read the declared Content-Length"
            ]
        );

        // A site that reads through the owner needs no entry.
        let folded = (
            "qpxd/src/http/codec/h1.rs".to_string(),
            "fn parse_declared_content_length() { qpx_core::http_content_length::declared_content_length(headers) }\n"
                .to_string(),
        );
        let violations = content_length_single_owner_violations(owner, &[folded]);
        assert!(
            !violations
                .iter()
                .any(|violation| violation.contains("qpxd/src/http/codec/h1.rs")),
            "{violations:?}"
        );

        // An owner that names no site says that every site that reads the
        // declaration through a helper calls the owner.
        let empty_owner = r#"
/// Every site that reads the declaration through a helper reads it through
/// the owner.
pub fn declared_content_length(headers: &HeaderMap) -> Result<Option<u64>, ContentLengthError> {
    Ok(None)
}
"#;
        let folded = (
            "qpxd/src/http/codec/h1.rs".to_string(),
            "fn parse_declared_content_length() { qpx_core::http_content_length::declared_content_length(headers) }\n"
                .to_string(),
        );
        assert!(
            content_length_single_owner_violations(empty_owner, std::slice::from_ref(&folded))
                .is_empty(),
            "a reader that calls the owner needs no entry"
        );

        // A reader that does not call the owner is a violation whether or not
        // the owner names a site.
        let unlisted = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            "fn parse_content_length() {}\n".to_string(),
        );
        assert_eq!(
            content_length_single_owner_violations(empty_owner, &[folded, unlisted]),
            [
                "qpxd/src/http/body/size/io.rs reads the declared Content-Length through its own helper and the owner does not name it"
            ]
        );

        // The request guard reads the declaration through the owner under a
        // name the gate knows, so a guard that stops calling the owner is
        // caught by it.
        let guard = (
            "qpxd/src/http/policy/guard.rs".to_string(),
            "fn declared_request_length() { qpx_core::http_content_length::declared_content_length(headers) }\n"
                .to_string(),
        );
        assert!(
            content_length_single_owner_violations(empty_owner, std::slice::from_ref(&guard))
                .is_empty(),
            "a guard that calls the owner needs no entry"
        );
        let guard_without_the_owner = (
            "qpxd/src/http/policy/guard.rs".to_string(),
            "fn declared_request_length() {}\n".to_string(),
        );
        assert_eq!(
            content_length_single_owner_violations(empty_owner, &[guard_without_the_owner]),
            [
                "qpxd/src/http/policy/guard.rs reads the declared Content-Length through its own helper and the owner does not name it"
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
    fn phase3_decision_service_gate_rejects_collecting_response_body() {
        assert!(
            decision_service_response_buffering_violations(
                r#"
                async fn collect_decision_service_response_body(mut body: Body, max_bytes: usize) -> Result<Vec<u8>> {
                    let mut out = Vec::new();
                    while let Some(frame) = body.frame().await {
                        let data = frame?.into_data().unwrap();
                        let next = out.len().checked_add(data.len()).unwrap();
                        if next > max_bytes { return Err(anyhow!("too large")); }
                        out.extend_from_slice(&data);
                    }
                    Ok(out)
                }
                "#,
            )
            .is_empty()
        );
        assert_eq!(
            decision_service_response_buffering_violations(
                r#"
                async fn collect_decision_service_response_body(body: Body) -> Result<Bytes> {
                    crate::http::body::to_bytes_limited(body, 1024).await
                }
                "#,
            ),
            [
                "missing cancellable bounded decision_service response collector",
                "decision_service response collector uses to_bytes_limited",
            ]
        );
        assert_eq!(
            decision_service_response_buffering_violations(
                r#"
                async fn collect_decision_service_response_body(mut body: Body, max_bytes: usize) -> Result<Vec<u8>> {
                    let bytes = body.collect().await?.to_bytes();
                    let mut out = Vec::new();
                    while let Some(frame) = body.frame().await {
                        let data = frame?.into_data().unwrap();
                        let next = out.len().checked_add(data.len()).unwrap();
                        if next > max_bytes { return Err(anyhow!("too large")); }
                        out.extend_from_slice(&data);
                    }
                    Ok(out)
                }
                "#,
            ),
            ["decision_service response collector uses collect().await"]
        );
        assert_eq!(
            decision_service_response_buffering_violations(
                r#"
                async fn parse_decision_service_response_body(body: Body) {
                    tokio::task::spawn_blocking(move || {
                        let bridge = SyncIoBridge::new(reader);
                    });
                }
                "#,
            ),
            [
                "missing cancellable bounded decision_service response collector",
                "decision_service response collector uses non-cancellable blocking parser",
            ]
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
                let forwarding_result: Result<()> = async {
                    if !prepared.body_leftover.is_empty() {
                        push_ring_bytes(&mut res_ring, &prepared.body_leftover, input_idle).await?;
                    }
                    push_ring_eof(&mut res_ring, input_idle).await
                }
                .await;
                if forwarding_result.is_err() {
                    abort_execution(exec_abort, stdin_task, exec_done).await;
                } else {
                    let _ = exec_done.await;
                    let _ = stdin_task.await;
                }
                let _ = stderr_task.await;
                drop(res_ring);
                release_ipc_shm_path(&res_path, shm_reusable);
                forwarding_result
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
                let forwarding_result: Result<()> = async {
                    if !prepared.body_leftover.is_empty() {
                        let _ = push_ring_bytes(&mut res_ring, &prepared.body_leftover, input_idle).await;
                    }
                    push_ring_eof(&mut res_ring, input_idle).await
                }
                .await;
                if forwarding_result.is_err() {
                    // Missing executor abort.
                } else {
                    let _ = exec_done.await;
                }
                drop(res_ring);
                release_ipc_shm_path(&res_path, shm_reusable);
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
                "SHM body_leftover push failures must propagate to forwarding cleanup",
                "SHM body_leftover push failures must abort execution and release response ring",
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
    fn phase3_reverse_shared_finalizer_call_order() {
        let http_rule = ResponseCaptureOrderRule {
            name: "reverse HTTP shared finalizer call",
            finalize: "finalize_reverse_dispatch_response(ReverseFinalizeResponseInput",
            capture: "Box::new((interim, resp))",
        };
        assert!(
            response_capture_order_violations(
                "finalize_reverse_dispatch_response(ReverseFinalizeResponseInput { }); Box::new((interim, resp))",
                &http_rule,
            )
            .is_empty()
        );
        assert_eq!(
            response_capture_order_violations("Box::new((interim, resp))", &http_rule),
            ["reverse HTTP shared finalizer call missing finalization marker"]
        );
        assert_eq!(
            response_capture_order_violations(
                "finalize_reverse_dispatch_response(ReverseFinalizeResponseInput { });",
                &http_rule
            ),
            ["reverse HTTP shared finalizer call missing response capture marker"]
        );
        assert_eq!(
            response_capture_order_violations(
                "Box::new((interim, resp)); finalize_reverse_dispatch_response(ReverseFinalizeResponseInput { });",
                &http_rule,
            ),
            ["reverse HTTP shared finalizer call captures before finalization"]
        );
        let ipc_rule = ResponseCaptureOrderRule {
            name: "reverse IPC shared finalizer call",
            finalize: "finalize_reverse_dispatch_response(ReverseFinalizeResponseInput",
            capture: "empty_interim_response(resp)",
        };
        assert!(
            response_capture_order_violations(
                "finalize_reverse_dispatch_response(ReverseFinalizeResponseInput { }); empty_interim_response(resp)",
                &ipc_rule,
            )
            .is_empty()
        );
        assert_eq!(
            response_capture_order_violations("empty_interim_response(resp)", &ipc_rule),
            ["reverse IPC shared finalizer call missing finalization marker"]
        );
        assert_eq!(
            response_capture_order_violations(
                "finalize_reverse_dispatch_response(ReverseFinalizeResponseInput { });",
                &ipc_rule
            ),
            ["reverse IPC shared finalizer call missing response capture marker"]
        );
        assert_eq!(
            response_capture_order_violations(
                "empty_interim_response(resp); finalize_reverse_dispatch_response(ReverseFinalizeResponseInput { });",
                &ipc_rule,
            ),
            ["reverse IPC shared finalizer call captures before finalization"]
        );
    }

    #[test]
    fn ci_acceptance_gate_rejects_missing_required_workflow_commands() {
        let ci = r#"
            dtolnay/rust-toolchain@1.96
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
            cargo test -p qpxd --release --test advanced_transport_perf --locked --features http3-backend-qpx,mitm -- --nocapture
            stage perf smoke compatibility artifact
            target/perf/perf-smoke.jsonl
            target/perf/advanced-transport-perf.jsonl
            qpx-perf-smoke-jsonl
            qpx-perf-audit-jsonl-qpx
            - perf_audit_qpx
            cargo bench -p qpxd --bench streaming_throughput --locked -- --sample-size 10
            target/perf/perf-audit-protocol-h3-crate-perf.jsonl
            target/perf/perf-audit-protocol-qpx-h3-perf.jsonl
            target/perf/perf-audit-advanced-transport-perf.jsonl
            cargo test -p qpxd --release --test perf_smoke --locked --features http3-backend-h3 -- --nocapture
            cargo test -p qpxd --release --test perf_smoke --locked --features http3-backend-qpx -- --nocapture
            runs-on: ubuntu-latest
            scripts/check-perf-runner.sh
            target/perf/runner.jsonl
            sudo apt-get install -y apache2 apache2-utils iproute2 lighttpd nginx nghttp2-client openssl squid valgrind wrk
            cargo build -p qpxd --release --locked
            target/perf/http2-compare-logs/**
            scripts/perf-audit-streaming-compare.sh "$QPX_STREAMING_COMPARE_JSON"
            target/perf/perf-audit-streaming-compare.jsonl
            target/perf/streaming-compare-logs/**
            scripts/perf-audit-allocation-profile.sh
            target/perf/perf-audit-allocation-profile.jsonl
            target/perf/allocations/**
            scripts/check-allocation-budget.sh target/perf/perf-audit-allocation-profile.jsonl perf/allocation-budget.json
            scripts/perf-audit-netem-compare.sh "$QPX_NETEM_COMPARE_JSON"
            target/perf/perf-audit-netem-proxy-compare.jsonl
            target/perf/perf-audit-netem-profile.jsonl
            target/perf/netem-proxy-compare-logs/**
            scripts/h3-interop/run.sh all
            target/perf/qpx-h3-interop-matrix.json
            target/perf/proxy-compare-logs/**
            python3 scripts/test-perf-policy.py
            python3 scripts/test-streaming-reference-comparison.py
            checkout pinned previous release
            d67a148e7ccbbd272750415213601005af0f38c5
            python3 scripts/perf-audit-policy.py run proxy
            ${{ runner.temp }}/qpx-perf-policy/proxy/**
            python3 scripts/perf-audit-policy.py run http2
            ${{ runner.temp }}/qpx-perf-policy/http2/**
            QPX_PERF_ASSESSMENT: shared
            scripts/perf-audit-profile.sh
            target/perf/perf-audit-profile-summary.jsonl
            target/perf/perf-audit-profile-events.jsonl
            target/perf/profiles/**
            CARGO_PROFILE_RELEASE_DEBUG: "1"
            CARGO_PROFILE_RELEASE_STRIP: "none"
            workflow_dispatch:
            release:
            types: [published]
            tags:
            "v*"
            scripts/ci-runner-minutes.py collect
            scripts/ci-runner-minutes.py report
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
            h3_content_length_state
            h3_trailer_sanitizer
            reverse_target_input_deserializer
            sse_event_observer
            streaming_requirement_config_validator
        "#;
        let codeql = "github/codeql-action/init@v4\ngithub/codeql-action/analyze@v4";
        let structure = "bash ./scripts/check-ci-acceptance-gates.sh\ncargo xtask structure\ncargo xtask budget";
        let release = r#"
            workflow_dispatch:
            tags:
            v*
            dtolnay/rust-toolchain@1.96
            tool: cargo-about
            cross build --workspace --release --locked --target ${{ matrix.target }} --features "${QPXD_SAMPLE_RUSTLS_FEATURES}"
            cargo build --workspace --release --locked --target ${{ matrix.target }} --features "${QPXD_SAMPLE_RUSTLS_FEATURES}"
            cargo about generate --fail --config about.toml --workspace --locked licenses/about.hbs > THIRDPARTY.md
            softprops/action-gh-release@v3
            id-token: write
            attestations: write
            actions/attest-build-provenance@v4.1.1
            subject-path: ${{ env.ASSET }}
            ASSET_SHA256=
            files: |
            ${{ env.ASSET_SHA256 }}
        "#;
        let about = r#"
            accepted = [
                "MIT",
                "MIT-0",
            ]
        "#;
        let public_api = "check_crate qpx-core\ncheck_crate qpx-auth\ncheck_crate qpx-h3\ncheck_crate qpx-acme\ncheck_crate qpx-observability";
        assert!(
            ci_acceptance_violations(ci, security, codeql, structure, release, about, public_api)
                .is_empty()
        );

        assert_eq!(
            ci_acceptance_violations(
                "cargo fmt --all -- --check",
                "cargo fuzz run \"${target}\"",
                "github/codeql-action/init@v4",
                "cargo xtask structure",
                "softprops/action-gh-release@v3",
                "",
                "check_crate qpx-core",
            ),
            [
                "ci.yml missing required job or command: dtolnay/rust-toolchain@1.96",
                "security-qa.yml missing ASAN or fuzz smoke coverage",
                "codeql.yml missing CodeQL init/analyze",
                "structure.yml must run acceptance, structure, and budget gates together",
                "release.yml missing release build, package, or publish gate",
                "about.toml missing MIT-0 license allowance",
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

        let variable_good = format!(
            "\
            qpx_core_api_hash={hash}\n\
            qpx_h3_api_hash={hash}\n\
            check_crate qpx-core \"$qpx_core_api_hash\"\n\
            check_crate qpx-auth {hash}\n\
            check_crate qpx-h3 \"$qpx_h3_api_hash\"\n\
            check_crate qpx-acme {hash}\n\
            check_crate qpx-observability {hash}\n"
        );
        assert!(public_api_snapshot_script_violations(&variable_good).is_empty());

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
                "security-qa workflow missing fuzz target auth_credential_parser",
                "security-qa workflow missing fuzz target cache_key",
                "security-qa workflow missing fuzz target client_hello_sniff",
                "security-qa workflow missing fuzz target connect_frame_observer",
                "security-qa workflow missing fuzz target datagram_capsule_parser",
                "security-qa workflow missing fuzz target dispatch_policy_match",
                "security-qa workflow missing fuzz target ftp_response_parser",
                "security-qa workflow missing fuzz target grpc_frame_observer",
                "security-qa workflow missing fuzz target grpc_web_binary_frame_observer",
                "security-qa workflow missing fuzz target grpc_web_text_base64_observer",
                "security-qa workflow missing fuzz target h3_content_length_state",
                "security-qa workflow missing fuzz target h3_trailer_sanitizer",
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
            wildcards = "allow"
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
            wildcards = "deny"
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
                "deny.toml bans.wildcards must be allow; xtask rejects external wildcard dependencies",
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
            rust-version = "1.96"

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
            rust-version = "1.91"

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
                "workspace.package.rust-version must be 1.96",
                "workspace rust lint dead_code must be deny",
                "workspace rust lint unsafe_op_in_unsafe_fn must be deny",
                "workspace rust lint unused must be deny",
                "workspace clippy lint undocumented_unsafe_blocks must be deny",
            ]
        );
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

    #[test]
    fn the_content_length_gate_sees_the_value_through_a_binding_of_the_entry() {
        // A binding of the entry the comparison found holds that entry
        // under a name of its own, so the value the site takes under
        // that name is the field's value.
        let bound = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let entry = header;
            return Some(entry.value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&bound.0, &bound.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/raw_head.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_value_through_a_closure_that_receives_the_entry() {
        // A closure that receives the entry a search found holds that
        // entry, so the value it takes is the field's value.
        let chain = (
            "qpxd/src/reverse/transport/raw_http1.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|entry| entry.value)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&chain.0, &chain.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/raw_http1.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_value_through_a_pattern_that_binds_the_entry() {
        // A search's result bound by a pattern holds the entry the
        // search found.
        let pattern = (
            "qpxd/src/reverse/transport/raw_http1.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    let Some(entry) = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
    else {
        return None;
    };
    Some(entry.value)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&pattern.0, &pattern.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/raw_http1.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_value_taken_out_of_a_helper_that_found_the_entry() {
        // A helper that finds the field's own entry hands that entry to
        // its caller, so a caller that takes the value out of the result
        // reads the declaration.
        let destructured = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn content_length_entry(headers: &[(&str, &str)]) -> Option<(&str, &str)> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .copied()
}

fn declared_length(headers: &[(&str, &str)]) -> Option<u64> {
    let (_, value) = content_length_entry(headers)?;
    value.parse::<u64>().ok()
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &destructured.0,
                &destructured.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when a closure takes the value out of the
        // result.
        let closed = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn content_length_entry(headers: &[(&str, &str)]) -> Option<(&str, &str)> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .copied()
}

fn declared_length(headers: &[(&str, &str)]) -> Option<u64> {
    content_length_entry(headers).and_then(|(_, value)| value.parse::<u64>().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&closed.0, &closed.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_value_through_a_helper_that_found_the_entry() {
        // A helper that found the entry hands it to its caller, so the
        // value the caller takes is the field's value.
        let helper = (
            "qpxd/src/reverse/transport/raw_http1.rs".to_string(),
            r#"
fn find_content_length(headers: &[Header<'_>]) -> Option<&Header<'_>> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
}

fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    let entry = find_content_length(headers)?;
    Some(entry.value)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&helper.0, &helper.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/raw_http1.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );
    }

    #[test]
    fn the_content_length_gate_allows_a_helper_that_found_another_entry() {
        // A helper that finds another header's entry does not hand the
        // field's entry over, so the value its caller takes is another
        // header's value.
        let other = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn find_content_type(headers: &[Header<'_>]) -> Option<&Header<'_>> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
}

fn other_value(headers: &[Header<'_>]) -> Option<&[u8]> {
    let entry = find_content_type(headers)?;
    Some(entry.value)
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other.0, &other.1, &[])
                .unwrap()
                .is_empty(),
            "a helper that finds another header's entry does not hand the field's entry over"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_helper_that_found_the_entry_in_another_file() {
        // A helper that found the entry hands it to its caller, and the
        // file the helper stands in does not matter.
        let finder = (
            "qpxd/src/upstream/raw_http1/entries.rs".to_string(),
            r#"
fn find_content_length(headers: &[Header<'_>]) -> Option<&Header<'_>> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
}
"#
            .to_string(),
        );
        let caller = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    let entry = find_content_length(headers)?;
    Some(entry.value)
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_workspace_violations(&[finder.clone(), caller.clone()], &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );
        // The helper on its own finds the entry and takes no value, so it
        // does not read the declaration.
        assert!(
            content_length_workspace_violations(std::slice::from_ref(&finder), &[])
                .unwrap()
                .is_empty(),
            "a helper that found the entry and took no value does not read the declaration"
        );
    }

    #[test]
    fn the_content_length_gate_allows_a_helper_that_found_another_entry_in_another_file() {
        // A helper of another file that finds another header's entry does
        // not hand the field's entry over, so the value its caller takes
        // is another header's value. The workspace holds a helper that
        // found the field's own entry as well, so the rule has a helper
        // to follow and still does not follow this one.
        let finder = (
            "qpxd/src/upstream/raw_http1/entries.rs".to_string(),
            r#"
fn find_content_length(headers: &[Header<'_>]) -> Option<&Header<'_>> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
}
"#
            .to_string(),
        );
        let other = (
            "qpxd/src/upstream/raw_http1/other_entries.rs".to_string(),
            r#"
fn find_content_type(headers: &[Header<'_>]) -> Option<&Header<'_>> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-type"))
}
"#
            .to_string(),
        );
        let caller = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn other_value(headers: &[Header<'_>]) -> Option<&[u8]> {
    let entry = find_content_type(headers)?;
    Some(entry.value)
}
"#
            .to_string(),
        );
        assert!(
            content_length_workspace_violations(&[finder, other, caller], &[])
                .unwrap()
                .is_empty(),
            "a helper of another file that finds another header's entry does not hand the field's entry over"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_site_that_copies_the_entry_name() {
        // A site that copies the name of the entry it holds holds that
        // entry's name, so the comparison under the copy finds the entry
        // and the value the site takes is that entry's value.
        let copied = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    for header in headers {
        let name = header.name.to_string();
        if name.eq_ignore_ascii_case("content-length") {
            return Some(header.value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&copied.0, &copied.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/raw_head.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the comparison itself holds the copy.
        let inline = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    for header in headers {
        if header.name.to_string().eq_ignore_ascii_case("content-length") {
            return Some(header.value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&inline.0, &inline.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/raw_head.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the copy is a copy of a name the site
        // already bound.
        let twice = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    for header in headers {
        let name = header.name.to_string();
        let key = name.clone();
        if key.eq_ignore_ascii_case("content-length") {
            return Some(header.value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&twice.0, &twice.1, &[]).unwrap(),
            [
                "qpxd/src/upstream/raw_http1/raw_head.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_field_through_a_copy_of_a_bound_name() {
        // A site that copies a name it bound holds that name, so a read
        // through the copy reads the declaration - the copy is taken of
        // the binding, not of the literal.
        let copied = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    let name = "content-length".to_string();
    let copy = name.clone();
    headers.get(&copy).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&copied.0, &copied.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the copy is taken of a constant the site
        // keeps the field's name in.
        let copied_constant = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
const LENGTH: &str = "content-length";

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    let copy = LENGTH.to_string();
    headers.get(&copy).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &copied_constant.0,
                &copied_constant.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site takes the name's text directly.
        let taken = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    let name = "content-length".to_string();
    headers.get(name.as_str()).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&taken.0, &taken.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );
    }

    #[test]
    fn the_content_length_gate_sees_the_field_through_a_copy_of_its_name() {
        // A site that copies the field's name holds that name, so a read
        // through the copy reads the declaration.
        let copied = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    let name = "content-length".to_string();
    headers.get(&name).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&copied.0, &copied.1).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length inline; it must call the owner"
            ]
        );
        assert_eq!(
            content_length_production_value_reader_violations(&copied.0, &copied.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );
    }

    #[test]
    fn the_content_length_gate_allows_a_site_that_copies_another_name() {
        // A site that copies the name of another header's entry and
        // compares it with another field does not read the declaration.
        let other = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn other_value(headers: &[Header<'_>]) -> Option<&[u8]> {
    for header in headers {
        let name = header.name.to_string();
        if name.eq_ignore_ascii_case("content-type") {
            return Some(header.value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other.0, &other.1, &[])
                .unwrap()
                .is_empty(),
            "a copy of another header's name compared with another field is not a reader"
        );

        // A site that copies the field's name, skips the entry and takes
        // another header's value does not read the declaration either.
        let skipping = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn other_value(headers: &[Header<'_>]) -> Option<&[u8]> {
    for header in headers {
        let name = header.name.to_string();
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        return Some(header.value);
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&skipping.0, &skipping.1, &[])
                .unwrap()
                .is_empty(),
            "a site that skips the field's entry does not read the declaration"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_comparison_inside_a_compound_condition() {
        // A condition that holds more than the comparison cannot be read
        // as skipping the entry, so the comparison in it still finds the
        // field's own entry: the code after the branch may hold it.
        let and_condition = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<String> {
    for (name, value) in headers.iter() {
        if name != CONTENT_LENGTH && !value.is_empty() {
            continue;
        }
        return Some(value.to_str().ok()?.to_string());
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &and_condition.0,
                &and_condition.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the condition holds the comparison with an
        // or.
        let or_condition = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<String> {
    for (name, value) in headers.iter() {
        if name != CONTENT_LENGTH || value.is_empty() {
            continue;
        }
        return Some(value.to_str().ok()?.to_string());
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &or_condition.0,
                &or_condition.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the comparison is an equal one inside a
        // condition that holds more.
        let equal_condition = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<String> {
    for (name, value) in headers.iter() {
        if name == CONTENT_LENGTH && !value.is_empty() {
            continue;
        }
        return Some(value.to_str().ok()?.to_string());
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &equal_condition.0,
                &equal_condition.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A condition that holds another field's name does not find the
        // field's own entry.
        let other_field = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn other_value(headers: &HeaderMap) -> Option<String> {
    for (name, value) in headers.iter() {
        if name != CONTENT_TYPE && !value.is_empty() {
            continue;
        }
        return Some(value.to_str().ok()?.to_string());
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other_field.0, &other_field.1, &[])
                .unwrap()
                .is_empty(),
            "a condition that holds another field's name does not find the field's own entry"
        );

        // The value has to come from the entry the comparison found: a
        // site that compares the field's name inside a condition that
        // holds more and takes another entry's value does not read the
        // declaration.
        let another_entry = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn other_value(headers: &HeaderMap, other: &HeaderMap) -> Option<String> {
    for header in headers.iter() {
        if header.name != CONTENT_LENGTH && !header.name.is_empty() {
            continue;
        }
    }
    other
        .get("x-other")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(
                &another_entry.0,
                &another_entry.1,
                &[]
            )
            .unwrap()
            .is_empty(),
            "a site that takes another entry's value does not read the declaration"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_name_the_site_builds_at_runtime() {
        // A site that builds the field's name at runtime and reads the
        // field through that name reads the declaration.
        let built = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    let name = String::from("content-length");
    headers.get(&name).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&built.0, &built.1).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length inline; it must call the owner"
            ]
        );
        assert_eq!(
            content_length_production_value_reader_violations(&built.0, &built.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site builds the name with a macro.
        let formatted = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> Option<String> {
    let name = format!("content-length");
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&formatted.0, &formatted.1, &[])
                .unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site writes the name out in pieces.
        let concatenated = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> Option<String> {
    let name = concat!("content-", "length");
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &concatenated.0,
                &concatenated.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site formats the name out of a piece it
        // writes down.
        let formatted_piece = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> Option<String> {
    let name = format!("content-{}", "length");
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &formatted_piece.0,
                &formatted_piece.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site compares the name with a method.
        let compared = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn declared_length(headers: &[Header<'_>]) -> Option<&[u8]> {
    let name = String::from("content-length");
    for header in headers {
        if header.name.eq_ignore_ascii_case(&name) {
            return Some(header.value);
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&compared.0, &compared.1, &[])
                .unwrap(),
            [
                "qpxd/src/upstream/raw_http1/raw_head.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A site that builds another header's name at runtime does not
        // read the declaration.
        let other = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn other_value(headers: &[(String, String)]) -> Option<String> {
    let name = String::from("content-type");
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other.0, &other.1, &[])
                .unwrap()
                .is_empty(),
            "a name built at runtime for another field is not a reader"
        );

        // A site that builds the field's name at runtime and removes the
        // field does not read the declaration either.
        let removing = (
            "qpxd/src/upstream/raw_http1/raw_head.rs".to_string(),
            r#"
fn strips(headers: &mut HeaderMap) {
    let name = String::from("content-length");
    headers.remove(&name);
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&removing.0, &removing.1, &[])
                .unwrap()
                .is_empty(),
            "a site that removes the field does not read the declaration"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_name_the_site_builds_from_bound_text() {
        // A site that writes a piece of the field's name out, binds that
        // piece to a name of its own and builds the name from it reads
        // the declaration.
        let bound_piece = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    let prefix = "content-";
    let name = format!("{prefix}length");
    headers.get(&name).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&bound_piece.0, &bound_piece.1).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length inline; it must call the owner"
            ]
        );
        assert_eq!(
            content_length_production_value_reader_violations(&bound_piece.0, &bound_piece.1, &[])
                .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site finds the field's own entry with
        // the name it built from the bound piece.
        let found = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> Option<String> {
    let prefix = "content-";
    let name = format!("{prefix}length");
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&found.0, &found.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site hands the piece to the macro under
        // the name the macro names it by.
        let named_argument = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> Option<String> {
    let name = format!("{prefix}length", prefix = "content-");
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(
                &named_argument.0,
                &named_argument.1,
                &[]
            )
            .unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site adds the two pieces it wrote out.
        let added = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> Option<String> {
    let name = String::from("content-") + "length";
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&added.0, &added.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site fills a placeholder with the
        // piece it bound.
        let filled = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> Option<String> {
    let prefix = "content-";
    let name = format!("{}{}", prefix, "length");
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&filled.0, &filled.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site adds the piece it bound to another
        // piece it wrote out.
        let bound_added = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> Option<String> {
    let prefix = "content-";
    let name = prefix + "length";
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&bound_added.0, &bound_added.1, &[])
                .unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A site that builds the name from a piece it did not write out
        // does not read the declaration: the gate cannot read the text
        // of a value that arrives at runtime.
        let runtime_piece = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)], suffix: &str) -> Option<String> {
    let name = format!("content-{suffix}");
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(
                &runtime_piece.0,
                &runtime_piece.1,
                &[]
            )
            .unwrap()
            .is_empty(),
            "a name built from text the site did not write out is not a reader"
        );

        // A site that builds another field's name from a bound piece
        // does not read the declaration either.
        let other_field = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
fn declared_length(headers: &[(String, String)]) -> Option<String> {
    let prefix = "content-";
    let name = format!("{prefix}type");
    for (header_name, value) in headers {
        if header_name == name {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&other_field.0, &other_field.1, &[])
                .unwrap()
                .is_empty(),
            "a name built from a bound piece of another field is not a reader"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_name_the_site_imports_under_another_name() {
        // A site that imports the field's name under a name of its own
        // reads the declaration through that name.
        let renamed = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
use http::header::CONTENT_LENGTH as LENGTH;

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(LENGTH).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_inline_reader_violations(&renamed.0, &renamed.1).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length inline; it must call the owner"
            ]
        );
        assert_eq!(
            content_length_production_value_reader_violations(&renamed.0, &renamed.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the import stands in a nested module: the
        // module's import is the file's import too, so the name it
        // brings the field's name under is followed.
        let nested = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
mod inner {
    use http::header::CONTENT_LENGTH as LENGTH;

    pub fn declared_length(headers: &HeaderMap) -> Option<u64> {
        headers.get(LENGTH).and_then(|value| value.to_str().ok()?.parse().ok())
    }
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&nested.0, &nested.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // An import inside a function body is not one of the file's
        // imports: it is a name that one function holds, so the gate
        // does not follow it.
        let in_function = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    use http::header::CONTENT_LENGTH as LENGTH;
    headers.get(LENGTH).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(&in_function.0, &in_function.1, &[])
                .unwrap()
                .is_empty(),
            "an import inside a function body is not followed"
        );

        // The same read when the import stands in a group.
        let grouped = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
use http::header::{CONTENT_LENGTH as LENGTH, HOST};

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(LENGTH).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&grouped.0, &grouped.1, &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site takes the imported name by a
        // reference.
        let referenced = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
use http::header::CONTENT_LENGTH as LENGTH;

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(&LENGTH).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&referenced.0, &referenced.1, &[])
                .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // The same read when the site finds the field's own entry with
        // the imported name.
        let found = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
use http::header::CONTENT_LENGTH as LENGTH;

fn declared_length(headers: &[(String, String)]) -> Option<String> {
    for (header_name, value) in headers {
        if header_name == LENGTH {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_production_value_reader_violations(&found.0, &found.1, &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner"
            ]
        );

        // A site that imports another name under that name does not read
        // the declaration.
        let another_name = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
use http::header::HOST as LENGTH;

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(LENGTH).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert!(
            content_length_production_value_reader_violations(
                &another_name.0,
                &another_name.1,
                &[]
            )
            .unwrap()
            .is_empty(),
            "a name the site imports for another field is not a reader"
        );
        assert!(
            content_length_inline_reader_violations(&another_name.0, &another_name.1)
                .unwrap()
                .is_empty(),
            "a name the site imports for another field is not a reader"
        );
    }

    #[test]
    fn the_content_length_gate_sees_a_constant_of_another_file() {
        // A site that keeps the field's name in a constant of another
        // file and reads the field through that constant reads the
        // declaration.
        let constants = (
            "qpxd/src/http/consts.rs".to_string(),
            r#"
pub const LENGTH_HEADER: &str = "content-length";
"#
            .to_string(),
        );
        let reader = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
use crate::http::consts::LENGTH_HEADER;

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(LENGTH_HEADER).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_workspace_violations(&[constants.clone(), reader.clone()], &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length inline; it must call the owner",
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner",
            ]
        );

        // The same read when the import stands in a nested module: the
        // module's import is the file's import too, so the constant it
        // brings in names the field.
        let nested = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
mod inner {
    use crate::http::consts::LENGTH_HEADER;

    pub fn declared_length(headers: &HeaderMap) -> Option<u64> {
        headers.get(LENGTH_HEADER).and_then(|value| value.to_str().ok()?.parse().ok())
    }
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_workspace_violations(&[constants.clone(), nested.clone()], &[]).unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length inline; it must call the owner",
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner",
            ]
        );

        // The same read when the import renames the constant.
        let renamed = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
use crate::http::consts::LENGTH_HEADER as LENGTH;

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(LENGTH).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_workspace_violations(&[constants.clone(), renamed.clone()], &[])
                .unwrap(),
            [
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length inline; it must call the owner",
                "qpxd/src/http/body/size/io.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner",
            ]
        );

        // The same read when the site finds the field's own entry with
        // the imported constant.
        let found = (
            "qpxd/src/reverse/transport/request_template.rs".to_string(),
            r#"
use crate::http::consts::LENGTH_HEADER;

fn declared_length(headers: &[(String, String)]) -> Option<String> {
    for (header_name, value) in headers {
        if header_name == LENGTH_HEADER {
            return Some(value.clone());
        }
    }
    None
}
"#
            .to_string(),
        );
        assert_eq!(
            content_length_workspace_violations(&[constants.clone(), found.clone()], &[]).unwrap(),
            [
                "qpxd/src/reverse/transport/request_template.rs: the function declared_length reads the declared Content-Length's value itself; it must call the owner",
            ]
        );

        // A constant of another file that holds another value does not
        // name the field.
        let another_value = (
            "qpxd/src/http/consts.rs".to_string(),
            r#"
pub const LENGTH_HEADER: &str = "x-length";
"#
            .to_string(),
        );
        assert!(
            content_length_workspace_violations(&[another_value, reader.clone()], &[])
                .unwrap()
                .is_empty(),
            "a constant of another file that holds another value does not name the field"
        );

        // A constant of a crate outside the workspace is not followed:
        // the gate does not read that crate, so it cannot say what the
        // constant holds.
        let outside = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
use external_crate::LENGTH_HEADER;

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(LENGTH_HEADER).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert!(
            content_length_workspace_violations(&[constants.clone(), outside.clone()], &[])
                .unwrap()
                .is_empty(),
            "a constant of a crate outside the workspace is not followed"
        );

        // A constant an import reaches through a glob is not followed:
        // the import does not name the constant.
        let glob = (
            "qpxd/src/http/body/size/io.rs".to_string(),
            r#"
use crate::http::consts::*;

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(LENGTH_HEADER).and_then(|value| value.to_str().ok()?.parse().ok())
}
"#
            .to_string(),
        );
        assert!(
            content_length_workspace_violations(&[constants.clone(), glob.clone()], &[])
                .unwrap()
                .is_empty(),
            "a constant an import reaches through a glob is not followed"
        );

        // A name two files define is not followed: one of the two holds
        // another value, so the gate cannot say which one the import
        // names.
        let ambiguous = (
            "qpxd/src/http/other_consts.rs".to_string(),
            r#"
pub const LENGTH_HEADER: &str = "x-length";
"#
            .to_string(),
        );
        assert!(
            content_length_workspace_violations(
                &[constants.clone(), ambiguous, reader.clone()],
                &[]
            )
            .unwrap()
            .is_empty(),
            "a name two files define is not followed"
        );
    }
}
