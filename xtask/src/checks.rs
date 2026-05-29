use crate::files::{is_test_file, rust_files_under};
use crate::function_lengths::function_length_warnings;
use crate::visitors::{FinalizeVisitor, PanicVisitor, UnwrapVisitor};
use anyhow::{Context, Result, anyhow, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use syn::visit::Visit;

const FINALIZE_RULES: &[FinalizeRule] = &[
    FinalizeRule {
        path: "qpxd/src/forward/request/mod.rs",
        allowed_functions: &[],
    },
    FinalizeRule {
        path: "qpxd/src/reverse/transport/mod.rs",
        allowed_functions: &["handle_request_with_interim"],
    },
    FinalizeRule {
        path: "qpxd/src/transparent/http/mod.rs",
        allowed_functions: &["handle_http_connection"],
    },
    FinalizeRule {
        path: "qpxd/src/http/mitm/mod.rs",
        allowed_functions: &[],
    },
];

const QPX_CORE_TLS_ALLOWED: &[&str] = &["rustls", "webpki-roots", "rcgen", "lru"];

#[derive(Clone, Copy)]
struct FinalizeRule {
    path: &'static str,
    allowed_functions: &'static [&'static str],
}

pub(crate) fn check_loc_budgets(root: &Path, budgets: &[(&str, usize, &str)]) -> Result<()> {
    let mut cmd = Command::new("./scripts/measure-structure.sh");
    cmd.current_dir(root);
    for (path, _, _) in budgets {
        cmd.arg(path);
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

    let mut violations = Vec::new();
    for (path, max, reason) in budgets {
        match values.get(*path) {
            Some(actual) if actual > max => {
                violations.push(format!("{path}: {actual} > {max} ({reason})"));
            }
            Some(_) => {}
            None => violations.push(format!("{path}: missing from measure output")),
        }
    }
    if !violations.is_empty() {
        bail!(
            "structure LOC budget violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_qpx_core_tls_baseline(root: &Path) -> Result<()> {
    let cargo_toml = root.join("qpx-core/Cargo.toml");
    let content = fs::read_to_string(&cargo_toml)
        .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
    let value = content
        .parse::<toml::Value>()
        .with_context(|| format!("failed to parse {}", cargo_toml.display()))?;
    let dependencies = value
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| anyhow!("qpx-core/Cargo.toml is missing [dependencies]"))?;

    let allowed = QPX_CORE_TLS_ALLOWED
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
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
    for rule in FINALIZE_RULES {
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

pub(crate) fn check_production_unwraps(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for path in rust_files_under(root.join("qpxd/src").as_path())? {
        if is_test_file(&path) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let syntax = syn::parse_file(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let mut visitor = UnwrapVisitor::default();
        visitor.visit_file(&syntax);
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path.as_path())
            .to_string_lossy();
        for call in visitor.unwraps {
            violations.push(format!("{rel}: unwrap() in {call}"));
        }
    }
    if !violations.is_empty() {
        bail!("production unwrap() violations:\n{}", violations.join("\n"));
    }
    Ok(())
}

pub(crate) fn check_production_panics(root: &Path) -> Result<()> {
    let mut violations = Vec::new();
    for path in rust_files_under(root.join("qpxd/src").as_path())? {
        if is_test_file(&path) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let syntax = syn::parse_file(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let mut visitor = PanicVisitor::default();
        visitor.visit_file(&syntax);
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path.as_path())
            .to_string_lossy();
        for call in visitor.panics {
            violations.push(format!(
                "{rel}: {}!() in {}",
                call.macro_name, call.enclosing_fn
            ));
        }
    }
    if !violations.is_empty() {
        bail!(
            "production panic/todo/unimplemented violations:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

pub(crate) fn check_function_lengths(root: &Path) -> Result<()> {
    const WARN_OVER_LINES: usize = 200;
    for path in rust_files_under(root.join("qpxd/src").as_path())? {
        if is_test_file(&path) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path.as_path())
            .to_string_lossy();
        for warning in function_length_warnings(rel.as_ref(), content.as_str(), WARN_OVER_LINES) {
            eprintln!("{warning}");
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
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path.as_path())
            .to_string_lossy();
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
    Ok(())
}
