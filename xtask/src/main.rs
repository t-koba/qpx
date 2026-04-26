use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use syn::visit::Visit;
use syn::{Expr, ExprCall, ImplItemFn, ItemFn};

const LOC_BUDGETS: &[(&str, usize, &str)] = &[
    (
        "qpxd/src/forward/h3_connect.rs",
        600,
        "phase 2 main-file budget",
    ),
    (
        "qpxd/src/reverse/transport.rs",
        600,
        "phase 2 main-file budget",
    ),
    (
        "qpxd/src/forward/connect.rs",
        800,
        "CONNECT entry remains intentionally consolidated; threshold relaxed from 600",
    ),
    (
        "qpxd/src/reverse/router.rs",
        600,
        "phase 2 main-file budget",
    ),
    (
        "qpxd/src/transparent/udp_path.rs",
        850,
        "release budget: transparent UDP session routing remains consolidated",
    ),
    (
        "qpxd/src/forward/request.rs",
        600,
        "phase 2 main-file budget",
    ),
    (
        "qpxd/src/forward/request_dispatch.rs",
        1100,
        "release budget: forward policy/cache/module dispatch remains consolidated",
    ),
    (
        "qpx-core/src/config/validate.rs",
        600,
        "phase 3 split budget",
    ),
    (
        "qpx-core/src/config/types/mod.rs",
        600,
        "phase 3 split budget",
    ),
    ("qpxd/src/runtime.rs", 600, "phase 4 split budget"),
    ("qpxd/src/upstream/origin.rs", 600, "phase 5 split budget"),
    (
        "qpxd/src/transparent/http_path.rs",
        250,
        "entrypoint should stay thin",
    ),
    ("qpxd/src/http/mitm.rs", 250, "entrypoint should stay thin"),
    (
        "qpxd/src/reverse/transport_dispatch.rs",
        1600,
        "release budget: reverse dispatcher keeps route-per-request retry/cache/interim orchestration consolidated",
    ),
    (
        "qpxd/src/transparent/http_dispatch.rs",
        650,
        "release budget: transparent HTTP policy/module dispatch remains consolidated",
    ),
    (
        "qpxd/src/http/mitm_dispatch.rs",
        650,
        "release budget: MITM policy/module dispatch remains consolidated",
    ),
    (
        "qpxd/src/forward/h3_qpx_connect.rs",
        1500,
        "qpx-h3 CONNECT dispatcher budget after relay extraction",
    ),
    (
        "qpxd/src/forward/h3_qpx_relay.rs",
        400,
        "qpx-h3 CONNECT relay state-machine budget",
    ),
    (
        "qpxd/src/http/modules.rs",
        1000,
        "HTTP module registry and shared module orchestration budget",
    ),
    (
        "qpxd/src/http/modules/response_compression.rs",
        550,
        "response compression module implementation budget",
    ),
    (
        "qpx-h3/src/server.rs",
        900,
        "qpx-h3 server driver budget after response sanitization extraction",
    ),
    (
        "qpx-h3/src/qpack.rs",
        1300,
        "qpx-h3 QPACK codec budget after field validation extraction",
    ),
    (
        "qpx-h3/src/response.rs",
        220,
        "qpx-h3 response sanitization module budget",
    ),
    (
        "qpx-h3/src/qpack_fields.rs",
        160,
        "qpx-h3 field validation module budget",
    ),
];

const FINALIZE_RULES: &[FinalizeRule] = &[
    FinalizeRule {
        path: "qpxd/src/forward/request.rs",
        allowed_functions: &[],
    },
    FinalizeRule {
        path: "qpxd/src/reverse/transport.rs",
        allowed_functions: &["handle_request_with_interim"],
    },
    FinalizeRule {
        path: "qpxd/src/transparent/http_path.rs",
        allowed_functions: &["handle_http_connection"],
    },
    FinalizeRule {
        path: "qpxd/src/http/mitm.rs",
        allowed_functions: &[],
    },
];

const QPX_CORE_TLS_ALLOWED: &[&str] = &["rustls", "webpki-roots", "rcgen", "lru"];

#[derive(Clone, Copy)]
struct FinalizeRule {
    path: &'static str,
    allowed_functions: &'static [&'static str],
}

fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("structure") => run_structure(),
        _ => bail!("usage: cargo xtask structure"),
    }
}

fn run_structure() -> Result<()> {
    let root = workspace_root()?;
    check_loc_budgets(&root)?;
    check_qpx_core_tls_baseline(&root)?;
    check_finalize_entrypoints(&root)?;
    println!("structure checks passed");
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("failed to resolve workspace root"))
}

fn check_loc_budgets(root: &Path) -> Result<()> {
    let mut cmd = Command::new("./scripts/measure-structure.sh");
    cmd.current_dir(root);
    for (path, _, _) in LOC_BUDGETS {
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
        let value = parts.pop().expect("value");
        let path = parts.join(" ");
        let parsed = value
            .parse::<usize>()
            .with_context(|| format!("invalid code_loc for {path}: {value}"))?;
        values.insert(path, parsed);
    }

    let mut violations = Vec::new();
    for (path, max, reason) in LOC_BUDGETS {
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

fn check_qpx_core_tls_baseline(root: &Path) -> Result<()> {
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

fn check_finalize_entrypoints(root: &Path) -> Result<()> {
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

#[derive(Default)]
struct FinalizeVisitor {
    fn_stack: Vec<String>,
    calls: Vec<FinalizeCall>,
}

struct FinalizeCall {
    enclosing_fn: String,
    callee: String,
}

impl FinalizeVisitor {
    fn push_fn<T>(&mut self, name: T)
    where
        T: Into<String>,
    {
        self.fn_stack.push(name.into());
    }

    fn pop_fn(&mut self) {
        self.fn_stack.pop();
    }

    fn current_fn(&self) -> String {
        self.fn_stack
            .last()
            .cloned()
            .unwrap_or_else(|| "<module>".to_string())
    }
}

impl<'ast> Visit<'ast> for FinalizeVisitor {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(path) = node.func.as_ref() {
            if let Some(segment) = path.path.segments.last() {
                let ident = segment.ident.to_string();
                if ident.starts_with("finalize_response") {
                    self.calls.push(FinalizeCall {
                        enclosing_fn: self.current_fn(),
                        callee: ident,
                    });
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}
