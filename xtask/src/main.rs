use anyhow::{Context, Result, anyhow, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use syn::visit::Visit;
use syn::{Attribute, Expr, ExprCall, ExprMethodCall, ImplItemFn, ItemFn, ItemMod, Macro, Meta};

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
        500,
        "transparent UDP session routing budget after dispatch extraction",
    ),
    (
        "qpxd/src/transparent/udp_dispatch.rs",
        450,
        "transparent UDP per-session dispatch and policy budget",
    ),
    (
        "qpxd/src/forward/request.rs",
        600,
        "phase 2 main-file budget",
    ),
    (
        "qpxd/src/forward/request_dispatch.rs",
        1300,
        "forward policy/module dispatch budget after cache/upstream extraction",
    ),
    (
        "qpxd/src/forward/request_dispatch_cache.rs",
        500,
        "forward cache lookup/collapse dispatch budget",
    ),
    (
        "qpxd/src/forward/request_dispatch_upstream.rs",
        400,
        "forward upstream dispatch/response-policy budget",
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
        1700,
        "reverse dispatcher budget after HTTP/IPC/cache extraction",
    ),
    (
        "qpxd/src/reverse/transport_dispatch_http.rs",
        450,
        "reverse HTTP retry/success dispatch budget",
    ),
    (
        "qpxd/src/reverse/transport_dispatch_ipc.rs",
        550,
        "reverse IPC and WebSocket dispatch budget",
    ),
    (
        "qpxd/src/reverse/transport_dispatch_cache.rs",
        600,
        "reverse cache lookup/collapse dispatch budget",
    ),
    (
        "qpxd/src/transparent/http_dispatch.rs",
        1200,
        "transparent HTTP dispatch budget after shared dispatch extraction",
    ),
    (
        "qpxd/src/http/mitm_dispatch.rs",
        800,
        "MITM dispatch budget after shared dispatch extraction",
    ),
    (
        "qpxd/src/lib.rs",
        1300,
        "qpxd library entry/control-loop budget after server task extraction",
    ),
    (
        "qpxd/src/server_sets.rs",
        650,
        "listener and sidecar server set orchestration budget",
    ),
    (
        "qpxd/src/server_tasks.rs",
        650,
        "proxy/admin task lifecycle budget",
    ),
    (
        "qpxd/src/forward/h3_qpx.rs",
        500,
        "qpx-h3 listener and handler entry budget after WebTransport extraction",
    ),
    (
        "qpxd/src/forward/h3_qpx_webtransport.rs",
        650,
        "qpx-h3 WebTransport relay state-machine budget",
    ),
    (
        "qpxd/src/forward/h3_qpx_webtransport_dispatch.rs",
        850,
        "qpx-h3 WebTransport request dispatch budget",
    ),
    (
        "qpxd/src/forward/h3_qpx_response.rs",
        320,
        "qpx-h3 response conversion and policy response budget",
    ),
    (
        "qpxd/src/forward/h3_qpx_connect.rs",
        1000,
        "qpx-h3 CONNECT dispatcher budget after prepare/policy extraction",
    ),
    (
        "qpxd/src/forward/h3_qpx_connect_prepare.rs",
        450,
        "qpx-h3 CONNECT preparation orchestration budget",
    ),
    (
        "qpxd/src/forward/h3_qpx_connect_policy.rs",
        450,
        "qpx-h3 CONNECT policy/rate-limit preparation budget",
    ),
    (
        "qpxd/src/forward/h3_qpx_connect_upstream.rs",
        320,
        "qpx-h3 CONNECT upstream/opening helper budget",
    ),
    (
        "qpxd/src/forward/h3_qpx_relay.rs",
        400,
        "qpx-h3 CONNECT relay state-machine budget",
    ),
    (
        "qpxd/src/http/modules/mod.rs",
        80,
        "HTTP module facade budget after registry/chain split",
    ),
    (
        "qpxd/src/http/modules/execution.rs",
        650,
        "HTTP module execution/session budget",
    ),
    (
        "qpxd/src/http/modules/response_compression.rs",
        600,
        "response compression module implementation budget",
    ),
    (
        "qpxd/src/http/dispatch/mod.rs",
        90,
        "shared HTTP dispatch facade budget",
    ),
    (
        "qpxd/src/http/dispatch/access.rs",
        80,
        "shared HTTP dispatch access response budget",
    ),
    (
        "qpxd/src/http/dispatch/audit.rs",
        140,
        "shared HTTP dispatch audit budget",
    ),
    (
        "qpxd/src/http/dispatch/guard.rs",
        60,
        "shared HTTP dispatch guard budget",
    ),
    (
        "qpxd/src/http/dispatch/metrics.rs",
        60,
        "shared HTTP dispatch metrics budget",
    ),
    (
        "qpxd/src/http/dispatch/outcome.rs",
        90,
        "shared HTTP dispatch outcome budget",
    ),
    (
        "qpxd/src/http/dispatch/rate_limit.rs",
        45,
        "shared HTTP dispatch rate-limit budget",
    ),
    (
        "qpxd/src/http/dispatch/cache.rs",
        180,
        "shared HTTP dispatch cache flow budget",
    ),
    (
        "qpxd/src/http/dispatch/connect_policy.rs",
        80,
        "shared HTTP dispatch CONNECT policy context budget",
    ),
    (
        "qpxd/src/http/dispatch/prepare.rs",
        120,
        "shared HTTP dispatch request preparation budget",
    ),
    (
        "qpxd/src/http/dispatch/response_policy.rs",
        140,
        "shared HTTP dispatch response policy budget",
    ),
    (
        "qpxd/src/http/dispatch/websocket.rs",
        90,
        "shared HTTP dispatch WebSocket proxy budget",
    ),
    (
        "qpxd/src/http/http1_codec.rs",
        1100,
        "HTTP/1 codec parser/serializer budget after request-body extraction",
    ),
    (
        "qpxd/src/http/http1_request_body.rs",
        300,
        "HTTP/1 request body forwarding budget",
    ),
    (
        "qpxd/src/http/http1_common.rs",
        100,
        "shared HTTP/1 codec helper budget",
    ),
    (
        "qpxd/src/reverse/h3_passthrough.rs",
        1200,
        "reverse HTTP/3 UDP passthrough state-machine budget",
    ),
    (
        "qpxd/src/udp_session_handoff.rs",
        1050,
        "UDP session export/restore handoff budget",
    ),
    (
        "qpxd/src/runtime/plan.rs",
        1050,
        "runtime execution plan compilation budget",
    ),
    (
        "qpxd/src/transparent/tls_path.rs",
        900,
        "transparent TLS decision path budget",
    ),
    (
        "qpxd/src/forward/h3_connect_handlers.rs",
        1050,
        "HTTP/3 CONNECT handler budget",
    ),
    (
        "qpxd/src/upstream/pool.rs",
        850,
        "upstream proxy connection pool budget",
    ),
    ("qpxd/src/ipc_client.rs", 850, "QPX IPC client budget"),
    ("qpxd/src/ftp.rs", 1000, "FTP-over-HTTP gateway budget"),
    ("qpxd/src/rate_limit.rs", 950, "rate limiting budget"),
    (
        "qpxd/src/upstream/origin/http_backend.rs",
        550,
        "origin HTTP backend budget after shared-client extraction",
    ),
    (
        "qpxd/src/upstream/origin/http_backend_shared.rs",
        300,
        "shared reverse HTTP client budget",
    ),
    (
        "qpxd/src/upstream/origin/http_backend_h2.rs",
        400,
        "origin HTTP/2 request/response helper budget",
    ),
    (
        "qpxd/src/upstream/origin/http_pool.rs",
        600,
        "origin HTTP/1/H2 connection acquisition and pool budget",
    ),
    (
        "qpxd/src/destination/mod.rs",
        100,
        "destination classifier facade budget",
    ),
    (
        "qpxd/src/destination/compile.rs",
        300,
        "destination named-set compilation budget",
    ),
    (
        "qpxd/src/destination/resolve.rs",
        650,
        "destination evidence resolution budget",
    ),
    (
        "qpxd/src/upstream/raw_http1.rs",
        950,
        "raw HTTP/1 upstream codec budget",
    ),
    (
        "qpxd/src/forward/h3_connect_udp.rs",
        900,
        "HTTP/3 CONNECT-UDP budget",
    ),
    (
        "qpxd/src/reverse/listener.rs",
        800,
        "reverse TCP/TLS listener budget",
    ),
    (
        "qpx-core/src/config/validate/rules.rs",
        1550,
        "core rule validation budget",
    ),
    (
        "qpx-core/src/config/validate/reverse.rs",
        800,
        "core reverse config validation budget",
    ),
    (
        "qpx-core/src/config/validate/security.rs",
        800,
        "core security config validation budget",
    ),
    (
        "qpx-core/src/config/types/canonical.rs",
        850,
        "canonical config type budget",
    ),
    (
        "qpx-core/src/prefilter.rs",
        900,
        "match prefilter implementation budget",
    ),
    (
        "qpx-core/src/shm_ring.rs",
        900,
        "shared-memory ring implementation budget",
    ),
    (
        "qpx-core/src/config/tests.rs",
        1250,
        "core config regression test budget",
    ),
    ("qpx-h3/src/server.rs", 1000, "qpx-h3 server driver budget"),
    ("qpxf/src/server.rs", 850, "qpxf IPC server budget"),
    ("qpx-acme/src/lib.rs", 800, "ACME integration budget"),
    (
        "qpxd/src/cache/tests.rs",
        1450,
        "cache regression test budget",
    ),
    (
        "qpxd/src/runtime_tests.rs",
        1050,
        "runtime regression test budget",
    ),
    (
        "qpxd/src/reverse/transport_tests.rs",
        2300,
        "reverse transport regression test budget",
    ),
    (
        "qpxd/src/forward/request_tests.rs",
        1150,
        "forward request regression test budget",
    ),
    (
        "qpxd/tests/perf_smoke.rs",
        1250,
        "qpxd perf smoke test budget",
    ),
    (
        "qpxd/tests/rfc911x_contract.rs",
        1400,
        "RFC 911x contract test budget",
    ),
    ("qpxd/tests/forward_e2e.rs", 1300, "forward e2e test budget"),
    (
        "qpxd/tests/advanced_transport_perf.rs",
        950,
        "advanced transport perf test budget",
    ),
    ("qpx-h3/tests/e2e.rs", 1200, "qpx-h3 e2e test budget"),
    (
        "qpxd/src/http3/quinn_socket/mod.rs",
        30,
        "QUIC broker facade budget after responsibility split",
    ),
    (
        "qpxd/src/http3/quinn_socket/broker.rs",
        600,
        "QUIC broker socket state budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/endpoint.rs",
        100,
        "QUIC endpoint socket preparation budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/frame.rs",
        260,
        "QUIC broker frame codec budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/handoff.rs",
        400,
        "QUIC broker handoff manifest budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/routing.rs",
        170,
        "QUIC broker CID route state budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/stream.rs",
        230,
        "QUIC broker platform stream adapter budget",
    ),
    (
        "qpxd/src/http3/quinn_socket/tasks.rs",
        160,
        "QUIC broker async task loop budget",
    ),
    (
        "qpx-h3/src/qpack/mod.rs",
        350,
        "qpx-h3 QPACK public facade budget after codec/table split",
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
    check_production_unwraps(&root)?;
    check_production_panics(&root)?;
    check_function_lengths(&root)?;
    check_dispatch_dependency_direction(&root)?;
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

fn check_production_unwraps(root: &Path) -> Result<()> {
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

fn check_production_panics(root: &Path) -> Result<()> {
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

fn check_function_lengths(root: &Path) -> Result<()> {
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

fn check_dispatch_dependency_direction(root: &Path) -> Result<()> {
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

fn rust_files_under(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }
    for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", path.display()))?;
        collect_rust_files(&entry.path(), files)?;
    }
    Ok(())
}

fn is_test_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.ends_with("_test.rs") || name.ends_with("_tests.rs") || name == "tests.rs"
        })
}

fn has_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| match &attr.meta {
        Meta::List(list) if attr.path().is_ident("cfg") => list.tokens.to_string().contains("test"),
        _ => false,
    })
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
        if let Expr::Path(path) = node.func.as_ref()
            && let Some(segment) = path.path.segments.last()
        {
            let ident = segment.ident.to_string();
            if ident.starts_with("finalize_response") {
                self.calls.push(FinalizeCall {
                    enclosing_fn: self.current_fn(),
                    callee: ident,
                });
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

#[derive(Default)]
struct UnwrapVisitor {
    fn_stack: Vec<String>,
    unwraps: Vec<String>,
}

struct PanicCall {
    enclosing_fn: String,
    macro_name: String,
}

#[derive(Default)]
struct PanicVisitor {
    fn_stack: Vec<String>,
    panics: Vec<PanicCall>,
}

impl PanicVisitor {
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

impl<'ast> Visit<'ast> for PanicVisitor {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if has_cfg_test(&node.attrs) || node.attrs.iter().any(|attr| attr.path().is_ident("test")) {
            return;
        }
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if let Some(segment) = node.path.segments.last() {
            let macro_name = segment.ident.to_string();
            if matches!(macro_name.as_str(), "panic" | "todo" | "unimplemented") {
                self.panics.push(PanicCall {
                    enclosing_fn: self.current_fn(),
                    macro_name,
                });
            }
        }
        syn::visit::visit_macro(self, node);
    }
}

fn function_length_warnings(path: &str, content: &str, warn_over_lines: usize) -> Vec<String> {
    let lines = content.lines().collect::<Vec<_>>();
    let mut warnings = Vec::new();
    let mut idx = 0;
    while idx < lines.len() {
        let line = lines[idx].trim_start();
        let Some(name) = function_name_from_line(line) else {
            idx += 1;
            continue;
        };
        let mut depth = 0isize;
        let mut started = false;
        for (end, line) in lines.iter().enumerate().skip(idx) {
            depth += line.matches('{').count() as isize;
            if line.contains('{') {
                started = true;
            }
            depth -= line.matches('}').count() as isize;
            if started && depth == 0 {
                let len = end - idx + 1;
                if len > warn_over_lines {
                    warnings.push(format!(
                        "function length warning: {path}: {name} is {len} lines (> {warn_over_lines})"
                    ));
                }
                idx = end;
                break;
            }
        }
        idx += 1;
    }
    warnings
}

fn function_name_from_line(line: &str) -> Option<String> {
    let prefix = line
        .strip_prefix("pub(crate) async fn ")
        .or_else(|| line.strip_prefix("pub(super) async fn "))
        .or_else(|| line.strip_prefix("pub async fn "))
        .or_else(|| line.strip_prefix("async fn "))
        .or_else(|| line.strip_prefix("pub(crate) fn "))
        .or_else(|| line.strip_prefix("pub(super) fn "))
        .or_else(|| line.strip_prefix("pub fn "))
        .or_else(|| line.strip_prefix("fn "))?;
    let name = prefix
        .split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .next()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

impl UnwrapVisitor {
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

impl<'ast> Visit<'ast> for UnwrapVisitor {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if has_cfg_test(&node.attrs) || node.attrs.iter().any(|attr| attr.path().is_ident("test")) {
            return;
        }
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.push_fn(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.pop_fn();
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if node.method == "unwrap" {
            self.unwraps.push(self.current_fn());
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}
