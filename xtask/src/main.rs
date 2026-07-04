use anyhow::{Result, bail};

mod checks;
mod files;
mod function_lengths;
mod visitors;

use budget::TOTAL_LOC_BUDGETS;
use checks::{
    check_dependency_duplicate_baseline, check_dependency_policy_config,
    check_dispatch_dependency_direction, check_documented_unsafe_blocks,
    check_finalize_entrypoints, check_function_lengths, check_http_body_spool_failure_handling,
    check_library_anyhow_boundaries, check_loc_budgets, check_metric_cardinality_policy,
    check_phase3_architecture_baselines, check_phase4_ci_acceptance_gates, check_production_panics,
    check_production_unwraps, check_public_api_snapshot_script, check_qpx_core_tls_baseline,
    check_qpxr_capture_publish_order, check_raw_metric_macro_baseline, check_refactor_docs,
    check_response_capture_after_finalize, check_secret_zeroize_boundaries,
    check_security_qa_fuzz_targets, check_test_helper_duplicate_baseline, check_total_loc_budgets,
    check_workspace_lint_posture,
};
use files::workspace_root;

mod budget;
fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("structure") => run_structure(),
        Some("budget") => run_budget(),
        _ => bail!("usage: cargo xtask <structure|budget>"),
    }
}

fn run_budget() -> Result<()> {
    let root = workspace_root()?;
    let loc_budgets = budget::loc_budgets()?;
    check_loc_budgets(&root, &loc_budgets)?;
    check_total_loc_budgets(&root, TOTAL_LOC_BUDGETS)?;
    println!("budget advisory checks completed");
    Ok(())
}

fn run_structure() -> Result<()> {
    let root = workspace_root()?;
    let loc_budgets = budget::loc_budgets()?;
    check_loc_budgets(&root, &loc_budgets)?;
    check_total_loc_budgets(&root, TOTAL_LOC_BUDGETS)?;
    check_qpx_core_tls_baseline(&root)?;
    check_finalize_entrypoints(&root)?;
    check_documented_unsafe_blocks(&root)?;
    check_production_unwraps(&root)?;
    check_production_panics(&root)?;
    check_library_anyhow_boundaries(&root)?;
    check_workspace_lint_posture(&root)?;
    check_dependency_duplicate_baseline(&root)?;
    check_dependency_policy_config(&root)?;
    check_raw_metric_macro_baseline(&root)?;
    check_metric_cardinality_policy(&root)?;
    check_test_helper_duplicate_baseline(&root)?;
    check_function_lengths(&root)?;
    check_dispatch_dependency_direction(&root)?;
    check_phase3_architecture_baselines(&root)?;
    check_refactor_docs(&root)?;
    check_phase4_ci_acceptance_gates(&root)?;
    check_public_api_snapshot_script(&root)?;
    check_security_qa_fuzz_targets(&root)?;
    check_secret_zeroize_boundaries(&root)?;
    check_response_capture_after_finalize(&root)?;
    check_qpxr_capture_publish_order(&root)?;
    check_http_body_spool_failure_handling(&root)?;
    println!("structure checks passed");
    Ok(())
}
