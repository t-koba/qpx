use anyhow::{Result, bail};

mod checks;
mod files;
mod function_lengths;
mod visitors;

use budget::LOC_BUDGETS;
use checks::{
    check_dispatch_dependency_direction, check_finalize_entrypoints, check_function_lengths,
    check_loc_budgets, check_production_panics, check_production_unwraps,
    check_qpx_core_tls_baseline,
};
use files::workspace_root;

mod budget;
fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("structure") => run_structure(),
        _ => bail!("usage: cargo xtask structure"),
    }
}

fn run_structure() -> Result<()> {
    let root = workspace_root()?;
    check_loc_budgets(&root, LOC_BUDGETS)?;
    check_qpx_core_tls_baseline(&root)?;
    check_finalize_entrypoints(&root)?;
    check_production_unwraps(&root)?;
    check_production_panics(&root)?;
    check_function_lengths(&root)?;
    check_dispatch_dependency_direction(&root)?;
    println!("structure checks passed");
    Ok(())
}
