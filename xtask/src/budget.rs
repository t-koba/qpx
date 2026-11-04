/// Measured whole-workspace baselines; `check_total_loc_budgets` reports
/// growth above them.
pub(crate) const TOTAL_LOC_BUDGETS: TotalLocBudgets = TotalLocBudgets {
    production_rust: 145_857,
    test_rust: 83_117,
    docs_markdown: 3_669,
};

pub(crate) struct TotalLocBudgets {
    pub(crate) production_rust: usize,
    pub(crate) test_rust: usize,
    pub(crate) docs_markdown: usize,
}
