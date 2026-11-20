/// Measured whole-workspace baselines; `check_total_loc_budgets` reports
/// growth above them.
pub(crate) const TOTAL_LOC_BUDGETS: TotalLocBudgets = TotalLocBudgets {
    production_rust: 143_697,
    test_rust: 90_377,
    docs_markdown: 3_712,
};

pub(crate) struct TotalLocBudgets {
    pub(crate) production_rust: usize,
    pub(crate) test_rust: usize,
    pub(crate) docs_markdown: usize,
}
