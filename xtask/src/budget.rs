use anyhow::{Context, Result, anyhow};

const LOC_BUDGET_DATA: &str = include_str!("../loc-budgets.tsv");

pub(crate) struct LocBudget {
    pub(crate) path: &'static str,
    pub(crate) max: usize,
    pub(crate) reason: &'static str,
}

pub(crate) fn loc_budgets() -> Result<Vec<LocBudget>> {
    LOC_BUDGET_DATA
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(idx, line)| parse_loc_budget_line(idx + 1, line))
        .collect()
}

fn parse_loc_budget_line(line_no: usize, line: &'static str) -> Result<LocBudget> {
    let (path, rest) = line
        .split_once('\t')
        .ok_or_else(|| anyhow!("missing max in loc budget line {line_no}"))?;
    let (max, reason) = rest
        .split_once('\t')
        .ok_or_else(|| anyhow!("missing reason in loc budget line {line_no}"))?;
    let max = max
        .parse()
        .with_context(|| format!("invalid max in loc budget line {line_no}"))?;
    Ok(LocBudget { path, max, reason })
}

pub(crate) const TOTAL_LOC_BUDGETS: TotalLocBudgets = TotalLocBudgets {
    production_rust: 108_912,
    test_rust: 32_227,
    docs_markdown: 2_467,
};

pub(crate) struct TotalLocBudgets {
    pub(crate) production_rust: usize,
    pub(crate) test_rust: usize,
    pub(crate) docs_markdown: usize,
}
