pub(crate) fn function_length_warnings(
    path: &str,
    content: &str,
    warn_over_lines: usize,
) -> Vec<String> {
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
