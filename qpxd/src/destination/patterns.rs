pub(super) fn normalize_regex_pattern(value: &str) -> &str {
    extract_regex_pattern(value).unwrap_or(value)
}

pub(super) fn extract_regex_pattern(item: &str) -> Option<&str> {
    item.strip_prefix("re:")
        .or_else(|| item.strip_prefix("regex:"))
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
}

pub(super) fn is_exact_pattern(item: &str) -> bool {
    !item.contains('*')
        && !item.contains('?')
        && !item.contains('[')
        && !item.contains(']')
        && !item.contains('{')
        && !item.contains('}')
}

pub(super) fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host.len() <= suffix.len() || !host.ends_with(suffix) {
        return false;
    }
    let boundary = host.len() - suffix.len();
    host.as_bytes().get(boundary.wrapping_sub(1)).copied() == Some(b'.')
}
