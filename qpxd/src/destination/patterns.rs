pub(super) fn normalize_regex_pattern(value: &str) -> &str {
    extract_regex_pattern(value).unwrap_or(value)
}

pub(super) fn extract_regex_pattern(item: &str) -> Option<&str> {
    strip_regex_prefix(item)
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
}

/// Match the explicit regex prefix without folding case, so `RE:` keeps
/// working. The returned body is sliced from the original item to preserve
/// regex operators such as `\D`, `\S`, `\B`, and Unicode spellings.
fn strip_regex_prefix(item: &str) -> Option<&str> {
    let bytes = item.as_bytes();
    if bytes.len() >= 3
        && bytes[0].eq_ignore_ascii_case(&b'r')
        && bytes[1].eq_ignore_ascii_case(&b'e')
        && bytes[2] == b':'
    {
        return item.get(3..);
    }
    if bytes.len() >= 6
        && bytes[0].eq_ignore_ascii_case(&b'r')
        && bytes[1].eq_ignore_ascii_case(&b'e')
        && bytes[2].eq_ignore_ascii_case(&b'g')
        && bytes[3].eq_ignore_ascii_case(&b'e')
        && bytes[4].eq_ignore_ascii_case(&b'x')
        && bytes[5] == b':'
    {
        return item.get(6..);
    }
    None
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
