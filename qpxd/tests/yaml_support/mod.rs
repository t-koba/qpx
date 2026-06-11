use std::path::Path;

fn yaml_single_quote(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('\'');
    for ch in input.chars() {
        if ch == '\'' {
            out.push_str("''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

pub fn yaml_quote_path(path: &Path) -> String {
    yaml_single_quote(&path.to_string_lossy())
}
