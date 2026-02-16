use anyhow::{anyhow, Result};
use regex::Regex;
use std::env;

pub fn expand_env(input: &str) -> Result<String> {
    let re = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")?;
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for caps in re.captures_iter(input) {
        let m = caps
            .get(0)
            .ok_or_else(|| anyhow!("envsubst capture error"))?;
        out.push_str(&input[last..m.start()]);
        let key = caps.get(1).unwrap().as_str();
        let default = caps.get(2).map(|m| m.as_str());
        let value = match env::var(key) {
            Ok(v) => v,
            Err(_) => match default {
                Some(d) => d.to_string(),
                None => return Err(anyhow!("missing environment variable: {}", key)),
            },
        };
        out.push_str(&value);
        last = m.end();
    }
    out.push_str(&input[last..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_without_variables() {
        let result = expand_env("hello world").unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn expands_set_variable() {
        env::set_var("QPX_TEST_ENVSUBST_A", "alpha");
        let result = expand_env("${QPX_TEST_ENVSUBST_A}").unwrap();
        assert_eq!(result, "alpha");
        env::remove_var("QPX_TEST_ENVSUBST_A");
    }

    #[test]
    fn uses_default_when_unset() {
        env::remove_var("QPX_TEST_ENVSUBST_UNSET");
        let result = expand_env("${QPX_TEST_ENVSUBST_UNSET:-fallback}").unwrap();
        assert_eq!(result, "fallback");
    }

    #[test]
    fn errors_on_missing_variable_without_default() {
        env::remove_var("QPX_TEST_ENVSUBST_MISSING");
        let result = expand_env("${QPX_TEST_ENVSUBST_MISSING}");
        assert!(result.is_err());
    }

    #[test]
    fn multiple_variables() {
        env::set_var("QPX_TEST_ENVSUBST_X", "one");
        env::set_var("QPX_TEST_ENVSUBST_Y", "two");
        let result = expand_env("${QPX_TEST_ENVSUBST_X}-${QPX_TEST_ENVSUBST_Y}").unwrap();
        assert_eq!(result, "one-two");
        env::remove_var("QPX_TEST_ENVSUBST_X");
        env::remove_var("QPX_TEST_ENVSUBST_Y");
    }

    #[test]
    fn preserves_surrounding_text() {
        env::set_var("QPX_TEST_ENVSUBST_MID", "val");
        let result = expand_env("prefix-${QPX_TEST_ENVSUBST_MID}-suffix").unwrap();
        assert_eq!(result, "prefix-val-suffix");
        env::remove_var("QPX_TEST_ENVSUBST_MID");
    }
}
