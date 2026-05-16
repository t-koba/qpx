use anyhow::{Result, anyhow};
use regex::Regex;
use std::env;

pub fn expand_env(input: &str) -> Result<String> {
    expand_env_with(input, |key| env::var(key).ok())
}

fn expand_env_with(input: &str, mut lookup: impl FnMut(&str) -> Option<String>) -> Result<String> {
    let re = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")?;
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for caps in re.captures_iter(input) {
        let m = caps
            .get(0)
            .ok_or_else(|| anyhow!("envsubst capture error"))?;
        out.push_str(&input[last..m.start()]);
        let key = caps
            .get(1)
            .ok_or_else(|| anyhow!("envsubst variable capture missing"))?
            .as_str();
        let default = caps.get(2).map(|m| m.as_str());
        let value = match lookup(key) {
            Some(v) => v,
            None => match default {
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
    use std::collections::HashMap;

    fn expand_env_from(input: &str, vars: &[(&str, &str)]) -> Result<String> {
        let vars = vars
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<HashMap<_, _>>();
        expand_env_with(input, |key| vars.get(key).cloned())
    }

    #[test]
    fn passthrough_without_variables() {
        let result = expand_env("hello world").unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn expands_set_variable() {
        let result = expand_env_from(
            "${QPX_TEST_ENVSUBST_A}",
            &[("QPX_TEST_ENVSUBST_A", "alpha")],
        )
        .unwrap();
        assert_eq!(result, "alpha");
    }

    #[test]
    fn uses_default_when_unset() {
        let result = expand_env_from("${QPX_TEST_ENVSUBST_UNSET:-fallback}", &[]).unwrap();
        assert_eq!(result, "fallback");
    }

    #[test]
    fn errors_on_missing_variable_without_default() {
        let result = expand_env_from("${QPX_TEST_ENVSUBST_MISSING}", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_variables() {
        let result = expand_env_from(
            "${QPX_TEST_ENVSUBST_X}-${QPX_TEST_ENVSUBST_Y}",
            &[
                ("QPX_TEST_ENVSUBST_X", "one"),
                ("QPX_TEST_ENVSUBST_Y", "two"),
            ],
        )
        .unwrap();
        assert_eq!(result, "one-two");
    }

    #[test]
    fn preserves_surrounding_text() {
        let result = expand_env_from(
            "prefix-${QPX_TEST_ENVSUBST_MID}-suffix",
            &[("QPX_TEST_ENVSUBST_MID", "val")],
        )
        .unwrap();
        assert_eq!(result, "prefix-val-suffix");
    }
}
