use regex::Regex;
use std::env;
use thiserror::Error;

type Result<T> = std::result::Result<T, EnvSubstError>;

/// Error returned while expanding `${VAR}` expressions.
#[derive(Debug, Error)]
pub enum EnvSubstError {
    /// Regex compilation failed.
    #[error("failed to compile environment substitution pattern")]
    Pattern(#[from] regex::Error),
    /// The regex matched without a full capture.
    #[error("envsubst capture error")]
    Capture,
    /// The variable-name capture was missing.
    #[error("envsubst variable capture missing")]
    VariableCaptureMissing,
    /// A variable was missing and no default was provided.
    #[error("missing environment variable: {0}")]
    MissingVariable(String),
}

/// Expands `${NAME}` and `${NAME:-default}` expressions using process env.
pub fn expand_env(input: &str) -> Result<String> {
    expand_env_with(input, |key| env::var(key).ok())
}

pub(crate) fn expand_env_with(
    input: &str,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<String> {
    let re = Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")?;
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    for caps in re.captures_iter(input) {
        let m = caps.get(0).ok_or(EnvSubstError::Capture)?;
        out.push_str(&input[last..m.start()]);
        let key = caps
            .get(1)
            .ok_or(EnvSubstError::VariableCaptureMissing)?
            .as_str();
        let default = caps.get(2).map(|m| m.as_str());
        let value = match lookup(key) {
            Some(v) => v,
            None => match default {
                Some(d) => d.to_string(),
                None => return Err(EnvSubstError::MissingVariable(key.to_string())),
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
