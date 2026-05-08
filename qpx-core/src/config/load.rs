use crate::envsubst::expand_env;
use anyhow::{anyhow, Context, Result};
use serde_yaml::{Mapping, Value};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use super::types::Config;
use super::validate::validate_config;

pub fn load_config(path: &Path) -> Result<Config> {
    let mut stack = Vec::new();
    let mut sources = Vec::new();
    let value = load_value(path, &mut stack, &mut sources)?;
    deserialize_config_value(value, format_args!("{}", path.display()))
}

pub fn load_config_with_sources(path: &Path) -> Result<(Config, Vec<PathBuf>)> {
    let mut stack = Vec::new();
    let mut sources = Vec::new();
    let value = load_value(path, &mut stack, &mut sources)?;
    let config = deserialize_config_value(value, format_args!("{}", path.display()))?;
    Ok((config, sources))
}

pub fn load_configs(paths: &[PathBuf]) -> Result<Config> {
    if paths.is_empty() {
        return Err(anyhow!("no config files provided"));
    }

    let mut sources = Vec::new();
    let mut merged = Value::Mapping(Mapping::new());
    for path in paths {
        let mut stack = Vec::new();
        let value = load_value(path, &mut stack, &mut sources)?;
        merged = merge_values(merged, value);
    }

    deserialize_config_value(
        merged,
        format_args!("merged config from {}", path_list(paths)),
    )
}

pub fn load_configs_with_sources(paths: &[PathBuf]) -> Result<(Config, Vec<PathBuf>)> {
    if paths.is_empty() {
        return Err(anyhow!("no config files provided"));
    }

    let mut sources = Vec::new();
    let mut merged = Value::Mapping(Mapping::new());
    for path in paths {
        let mut stack = Vec::new();
        let value = load_value(path, &mut stack, &mut sources)?;
        merged = merge_values(merged, value);
    }

    let config = deserialize_config_value(
        merged,
        format_args!("merged config from {}", path_list(paths)),
    )?;
    Ok((config, sources))
}

fn deserialize_config_value(value: Value, context: fmt::Arguments<'_>) -> Result<Config> {
    use serde::de::IntoDeserializer;

    let context = context.to_string();
    let mut ignored = Vec::new();
    let de = value.into_deserializer();
    let config: Config = serde_ignored::deserialize(de, |path| ignored.push(path.to_string()))
        .map_err(|err| anyhow!("failed to deserialize config: {context}: {err}"))?;
    if !ignored.is_empty() {
        ignored.sort();
        ignored.dedup();
        return Err(anyhow!(
            "unknown config keys in {context} (fix typos to avoid unexpected defaults): {}",
            ignored.join(", ")
        ));
    }
    validate_config(&config)?;
    Ok(config)
}

fn path_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn load_value(path: &Path, stack: &mut Vec<PathBuf>, sources: &mut Vec<PathBuf>) -> Result<Value> {
    let canonical =
        fs::canonicalize(path).with_context(|| format!("config not found: {}", path.display()))?;
    if stack.contains(&canonical) {
        return Err(anyhow!(
            "config include loop detected at {}",
            canonical.display()
        ));
    }
    if !sources.contains(&canonical) {
        sources.push(canonical.clone());
    }
    stack.push(canonical.clone());

    let raw = fs::read_to_string(&canonical)
        .with_context(|| format!("failed to read config: {}", canonical.display()))?;
    let expanded = expand_env(&raw)
        .with_context(|| format!("env expansion failed for {}", canonical.display()))?;
    let mut value: Value = serde_yaml::from_str(&expanded)
        .with_context(|| format!("yaml parse failed for {}", canonical.display()))?;

    let mut merged = Value::Mapping(Mapping::new());
    if let Value::Mapping(map) = &mut value {
        if let Some(includes) = map.remove(Value::String("include".to_string())) {
            let include_list = includes.as_sequence().cloned().unwrap_or_default();
            for inc in include_list {
                let inc_path = match inc {
                    Value::String(s) => canonical.parent().unwrap_or(Path::new(".")).join(s),
                    _ => return Err(anyhow!("include entries must be strings")),
                };
                let inc_value = load_value(&inc_path, stack, sources)?;
                merged = merge_values(merged, inc_value);
            }
        }
    }

    merged = merge_values(merged, value);
    stack.pop();
    Ok(merged)
}

fn merge_values(base: Value, overlay: Value) -> Value {
    merge_values_at(&[], base, overlay)
}

fn merge_values_at(path: &[String], base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Mapping(mut a), Value::Mapping(b)) => {
            for (k, v) in b {
                let mut next_path = path.to_vec();
                if let Value::String(key) = &k {
                    next_path.push(key.clone());
                }
                let entry = a.remove(&k);
                let merged = match entry {
                    Some(existing) if should_append_sequence(next_path.as_slice()) => {
                        merge_sequence_values(existing, v)
                    }
                    Some(existing) => merge_values_at(next_path.as_slice(), existing, v),
                    None => v,
                };
                a.insert(k, merged);
            }
            Value::Mapping(a)
        }
        (_, v) => v,
    }
}

fn should_append_sequence(path: &[String]) -> bool {
    matches!(
        path,
        [key] if matches!(key.as_str(), "edges" | "upstreams" | "caches")
    ) || matches!(
        path,
        [section, key]
            if matches!(
                (section.as_str(), key.as_str()),
                ("http", "guard_profiles")
                    | ("http", "module_chains")
                    | ("traffic", "rate_limit_profiles")
                    | ("security", "identity_sources")
                    | ("security", "named_sets")
                    | ("security", "upstream_trust_profiles")
            )
    ) || matches!(
        path,
        [section, subsection, key]
            if matches!(
                (section.as_str(), subsection.as_str(), key.as_str()),
                ("security", "decisions", "ext_authz")
                    | ("security", "auth", "users")
            )
    )
}

fn merge_sequence_values(base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Sequence(mut a), Value::Sequence(b)) => {
            a.extend(b);
            Value::Sequence(a)
        }
        (_, v) => v,
    }
}
