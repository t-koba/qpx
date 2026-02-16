use crate::envsubst::expand_env;
use anyhow::{anyhow, Context, Result};
use serde_yaml::{Mapping, Value};
use std::fs;
use std::path::{Path, PathBuf};

use super::types::Config;
use super::validate::validate_config;

pub fn load_config(path: &Path) -> Result<Config> {
    use serde::de::IntoDeserializer;

    let mut stack = Vec::new();
    let mut sources = Vec::new();
    let value = load_value(path, &mut stack, &mut sources)?;
    let mut ignored = Vec::new();
    let de = value.into_deserializer();
    let config: Config = serde_ignored::deserialize(de, |path| ignored.push(path.to_string()))
        .with_context(|| format!("failed to deserialize config: {}", path.display()))?;
    if !ignored.is_empty() {
        ignored.sort();
        ignored.dedup();
        return Err(anyhow!(
            "unknown config keys (fix typos to avoid unexpected defaults): {}",
            ignored.join(", ")
        ));
    }
    validate_config(&config)?;
    Ok(config)
}

pub fn load_config_with_sources(path: &Path) -> Result<(Config, Vec<PathBuf>)> {
    use serde::de::IntoDeserializer;

    let mut stack = Vec::new();
    let mut sources = Vec::new();
    let value = load_value(path, &mut stack, &mut sources)?;
    let mut ignored = Vec::new();
    let de = value.into_deserializer();
    let config: Config = serde_ignored::deserialize(de, |path| ignored.push(path.to_string()))
        .with_context(|| format!("failed to deserialize config: {}", path.display()))?;
    if !ignored.is_empty() {
        ignored.sort();
        ignored.dedup();
        return Err(anyhow!(
            "unknown config keys (fix typos to avoid unexpected defaults): {}",
            ignored.join(", ")
        ));
    }
    validate_config(&config)?;
    Ok((config, sources))
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
    match (base, overlay) {
        (Value::Mapping(mut a), Value::Mapping(b)) => {
            for (k, v) in b {
                let entry = a.remove(&k);
                let merged = match entry {
                    Some(existing) => merge_values(existing, v),
                    None => v,
                };
                a.insert(k, merged);
            }
            Value::Mapping(a)
        }
        (_, v) => v,
    }
}
