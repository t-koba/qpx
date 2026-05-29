use std::path::Path;

use qpx_core::envsubst::expand_env;

use super::QpxfConfig;

pub fn load_config(path: &Path) -> anyhow::Result<QpxfConfig> {
    let content = std::fs::read_to_string(path)?;
    let expanded = expand_env(&content)?;
    let config: QpxfConfig = serde_yaml::from_str(&expanded)?;
    Ok(config)
}
