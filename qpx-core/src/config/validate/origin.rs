use super::super::types::OriginConfig;
use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::path::Path;

pub(super) fn validate_origins(origins: &OriginConfig) -> Result<()> {
    let mut names = HashSet::new();
    for origin in &origins.webdav {
        if origin.name.trim().is_empty() {
            return Err(anyhow!("origins.webdav[].name must not be empty"));
        }
        if !names.insert(origin.name.as_str()) {
            return Err(anyhow!("duplicate WebDAV origin name: {}", origin.name));
        }
        if !Path::new(&origin.root).is_absolute() || !Path::new(&origin.metadata).is_absolute() {
            return Err(anyhow!(
                "WebDAV origin {} root and metadata paths must be absolute",
                origin.name
            ));
        }
        let root = Path::new(&origin.root);
        let metadata = Path::new(&origin.metadata);
        if metadata == root || metadata.starts_with(root) {
            return Err(anyhow!(
                "WebDAV origin {} metadata must be outside its served root",
                origin.name
            ));
        }
        if origin.max_depth == 0
            || origin.max_multistatus_entries == 0
            || origin.max_lock_timeout_seconds == 0
        {
            return Err(anyhow!(
                "WebDAV origin {} limits must be greater than zero",
                origin.name
            ));
        }
    }
    Ok(())
}
