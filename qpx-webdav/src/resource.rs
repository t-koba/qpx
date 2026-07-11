use anyhow::{Result, anyhow};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Canonical, root-relative WebDAV resource identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    pub fn parse(path: &str) -> Result<Self> {
        let decoded = percent_decode_str(path)
            .decode_utf8()
            .map_err(|_| anyhow!("WebDAV resource path is not valid UTF-8"))?;
        let path = decoded.split(['?', '#']).next().unwrap_or_default();
        let mut segments = Vec::new();
        for segment in path.split('/') {
            match segment {
                "" | "." => {}
                ".." => return Err(anyhow!("WebDAV resource path traversal is forbidden")),
                value
                    if value.contains('\\')
                        || value.contains('\0')
                        || value.chars().any(char::is_control) =>
                {
                    return Err(anyhow!(
                        "WebDAV resource path contains a forbidden character"
                    ));
                }
                value => segments.push(value),
            }
        }
        Ok(Self(format!("/{}", segments.join("/"))))
    }

    pub fn root() -> Self {
        Self("/".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|segment| !segment.is_empty())
    }

    pub fn parent(&self) -> Option<Self> {
        if self.0 == "/" {
            return None;
        }
        let (parent, _) = self.0.rsplit_once('/')?;
        Some(if parent.is_empty() {
            Self::root()
        } else {
            Self(parent.to_string())
        })
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_resource_paths_and_rejects_traversal() {
        assert_eq!(ResourceId::parse("/a//b").unwrap().as_str(), "/a/b");
        assert_eq!(
            ResourceId::parse("/%E6%96%87%E6%9B%B8").unwrap().as_str(),
            "/文書"
        );
        assert!(ResourceId::parse("/a/%2e%2e/secret").is_err());
        assert!(ResourceId::parse("/a%2fb/../secret").is_err());
        assert!(ResourceId::parse("/a\\b").is_err());
    }
}
