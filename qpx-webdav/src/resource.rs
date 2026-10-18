use anyhow::{Result, anyhow};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::sync::Arc;

/// Canonical, root-relative WebDAV resource identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceId(Arc<str>);

impl ResourceId {
    pub fn parse(path: &str) -> Result<Self> {
        let decoded = percent_decode_str(path)
            .decode_utf8()
            .map_err(|_| anyhow!("WebDAV resource path is not valid UTF-8"))?;
        let path = decoded.split(['?', '#']).next().unwrap_or_default();
        let mut canonical = String::with_capacity(path.len().saturating_add(1));
        canonical.push('/');
        let mut has_segment = false;
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
                value => {
                    if has_segment {
                        canonical.push('/');
                    }
                    canonical.push_str(value);
                    has_segment = true;
                }
            }
        }
        Ok(Self(canonical.into()))
    }

    /// Validate the representation emitted by Serialize, not a URL path.
    /// Percent sequences are literal here: decoding again would change valid
    /// identifiers such as `/%2e`, originally parsed from `/%252e`.
    fn from_canonical(path: String) -> Result<Self> {
        let relative = path
            .strip_prefix('/')
            .ok_or_else(|| anyhow!("WebDAV resource path must be root-relative"))?;
        if !relative.is_empty()
            && relative
                .split('/')
                .any(|segment| matches!(segment, "" | "." | ".."))
        {
            return Err(anyhow!("WebDAV resource path is not canonical"));
        }
        if path.contains(['?', '#', '\\']) || path.chars().any(char::is_control) {
            return Err(anyhow!(
                "WebDAV resource path contains a forbidden character"
            ));
        }
        Ok(Self(path.into()))
    }

    pub fn root() -> Self {
        Self(Arc::from("/"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_same_resource(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self == other
    }

    /// Returns true when `other` names this resource or a descendant of it.
    ///
    /// Both identifiers are already canonical root-relative paths, so a
    /// segment-boundary prefix check is sufficient (`/a` contains `/a/b` but
    /// not `/ab`; the root contains every resource).
    pub(crate) fn is_ancestor_or_same(&self, other: &Self) -> bool {
        self == other
            || self.is_root()
            || other
                .as_str()
                .strip_prefix(self.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    pub fn is_root(&self) -> bool {
        self.0.as_ref() == "/"
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|segment| !segment.is_empty())
    }

    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        let (parent, _) = self.0.rsplit_once('/')?;
        Some(if parent.is_empty() {
            Self::root()
        } else {
            Self(Arc::from(parent))
        })
    }
}

impl Serialize for ResourceId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ResourceId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_canonical(value).map_err(serde::de::Error::custom)
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
    fn deserialize_rejects_noncanonical_resource_paths() {
        for path in [
            "/../outside.txt",
            "/a/../../outside.txt",
            "",
            "outside.txt",
            "../outside.txt",
            "//outside.txt",
            "/a//b",
            "/a/",
            "/.",
            "/a/./b",
            "/a/..",
            "/a?query",
            "/a#fragment",
            "/a\\b",
            "/a\0b",
            "/a\nb",
            "/a\u{7f}b",
            "/a\u{85}b",
        ] {
            let json = serde_json::to_string(path).unwrap();
            assert!(
                serde_json::from_str::<ResourceId>(&json).is_err(),
                "accepted noncanonical path {path:?}"
            );
        }
        // JSON escapes must not hide traversal from canonical validation.
        assert!(serde_json::from_str::<ResourceId>(r#""/\u002e\u002e/outside.txt""#).is_err());
    }

    #[test]
    fn serialized_resource_ids_roundtrip_without_percent_decoding() {
        for input in [
            "/",
            "/a//./b/",
            "/%E6%96%87%E6%9B%B8",
            "/%252e/%252f/%252e%252e/outside.txt",
            "/%253f/%2523/%255c/%2500/%250a/%25/not%25hex",
        ] {
            let resource = ResourceId::parse(input).unwrap();
            let json = serde_json::to_string(&resource).unwrap();
            let restored: ResourceId = serde_json::from_str(&json).unwrap();
            assert_eq!(restored.as_str(), resource.as_str());
            assert_eq!(restored, resource);
        }
        let resource = ResourceId::parse("/%252e/%252f").unwrap();
        assert_eq!(resource.as_str(), "/%2e/%2f");
    }

    #[test]
    fn deserialized_resource_cannot_overwrite_a_filesystem_sibling() {
        use crate::{FileSystemDataStore, WebDavDataStore};

        let directory = tempfile::tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path().join("root")).unwrap();
        let sentinel = directory.path().join("outside.txt");
        std::fs::write(&sentinel, b"sentinel").unwrap();

        let attempt = serde_json::from_str::<ResourceId>(r#""/../outside.txt""#)
            .map_err(anyhow::Error::from)
            .and_then(|resource| store.put(&resource, b"overwritten", None));
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
        assert!(attempt.is_err());

        // Percent sequences in serialized canonical paths are literal filenames,
        // not another opportunity for URL decoding or traversal.
        let literal: ResourceId = serde_json::from_str(r#""/%2e%2e/outside.txt""#).unwrap();
        let parent = literal.parent().unwrap();
        store.create_collection(&parent).unwrap();
        store.put(&literal, b"inside", None).unwrap();
        assert_eq!(store.read(&literal).unwrap(), b"inside".as_slice());
        assert_eq!(
            std::fs::read(store.root().join("%2e%2e/outside.txt")).unwrap(),
            b"inside"
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    }

    #[test]
    fn ancestor_or_same_checks_segment_boundaries() {
        let parent = ResourceId::parse("/a").unwrap();
        assert!(parent.is_ancestor_or_same(&ResourceId::parse("/a").unwrap()));
        assert!(parent.is_ancestor_or_same(&ResourceId::parse("/a/b").unwrap()));
        assert!(parent.is_ancestor_or_same(&ResourceId::parse("/a/b/c").unwrap()));
        assert!(!parent.is_ancestor_or_same(&ResourceId::parse("/ab").unwrap()));
        assert!(!parent.is_ancestor_or_same(&ResourceId::parse("/b").unwrap()));
        assert!(!parent.is_ancestor_or_same(&ResourceId::parse("/").unwrap()));

        let root = ResourceId::root();
        assert!(root.is_ancestor_or_same(&ResourceId::parse("/").unwrap()));
        assert!(root.is_ancestor_or_same(&parent));
        assert!(!parent.is_ancestor_or_same(&root));
    }

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
