use crate::{ResourceId, ResourceMetadata, WebDavDataStore};
use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use uuid::Uuid;

#[derive(Debug)]
pub struct FileSystemDataStore {
    root: PathBuf,
}

impl FileSystemDataStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        fs::create_dir_all(root.as_ref())?;
        let root = root.as_ref().canonicalize()?;
        if fs::symlink_metadata(&root)?.file_type().is_symlink() {
            return Err(anyhow!("WebDAV root must not be a symlink"));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve(&self, resource: &ResourceId, allow_missing_leaf: bool) -> Result<PathBuf> {
        let mut path = self.root.clone();
        let segments = resource.segments().collect::<Vec<_>>();
        for (index, segment) in segments.iter().enumerate() {
            path.push(segment);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(anyhow!("WebDAV symlink traversal is forbidden"));
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && allow_missing_leaf
                        && index + 1 == segments.len() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(path)
    }

    fn require_parent(&self, resource: &ResourceId) -> Result<PathBuf> {
        let parent = resource
            .parent()
            .ok_or_else(|| anyhow!("WebDAV root has no parent"))?;
        let path = self.resolve(&parent, false)?;
        if !path.is_dir() {
            return Err(anyhow!("WebDAV parent is not a collection"));
        }
        Ok(path)
    }

    fn remove_existing(&self, path: &Path) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow!("WebDAV symlink traversal is forbidden"));
        }
        if metadata.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(source)?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow!("WebDAV symlink traversal is forbidden"));
        }
        if metadata.is_file() {
            fs::copy(source, destination)?;
            return Ok(());
        }
        fs::create_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            Self::copy_tree(&entry.path(), &destination.join(entry.file_name()))?;
        }
        Ok(())
    }
}

impl WebDavDataStore for FileSystemDataStore {
    fn metadata(&self, resource: &ResourceId) -> Result<Option<ResourceMetadata>> {
        let path = match self.resolve(resource, false) {
            Ok(path) => path,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let metadata = fs::metadata(path)?;
        let modified = metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let etag_material = format!("{}:{}:{}", resource, metadata.len(), modified);
        let etag = format!("\"{:x}\"", Sha256::digest(etag_material.as_bytes()));
        Ok(Some(ResourceMetadata {
            is_collection: metadata.is_dir(),
            content_length: metadata.len(),
            content_type: None,
            etag,
            modified_unix_seconds: modified,
        }))
    }

    fn read(&self, resource: &ResourceId) -> Result<Vec<u8>> {
        let path = self.resolve(resource, false)?;
        if !path.is_file() {
            return Err(anyhow!("WebDAV resource is not a regular file"));
        }
        fs::read(path).map_err(Into::into)
    }

    fn put(&self, resource: &ResourceId, body: &[u8], _content_type: Option<&str>) -> Result<bool> {
        self.require_parent(resource)?;
        let path = self.resolve(resource, true)?;
        let created = !path.exists();
        if !created && !fs::symlink_metadata(&path)?.is_file() {
            return Err(anyhow!("WebDAV PUT target is not a regular file"));
        }
        let temporary = path.with_extension(format!("qpx-upload-{}", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)
            .with_context(|| "failed to atomically install DAV resource")?;
        Ok(created)
    }

    fn create_collection(&self, resource: &ResourceId) -> Result<()> {
        self.require_parent(resource)?;
        fs::create_dir(self.resolve(resource, true)?)?;
        Ok(())
    }

    fn delete(&self, resource: &ResourceId) -> Result<()> {
        if resource == &ResourceId::root() {
            return Err(anyhow!("WebDAV root deletion is forbidden"));
        }
        let path = self.resolve(resource, false)?;
        self.remove_existing(&path)
    }

    fn copy(&self, source: &ResourceId, destination: &ResourceId, overwrite: bool) -> Result<()> {
        let source = self.resolve(source, false)?;
        self.require_parent(destination)?;
        let destination = self.resolve(destination, true)?;
        if destination.exists() {
            if !overwrite {
                return Err(anyhow!("WebDAV destination already exists"));
            }
            self.remove_existing(&destination)?;
        }
        Self::copy_tree(&source, &destination)
    }

    fn move_resource(
        &self,
        source: &ResourceId,
        destination: &ResourceId,
        overwrite: bool,
    ) -> Result<()> {
        let source = self.resolve(source, false)?;
        self.require_parent(destination)?;
        let destination = self.resolve(destination, true)?;
        if destination.exists() {
            if !overwrite {
                return Err(anyhow!("WebDAV destination already exists"));
            }
            self.remove_existing(&destination)?;
        }
        fs::rename(source, destination).with_context(|| "WebDAV MOVE must be atomic")
    }

    fn children(&self, resource: &ResourceId) -> Result<Vec<ResourceId>> {
        let path = self.resolve(resource, false)?;
        if !path.is_dir() {
            return Ok(Vec::new());
        }
        let mut children = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_symlink() {
                return Err(anyhow!("WebDAV collection contains a forbidden symlink"));
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("WebDAV resource name is not valid UTF-8"))?;
            children.push(ResourceId::parse(&format!("{resource}/{name}"))?);
        }
        children.sort();
        Ok(children)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn filesystem_store_is_atomic_and_confined() {
        let directory = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        store
            .create_collection(&ResourceId::parse("/docs").unwrap())
            .unwrap();
        let file = ResourceId::parse("/docs/report.txt").unwrap();
        assert!(store.put(&file, b"first", Some("text/plain")).unwrap());
        assert!(!store.put(&file, b"second", Some("text/plain")).unwrap());
        assert_eq!(store.read(&file).unwrap(), b"second");
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_store_rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().unwrap();
        let outside = tempdir().unwrap();
        symlink(outside.path(), directory.path().join("escape")).unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        assert!(
            store
                .read(&ResourceId::parse("/escape/secret").unwrap())
                .is_err()
        );
    }
}
