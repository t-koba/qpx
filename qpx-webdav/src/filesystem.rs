use crate::{ResourceId, ResourceMetadata, ResourceRead, WebDavDataStore};
use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use bytes::Bytes;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const READ_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;
const READ_CACHE_MAX_ENTRIES: usize = 64;
const READ_CACHE_MAX_OBJECT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
struct ReadCacheEntry {
    resource: ResourceId,
    content_length: u64,
    modified: SystemTime,
    read: ResourceRead,
}

#[derive(Debug, Clone, Default)]
struct ReadCacheSnapshot {
    entries: Vec<ReadCacheEntry>,
}

#[derive(Debug)]
pub struct FileSystemDataStore {
    root: PathBuf,
    read_cache: ArcSwap<ReadCacheSnapshot>,
}

impl FileSystemDataStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        fs::create_dir_all(root.as_ref())?;
        let root = root.as_ref().canonicalize()?;
        if fs::symlink_metadata(&root)?.file_type().is_symlink() {
            return Err(anyhow!("WebDAV root must not be a symlink"));
        }
        Ok(Self {
            root,
            read_cache: ArcSwap::from_pointee(ReadCacheSnapshot::default()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resource_path_buffer(&self, resource: &ResourceId) -> PathBuf {
        let capacity = self
            .root
            .as_os_str()
            .as_encoded_bytes()
            .len()
            .saturating_add(resource.as_str().len())
            .saturating_add(1);
        let mut path = PathBuf::with_capacity(capacity);
        path.push(&self.root);
        path
    }

    fn resolve(&self, resource: &ResourceId, allow_missing_leaf: bool) -> Result<PathBuf> {
        let mut path = self.resource_path_buffer(resource);
        let mut segments = resource.segments().peekable();
        while let Some(segment) = segments.next() {
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
                        && segments.peek().is_none() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(path)
    }

    fn resolve_existing(&self, resource: &ResourceId) -> Result<(PathBuf, fs::Metadata)> {
        let mut path = self.resource_path_buffer(resource);
        if resource.is_root() {
            return Ok((path, fs::symlink_metadata(&self.root)?));
        }
        let mut leaf_metadata = None;
        for segment in resource.segments() {
            path.push(segment);
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(anyhow!("WebDAV symlink traversal is forbidden"));
            }
            leaf_metadata = Some(metadata);
        }
        Ok((
            path,
            leaf_metadata.ok_or_else(|| anyhow!("WebDAV resource path is empty"))?,
        ))
    }

    fn resource_metadata(metadata: &fs::Metadata) -> Result<(ResourceMetadata, SystemTime)> {
        let modified_time = metadata.modified()?;
        let modified = modified_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let modified_nanos = modified_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        Ok((
            ResourceMetadata {
                is_collection: metadata.is_dir(),
                content_length: metadata.len(),
                content_type: None,
                etag: format!(
                    "\"{:x}-{:x}-{:x}\"",
                    metadata.len(),
                    modified,
                    modified_nanos
                ),
                modified_unix_seconds: modified,
            },
            modified_time,
        ))
    }

    fn invalidate_read_cache(&self, resource: &ResourceId) {
        self.read_cache.rcu(|current| {
            let mut entries = Vec::with_capacity(current.entries.len());
            for entry in &current.entries {
                if resource_contains(resource, &entry.resource) {
                    continue;
                }
                entries.push(entry.clone());
            }
            Arc::new(ReadCacheSnapshot { entries })
        });
    }

    fn cache_read(
        &self,
        resource: &ResourceId,
        content_length: u64,
        modified: SystemTime,
        read: &ResourceRead,
    ) {
        if read.body.len() > READ_CACHE_MAX_OBJECT_BYTES {
            return;
        }
        let new_entry = ReadCacheEntry {
            resource: resource.clone(),
            content_length,
            modified,
            read: read.clone(),
        };
        self.read_cache.rcu(|current| {
            let mut entries =
                Vec::with_capacity(current.entries.len().min(READ_CACHE_MAX_ENTRIES - 1) + 1);
            entries.push(new_entry.clone());
            let mut total_bytes = read.body.len();
            for entry in &current.entries {
                if entry.resource == *resource
                    || entries.len() == READ_CACHE_MAX_ENTRIES
                    || total_bytes + entry.read.body.len() > READ_CACHE_MAX_BYTES
                {
                    continue;
                }
                total_bytes += entry.read.body.len();
                entries.push(entry.clone());
            }
            Arc::new(ReadCacheSnapshot { entries })
        });
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
        let metadata = match self.resolve_existing(resource) {
            Ok((_, metadata)) => metadata,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        Ok(Some(Self::resource_metadata(&metadata)?.0))
    }

    fn read(&self, resource: &ResourceId) -> Result<Bytes> {
        let Some(read) = self.read_with_metadata(resource)? else {
            return Err(anyhow!("WebDAV resource does not exist"));
        };
        if read.metadata.is_collection {
            return Err(anyhow!("WebDAV resource is not a regular file"));
        }
        Ok(read.body)
    }

    fn read_with_metadata(&self, resource: &ResourceId) -> Result<Option<ResourceRead>> {
        let (path, metadata) = match self.resolve_existing(resource) {
            Ok(resolved) => resolved,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let modified = metadata.modified()?;
        if !metadata.is_file() {
            let resource_metadata = Self::resource_metadata(&metadata)?.0;
            let etag = http::HeaderValue::from_str(&resource_metadata.etag)?;
            return Ok(Some(ResourceRead {
                metadata: Arc::new(resource_metadata),
                etag,
                body: Bytes::new(),
                file: None,
            }));
        }
        let snapshot = self.read_cache.load();
        if let Some(entry) = snapshot.entries.iter().find(|entry| {
            entry.resource.is_same_resource(resource)
                && entry.content_length == metadata.len()
                && entry.modified == modified
        }) {
            return Ok(Some(entry.read.clone()));
        }
        drop(snapshot);
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&path)?;
        let opened_metadata = file.metadata()?;
        if !opened_metadata.is_file()
            || opened_metadata.len() != metadata.len()
            || opened_metadata.modified()? != modified
        {
            return Err(anyhow!("WebDAV resource changed while it was opened"));
        }
        let mut bytes = Vec::with_capacity(metadata.len().min(usize::MAX as u64) as usize);
        file.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(anyhow!("WebDAV resource length changed while it was read"));
        }
        let completed_metadata = file.metadata()?;
        if completed_metadata.len() != metadata.len() || completed_metadata.modified()? != modified
        {
            return Err(anyhow!("WebDAV resource changed while it was read"));
        }
        let body = Bytes::from(bytes);
        let resource_metadata = Self::resource_metadata(&metadata)?.0;
        let etag = http::HeaderValue::from_str(&resource_metadata.etag)?;
        let read = ResourceRead {
            metadata: Arc::new(resource_metadata),
            etag,
            body,
            file: Some(Arc::new(file)),
        };
        self.cache_read(resource, metadata.len(), modified, &read);
        Ok(Some(read))
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
        self.invalidate_read_cache(resource);
        Ok(created)
    }

    fn create_collection(&self, resource: &ResourceId) -> Result<()> {
        self.require_parent(resource)?;
        fs::create_dir(self.resolve(resource, true)?)?;
        Ok(())
    }

    fn delete(&self, resource: &ResourceId) -> Result<()> {
        if resource.is_root() {
            return Err(anyhow!("WebDAV root deletion is forbidden"));
        }
        let path = self.resolve(resource, false)?;
        self.remove_existing(&path)?;
        self.invalidate_read_cache(resource);
        Ok(())
    }

    fn copy(&self, source: &ResourceId, destination: &ResourceId, overwrite: bool) -> Result<()> {
        let source_path = self.resolve(source, false)?;
        self.require_parent(destination)?;
        let destination_path = self.resolve(destination, true)?;
        if destination_path.exists() {
            if !overwrite {
                return Err(anyhow!("WebDAV destination already exists"));
            }
            self.remove_existing(&destination_path)?;
        }
        Self::copy_tree(&source_path, &destination_path)?;
        self.invalidate_read_cache(destination);
        Ok(())
    }

    fn move_resource(
        &self,
        source: &ResourceId,
        destination: &ResourceId,
        overwrite: bool,
    ) -> Result<()> {
        let source_path = self.resolve(source, false)?;
        self.require_parent(destination)?;
        let destination_path = self.resolve(destination, true)?;
        if destination_path.exists() {
            if !overwrite {
                return Err(anyhow!("WebDAV destination already exists"));
            }
            self.remove_existing(&destination_path)?;
        }
        fs::rename(source_path, destination_path).with_context(|| "WebDAV MOVE must be atomic")?;
        self.invalidate_read_cache(source);
        self.invalidate_read_cache(destination);
        Ok(())
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

fn resource_contains(parent: &ResourceId, child: &ResourceId) -> bool {
    parent == child
        || parent.is_root()
        || child
            .as_str()
            .strip_prefix(parent.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
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
        assert_eq!(store.read(&file).unwrap(), b"first".as_slice());
        assert!(!store.put(&file, b"second", Some("text/plain")).unwrap());
        assert_eq!(store.read(&file).unwrap(), b"second".as_slice());
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
