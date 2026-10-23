use crate::{ResourceId, ResourceMetadata, ResourceRead, WebDavDataStore};
use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use bytes::Bytes;
use cap_fs_ext::{OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
#[cfg(unix)]
use cap_primitives::fs::OpenOptionsExt as _;
use cap_primitives::fs::{self as cap, FollowSymlinks, Metadata, OpenOptions};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const READ_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;
const READ_CACHE_MAX_ENTRIES: usize = 64;
// Keep replayable bodies in memory only while they fit the cache body's
// in-memory tier. Larger resources use their verified file region directly so
// a zero-copy response does not first pay for a redundant materialization.
const READ_CACHE_MAX_OBJECT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct ReadCacheEntry {
    resource: ResourceId,
    content_length: u64,
    modified: SystemTime,
    file_identity: Option<FileIdentity>,
    read: ResourceRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(unix)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(not(unix))]
struct FileIdentity;

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use cap_primitives::fs::MetadataExt as _;

    Some(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn file_identity(_metadata: &Metadata) -> Option<FileIdentity> {
    None
}

#[derive(Debug, Clone, Default)]
struct ReadCacheSnapshot {
    entries: Vec<ReadCacheEntry>,
}

#[derive(Debug)]
pub struct FileSystemDataStore {
    root: PathBuf,
    directory: fs::File,
    read_cache: ArcSwap<ReadCacheSnapshot>,
}

impl FileSystemDataStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = std::path::absolute(root)?;
        // Configuration may have linked ancestors. Acquire them once using
        // ambient authority, but create/open the root leaf relative to that
        // acquired parent without following a link.
        let directory = if let Some(name) = root.file_name() {
            let parent = acquire_configured_directory(root.parent().unwrap())?;
            match cap::open_dir_nofollow(&parent, Path::new(name)) {
                Ok(directory) => directory,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    create_directory(&parent, Path::new(name))?;
                    cap::open_dir_nofollow(&parent, Path::new(name))?
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            acquire_configured_directory(&root)?
        };
        Ok(Self {
            root,
            directory,
            read_cache: ArcSwap::from_pointee(ReadCacheSnapshot::default()),
        })
    }

    /// Advisory configured location only: after a local rename it may no
    /// longer name the acquired directory. Never use this path as I/O authority.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve_parent(&self, resource: &ResourceId) -> Result<Parent> {
        let mut directory = self.directory.try_clone()?;
        let mut segments = resource.segments().peekable();
        while let Some(segment) = segments.next() {
            if segments.peek().is_none() {
                return Ok(Parent {
                    directory,
                    name: segment.into(),
                });
            }
            directory = cap::open_dir_nofollow(&directory, Path::new(segment))?;
        }
        // Only read/stat/list use this reference; mutations reject the root.
        Ok(Parent {
            directory,
            name: ".".into(),
        })
    }

    fn resource_metadata(metadata: &Metadata) -> Result<(ResourceMetadata, SystemTime)> {
        let modified_time = metadata.modified()?.into_std();
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
                if resource.is_ancestor_or_same(&entry.resource) {
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
        metadata: &Metadata,
        modified: SystemTime,
        read: &ResourceRead,
    ) {
        let file_identity = file_identity(metadata);
        let complete_body = read.body.len() as u64 == metadata.len();
        let reusable_file_region =
            read.body.is_empty() && read.file.is_some() && file_identity.is_some();
        if (!complete_body && !reusable_file_region)
            || read.body.len() > READ_CACHE_MAX_OBJECT_BYTES
        {
            return;
        }
        let mut cached_read = read.clone();
        if file_identity.is_none() {
            // Without identity checks only the materialized body is reusable.
            // In particular, retaining an idle file handle on Windows prevents
            // renaming its ancestor directory, even with delete sharing.
            cached_read.file = None;
        }
        let new_entry = ReadCacheEntry {
            resource: resource.clone(),
            content_length: metadata.len(),
            modified,
            file_identity,
            read: cached_read,
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

    fn read_resource(
        &self,
        resource: &ResourceId,
        file_backed: bool,
    ) -> Result<Option<ResourceRead>> {
        // Open before consulting the cache. Only the no-follow open and its
        // own metadata authorize a read, never a check on a pathname.
        let mut file = match self
            .resolve_parent(resource)
            .and_then(|parent| parent.open_read())
        {
            Ok(file) => file,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = Metadata::from_file(&file)?;
        let (resource_metadata, modified) = Self::resource_metadata(&metadata)?;
        let etag = http::HeaderValue::from_str(&resource_metadata.etag)?;
        if !metadata.is_file() {
            return Ok(Some(ResourceRead {
                metadata: Arc::new(resource_metadata),
                etag,
                body: Bytes::new(),
                file: None,
            }));
        }
        let identity = file_identity(&metadata);
        if let Some(entry) = self.read_cache.load().entries.iter().find(|entry| {
            entry.resource.is_same_resource(resource)
                && entry.content_length == metadata.len()
                && entry.modified == modified
                && entry.file_identity == identity
                && (entry.read.body.len() as u64 == metadata.len()
                    || (file_backed && entry.read.file.is_some() && identity.is_some()))
        }) {
            let mut read = entry.read.clone();
            if read.file.is_none() {
                // The cache may retain bytes without a handle. Preserve file-
                // backed responses using this read's verified no-follow open.
                read.file = Some(Arc::new(file));
            }
            return Ok(Some(read));
        }
        let mut body = Bytes::new();
        if !file_backed || metadata.len() <= READ_CACHE_MAX_OBJECT_BYTES as u64 {
            let mut bytes = Vec::with_capacity(metadata.len().min(usize::MAX as u64) as usize);
            file.read_to_end(&mut bytes)?;
            if bytes.len() as u64 != metadata.len() {
                return Err(anyhow!("WebDAV resource length changed while it was read"));
            }
            body = Bytes::from(bytes);
        }
        let completed = Metadata::from_file(&file)?;
        if completed.len() != metadata.len() || completed.modified()?.into_std() != modified {
            return Err(anyhow!("WebDAV resource changed while it was read"));
        }
        let read = ResourceRead {
            metadata: Arc::new(resource_metadata),
            etag,
            body,
            file: Some(Arc::new(file)),
        };
        self.cache_read(resource, &metadata, modified, &read);
        Ok(Some(read))
    }
}

// Only startup configuration uses ambient paths. Missing ancestors are made
// under an acquired parent, rather than checked and later reopened by pathname.
fn acquire_configured_directory(path: &Path) -> Result<fs::File> {
    match cap::open_ambient_dir(path, cap_primitives::ambient_authority()) {
        Ok(directory) => Ok(directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = acquire_configured_directory(
                path.parent()
                    .ok_or_else(|| anyhow!("WebDAV root has no ancestor"))?,
            )?;
            if let Some(name) = path.file_name() {
                create_directory(&parent, Path::new(name))?;
                Ok(cap::open_dir(&parent, Path::new(name))?)
            } else {
                // A configured `missing/..` still creates `missing`, just as
                // create_dir_all did. Only configuration has parent authority.
                Ok(cap::open_parent_dir(
                    &parent,
                    cap_primitives::ambient_authority(),
                )?)
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn create_directory(parent: &fs::File, name: &Path) -> Result<()> {
    match cap::create_dir(parent, name, &cap::DirOptions::new()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// One owned directory capability plus one basename. Local renames do not
/// change which directory object this capability authorizes.
struct Parent {
    directory: fs::File,
    name: PathBuf,
}

impl Parent {
    fn metadata(&self) -> Result<Option<Metadata>> {
        match cap::stat(&self.directory, &self.name, FollowSymlinks::No) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err(anyhow!("WebDAV symlink traversal is forbidden"))
            }
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn validate_read_type(metadata: &Metadata) -> Result<()> {
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(anyhow!(
                "WebDAV read target is not a regular file or directory"
            ));
        }
        Ok(())
    }
    fn open_read(&self) -> Result<fs::File> {
        let metadata = self
            .metadata()?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        self.open_read_with_hint(&metadata)
    }
    fn open_read_with_hint(&self, metadata: &Metadata) -> Result<fs::File> {
        Self::validate_read_type(metadata)?;
        let mut options = OpenOptions::new();
        // On Windows maybe_dir also denies delete sharing. Apply it only to
        // directories, so retained regular-file regions do not block PUT/MOVE.
        // This stat is only a type hint: the subsequent no-follow open remains
        // authoritative if the leaf changes in between.
        options
            .read(true)
            .follow(FollowSymlinks::No)
            .maybe_dir(metadata.is_dir());
        // A regular file or directory can be replaced with a FIFO after stat.
        // Never block on its open; reject the opened special type before I/O.
        #[cfg(unix)]
        options.custom_flags(libc::O_NONBLOCK);
        let file = cap::open(&self.directory, &self.name, &options)?;
        Self::validate_read_type(&Metadata::from_file(&file)?)?;
        Ok(file)
    }
    fn open_dir(&self) -> Result<fs::File> {
        Ok(cap::open_dir_nofollow(&self.directory, &self.name)?)
    }
    fn child(directory: &fs::File, name: std::ffi::OsString) -> Result<Self> {
        Ok(Self {
            directory: directory.try_clone()?,
            name: name.into(),
        })
    }
    fn remove(&self) -> Result<()> {
        let Some(metadata) = self.metadata()? else {
            return Ok(());
        };
        if metadata.is_dir() {
            let directory = self.open_dir()?;
            Self::remove_children(&directory)?;
            // Windows may prevent deletion while the leaf is open. Retain the
            // parent; a relative final unlink never traverses a replacement.
            drop(directory);
            cap::remove_dir(&self.directory, &self.name)?;
        } else {
            cap::remove_file(&self.directory, &self.name)?;
        }
        Ok(())
    }
    fn remove_children(directory: &fs::File) -> Result<()> {
        for entry in cap::read_base_dir(directory)? {
            let child = Self::child(directory, entry?.file_name())?;
            let metadata = cap::stat(directory, &child.name, FollowSymlinks::No)?;
            if metadata.file_type().is_symlink() {
                // Nested links are unlinked, unlike explicitly addressed links.
                // Stable Windows Rust cannot distinguish directory links via
                // FileTypeExt, so retry the directory unlink form if removing
                // the link as a file fails. Both operations are relative to
                // the pinned parent and unlink, rather than traverse, the link.
                let remove_file = cap::remove_file(directory, &child.name);
                #[cfg(windows)]
                if let Err(file_error) = remove_file {
                    if cap::remove_dir(directory, &child.name).is_err() {
                        return Err(file_error.into());
                    }
                }
                #[cfg(not(windows))]
                remove_file?;
            } else {
                child.remove()?;
            }
        }
        Ok(())
    }
    fn copy_to(&self, destination: &Self) -> Result<()> {
        let mut source = self.open_read()?;
        let metadata = source.metadata()?;
        if metadata.is_file() {
            destination.copy_file(&mut source, metadata.permissions())?;
        } else {
            cap::create_dir(
                &destination.directory,
                &destination.name,
                &cap::DirOptions::new(),
            )?;
            let target = destination.open_dir()?;
            for entry in cap::read_base_dir(&source)? {
                let name = entry?.file_name();
                Self::child(&source, name.clone())?.copy_to(&Self::child(&target, name)?)?;
            }
        }
        Ok(())
    }
    fn create_copy_file(&self, permissions: &fs::Permissions) -> Result<fs::File> {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        // Restrict access before the first byte is copied, including on error.
        // The final chmod still restores source permissions masked by umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            options.mode(permissions.mode());
        }
        #[cfg(not(unix))]
        let _ = permissions;
        Ok(cap::open(&self.directory, &self.name, &options)?)
    }
    fn copy_file(&self, source: &mut fs::File, permissions: fs::Permissions) -> Result<()> {
        let mut output = self.create_copy_file(&permissions)?;
        std::io::copy(source, &mut output)?;
        output.set_permissions(permissions)?;
        Ok(())
    }
    fn put(&self, body: &[u8]) -> Result<bool> {
        let metadata = self.metadata()?;
        let created = metadata.is_none();
        if metadata.is_some_and(|metadata| !metadata.is_file()) {
            return Err(anyhow!("WebDAV PUT target is not a regular file"));
        }
        let temporary = PathBuf::from(format!(".qpx-upload-{}", Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options
            .create_new(true)
            .write(true)
            .follow(FollowSymlinks::No);
        let file = cap::open(&self.directory, &temporary, &options)?;
        self.install(body, &temporary, file)?;
        Ok(created)
    }

    fn install(&self, body: &[u8], temporary: &Path, mut file: fs::File) -> Result<()> {
        let result = (|| -> Result<()> {
            file.write_all(body)?;
            file.sync_all()?;
            drop(file);
            cap::rename(&self.directory, temporary, &self.directory, &self.name)
                .with_context(|| "failed to atomically install DAV resource")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = cap::remove_file(&self.directory, temporary);
        }
        result
    }
    fn prepare_destination(&self, overwrite: bool) -> Result<()> {
        if self.metadata()?.is_some() {
            if !overwrite {
                return Err(anyhow!("WebDAV destination already exists"));
            }
            self.remove()?;
        }
        Ok(())
    }
}

impl WebDavDataStore for FileSystemDataStore {
    fn metadata(&self, resource: &ResourceId) -> Result<Option<ResourceMetadata>> {
        let metadata = match self
            .resolve_parent(resource)
            .and_then(|parent| parent.metadata())
        {
            Ok(Some(metadata)) => metadata,
            Ok(None) => return Ok(None),
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(Some(Self::resource_metadata(&metadata)?.0))
    }
    fn read(&self, resource: &ResourceId) -> Result<Bytes> {
        let read = self
            .read_with_metadata(resource)?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        if read.metadata.is_collection {
            return Err(anyhow!("WebDAV resource is not a regular file"));
        }
        Ok(read.body)
    }
    fn read_with_metadata(&self, resource: &ResourceId) -> Result<Option<ResourceRead>> {
        self.read_resource(resource, false)
    }
    fn read_with_metadata_and_content_type_file_backed(
        &self,
        resource: &ResourceId,
        content_type: Option<String>,
    ) -> Result<Option<ResourceRead>> {
        let Some(mut read) = self.read_resource(resource, true)? else {
            return Ok(None);
        };
        if read.metadata.content_type != content_type {
            Arc::make_mut(&mut read.metadata).content_type = content_type;
        }
        Ok(Some(read))
    }
    fn put(&self, resource: &ResourceId, body: &[u8], _content_type: Option<&str>) -> Result<bool> {
        if resource.is_root() {
            return Err(anyhow!("WebDAV root has no parent"));
        }
        let parent = self.resolve_parent(resource)?;
        let created = parent.put(body)?;
        self.invalidate_read_cache(resource);
        Ok(created)
    }
    fn create_collection(&self, resource: &ResourceId) -> Result<()> {
        if resource.is_root() {
            return Err(anyhow!("WebDAV root has no parent"));
        }
        let parent = self.resolve_parent(resource)?;
        cap::create_dir(&parent.directory, &parent.name, &cap::DirOptions::new())?;
        Ok(())
    }
    fn delete(&self, resource: &ResourceId) -> Result<()> {
        if resource.is_root() {
            return Err(anyhow!("WebDAV root deletion is forbidden"));
        }
        let parent = self.resolve_parent(resource)?;
        if parent.metadata()?.is_none() {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
        }
        parent.remove()?;
        self.invalidate_read_cache(resource);
        Ok(())
    }
    fn copy(&self, source: &ResourceId, destination: &ResourceId, overwrite: bool) -> Result<()> {
        if source.is_ancestor_or_same(destination) || destination.is_ancestor_or_same(source) {
            return Err(anyhow!("WebDAV source and destination must not overlap"));
        }
        let source = self.resolve_parent(source)?;
        source
            .metadata()?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        let target = self.resolve_parent(destination)?;
        target.prepare_destination(overwrite)?;
        source.copy_to(&target)?;
        self.invalidate_read_cache(destination);
        Ok(())
    }
    fn move_resource(
        &self,
        source: &ResourceId,
        destination: &ResourceId,
        overwrite: bool,
    ) -> Result<()> {
        if source.is_ancestor_or_same(destination) || destination.is_ancestor_or_same(source) {
            return Err(anyhow!("WebDAV source and destination must not overlap"));
        }
        let origin = self.resolve_parent(source)?;
        origin
            .metadata()?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        let target = self.resolve_parent(destination)?;
        target.prepare_destination(overwrite)?;
        cap::rename(
            &origin.directory,
            &origin.name,
            &target.directory,
            &target.name,
        )
        .with_context(|| "WebDAV MOVE must be atomic")?;
        self.invalidate_read_cache(source);
        self.invalidate_read_cache(destination);
        Ok(())
    }
    fn children(&self, resource: &ResourceId) -> Result<Vec<ResourceId>> {
        let parent = self.resolve_parent(resource)?;
        let metadata = parent
            .metadata()?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        if !metadata.is_dir() {
            return Ok(Vec::new());
        }
        let directory = parent.open_dir()?;
        let mut children = Vec::new();
        for entry in cap::read_base_dir(&directory)? {
            let name = entry?.file_name();
            Parent::child(&directory, name.clone())?.metadata()?;
            let name = name
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

    fn id(path: &str) -> ResourceId {
        ResourceId::parse(path).unwrap()
    }

    // A Windows directory capability can block replacement outright. That is a
    // safe outcome, not a skipped security test: validate the old object and
    // still execute the complete operation lifecycle against the pinned handle.
    fn replace_directory(path: &Path, saved: &Path, outside: &Path) -> bool {
        if let Err(error) = fs::rename(path, saved) {
            #[cfg(windows)]
            {
                assert!(matches!(error.raw_os_error(), Some(5 | 32 | 33)), "{error}");
                assert!(path.is_dir());
                assert!(!saved.exists());
                return false;
            }
            #[cfg(not(windows))]
            panic!("replacement failed: {error}");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside, path).unwrap();
        #[cfg(not(unix))]
        {
            // No symlink privilege is required for the replacement regression.
            // A substituted ordinary directory must not become authoritative.
            fs::create_dir(path).unwrap();
            fs::write(path.join("sentinel"), b"outside").unwrap();
            let _ = outside;
        }
        true
    }

    fn exercise_store(store: &FileSystemDataStore, scenario: &str) {
        assert!(store.metadata(&id("/")).unwrap().unwrap().is_collection);
        store.create_collection(&id("/docs")).unwrap();
        assert!(store.put(&id("/docs/a"), b"first", None).unwrap());
        assert_eq!(store.read(&id("/docs/a")).unwrap(), b"first".as_slice());
        assert!(!store.put(&id("/docs/a"), b"second", None).unwrap());
        assert_eq!(store.read(&id("/docs/a")).unwrap(), b"second".as_slice());
        store.copy(&id("/docs"), &id("/copied"), false).unwrap();
        assert_eq!(
            store.children(&id("/copied")).unwrap(),
            vec![id("/copied/a")]
        );
        assert_eq!(store.read(&id("/copied/a")).unwrap(), b"second".as_slice());
        store
            .move_resource(&id("/copied"), &id("/moved"), false)
            .unwrap_or_else(|error| {
                panic!("{scenario}: directory MOVE /copied -> /moved failed: {error:#}")
            });
        assert!(store.metadata(&id("/copied")).unwrap().is_none());
        assert_eq!(store.read(&id("/moved/a")).unwrap(), b"second".as_slice());
        store.put(&id("/target"), b"old", None).unwrap();
        store.read(&id("/target")).unwrap(); // prime destination cache
        store.copy(&id("/moved/a"), &id("/target"), true).unwrap();
        assert_eq!(store.read(&id("/target")).unwrap(), b"second".as_slice());
        store.put(&id("/moved/a"), b"third", None).unwrap();
        store
            .move_resource(&id("/moved/a"), &id("/target"), true)
            .unwrap_or_else(|error| {
                panic!("{scenario}: overwrite MOVE /moved/a -> /target failed: {error:#}")
            });
        assert!(store.metadata(&id("/moved/a")).unwrap().is_none());
        assert_eq!(store.read(&id("/target")).unwrap(), b"third".as_slice());
        store.delete(&id("/docs")).unwrap();
        store.delete(&id("/moved")).unwrap();
        store.delete(&id("/target")).unwrap();
        assert!(store.children(&id("/")).unwrap().is_empty());
    }

    #[test]
    fn root_and_root_ancestor_replacement_do_not_redirect_operations() {
        for replace_ancestor in [false, true] {
            let directory = tempdir().unwrap();
            let outside = tempdir().unwrap();
            fs::write(outside.path().join("sentinel"), b"outside").unwrap();
            let ancestor = directory.path().join("ancestor");
            let root = ancestor.join("root");
            let store = FileSystemDataStore::open(&root).unwrap();
            let replaced = if replace_ancestor { &ancestor } else { &root };
            let saved = directory.path().join("saved");
            let changed = replace_directory(replaced, &saved, outside.path());
            let scenario =
                format!("replace_ancestor={replace_ancestor}, replacement_changed={changed}");
            exercise_store(&store, &scenario);
            assert_eq!(
                fs::read(outside.path().join("sentinel")).unwrap(),
                b"outside"
            );
            assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
            #[cfg(not(unix))]
            if changed {
                assert_eq!(fs::read_dir(replaced).unwrap().count(), 1);
            }
            let pinned_root = if changed {
                if replace_ancestor {
                    saved.join("root")
                } else {
                    saved
                }
            } else {
                root
            };
            assert_eq!(fs::read_dir(pinned_root).unwrap().count(), 0);
        }
    }

    #[test]
    fn acquired_parent_survives_replacement_before_leaf_operations() {
        let directory = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("sentinel"), b"outside").unwrap();
        let store = FileSystemDataStore::open(directory.path().join("root")).unwrap();
        store.create_collection(&id("/parent")).unwrap();
        store.put(&id("/parent/a"), b"original", None).unwrap();
        let source = store.resolve_parent(&id("/parent/a")).unwrap();
        let target = store.resolve_parent(&id("/parent/b")).unwrap();
        let replaced = store.root().join("parent");
        let saved = directory.path().join("saved");
        let changed = replace_directory(&replaced, &saved, outside.path());
        assert!(!source.put(b"updated").unwrap());
        source.copy_to(&target).unwrap();
        let mut bytes = Vec::new();
        target.open_read().unwrap().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"updated");
        source.remove().unwrap();
        target.remove().unwrap();
        assert_eq!(
            fs::read_dir(if changed { &saved } else { &replaced })
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read(outside.path().join("sentinel")).unwrap(),
            b"outside"
        );
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
    }

    #[test]
    fn recursive_delete_uses_acquired_directory_after_replacement() {
        let directory = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("sentinel"), b"outside").unwrap();
        let store = FileSystemDataStore::open(directory.path().join("root")).unwrap();
        store.create_collection(&id("/tree")).unwrap();
        store.create_collection(&id("/tree/nested")).unwrap();
        store
            .put(&id("/tree/nested/file"), b"inside", None)
            .unwrap();
        let tree = store
            .resolve_parent(&id("/tree"))
            .unwrap()
            .open_dir()
            .unwrap();
        let replaced = store.root().join("tree");
        let saved = directory.path().join("saved");
        let changed = replace_directory(&replaced, &saved, outside.path());
        Parent::remove_children(&tree).unwrap();
        assert_eq!(
            fs::read_dir(if changed { &saved } else { &replaced })
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read(outside.path().join("sentinel")).unwrap(),
            b"outside"
        );
    }

    #[cfg(windows)]
    #[test]
    fn recursive_delete_unlinks_nested_directory_symlinks() {
        let directory = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("sentinel"), b"outside").unwrap();
        let store = FileSystemDataStore::open(directory.path().join("root")).unwrap();
        let link = store.root().join("link");
        if let Err(error) = std::os::windows::fs::symlink_dir(outside.path(), &link) {
            // Some Windows environments do not grant symbolic-link creation.
            // Exercise the regression wherever the host policy permits it.
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("create directory symlink: {error}");
        }

        Parent::remove_children(&store.directory).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert_eq!(
            fs::read(outside.path().join("sentinel")).unwrap(),
            b"outside"
        );
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn every_operation_rejects_in_root_and_outside_links() {
        use std::os::unix::fs::symlink;
        for inside in [false, true] {
            let directory = tempdir().unwrap();
            let outside = tempdir().unwrap();
            let store = FileSystemDataStore::open(directory.path()).unwrap();
            store.create_collection(&id("/real")).unwrap();
            store.put(&id("/real/file"), b"inside", None).unwrap();
            fs::write(outside.path().join("file"), b"outside").unwrap();
            let target = if inside {
                directory.path().join("real")
            } else {
                outside.path().to_path_buf()
            };
            symlink(&target, directory.path().join("link")).unwrap();
            symlink(target.join("file"), directory.path().join("leaf")).unwrap();
            for linked in [id("/link"), id("/leaf"), id("/link/file")] {
                assert!(store.metadata(&linked).is_err());
                assert!(store.read(&linked).is_err());
                assert!(
                    store
                        .read_with_metadata_and_content_type_file_backed(&linked, None)
                        .is_err()
                );
                assert!(store.put(&linked, b"bad", None).is_err());
                assert!(store.create_collection(&linked).is_err());
                assert!(store.children(&linked).is_err());
                assert!(store.delete(&linked).is_err());
                assert!(store.copy(&linked, &id("/copied"), true).is_err());
                assert!(store.move_resource(&linked, &id("/moved"), true).is_err());
                assert!(store.copy(&id("/real/file"), &linked, true).is_err());
                assert!(
                    store
                        .move_resource(&id("/real/file"), &linked, true)
                        .is_err()
                );
            }
            assert!(store.put(&id("/link/new"), b"bad", None).is_err());
            assert!(store.create_collection(&id("/link/newdir")).is_err());
            assert!(store.children(&id("/")).is_err());
            store.create_collection(&id("/nested")).unwrap();
            symlink(&target, directory.path().join("nested/link")).unwrap();
            assert!(store.copy(&id("/nested"), &id("/copytree"), true).is_err());
            store.delete(&id("/nested")).unwrap(); // nested links are unlinked
            assert_eq!(fs::read(outside.path().join("file")).unwrap(), b"outside");
            assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
            assert_eq!(store.read(&id("/real/file")).unwrap(), b"inside".as_slice());
        }
    }

    #[test]
    fn configured_missing_parent_and_parent_components_are_created() {
        let directory = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path().join("missing/../root")).unwrap();
        store.put(&id("/file"), b"inside", None).unwrap();
        // Unix preserves `..` until lookup; Windows absolute path processing
        // normalizes it before lookup and need not create the canceled segment.
        #[cfg(unix)]
        assert!(directory.path().join("missing").is_dir());
        assert_eq!(
            fs::read(directory.path().join("root/file")).unwrap(),
            b"inside"
        );
    }

    #[cfg(unix)]
    #[test]
    fn configured_linked_ancestor_is_allowed_but_root_leaf_is_not() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().unwrap();
        let actual = tempdir().unwrap();
        symlink(actual.path(), directory.path().join("ancestor")).unwrap();
        let store = FileSystemDataStore::open(directory.path().join("ancestor/new/root")).unwrap();
        store.put(&id("/file"), b"inside", None).unwrap();
        assert_eq!(
            fs::read(actual.path().join("new/root/file")).unwrap(),
            b"inside"
        );
        symlink(actual.path(), directory.path().join("leaf")).unwrap();
        assert!(FileSystemDataStore::open(directory.path().join("leaf")).is_err());
    }

    #[test]
    fn cached_read_never_authorizes_a_substituted_leaf() {
        let directory = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        store.put(&id("/file"), b"inside", None).unwrap();
        let first = store.read_with_metadata(&id("/file")).unwrap().unwrap();
        let old = directory.path().join("old");
        fs::rename(directory.path().join("file"), &old).unwrap();
        fs::write(outside.path().join("file"), b"outside").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path().join("file"), directory.path().join("file"))
            .unwrap();
        #[cfg(not(unix))]
        fs::create_dir(directory.path().join("file")).unwrap();
        #[cfg(unix)]
        assert!(store.read_with_metadata(&id("/file")).is_err());
        #[cfg(not(unix))]
        assert!(
            store
                .read_with_metadata(&id("/file"))
                .unwrap()
                .unwrap()
                .metadata
                .is_collection
        );
        assert_eq!(first.body, b"inside".as_slice());
        assert_eq!(fs::read(outside.path().join("file")).unwrap(), b"outside");
    }

    #[test]
    fn failed_atomic_put_cleans_its_temporary_file() {
        let directory = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        let parent = store.resolve_parent(&id("/file")).unwrap();
        let temporary = Path::new(".qpx-upload-test");
        let mut options = OpenOptions::new();
        options
            .create_new(true)
            .write(true)
            .follow(FollowSymlinks::No);
        let file = cap::open(&parent.directory, temporary, &options).unwrap();
        // Deterministically replace a previously missing target with a directory
        // before install. The real rename fails and the real cleanup runs.
        fs::create_dir(directory.path().join("file")).unwrap();
        assert!(parent.install(b"body", temporary, file).is_err());
        assert_eq!(store.children(&id("/")).unwrap(), vec![id("/file")]);
    }

    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a live, NUL-terminated string for this call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    #[cfg(unix)]
    #[test]
    fn special_file_reads_and_copies_are_bounded() {
        const CHILD: &str = "QPX_WEBDAV_FIFO_TEST_CHILD";
        if let Some(directory) = std::env::var_os(CHILD) {
            let directory = PathBuf::from(directory);
            let store = FileSystemDataStore::open(directory.as_path()).unwrap();
            make_fifo(&directory.as_path().join("fifo"));
            // No writer ever opens this FIFO. Blocking open would hang, even
            // for file-backed responses that do not materialize any bytes.
            assert!(store.read_with_metadata(&id("/fifo")).is_err());
            assert!(
                store
                    .read_with_metadata_and_content_type_file_backed(&id("/fifo"), None)
                    .is_err()
            );
            assert!(store.copy(&id("/fifo"), &id("/copy"), false).is_err());
            assert!(!directory.as_path().join("copy").exists());
            for read in [
                store.read_with_metadata(&id("/")).unwrap().unwrap(),
                store
                    .read_with_metadata_and_content_type_file_backed(&id("/"), None)
                    .unwrap()
                    .unwrap(),
            ] {
                assert!(read.metadata.is_collection);
                assert!(read.body.is_empty());
                assert!(read.file.is_none());
            }
            // Deterministically replace each authorized type hint before the
            // real no-follow open. No timing race or writer is involved.
            let parent = store.resolve_parent(&id("/raced")).unwrap();
            for is_directory in [false, true] {
                let path = directory.as_path().join("raced");
                if is_directory {
                    fs::create_dir(&path).unwrap();
                } else {
                    fs::write(&path, b"regular").unwrap();
                }
                let hint = parent.metadata().unwrap().unwrap();
                if is_directory {
                    fs::remove_dir(&path).unwrap();
                } else {
                    fs::remove_file(&path).unwrap();
                }
                make_fifo(&path);
                assert!(parent.open_read_with_hint(&hint).is_err());
                fs::remove_file(&path).unwrap();
            }
            return;
        }
        // A disposable process bounds regressions without leaking a blocked
        // thread into the suite. Kill and reap on timeout before failing.
        let directory = tempdir().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "filesystem::tests::special_file_reads_and_copies_are_bounded",
                "--nocapture",
            ])
            .env(CHILD, directory.path())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "FIFO child failed: {status}");
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("FIFO read/copy blocked");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn copy_creation_and_failure_never_broaden_source_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        store.put(&id("/source"), b"private", None).unwrap();
        let path = directory.path().join("source");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let permissions = fs::metadata(&path).unwrap().permissions();
        let target = store.resolve_parent(&id("/created")).unwrap();
        // This is the real create_new boundary, before any copy or final chmod.
        let created = target.create_copy_file(&permissions).unwrap();
        assert_eq!(created.metadata().unwrap().len(), 0);
        assert_eq!(created.metadata().unwrap().permissions().mode() & 0o177, 0);
        drop(created);

        // A write-only source forces the real transfer to fail after creation.
        // Keep this bounded and independent of data size, disk limits or races.
        let mut unreadable = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let failed = store.resolve_parent(&id("/failed")).unwrap();
        assert!(failed.copy_file(&mut unreadable, permissions).is_err());
        let partial = fs::metadata(directory.path().join("failed")).unwrap();
        assert_eq!(partial.permissions().mode() & 0o177, 0);
        assert_eq!(partial.len(), 0);
        store.copy(&id("/source"), &id("/success"), false).unwrap();
        assert_eq!(
            fs::read(directory.path().join("success")).unwrap(),
            b"private"
        );
        assert_eq!(
            fs::metadata(directory.path().join("success"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_preserves_file_permissions_and_cache_checks_replacement_identity() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        store.put(&id("/file"), b"first", None).unwrap();
        let path = directory.path().join("file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let old = store.read_with_metadata(&id("/file")).unwrap().unwrap();
        store.copy(&id("/file"), &id("/copy"), false).unwrap();
        assert_eq!(
            fs::metadata(directory.path().join("copy"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"other").unwrap();
        fs::File::options()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
        fs::rename(replacement, path).unwrap();
        assert_eq!(old.body, b"first".as_slice());
        let mut retained_bytes = [0; 5];
        std::os::unix::fs::FileExt::read_exact_at(
            old.file.as_ref().unwrap().as_ref(),
            &mut retained_bytes,
            0,
        )
        .unwrap();
        assert_eq!(&retained_bytes, b"first");
        assert_eq!(store.read(&id("/file")).unwrap(), b"other".as_slice());
        assert_eq!(
            store.children(&id("/")).unwrap(),
            vec![id("/copy"), id("/file")]
        );
    }

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

    #[test]
    fn file_backed_reads_preserve_materialized_read_api() {
        let directory = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        let file = ResourceId::parse("/asset.bin").unwrap();
        assert!(store.put(&file, b"payload", None).unwrap());

        let backed = store
            .read_with_metadata_and_content_type_file_backed(&file, None)
            .unwrap()
            .expect("file-backed resource");
        assert_eq!(backed.body, Bytes::from_static(b"payload"));
        assert!(backed.file.is_some());
        assert_eq!(store.read(&file).unwrap(), b"payload".as_slice());
    }

    #[test]
    fn cached_reads_preserve_file_responses_without_blocking_collection_move() {
        for file_backed in [false, true] {
            let directory = tempdir().unwrap();
            let store = FileSystemDataStore::open(directory.path()).unwrap();
            store.create_collection(&id("/source")).unwrap();
            let file = id("/source/file");
            store.put(&file, b"payload", None).unwrap();
            let first = store.read_resource(&file, file_backed).unwrap().unwrap();
            let cached = store.read_resource(&file, file_backed).unwrap().unwrap();
            assert_eq!(first.body.as_ptr(), cached.body.as_ptr());
            assert_eq!(cached.body, b"payload".as_slice());
            let mut response_file = cached.file.as_ref().unwrap().try_clone().unwrap();
            std::io::Seek::rewind(&mut response_file).unwrap();
            let mut response_body = Vec::new();
            response_file.read_to_end(&mut response_body).unwrap();
            assert_eq!(response_body, b"payload");
            if file_identity(&Metadata::from_file(&response_file).unwrap()).is_none() {
                assert!(store.read_cache.load().entries[0].read.file.is_none());
            }
            // No response is active, but its reusable body stays cached.
            drop(response_file);
            drop(cached);
            drop(first);
            store
                .move_resource(&id("/source"), &id("/moved"), false)
                .unwrap();
            assert!(store.metadata(&file).unwrap().is_none());
            assert_eq!(
                store.read(&id("/moved/file")).unwrap(),
                b"payload".as_slice()
            );
            store.delete(&id("/moved")).unwrap();
        }
    }

    #[test]
    fn large_file_backed_reads_retain_zero_copy_region_without_materializing_body() {
        let directory = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        let file = ResourceId::parse("/large.bin").unwrap();
        let content = vec![b'x'; READ_CACHE_MAX_OBJECT_BYTES + 1];
        assert!(store.put(&file, &content, None).unwrap());

        let backed = store
            .read_with_metadata_and_content_type_file_backed(&file, None)
            .unwrap()
            .expect("file-backed resource");
        assert!(backed.body.is_empty());
        assert_eq!(backed.metadata.content_length, content.len() as u64);
        let first_file = backed.file.expect("open file region");

        let cached = store
            .read_with_metadata_and_content_type_file_backed(&file, None)
            .unwrap()
            .expect("cached file-backed resource");
        let cached_file = cached.file.expect("cached open file region");
        #[cfg(unix)]
        assert!(Arc::ptr_eq(&first_file, &cached_file));
        #[cfg(not(unix))]
        drop(cached_file);

        assert!(!store.put(&file, &content, None).unwrap());
        let replaced = store
            .read_with_metadata_and_content_type_file_backed(&file, None)
            .unwrap()
            .expect("replaced file-backed resource");
        let replaced_file = replaced.file.expect("replaced open file region");
        assert!(!Arc::ptr_eq(&first_file, &replaced_file));
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

    #[test]
    fn copy_and_move_reject_same_or_descendant_destinations() {
        let directory = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        let source = ResourceId::parse("/source").unwrap();
        let child = ResourceId::parse("/source/child").unwrap();
        let file = ResourceId::parse("/source/file.txt").unwrap();
        store.create_collection(&source).unwrap();
        store.create_collection(&child).unwrap();
        store.put(&file, b"payload", None).unwrap();

        let descendant = ResourceId::parse("/source/child/copied").unwrap();
        assert!(store.copy(&source, &descendant, true).is_err());
        assert!(store.metadata(&descendant).unwrap().is_none());
        assert!(store.metadata(&source).unwrap().is_some());
        assert_eq!(store.read(&file).unwrap(), b"payload".as_slice());

        assert!(store.copy(&source, &source, true).is_err());
        assert!(store.metadata(&source).unwrap().is_some());
        assert_eq!(store.read(&file).unwrap(), b"payload".as_slice());

        let exact_file = ResourceId::parse("/exact.txt").unwrap();
        store.put(&exact_file, b"exact", None).unwrap();
        assert!(store.copy(&exact_file, &exact_file, true).is_err());
        assert_eq!(store.read(&exact_file).unwrap(), b"exact".as_slice());

        let moved = ResourceId::parse("/source/child/moved").unwrap();
        assert!(store.move_resource(&source, &moved, true).is_err());
        assert!(store.metadata(&moved).unwrap().is_none());
        assert!(store.metadata(&source).unwrap().is_some());
        assert_eq!(store.read(&file).unwrap(), b"payload".as_slice());

        assert!(store.move_resource(&source, &source, true).is_err());
        assert!(store.metadata(&source).unwrap().is_some());
        assert_eq!(store.read(&file).unwrap(), b"payload".as_slice());

        assert!(store.move_resource(&exact_file, &exact_file, true).is_err());
        assert_eq!(store.read(&exact_file).unwrap(), b"exact".as_slice());
    }

    #[test]
    fn copy_and_move_onto_ancestor_are_rejected_and_preserve_data() {
        let directory = tempdir().unwrap();
        let store = FileSystemDataStore::open(directory.path()).unwrap();
        let ancestor = ResourceId::parse("/a").unwrap();
        let source = ResourceId::parse("/a/b").unwrap();
        let payload = ResourceId::parse("/a/b/payload.txt").unwrap();
        store.create_collection(&ancestor).unwrap();
        store.create_collection(&source).unwrap();
        store.put(&payload, b"payload", None).unwrap();

        assert!(store.copy(&source, &ancestor, true).is_err());
        assert!(store.metadata(&ancestor).unwrap().is_some());
        assert!(store.metadata(&source).unwrap().is_some());
        assert_eq!(store.read(&payload).unwrap(), b"payload".as_slice());

        assert!(store.move_resource(&source, &ancestor, true).is_err());
        assert!(store.metadata(&ancestor).unwrap().is_some());
        assert!(store.metadata(&source).unwrap().is_some());
        assert_eq!(store.read(&payload).unwrap(), b"payload".as_slice());
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_store_rejects_symlinked_root() {
        use std::os::unix::fs::symlink;
        let target = tempdir().unwrap();
        let parent = tempdir().unwrap();
        let link = parent.path().join("linked-root");
        symlink(target.path(), &link).unwrap();
        assert!(FileSystemDataStore::open(&link).is_err());
        // Direct directory roots keep working.
        assert!(FileSystemDataStore::open(target.path()).is_ok());
    }
}
