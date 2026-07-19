use crate::ResourceId;
use anyhow::Result;
use bytes::Bytes;
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingAlreadyExists;

impl std::fmt::Display for BindingAlreadyExists {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebDAV binding already exists")
    }
}

impl std::error::Error for BindingAlreadyExists {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMetadata {
    pub is_collection: bool,
    pub content_length: u64,
    pub content_type: Option<String>,
    pub etag: String,
    pub modified_unix_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct ResourceRead {
    pub metadata: Arc<ResourceMetadata>,
    pub etag: HeaderValue,
    pub body: Bytes,
    pub file: Option<Arc<File>>,
}

#[derive(Debug, Clone)]
pub struct ResourceFileRegion {
    pub file: Arc<File>,
    pub offset: u64,
    pub len: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceAccessContext {
    pub resolved_resource: Option<ResourceId>,
    pub properties: Vec<DeadProperty>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadProperty {
    pub namespace: String,
    pub name: String,
    pub value_xml: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockDepth {
    Zero,
    Infinity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockScope {
    Exclusive,
    Shared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRecord {
    pub token: String,
    pub resource: ResourceId,
    pub owner_xml: Option<String>,
    pub depth: LockDepth,
    pub scope: LockScope,
    pub expires_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRecord {
    pub version_name: String,
    pub resource: ResourceId,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub properties: Vec<DeadProperty>,
    pub created_unix_seconds: u64,
}

impl LockRecord {
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now.duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() >= self.expires_unix_seconds)
            .unwrap_or(false)
    }
}

pub trait WebDavDataStore: Send + Sync + 'static {
    fn metadata(&self, resource: &ResourceId) -> Result<Option<ResourceMetadata>>;
    fn read(&self, resource: &ResourceId) -> Result<Bytes>;
    fn read_with_metadata(&self, resource: &ResourceId) -> Result<Option<ResourceRead>>;
    fn read_with_metadata_and_content_type(
        &self,
        resource: &ResourceId,
        content_type: Option<String>,
    ) -> Result<Option<ResourceRead>> {
        let Some(mut read) = self.read_with_metadata(resource)? else {
            return Ok(None);
        };
        if read.metadata.content_type != content_type {
            Arc::make_mut(&mut read.metadata).content_type = content_type;
        }
        Ok(Some(read))
    }

    /// Reads metadata and returns an open file region when the caller can use zero-copy output.
    /// Implementations that cannot safely expose a file region must retain the materialized
    /// body, which keeps non-HTTP/1.1 and encrypted transports fully portable.
    fn read_with_metadata_and_content_type_file_backed(
        &self,
        resource: &ResourceId,
        content_type: Option<String>,
    ) -> Result<Option<ResourceRead>> {
        self.read_with_metadata_and_content_type(resource, content_type)
    }
    fn put(&self, resource: &ResourceId, body: &[u8], content_type: Option<&str>) -> Result<bool>;
    fn create_collection(&self, resource: &ResourceId) -> Result<()>;
    fn delete(&self, resource: &ResourceId) -> Result<()>;
    fn copy(&self, source: &ResourceId, destination: &ResourceId, overwrite: bool) -> Result<()>;
    fn move_resource(
        &self,
        source: &ResourceId,
        destination: &ResourceId,
        overwrite: bool,
    ) -> Result<()>;
    fn children(&self, resource: &ResourceId) -> Result<Vec<ResourceId>>;
}

pub trait WebDavMetadataStore: Send + Sync + 'static {
    fn content_type(&self, resource: &ResourceId) -> Result<Option<String>>;
    fn set_content_type(&self, resource: &ResourceId, content_type: Option<&str>) -> Result<()>;
    fn properties(&self, resource: &ResourceId) -> Result<Vec<DeadProperty>>;
    fn set_properties(&self, resource: &ResourceId, properties: &[DeadProperty]) -> Result<()>;
    fn remove_properties(&self, resource: &ResourceId, names: &[(String, String)]) -> Result<()>;
    fn patch_properties(
        &self,
        resource: &ResourceId,
        set: &[DeadProperty],
        remove: &[(String, String)],
    ) -> Result<()>;
    fn locks(&self, resource: &ResourceId, include_ancestors: bool) -> Result<Vec<LockRecord>>;
    fn put_lock(&self, lock: &LockRecord) -> Result<()>;
    fn remove_lock(&self, token: &str) -> Result<bool>;
    fn remove_resource_metadata(&self, resource: &ResourceId) -> Result<()>;
    fn copy_resource_metadata(&self, source: &ResourceId, destination: &ResourceId) -> Result<()>;
    fn move_resource_metadata(&self, source: &ResourceId, destination: &ResourceId) -> Result<()>;
    fn versions(&self, resource: &ResourceId) -> Result<Vec<VersionRecord>>;
    fn put_version(&self, version: &VersionRecord) -> Result<()>;
    fn checkout_owner(&self, resource: &ResourceId) -> Result<Option<String>>;
    fn set_checkout_owner(&self, resource: &ResourceId, owner: Option<&str>) -> Result<()>;
    fn resolve_binding(&self, resource: &ResourceId) -> Result<ResourceId>;
    fn resolve_binding_if_present(&self, resource: &ResourceId) -> Result<Option<ResourceId>>;
    fn put_binding(&self, alias: &ResourceId, target: &ResourceId, replace: bool) -> Result<()>;
    fn remove_binding(&self, alias: &ResourceId) -> Result<bool>;
    fn child_bindings(&self, collection: &ResourceId) -> Result<Vec<ResourceId>>;
    fn resource_access_context(&self, resource: &ResourceId) -> Result<ResourceAccessContext> {
        let resolved_resource = self.resolve_binding_if_present(resource)?;
        let effective = resolved_resource.as_ref().unwrap_or(resource);
        let properties = self.properties(effective)?;
        let content_type = self.content_type(effective)?;
        Ok(ResourceAccessContext {
            resolved_resource,
            properties,
            content_type,
        })
    }
}

/// Combined data and metadata transaction boundary used by `WebDavService`.
pub trait WebDavStore: WebDavDataStore + WebDavMetadataStore {}

impl<T> WebDavStore for T where T: WebDavDataStore + WebDavMetadataStore {}

#[derive(Debug)]
pub struct PersistentWebDavStore<D, M> {
    data: D,
    metadata: M,
}

impl<D, M> PersistentWebDavStore<D, M> {
    pub fn new(data: D, metadata: M) -> Self {
        Self { data, metadata }
    }

    pub fn data(&self) -> &D {
        &self.data
    }

    pub fn metadata_store(&self) -> &M {
        &self.metadata
    }
}

impl<D: WebDavDataStore, M: WebDavMetadataStore> WebDavDataStore for PersistentWebDavStore<D, M> {
    fn metadata(&self, resource: &ResourceId) -> Result<Option<ResourceMetadata>> {
        let Some(mut metadata) = self.data.metadata(resource)? else {
            return Ok(None);
        };
        metadata.content_type = self.metadata.content_type(resource)?;
        Ok(Some(metadata))
    }

    fn read(&self, resource: &ResourceId) -> Result<Bytes> {
        self.data.read(resource)
    }

    fn read_with_metadata(&self, resource: &ResourceId) -> Result<Option<ResourceRead>> {
        let content_type = self.metadata.content_type(resource)?;
        self.read_with_metadata_and_content_type(resource, content_type)
    }

    fn read_with_metadata_and_content_type(
        &self,
        resource: &ResourceId,
        content_type: Option<String>,
    ) -> Result<Option<ResourceRead>> {
        let Some(mut read) = self.data.read_with_metadata(resource)? else {
            return Ok(None);
        };
        if read.metadata.content_type != content_type {
            Arc::make_mut(&mut read.metadata).content_type = content_type;
        }
        Ok(Some(read))
    }

    fn read_with_metadata_and_content_type_file_backed(
        &self,
        resource: &ResourceId,
        content_type: Option<String>,
    ) -> Result<Option<ResourceRead>> {
        let Some(mut read) = self
            .data
            .read_with_metadata_and_content_type_file_backed(resource, content_type.clone())?
        else {
            return Ok(None);
        };
        if read.metadata.content_type != content_type {
            Arc::make_mut(&mut read.metadata).content_type = content_type;
        }
        Ok(Some(read))
    }

    fn put(&self, resource: &ResourceId, body: &[u8], content_type: Option<&str>) -> Result<bool> {
        let created = self.data.put(resource, body, content_type)?;
        self.metadata.set_content_type(resource, content_type)?;
        Ok(created)
    }

    fn create_collection(&self, resource: &ResourceId) -> Result<()> {
        self.data.create_collection(resource)
    }

    fn delete(&self, resource: &ResourceId) -> Result<()> {
        self.data.delete(resource)
    }

    fn copy(&self, source: &ResourceId, destination: &ResourceId, overwrite: bool) -> Result<()> {
        self.data.copy(source, destination, overwrite)
    }

    fn move_resource(
        &self,
        source: &ResourceId,
        destination: &ResourceId,
        overwrite: bool,
    ) -> Result<()> {
        self.data.move_resource(source, destination, overwrite)
    }

    fn children(&self, resource: &ResourceId) -> Result<Vec<ResourceId>> {
        self.data.children(resource)
    }
}

impl<D: Send + Sync + 'static, M: WebDavMetadataStore> WebDavMetadataStore
    for PersistentWebDavStore<D, M>
{
    fn content_type(&self, resource: &ResourceId) -> Result<Option<String>> {
        self.metadata.content_type(resource)
    }

    fn set_content_type(&self, resource: &ResourceId, content_type: Option<&str>) -> Result<()> {
        self.metadata.set_content_type(resource, content_type)
    }

    fn properties(&self, resource: &ResourceId) -> Result<Vec<DeadProperty>> {
        self.metadata.properties(resource)
    }

    fn set_properties(&self, resource: &ResourceId, properties: &[DeadProperty]) -> Result<()> {
        self.metadata.set_properties(resource, properties)
    }

    fn remove_properties(&self, resource: &ResourceId, names: &[(String, String)]) -> Result<()> {
        self.metadata.remove_properties(resource, names)
    }

    fn patch_properties(
        &self,
        resource: &ResourceId,
        set: &[DeadProperty],
        remove: &[(String, String)],
    ) -> Result<()> {
        self.metadata.patch_properties(resource, set, remove)
    }

    fn locks(&self, resource: &ResourceId, include_ancestors: bool) -> Result<Vec<LockRecord>> {
        self.metadata.locks(resource, include_ancestors)
    }

    fn put_lock(&self, lock: &LockRecord) -> Result<()> {
        self.metadata.put_lock(lock)
    }

    fn remove_lock(&self, token: &str) -> Result<bool> {
        self.metadata.remove_lock(token)
    }

    fn remove_resource_metadata(&self, resource: &ResourceId) -> Result<()> {
        self.metadata.remove_resource_metadata(resource)
    }

    fn copy_resource_metadata(&self, source: &ResourceId, destination: &ResourceId) -> Result<()> {
        self.metadata.copy_resource_metadata(source, destination)
    }

    fn move_resource_metadata(&self, source: &ResourceId, destination: &ResourceId) -> Result<()> {
        self.metadata.move_resource_metadata(source, destination)
    }

    fn versions(&self, resource: &ResourceId) -> Result<Vec<VersionRecord>> {
        self.metadata.versions(resource)
    }

    fn put_version(&self, version: &VersionRecord) -> Result<()> {
        self.metadata.put_version(version)
    }

    fn checkout_owner(&self, resource: &ResourceId) -> Result<Option<String>> {
        self.metadata.checkout_owner(resource)
    }

    fn set_checkout_owner(&self, resource: &ResourceId, owner: Option<&str>) -> Result<()> {
        self.metadata.set_checkout_owner(resource, owner)
    }

    fn resolve_binding(&self, resource: &ResourceId) -> Result<ResourceId> {
        self.metadata.resolve_binding(resource)
    }

    fn resolve_binding_if_present(&self, resource: &ResourceId) -> Result<Option<ResourceId>> {
        self.metadata.resolve_binding_if_present(resource)
    }

    fn put_binding(&self, alias: &ResourceId, target: &ResourceId, replace: bool) -> Result<()> {
        self.metadata.put_binding(alias, target, replace)
    }

    fn remove_binding(&self, alias: &ResourceId) -> Result<bool> {
        self.metadata.remove_binding(alias)
    }

    fn child_bindings(&self, collection: &ResourceId) -> Result<Vec<ResourceId>> {
        self.metadata.child_bindings(collection)
    }

    fn resource_access_context(&self, resource: &ResourceId) -> Result<ResourceAccessContext> {
        self.metadata.resource_access_context(resource)
    }
}
