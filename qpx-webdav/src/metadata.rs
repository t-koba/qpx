use crate::{
    BindingAlreadyExists, DeadProperty, LockRecord, ResourceId, VersionRecord, WebDavMetadataStore,
};
use anyhow::Result;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::time::SystemTime;

const PROPERTIES: TableDefinition<&str, &[u8]> = TableDefinition::new("webdav_properties_v1");
const LOCKS: TableDefinition<&str, &[u8]> = TableDefinition::new("webdav_locks_v1");
const VERSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("webdav_versions_v1");
const CHECKOUTS: TableDefinition<&str, &str> = TableDefinition::new("webdav_checkouts_v1");
const BINDINGS: TableDefinition<&str, &str> = TableDefinition::new("webdav_bindings_v1");
const CONTENT_TYPES: TableDefinition<&str, &str> = TableDefinition::new("webdav_content_types_v1");

#[derive(Debug)]
pub struct RedbMetadataStore {
    database: Database,
}

impl RedbMetadataStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let database = Database::create(path)?;
        let transaction = database.begin_write()?;
        transaction.open_table(PROPERTIES)?;
        transaction.open_table(LOCKS)?;
        transaction.open_table(VERSIONS)?;
        transaction.open_table(CHECKOUTS)?;
        transaction.open_table(BINDINGS)?;
        transaction.open_table(CONTENT_TYPES)?;
        transaction.commit()?;
        Ok(Self { database })
    }

    fn read_properties(&self, resource: &ResourceId) -> Result<Vec<DeadProperty>> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(PROPERTIES)?;
        let Some(value) = table.get(resource.as_str())? else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_slice(value.value())?)
    }

    fn read_bindings(&self) -> Result<BTreeMap<ResourceId, ResourceId>> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(BINDINGS)?;
        let mut bindings = BTreeMap::new();
        for entry in table.iter()? {
            let (alias, target) = entry?;
            bindings.insert(
                ResourceId::parse(alias.value())?,
                ResourceId::parse(target.value())?,
            );
        }
        Ok(bindings)
    }
}

impl WebDavMetadataStore for RedbMetadataStore {
    fn content_type(&self, resource: &ResourceId) -> Result<Option<String>> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(CONTENT_TYPES)?;
        Ok(table
            .get(resource.as_str())?
            .map(|value| value.value().to_owned()))
    }

    fn set_content_type(&self, resource: &ResourceId, content_type: Option<&str>) -> Result<()> {
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(CONTENT_TYPES)?;
            if let Some(content_type) = content_type {
                table.insert(resource.as_str(), content_type)?;
            } else {
                table.remove(resource.as_str())?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn properties(&self, resource: &ResourceId) -> Result<Vec<DeadProperty>> {
        self.read_properties(resource)
    }

    fn set_properties(&self, resource: &ResourceId, properties: &[DeadProperty]) -> Result<()> {
        let mut merged = self.read_properties(resource)?;
        for property in properties {
            merged.retain(|existing| {
                existing.namespace != property.namespace || existing.name != property.name
            });
            merged.push(property.clone());
        }
        let encoded = serde_json::to_vec(&merged)?;
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(PROPERTIES)?;
            table.insert(resource.as_str(), encoded.as_slice())?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn remove_properties(&self, resource: &ResourceId, names: &[(String, String)]) -> Result<()> {
        let mut properties = self.read_properties(resource)?;
        properties.retain(|property| {
            !names
                .iter()
                .any(|(namespace, name)| namespace == &property.namespace && name == &property.name)
        });
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(PROPERTIES)?;
            if properties.is_empty() {
                table.remove(resource.as_str())?;
            } else {
                let encoded = serde_json::to_vec(&properties)?;
                table.insert(resource.as_str(), encoded.as_slice())?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn patch_properties(
        &self,
        resource: &ResourceId,
        set: &[DeadProperty],
        remove: &[(String, String)],
    ) -> Result<()> {
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(PROPERTIES)?;
            let mut properties = table
                .get(resource.as_str())?
                .map(|value| serde_json::from_slice::<Vec<DeadProperty>>(value.value()))
                .transpose()?
                .unwrap_or_default();
            properties.retain(|property| {
                !remove.iter().any(|(namespace, name)| {
                    namespace == &property.namespace && name == &property.name
                }) && !set.iter().any(|replacement| {
                    replacement.namespace == property.namespace && replacement.name == property.name
                })
            });
            properties.extend_from_slice(set);
            if properties.is_empty() {
                table.remove(resource.as_str())?;
            } else {
                let encoded = serde_json::to_vec(&properties)?;
                table.insert(resource.as_str(), encoded.as_slice())?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn locks(&self, resource: &ResourceId, include_ancestors: bool) -> Result<Vec<LockRecord>> {
        let now = SystemTime::now();
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(LOCKS)?;
        let mut locks = Vec::new();
        for entry in table.iter()? {
            let (_, value) = entry?;
            let lock: LockRecord = serde_json::from_slice(value.value())?;
            let descendant = if lock.resource == ResourceId::root() {
                resource != &ResourceId::root()
            } else {
                resource.as_str().starts_with(&format!(
                    "{}/",
                    lock.resource.as_str().trim_end_matches('/')
                ))
            };
            let applies = lock.resource == *resource
                || include_ancestors && lock.depth == crate::LockDepth::Infinity && descendant;
            if applies && !lock.is_expired(now) {
                locks.push(lock);
            }
        }
        Ok(locks)
    }

    fn put_lock(&self, lock: &LockRecord) -> Result<()> {
        let encoded = serde_json::to_vec(lock)?;
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(LOCKS)?;
            table.insert(lock.token.as_str(), encoded.as_slice())?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn remove_lock(&self, token: &str) -> Result<bool> {
        let transaction = self.database.begin_write()?;
        let removed = {
            let mut table = transaction.open_table(LOCKS)?;
            table.remove(token)?.is_some()
        };
        transaction.commit()?;
        Ok(removed)
    }

    fn remove_resource_metadata(&self, resource: &ResourceId) -> Result<()> {
        let transaction = self.database.begin_write()?;
        {
            let mut properties = transaction.open_table(PROPERTIES)?;
            properties.remove(resource.as_str())?;
            let mut content_types = transaction.open_table(CONTENT_TYPES)?;
            content_types.remove(resource.as_str())?;
            let mut locks = transaction.open_table(LOCKS)?;
            let tokens = locks
                .iter()?
                .filter_map(|entry| {
                    let (token, value) = entry.ok()?;
                    let lock: LockRecord = serde_json::from_slice(value.value()).ok()?;
                    (lock.resource == *resource).then(|| token.value().to_string())
                })
                .collect::<Vec<_>>();
            for token in tokens {
                locks.remove(token.as_str())?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn copy_resource_metadata(&self, source: &ResourceId, destination: &ResourceId) -> Result<()> {
        let properties = self.read_properties(source)?;
        self.set_properties(destination, &properties)?;
        let content_type = self.content_type(source)?;
        self.set_content_type(destination, content_type.as_deref())
    }

    fn move_resource_metadata(&self, source: &ResourceId, destination: &ResourceId) -> Result<()> {
        let properties = self.read_properties(source)?;
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(PROPERTIES)?;
            table.remove(source.as_str())?;
            if !properties.is_empty() {
                let encoded = serde_json::to_vec(&properties)?;
                table.insert(destination.as_str(), encoded.as_slice())?;
            }
            let mut content_types = transaction.open_table(CONTENT_TYPES)?;
            let content_type = content_types
                .remove(source.as_str())?
                .map(|value| value.value().to_owned());
            if let Some(content_type) = content_type {
                content_types.insert(destination.as_str(), content_type.as_str())?;
            }
            let mut versions = transaction.open_table(VERSIONS)?;
            let version_value = versions
                .remove(source.as_str())?
                .map(|encoded| encoded.value().to_vec());
            if let Some(value) = version_value {
                let mut records = serde_json::from_slice::<Vec<VersionRecord>>(&value)?;
                for record in &mut records {
                    record.resource = destination.clone();
                }
                let encoded = serde_json::to_vec(&records)?;
                versions.insert(destination.as_str(), encoded.as_slice())?;
            }
            let mut checkouts = transaction.open_table(CHECKOUTS)?;
            let checkout_owner = checkouts
                .remove(source.as_str())?
                .map(|owner| owner.value().to_owned());
            if let Some(value) = checkout_owner {
                checkouts.insert(destination.as_str(), value.as_str())?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn versions(&self, resource: &ResourceId) -> Result<Vec<VersionRecord>> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(VERSIONS)?;
        table
            .get(resource.as_str())?
            .map(|value| serde_json::from_slice(value.value()).map_err(Into::into))
            .unwrap_or_else(|| Ok(Vec::new()))
    }

    fn put_version(&self, version: &VersionRecord) -> Result<()> {
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(VERSIONS)?;
            let mut versions = table
                .get(version.resource.as_str())?
                .map(|value| serde_json::from_slice::<Vec<VersionRecord>>(value.value()))
                .transpose()?
                .unwrap_or_default();
            if versions
                .iter()
                .any(|existing| existing.version_name == version.version_name)
            {
                anyhow::bail!("WebDAV version name already exists");
            }
            versions.push(version.clone());
            let encoded = serde_json::to_vec(&versions)?;
            table.insert(version.resource.as_str(), encoded.as_slice())?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn checkout_owner(&self, resource: &ResourceId) -> Result<Option<String>> {
        let transaction = self.database.begin_read()?;
        let table = transaction.open_table(CHECKOUTS)?;
        Ok(table
            .get(resource.as_str())?
            .map(|owner| owner.value().to_owned()))
    }

    fn set_checkout_owner(&self, resource: &ResourceId, owner: Option<&str>) -> Result<()> {
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(CHECKOUTS)?;
            if let Some(owner) = owner {
                table.insert(resource.as_str(), owner)?;
            } else {
                table.remove(resource.as_str())?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn resolve_binding(&self, resource: &ResourceId) -> Result<ResourceId> {
        resolve_with_bindings(resource, &self.read_bindings()?)
    }

    fn put_binding(&self, alias: &ResourceId, target: &ResourceId, replace: bool) -> Result<()> {
        if alias == &ResourceId::root() || alias == target {
            anyhow::bail!("WebDAV binding would create a cycle");
        }
        let mut bindings = self.read_bindings()?;
        if bindings.contains_key(alias) && !replace {
            return Err(BindingAlreadyExists.into());
        }
        bindings.insert(alias.clone(), target.clone());
        resolve_with_bindings(alias, &bindings)?;
        let transaction = self.database.begin_write()?;
        {
            let mut table = transaction.open_table(BINDINGS)?;
            table.insert(alias.as_str(), target.as_str())?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn remove_binding(&self, alias: &ResourceId) -> Result<bool> {
        let transaction = self.database.begin_write()?;
        let removed = {
            let mut table = transaction.open_table(BINDINGS)?;
            table.remove(alias.as_str())?.is_some()
        };
        transaction.commit()?;
        Ok(removed)
    }

    fn child_bindings(&self, collection: &ResourceId) -> Result<Vec<ResourceId>> {
        Ok(self
            .read_bindings()?
            .into_keys()
            .filter(|alias| alias.parent().as_ref() == Some(collection))
            .collect())
    }
}

fn resolve_with_bindings(
    resource: &ResourceId,
    bindings: &BTreeMap<ResourceId, ResourceId>,
) -> Result<ResourceId> {
    let mut current = resource.clone();
    let mut visited = HashSet::new();
    for _ in 0..32 {
        if !visited.insert(current.clone()) {
            anyhow::bail!("WebDAV binding cycle detected");
        }
        let matched = bindings
            .iter()
            .filter(|(alias, _)| {
                current.as_str() == alias.as_str()
                    || current
                        .as_str()
                        .starts_with(&format!("{}/", alias.as_str()))
            })
            .max_by_key(|(alias, _)| alias.as_str().len());
        let Some((alias, target)) = matched else {
            return Ok(current);
        };
        let suffix = current
            .as_str()
            .strip_prefix(alias.as_str())
            .expect("matched binding prefix");
        current = ResourceId::parse(&format!("{}{suffix}", target.as_str()))?;
    }
    anyhow::bail!("WebDAV binding resolution exceeds 32 hops")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn redb_properties_commit_and_survive_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("metadata.redb");
        let resource = ResourceId::parse("/docs/report").unwrap();
        {
            let store = RedbMetadataStore::open(&path).unwrap();
            store
                .set_properties(
                    &resource,
                    &[DeadProperty {
                        namespace: "urn:test".to_string(),
                        name: "classification".to_string(),
                        value_xml: "<x>internal</x>".to_string(),
                    }],
                )
                .unwrap();
        }
        let reopened = RedbMetadataStore::open(path).unwrap();
        assert_eq!(reopened.properties(&resource).unwrap().len(), 1);
    }
}
