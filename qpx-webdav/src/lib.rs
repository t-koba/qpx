//! WebDAV and CalDAV origin semantics for qpxd.

mod acl;
mod caldav;
mod filesystem;
mod metadata;
mod resource;
mod service;
mod store;

pub use acl::{Ace, AclPolicy, AclPrincipal, DavPrivilege};
pub use filesystem::FileSystemDataStore;
pub use metadata::RedbMetadataStore;
pub use resource::ResourceId;
pub use service::{AclDecision, WebDavRequestContext, WebDavService};
pub use store::{
    BindingAlreadyExists, DeadProperty, LockDepth, LockRecord, LockScope, PersistentWebDavStore,
    ResourceAccessContext, ResourceFileRegion, ResourceMetadata, ResourceRead, VersionRecord,
    WebDavDataStore, WebDavMetadataStore, WebDavStore,
};
