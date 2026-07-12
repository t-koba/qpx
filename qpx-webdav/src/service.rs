use crate::caldav::{
    CALDAV_NAMESPACE, CALENDAR_MARKER, CalendarInstant, format_datetime, parse_datetime,
    validate_calendar,
};
use crate::{
    AclPolicy, BindingAlreadyExists, DavPrivilege, DeadProperty, LockDepth, LockRecord, LockScope,
    ResourceId, VersionRecord, WebDavStore,
};
use anyhow::{Result, anyhow};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebDavRequestContext {
    pub subject: Option<String>,
    pub tenant: Option<String>,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    pub entitlements: Vec<String>,
    pub assurance: Option<String>,
}

type Authorizer = dyn Fn(&WebDavRequestContext, &ResourceId, &Method) -> AclDecision + Send + Sync;

const ACL_POLICY_NAMESPACE: &str = "urn:qpx:webdav:internal";
const ACL_POLICY_NAME: &str = "acl-policy-v1";

pub struct WebDavService<S> {
    store: Arc<S>,
    authorizer: Arc<Authorizer>,
    max_depth: usize,
    max_multistatus_entries: usize,
    max_lock_timeout_seconds: u64,
}

impl<S: WebDavStore> WebDavService<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            authorizer: Arc::new(|_, _, _| AclDecision::Allow),
            max_depth: 32,
            max_multistatus_entries: 10_000,
            max_lock_timeout_seconds: 86_400,
        }
    }

    pub fn with_authorizer(
        mut self,
        authorizer: impl Fn(&WebDavRequestContext, &ResourceId, &Method) -> AclDecision
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.authorizer = Arc::new(authorizer);
        self
    }

    pub fn with_limits(
        mut self,
        max_depth: usize,
        max_multistatus_entries: usize,
        max_lock_timeout_seconds: u64,
    ) -> Result<Self> {
        if max_depth == 0 || max_multistatus_entries == 0 || max_lock_timeout_seconds == 0 {
            return Err(anyhow!("WebDAV limits must be greater than zero"));
        }
        self.max_depth = max_depth;
        self.max_multistatus_entries = max_multistatus_entries;
        self.max_lock_timeout_seconds = max_lock_timeout_seconds;
        Ok(self)
    }

    pub fn handle(
        &self,
        request: Request<Vec<u8>>,
        context: &WebDavRequestContext,
    ) -> Result<Response<Vec<u8>>> {
        let request_resource = ResourceId::parse(request.uri().path())?;
        let resource = self.store.resolve_binding(&request_resource)?;
        if (self.authorizer)(context, &resource, request.method()) == AclDecision::Deny {
            return response(StatusCode::FORBIDDEN, Vec::new());
        }
        if !self.acl_allows(context, &resource, request.method())? {
            return response(StatusCode::FORBIDDEN, Vec::new());
        }
        if matches!(
            request.method().as_str(),
            "PUT" | "DELETE" | "PROPPATCH" | "ACL" | "MOVE"
        ) && !self.store.versions(&resource)?.is_empty()
            && self.store.checkout_owner(&resource)?.as_deref() != context.subject.as_deref()
        {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        match request.method().as_str() {
            "OPTIONS" => self.options(),
            "GET" => self.get(&resource, false),
            "HEAD" => self.get(&resource, true),
            "PUT" => self.put(&resource, request.headers(), request.body()),
            "DELETE" => self.delete(&resource, request.headers()),
            "MKCOL" => self.mkcol(&resource, request.headers(), request.body()),
            "MKCALENDAR" => self.mkcalendar(&resource, request.headers(), request.body()),
            "PROPFIND" => self.propfind(&resource, request.headers(), request.body()),
            "PROPPATCH" => self.proppatch(&resource, request.headers(), request.body()),
            "LOCK" => self.lock(&resource, request.headers(), request.body()),
            "UNLOCK" => self.unlock(&resource, request.headers()),
            "COPY" => self.copy_or_move(&resource, request.headers(), false),
            "MOVE" => self.copy_or_move(&resource, request.headers(), true),
            "SEARCH" => self.search(&resource, request.body()),
            "ACL" => self.set_acl(&resource, request.body()),
            "VERSION-CONTROL" => self.version_control(&resource),
            "CHECKOUT" => self.checkout(&resource, context),
            "CHECKIN" => self.checkin(&resource, context),
            "UPDATE" => self.update_version(&resource, request.headers(), false),
            "MERGE" => self.update_version(&resource, request.headers(), true),
            "REPORT" => self.report(&resource, request.body()),
            "BIND" => self.bind(&request_resource, request.body(), false),
            "REBIND" => self.bind(&request_resource, request.body(), true),
            "UNBIND" => self.unbind(&request_resource, request.body()),
            _ => response(StatusCode::METHOD_NOT_ALLOWED, Vec::new()),
        }
    }

    fn options(&self) -> Result<Response<Vec<u8>>> {
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(
                "dav",
                "1, 2, access-control, calendar-access, extended-mkcol, version-control, checkout-in-place, bind",
            )
            .header("dasl", "<DAV:basicsearch>")
            .header(
                http::header::ALLOW,
                "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MKCALENDAR, PROPFIND, PROPPATCH, LOCK, UNLOCK, COPY, MOVE, SEARCH, ACL, VERSION-CONTROL, CHECKOUT, CHECKIN, UPDATE, MERGE, REPORT, BIND, UNBIND, REBIND",
            )
            .body(Vec::new())
            .map_err(Into::into)
    }

    fn get(&self, resource: &ResourceId, head: bool) -> Result<Response<Vec<u8>>> {
        let Some(metadata) = self.store.metadata(resource)? else {
            return response(StatusCode::NOT_FOUND, Vec::new());
        };
        if metadata.is_collection {
            return response(StatusCode::METHOD_NOT_ALLOWED, Vec::new());
        }
        let body = if head {
            Vec::new()
        } else {
            self.store.read(resource)?
        };
        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_LENGTH, metadata.content_length)
            .header(http::header::ETAG, metadata.etag);
        if let Some(content_type) = metadata.content_type {
            builder = builder.header(http::header::CONTENT_TYPE, content_type);
        }
        builder.body(body).map_err(Into::into)
    }

    fn put(
        &self,
        resource: &ResourceId,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Response<Vec<u8>>> {
        if !self.parent_collection_exists(resource)? {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        if let Some(status) = self.lock_failure_status(resource, headers)? {
            return response(status, Vec::new());
        }
        if self.is_calendar_collection_parent(resource)? {
            let content_type = headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(';').next().unwrap_or(value).trim());
            if content_type != Some("text/calendar") {
                return response(StatusCode::UNSUPPORTED_MEDIA_TYPE, Vec::new());
            }
            validate_calendar(body)?;
        }
        let created = self.store.put(
            resource,
            body,
            headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
        )?;
        response(
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::NO_CONTENT
            },
            Vec::new(),
        )
    }

    fn delete(&self, resource: &ResourceId, headers: &HeaderMap) -> Result<Response<Vec<u8>>> {
        if self.store.metadata(resource)?.is_none() {
            return response(StatusCode::NOT_FOUND, Vec::new());
        }
        if let Some(status) = self.lock_failure_status(resource, headers)? {
            return response(status, Vec::new());
        }
        self.store.delete(resource)?;
        self.store.remove_resource_metadata(resource)?;
        response(StatusCode::NO_CONTENT, Vec::new())
    }

    fn mkcol(
        &self,
        resource: &ResourceId,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Response<Vec<u8>>> {
        if !self.parent_collection_exists(resource)? {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        if let Some(status) = self.lock_failure_status(resource, headers)? {
            return response(status, Vec::new());
        }
        if self.store.metadata(resource)?.is_some() {
            return response(StatusCode::METHOD_NOT_ALLOWED, Vec::new());
        }
        let properties = if body.is_empty() {
            Vec::new()
        } else {
            let content_type = headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(';').next().unwrap_or(value).trim());
            if !matches!(content_type, Some("application/xml" | "text/xml")) {
                return response(StatusCode::UNSUPPORTED_MEDIA_TYPE, Vec::new());
            }
            let patch = parse_property_update_allow_empty(body)?;
            if !patch.remove.is_empty() || patch.set.iter().any(is_protected_live_property) {
                return response(StatusCode::FORBIDDEN, Vec::new());
            }
            patch.set
        };
        self.store.create_collection(resource)?;
        if !properties.is_empty()
            && let Err(error) = self.store.set_properties(resource, &properties)
        {
            self.store.delete(resource)?;
            return Err(error);
        }
        response(StatusCode::CREATED, Vec::new())
    }

    fn mkcalendar(
        &self,
        resource: &ResourceId,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Response<Vec<u8>>> {
        if !self.parent_collection_exists(resource)? {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        if self.store.metadata(resource)?.is_some() {
            return response(StatusCode::METHOD_NOT_ALLOWED, Vec::new());
        }
        let mut properties = Vec::new();
        if !body.is_empty() {
            let content_type = headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(';').next().unwrap_or(value).trim());
            if !matches!(content_type, Some("application/xml" | "text/xml")) {
                return response(StatusCode::UNSUPPORTED_MEDIA_TYPE, Vec::new());
            }
            let patch = parse_property_update_allow_empty(body)?;
            if !patch.remove.is_empty() || patch.set.iter().any(is_protected_live_property) {
                return response(StatusCode::FORBIDDEN, Vec::new());
            }
            properties = patch.set;
        }
        self.store.create_collection(resource)?;
        properties.push(DeadProperty {
            namespace: CALDAV_NAMESPACE.to_owned(),
            name: CALENDAR_MARKER.to_owned(),
            value_xml: "true".to_owned(),
        });
        if let Err(error) = self.store.set_properties(resource, &properties) {
            self.store.delete(resource)?;
            return Err(error);
        }
        response(StatusCode::CREATED, Vec::new())
    }

    fn is_calendar_collection_parent(&self, resource: &ResourceId) -> Result<bool> {
        let Some(parent) = resource.parent() else {
            return Ok(false);
        };
        Ok(self.store.properties(&parent)?.iter().any(|property| {
            property.namespace == CALDAV_NAMESPACE && property.name == CALENDAR_MARKER
        }))
    }

    fn parent_collection_exists(&self, resource: &ResourceId) -> Result<bool> {
        let Some(parent) = resource.parent() else {
            return Ok(false);
        };
        Ok(self
            .store
            .metadata(&parent)?
            .is_some_and(|metadata| metadata.is_collection))
    }

    fn propfind(
        &self,
        resource: &ResourceId,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Response<Vec<u8>>> {
        if !body.is_empty() && validate_propfind_body(body).is_err() {
            return response(StatusCode::BAD_REQUEST, Vec::new());
        }
        let depth = parse_depth(headers, self.max_depth)?;
        let mut resources = vec![resource.clone()];
        self.collect_descendants(resource, depth, &mut resources)?;
        if resources.len() > self.max_multistatus_entries {
            return response(StatusCode::INSUFFICIENT_STORAGE, Vec::new());
        }
        self.multistatus_resources(resources)
    }

    fn multistatus_resources(
        &self,
        resources: impl IntoIterator<Item = ResourceId>,
    ) -> Result<Response<Vec<u8>>> {
        let mut xml =
            String::from(r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">"#);
        for resource in resources {
            let resolved = self.store.resolve_binding(&resource)?;
            let Some(metadata) = self.store.metadata(&resolved)? else {
                continue;
            };
            let properties = self.store.properties(&resolved)?;
            let is_calendar = properties.iter().any(|property| {
                property.namespace == CALDAV_NAMESPACE && property.name == CALENDAR_MARKER
            });
            let mut href = resource.as_str().to_owned();
            if metadata.is_collection && !href.ends_with('/') {
                href.push('/');
            }
            xml.push_str("<D:response><D:href>");
            xml.push_str(&escape_xml(&href));
            xml.push_str("</D:href><D:propstat><D:prop>");
            if metadata.is_collection {
                xml.push_str("<D:resourcetype><D:collection/>");
                if is_calendar {
                    xml.push_str("<C:calendar xmlns:C=\"urn:ietf:params:xml:ns:caldav\"/>");
                }
                xml.push_str("</D:resourcetype>");
                xml.push_str("<D:current-user-principal><D:href>");
                xml.push_str(&escape_xml(&href));
                xml.push_str("</D:href></D:current-user-principal>");
                xml.push_str(
                    "<C:calendar-home-set xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:href>",
                );
                xml.push_str(&escape_xml(&href));
                xml.push_str("</D:href></C:calendar-home-set>");
            } else {
                xml.push_str("<D:resourcetype/>");
            }
            xml.push_str("<D:getetag>");
            xml.push_str(&escape_xml(&metadata.etag));
            xml.push_str("</D:getetag><D:getcontentlength>");
            xml.push_str(&metadata.content_length.to_string());
            xml.push_str("</D:getcontentlength>");
            for property in properties {
                if property.namespace == ACL_POLICY_NAMESPACE && property.name == ACL_POLICY_NAME
                    || property.namespace == CALDAV_NAMESPACE && property.name == CALENDAR_MARKER
                {
                    continue;
                }
                if !is_xml_local_name(&property.name) {
                    return Err(anyhow!(
                        "WebDAV property name is not a valid XML local name"
                    ));
                }
                if property.namespace.is_empty() {
                    xml.push('<');
                    xml.push_str(&property.name);
                    xml.push('>');
                } else {
                    xml.push_str("<Q:");
                    xml.push_str(&property.name);
                    xml.push_str(" xmlns:Q=\"");
                    xml.push_str(&escape_xml(&property.namespace));
                    xml.push_str("\">");
                }
                xml.push_str(&escape_xml(&property.value_xml));
                xml.push_str(if property.namespace.is_empty() {
                    "</"
                } else {
                    "</Q:"
                });
                xml.push_str(&property.name);
                xml.push('>');
            }
            xml.push_str("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
        }
        xml.push_str("</D:multistatus>");
        Response::builder()
            .status(StatusCode::MULTI_STATUS)
            .header(http::header::CONTENT_TYPE, "application/xml; charset=utf-8")
            .body(xml.into_bytes())
            .map_err(Into::into)
    }

    fn search(&self, request_resource: &ResourceId, body: &[u8]) -> Result<Response<Vec<u8>>> {
        let query = parse_basic_search(body, self.max_depth)?;
        if !resource_contains(request_resource, &query.scope) {
            return response(StatusCode::FORBIDDEN, Vec::new());
        }
        if self.store.metadata(&query.scope)?.is_none() {
            return response(StatusCode::NOT_FOUND, Vec::new());
        }
        let mut resources = vec![query.scope.clone()];
        self.collect_descendants(&query.scope, query.depth, &mut resources)?;
        if resources.len() > self.max_multistatus_entries {
            return response(StatusCode::INSUFFICIENT_STORAGE, Vec::new());
        }
        let mut matches = Vec::new();
        for resource in resources {
            if self.search_matches(&resource, &query.predicate)? {
                matches.push(resource);
            }
        }
        self.multistatus_resources(matches)
    }

    fn search_matches(&self, resource: &ResourceId, predicate: &SearchPredicate) -> Result<bool> {
        let Some(metadata) = self.store.metadata(resource)? else {
            return Ok(false);
        };
        match predicate {
            SearchPredicate::All => Ok(true),
            SearchPredicate::IsCollection => Ok(metadata.is_collection),
            SearchPredicate::Contains(needle) => {
                if metadata.is_collection {
                    return Ok(false);
                }
                let body = self.store.read(resource)?;
                Ok(String::from_utf8_lossy(&body).contains(needle))
            }
            SearchPredicate::PropertyEquals {
                namespace,
                name,
                value,
            } => {
                let live_value = match (namespace.as_str(), name.as_str()) {
                    ("DAV:", "getetag") => Some(metadata.etag),
                    ("DAV:", "getcontentlength") => Some(metadata.content_length.to_string()),
                    ("DAV:", "resourcetype") if metadata.is_collection => {
                        Some("collection".to_owned())
                    }
                    _ => None,
                };
                if live_value.as_deref() == Some(value) {
                    return Ok(true);
                }
                Ok(self.store.properties(resource)?.iter().any(|property| {
                    property.namespace == *namespace
                        && property.name == *name
                        && property.value_xml == *value
                }))
            }
        }
    }

    fn acl_allows(
        &self,
        context: &WebDavRequestContext,
        resource: &ResourceId,
        method: &Method,
    ) -> Result<bool> {
        let policy = self
            .store
            .properties(resource)?
            .into_iter()
            .find(|property| {
                property.namespace == ACL_POLICY_NAMESPACE && property.name == ACL_POLICY_NAME
            })
            .map(|property| serde_json::from_str::<AclPolicy>(&property.value_xml))
            .transpose()?;
        let Some(policy) = policy else {
            return Ok(true);
        };
        let privilege = match method.as_str() {
            "GET" | "HEAD" | "PROPFIND" | "SEARCH" | "OPTIONS" => DavPrivilege::Read,
            "ACL" => DavPrivilege::WriteAcl,
            _ => DavPrivilege::Write,
        };
        Ok(policy.allows(context, privilege))
    }

    fn set_acl(&self, resource: &ResourceId, body: &[u8]) -> Result<Response<Vec<u8>>> {
        if self.store.metadata(resource)?.is_none() {
            return response(StatusCode::NOT_FOUND, Vec::new());
        }
        let policy = AclPolicy::parse(body)?;
        self.store.set_properties(
            resource,
            &[
                DeadProperty {
                    namespace: "DAV:".to_owned(),
                    name: "acl".to_owned(),
                    value_xml: String::from_utf8(body.to_vec())?,
                },
                DeadProperty {
                    namespace: ACL_POLICY_NAMESPACE.to_owned(),
                    name: ACL_POLICY_NAME.to_owned(),
                    value_xml: serde_json::to_string(&policy)?,
                },
            ],
        )?;
        response(StatusCode::OK, Vec::new())
    }

    fn version_control(&self, resource: &ResourceId) -> Result<Response<Vec<u8>>> {
        if self.store.metadata(resource)?.is_none() {
            return response(StatusCode::NOT_FOUND, Vec::new());
        }
        if self.store.versions(resource)?.is_empty() {
            self.create_version(resource)?;
        }
        response(StatusCode::OK, Vec::new())
    }

    fn checkout(
        &self,
        resource: &ResourceId,
        context: &WebDavRequestContext,
    ) -> Result<Response<Vec<u8>>> {
        let Some(subject) = context.subject.as_deref() else {
            return response(StatusCode::FORBIDDEN, Vec::new());
        };
        if self.store.versions(resource)?.is_empty() {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        if self.store.checkout_owner(resource)?.is_some() {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        self.store.set_checkout_owner(resource, Some(subject))?;
        response(StatusCode::OK, Vec::new())
    }

    fn checkin(
        &self,
        resource: &ResourceId,
        context: &WebDavRequestContext,
    ) -> Result<Response<Vec<u8>>> {
        let owner = self.store.checkout_owner(resource)?;
        if owner.is_none() || owner.as_deref() != context.subject.as_deref() {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        let version = self.create_version(resource)?;
        self.store.set_checkout_owner(resource, None)?;
        Response::builder()
            .status(StatusCode::CREATED)
            .header(
                "location",
                format!("{}/.versions/{version}", resource.as_str()),
            )
            .body(Vec::new())
            .map_err(Into::into)
    }

    fn create_version(&self, resource: &ResourceId) -> Result<String> {
        let metadata = self
            .store
            .metadata(resource)?
            .ok_or_else(|| anyhow!("WebDAV version target does not exist"))?;
        if metadata.is_collection {
            return Err(anyhow!("collection versioning is not supported"));
        }
        let version_name = Uuid::new_v4().to_string();
        self.store.put_version(&VersionRecord {
            version_name: version_name.clone(),
            resource: resource.clone(),
            body: self.store.read(resource)?,
            content_type: metadata.content_type,
            properties: self.store.properties(resource)?,
            created_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        })?;
        Ok(version_name)
    }

    fn update_version(
        &self,
        resource: &ResourceId,
        headers: &HeaderMap,
        merge: bool,
    ) -> Result<Response<Vec<u8>>> {
        let header = if merge { "source" } else { "version-name" };
        let Some(version_name) = headers
            .get(header)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim_end_matches('/').rsplit('/').next())
        else {
            return response(StatusCode::BAD_REQUEST, Vec::new());
        };
        let Some(version) = self
            .store
            .versions(resource)?
            .into_iter()
            .find(|version| version.version_name == version_name)
        else {
            return response(StatusCode::NOT_FOUND, Vec::new());
        };
        self.store
            .put(resource, &version.body, version.content_type.as_deref())?;
        let names = self
            .store
            .properties(resource)?
            .into_iter()
            .map(|property| (property.namespace, property.name))
            .collect::<Vec<_>>();
        self.store.remove_properties(resource, &names)?;
        self.store.set_properties(resource, &version.properties)?;
        if merge {
            self.create_version(resource)?;
        }
        response(StatusCode::OK, Vec::new())
    }

    fn version_report(&self, resource: &ResourceId) -> Result<Response<Vec<u8>>> {
        let mut xml =
            String::from(r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">"#);
        for version in self.store.versions(resource)? {
            xml.push_str("<D:response><D:href>");
            xml.push_str(&escape_xml(&format!(
                "{}/.versions/{}",
                resource.as_str(),
                version.version_name
            )));
            xml.push_str("</D:href><D:propstat><D:prop><D:version-name>");
            xml.push_str(&escape_xml(&version.version_name));
            xml.push_str("</D:version-name></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
        }
        xml.push_str("</D:multistatus>");
        Response::builder()
            .status(StatusCode::MULTI_STATUS)
            .header(http::header::CONTENT_TYPE, "application/xml; charset=utf-8")
            .body(xml.into_bytes())
            .map_err(Into::into)
    }

    fn report(&self, resource: &ResourceId, body: &[u8]) -> Result<Response<Vec<u8>>> {
        match parse_report(body)? {
            ReportRequest::VersionTree => self.version_report(resource),
            ReportRequest::CalendarQuery {
                component,
                start,
                end,
                text_filters,
            } => self.calendar_query(resource, component.as_deref(), start, end, &text_filters),
            ReportRequest::FreeBusy { start, end } => self.free_busy(resource, start, end),
        }
    }

    fn calendar_query(
        &self,
        collection: &ResourceId,
        component: Option<&str>,
        start: Option<CalendarInstant>,
        end: Option<CalendarInstant>,
        text_filters: &[CalendarTextFilter],
    ) -> Result<Response<Vec<u8>>> {
        if !self.is_calendar_collection(collection)? {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        let mut matches = Vec::new();
        for child in self.store.children(collection)? {
            let Some(metadata) = self.store.metadata(&child)? else {
                continue;
            };
            if metadata.is_collection || !is_calendar_content_type(metadata.content_type.as_deref())
            {
                continue;
            }
            let objects = validate_calendar(&self.store.read(&child)?)?;
            let body = self.store.read(&child)?;
            if objects.iter().any(|object| {
                component.is_none_or(|name| object.component == name)
                    && start.is_none_or(|lower| object.end >= lower)
                    && end.is_none_or(|upper| object.start < upper)
            }) && text_filters
                .iter()
                .all(|filter| calendar_text_filter_matches(&body, filter))
            {
                matches.push(child);
            }
        }
        if matches.len() > self.max_multistatus_entries {
            return response(StatusCode::INSUFFICIENT_STORAGE, Vec::new());
        }
        self.calendar_multistatus(matches)
    }

    fn calendar_multistatus(
        &self,
        resources: impl IntoIterator<Item = ResourceId>,
    ) -> Result<Response<Vec<u8>>> {
        let mut xml = String::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">"#,
        );
        for resource in resources {
            let resolved = self.store.resolve_binding(&resource)?;
            let Some(metadata) = self.store.metadata(&resolved)? else {
                continue;
            };
            if metadata.is_collection || !is_calendar_content_type(metadata.content_type.as_deref())
            {
                continue;
            }
            let body = self.store.read(&resolved)?;
            let calendar = std::str::from_utf8(&body)
                .map_err(|_| anyhow!("stored calendar resource is not UTF-8"))?;
            xml.push_str("<D:response><D:href>");
            xml.push_str(&escape_xml(resource.as_str()));
            xml.push_str("</D:href><D:propstat><D:prop><D:getetag>");
            xml.push_str(&escape_xml(&metadata.etag));
            xml.push_str(
                "</D:getetag><C:calendar-data content-type=\"text/calendar\" version=\"2.0\">",
            );
            xml.push_str(&escape_xml(calendar));
            xml.push_str("</C:calendar-data></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
        }
        xml.push_str("</D:multistatus>");
        Response::builder()
            .status(StatusCode::MULTI_STATUS)
            .header(http::header::CONTENT_TYPE, "application/xml; charset=utf-8")
            .body(xml.into_bytes())
            .map_err(Into::into)
    }

    fn free_busy(
        &self,
        collection: &ResourceId,
        start: CalendarInstant,
        end: CalendarInstant,
    ) -> Result<Response<Vec<u8>>> {
        if !self.is_calendar_collection(collection)? {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        let mut periods = Vec::new();
        for child in self.store.children(collection)? {
            let Some(metadata) = self.store.metadata(&child)? else {
                continue;
            };
            if metadata.is_collection || !is_calendar_content_type(metadata.content_type.as_deref())
            {
                continue;
            }
            for object in validate_calendar(&self.store.read(&child)?)? {
                if object.component == "VEVENT" && object.end >= start && object.start < end {
                    periods.push(format!(
                        "{}/{}",
                        format_datetime(object.start),
                        format_datetime(object.end)
                    ));
                }
            }
        }
        periods.sort();
        let body = format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VFREEBUSY\r\nFREEBUSY:{}\r\nEND:VFREEBUSY\r\nEND:VCALENDAR\r\n",
            periods.join(",")
        );
        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/calendar; charset=utf-8")
            .body(body.into_bytes())
            .map_err(Into::into)
    }

    fn is_calendar_collection(&self, resource: &ResourceId) -> Result<bool> {
        Ok(self.store.properties(resource)?.iter().any(|property| {
            property.namespace == CALDAV_NAMESPACE && property.name == CALENDAR_MARKER
        }))
    }

    fn bind(
        &self,
        collection: &ResourceId,
        body: &[u8],
        replace: bool,
    ) -> Result<Response<Vec<u8>>> {
        let request = parse_binding_request(body, if replace { "rebind" } else { "bind" })?;
        let href = request
            .href
            .ok_or_else(|| anyhow!("WebDAV binding href is required"))?;
        let href_path = href
            .parse::<http::Uri>()
            .ok()
            .map(|uri| uri.path().to_owned())
            .unwrap_or(href);
        let target = self
            .store
            .resolve_binding(&ResourceId::parse(&href_path)?)?;
        if self.store.metadata(&target)?.is_none() {
            return response(StatusCode::NOT_FOUND, Vec::new());
        }
        let alias = binding_child(collection, &request.segment)?;
        match self.store.put_binding(&alias, &target, replace) {
            Ok(()) => response(StatusCode::CREATED, Vec::new()),
            Err(error) if error.downcast_ref::<BindingAlreadyExists>().is_some() => {
                response(StatusCode::PRECONDITION_FAILED, Vec::new())
            }
            Err(error) => Err(error),
        }
    }

    fn unbind(&self, collection: &ResourceId, body: &[u8]) -> Result<Response<Vec<u8>>> {
        let request = parse_binding_request(body, "unbind")?;
        let alias = binding_child(collection, &request.segment)?;
        if !self.store.remove_binding(&alias)? {
            return response(StatusCode::NOT_FOUND, Vec::new());
        }
        response(StatusCode::NO_CONTENT, Vec::new())
    }

    fn proppatch(
        &self,
        resource: &ResourceId,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Response<Vec<u8>>> {
        if self.store.metadata(resource)?.is_none() {
            return response(StatusCode::NOT_FOUND, Vec::new());
        }
        if let Some(status) = self.lock_failure_status(resource, headers)? {
            return response(status, Vec::new());
        }
        let patch = parse_property_update(body)?;
        if patch.set.iter().any(is_protected_live_property)
            || patch
                .remove
                .iter()
                .any(|(namespace, name)| is_protected_property_name(namespace, name))
        {
            return response(StatusCode::FORBIDDEN, Vec::new());
        }
        self.store
            .patch_properties(resource, &patch.set, &patch.remove)?;
        multistatus_property_response(resource, patch.names())
    }

    fn collect_descendants(
        &self,
        resource: &ResourceId,
        remaining_depth: usize,
        resources: &mut Vec<ResourceId>,
    ) -> Result<()> {
        if remaining_depth == 0 {
            return Ok(());
        }
        for child in self.store.children(resource)? {
            resources.push(child.clone());
            if resources.len() > self.max_multistatus_entries {
                return Ok(());
            }
            self.collect_descendants(&child, remaining_depth - 1, resources)?;
        }
        for binding in self.store.child_bindings(resource)? {
            resources.push(binding);
            if resources.len() > self.max_multistatus_entries {
                return Ok(());
            }
        }
        Ok(())
    }

    fn lock(
        &self,
        resource: &ResourceId,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Response<Vec<u8>>> {
        reject_unsafe_xml(body)?;
        let timeout_seconds = parse_timeout(headers, self.max_lock_timeout_seconds);
        let depth = match headers.get("depth").and_then(|value| value.to_str().ok()) {
            Some("0") => LockDepth::Zero,
            Some("infinity") | None => LockDepth::Infinity,
            _ => return response(StatusCode::BAD_REQUEST, Vec::new()),
        };
        if body.is_empty() {
            let supplied = headers
                .get("if")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let Some(mut lock) = self
                .store
                .locks(resource, true)?
                .into_iter()
                .find(|lock| supplied.contains(&lock.token))
            else {
                return response(StatusCode::PRECONDITION_FAILED, Vec::new());
            };
            lock.expires_unix_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .saturating_add(timeout_seconds);
            self.store.put_lock(&lock)?;
            return lock_response(&lock, timeout_seconds, StatusCode::OK);
        }
        let scope = if String::from_utf8_lossy(body).contains("shared") {
            LockScope::Shared
        } else {
            LockScope::Exclusive
        };
        let existing = self.store.locks(resource, true)?;
        if existing
            .iter()
            .any(|lock| lock.scope == LockScope::Exclusive || scope == LockScope::Exclusive)
        {
            return response(locked_status(), Vec::new());
        }
        let created = self.store.metadata(resource)?.is_none();
        if created {
            if !self.parent_collection_exists(resource)? {
                return response(StatusCode::CONFLICT, Vec::new());
            }
            self.store.put(resource, &[], None)?;
        }
        let token = format!("opaquelocktoken:{}", Uuid::new_v4());
        let expires_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .saturating_add(timeout_seconds);
        let lock = LockRecord {
            token: token.clone(),
            resource: resource.clone(),
            owner_xml: (!body.is_empty()).then(|| String::from_utf8_lossy(body).into_owned()),
            depth,
            scope,
            expires_unix_seconds,
        };
        self.store.put_lock(&lock)?;
        lock_response(
            &lock,
            timeout_seconds,
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
        )
    }

    fn unlock(&self, resource: &ResourceId, headers: &HeaderMap) -> Result<Response<Vec<u8>>> {
        let Some(token) = headers
            .get("lock-token")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().trim_start_matches('<').trim_end_matches('>'))
        else {
            return response(StatusCode::BAD_REQUEST, Vec::new());
        };
        let owns_token = self
            .store
            .locks(resource, false)?
            .iter()
            .any(|lock| lock.token == token);
        if !owns_token || !self.store.remove_lock(token)? {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        response(StatusCode::NO_CONTENT, Vec::new())
    }

    fn copy_or_move(
        &self,
        source: &ResourceId,
        headers: &HeaderMap,
        move_resource: bool,
    ) -> Result<Response<Vec<u8>>> {
        let Some(destination) = headers
            .get("destination")
            .and_then(|value| value.to_str().ok())
        else {
            return response(StatusCode::BAD_REQUEST, Vec::new());
        };
        let destination_uri = destination
            .parse::<http::Uri>()
            .map_err(|_| anyhow!("WebDAV Destination is not a valid URI"))?;
        let destination = ResourceId::parse(destination_uri.path())?;
        let overwrite = match headers
            .get("overwrite")
            .and_then(|value| value.to_str().ok())
        {
            None | Some("T" | "t") => true,
            Some("F" | "f") => false,
            Some(_) => return response(StatusCode::BAD_REQUEST, Vec::new()),
        };
        let Some(source_metadata) = self.store.metadata(source)? else {
            return response(StatusCode::NOT_FOUND, Vec::new());
        };
        if source == &destination {
            return response(StatusCode::FORBIDDEN, Vec::new());
        }
        if !self.parent_collection_exists(&destination)? {
            return response(StatusCode::CONFLICT, Vec::new());
        }
        let destination_exists = self.store.metadata(&destination)?.is_some();
        if destination_exists && !overwrite {
            return response(StatusCode::PRECONDITION_FAILED, Vec::new());
        }
        let depth = headers
            .get("depth")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("infinity");
        if (move_resource && depth != "infinity") || !matches!(depth, "0" | "infinity") {
            return response(StatusCode::BAD_REQUEST, Vec::new());
        }
        let created = !destination_exists;
        if let Some(status) = self.lock_failure_status(&destination, headers)? {
            return response(status, Vec::new());
        }
        if move_resource && let Some(status) = self.lock_failure_status(source, headers)? {
            return response(status, Vec::new());
        }
        if move_resource {
            self.store.move_resource(source, &destination, overwrite)?;
            if let Err(error) = self.store.move_resource_metadata(source, &destination) {
                let _ = self.store.move_resource(&destination, source, true);
                return Err(error);
            }
        } else if source_metadata.is_collection && depth == "0" {
            if destination_exists {
                self.store.delete(&destination)?;
                self.store.remove_resource_metadata(&destination)?;
            }
            self.store.create_collection(&destination)?;
            if let Err(error) = self.store.copy_resource_metadata(source, &destination) {
                let _ = self.store.delete(&destination);
                return Err(error);
            }
        } else {
            self.store.copy(source, &destination, overwrite)?;
            if let Err(error) = self.store.copy_resource_metadata(source, &destination) {
                let _ = self.store.delete(&destination);
                return Err(error);
            }
        }
        response(
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::NO_CONTENT
            },
            Vec::new(),
        )
    }

    fn lock_failure_status(
        &self,
        resource: &ResourceId,
        headers: &HeaderMap,
    ) -> Result<Option<StatusCode>> {
        let locks = self.store.locks(resource, true)?;
        let if_header = headers
            .get("if")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !if_header.is_empty() && !self.if_header_satisfied(resource, if_header, &locks)? {
            return Ok(Some(StatusCode::PRECONDITION_FAILED));
        }
        if locks.is_empty() {
            return Ok(None);
        }
        let if_match = headers
            .get(http::header::IF_MATCH)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if locks.iter().all(|lock| {
            if_header_tokens(if_header).any(|token| token == lock.token)
                || if_match.contains(&lock.token)
        }) {
            Ok(None)
        } else if headers.contains_key("if") {
            Ok(Some(StatusCode::PRECONDITION_FAILED))
        } else {
            Ok(Some(locked_status()))
        }
    }

    fn if_header_satisfied(
        &self,
        resource: &ResourceId,
        header: &str,
        locks: &[LockRecord],
    ) -> Result<bool> {
        let etag = self.store.metadata(resource)?.map(|metadata| metadata.etag);
        let mut lists = Vec::new();
        let mut remaining = header;
        while let Some(start) = remaining.find('(') {
            remaining = &remaining[start + 1..];
            let Some(end) = remaining.find(')') else {
                break;
            };
            lists.push(&remaining[..end]);
            remaining = &remaining[end + 1..];
        }
        if lists.is_empty() {
            return Ok(false);
        }
        if let Some(etag) = etag.as_deref()
            && lists.iter().any(|list| {
                locks
                    .iter()
                    .any(|lock| list.contains(&format!("<{}>", lock.token)))
                    && list.contains(&format!("[{etag}]"))
            })
        {
            return Ok(true);
        }
        Ok(lists.into_iter().any(|list| {
            let mut cursor = list.trim();
            let mut satisfied = true;
            let mut conditions = 0usize;
            while !cursor.is_empty() {
                let (negate, rest) = if let Some(rest) = cursor.strip_prefix("Not ") {
                    (true, rest.trim_start())
                } else {
                    (false, cursor)
                };
                let (value, rest, is_token) = if let Some(rest) = rest.strip_prefix('<') {
                    let Some(end) = rest.find('>') else {
                        return false;
                    };
                    (&rest[..end], &rest[end + 1..], true)
                } else if let Some(rest) = rest.strip_prefix('[') {
                    let Some(end) = rest.find(']') else {
                        return false;
                    };
                    (&rest[..end], &rest[end + 1..], false)
                } else {
                    return false;
                };
                let mut condition = if is_token {
                    locks.iter().any(|lock| lock.token == value)
                } else {
                    etag.as_deref().is_some_and(|etag| {
                        etag == value || etag.trim_matches('"') == value.trim_matches('"')
                    })
                };
                if negate {
                    condition = !condition;
                }
                satisfied &= condition;
                conditions += 1;
                cursor = rest.trim_start();
            }
            conditions > 0 && satisfied
        }))
    }
}

fn parse_depth(headers: &HeaderMap, max_depth: usize) -> Result<usize> {
    match headers.get("depth").and_then(|value| value.to_str().ok()) {
        None | Some("infinity") => Ok(max_depth),
        Some("0") => Ok(0),
        Some("1") => Ok(1),
        Some(_) => Err(anyhow!("invalid WebDAV Depth header")),
    }
}

fn parse_timeout(headers: &HeaderMap, maximum: u64) -> u64 {
    headers
        .get("timeout")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .split(',')
                .find_map(|item| item.trim().strip_prefix("Second-")?.parse::<u64>().ok())
        })
        .unwrap_or(maximum)
        .min(maximum)
        .max(1)
}

fn reject_unsafe_xml(body: &[u8]) -> Result<()> {
    if body.len() > 64 * 1024 {
        return Err(anyhow!("WebDAV XML body exceeds 64 KiB"));
    }
    let upper = String::from_utf8_lossy(body).to_ascii_uppercase();
    if upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY") {
        return Err(anyhow!("WebDAV XML entity declarations are forbidden"));
    }
    Ok(())
}

fn validate_propfind_body(body: &[u8]) -> Result<()> {
    reject_unsafe_xml(body)?;
    let mut reader = NsReader::from_reader(body);
    let mut root = None::<(String, String)>;
    let mut depth = 0usize;
    loop {
        let (resolution, event) = reader.read_resolved_event()?;
        match event {
            Event::Start(element) => {
                let namespace = resolved_namespace(resolution)?;
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                if root.is_none() {
                    root = Some((namespace, name));
                }
                depth += 1;
            }
            Event::Empty(element) => {
                let namespace = resolved_namespace(resolution)?;
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                if root.is_none() {
                    root = Some((namespace, name));
                }
            }
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("PROPFIND XML nesting is invalid"))?
            }
            Event::DocType(_) => return Err(anyhow!("WebDAV XML document types are forbidden")),
            Event::Eof => break,
            Event::Decl(_)
            | Event::PI(_)
            | Event::Comment(_)
            | Event::GeneralRef(_)
            | Event::Text(_)
            | Event::CData(_) => {}
        }
    }
    if depth != 0
        || !matches!(root.as_ref(), Some((namespace, name)) if namespace == "DAV:" && name == "propfind")
    {
        return Err(anyhow!("PROPFIND XML root is invalid"));
    }
    Ok(())
}

fn xml_attribute(element: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>> {
    for attribute in element.attributes() {
        let attribute = attribute?;
        if attribute.key.local_name().as_ref() == name {
            return Ok(Some(
                attribute
                    .normalized_value(XmlVersion::Implicit1_0)?
                    .into_owned(),
            ));
        }
    }
    Ok(None)
}

enum ReportRequest {
    VersionTree,
    CalendarQuery {
        component: Option<String>,
        start: Option<CalendarInstant>,
        end: Option<CalendarInstant>,
        text_filters: Vec<CalendarTextFilter>,
    },
    FreeBusy {
        start: CalendarInstant,
        end: CalendarInstant,
    },
}

#[derive(Debug)]
struct CalendarTextFilter {
    property: String,
    value: String,
    negate: bool,
    match_type: CalendarTextMatchType,
}

#[derive(Debug, Default)]
enum CalendarTextMatchType {
    Equals,
    StartsWith,
    EndsWith,
    #[default]
    Contains,
}

fn parse_report(body: &[u8]) -> Result<ReportRequest> {
    reject_unsafe_xml(body)?;
    if body.is_empty() {
        return Ok(ReportRequest::VersionTree);
    }
    let mut reader = NsReader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut root = None::<(String, String)>;
    let mut component = None;
    let mut start = None;
    let mut end = None;
    let mut text_filters = Vec::new();
    let mut property_filter = None::<String>;
    let mut pending_text_filter = None::<CalendarTextFilter>;
    let mut depth = 0usize;
    loop {
        let (resolution, event) = reader.read_resolved_event()?;
        match event {
            Event::Start(element) => {
                let namespace = resolved_namespace(resolution)?;
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                if root.is_none() {
                    root = Some((namespace.clone(), name.clone()));
                }
                if namespace == CALDAV_NAMESPACE && name == "comp-filter" {
                    for attribute in element.attributes() {
                        let attribute = attribute?;
                        if attribute.key.local_name().as_ref() == b"name" {
                            let value = attribute
                                .normalized_value(XmlVersion::Implicit1_0)?
                                .into_owned();
                            if value != "VCALENDAR" {
                                component = Some(value);
                            }
                        }
                    }
                }
                if namespace == CALDAV_NAMESPACE && name == "time-range" {
                    for attribute in element.attributes() {
                        let attribute = attribute?;
                        let value = attribute.normalized_value(XmlVersion::Implicit1_0)?;
                        match attribute.key.local_name().as_ref() {
                            b"start" => start = Some(parse_datetime(&value)?),
                            b"end" => end = Some(parse_datetime(&value)?),
                            _ => {}
                        }
                    }
                }
                if namespace == CALDAV_NAMESPACE && name == "prop-filter" {
                    property_filter = xml_attribute(&element, b"name")?;
                }
                if namespace == CALDAV_NAMESPACE && name == "text-match" {
                    let property = property_filter
                        .clone()
                        .ok_or_else(|| anyhow!("CalDAV text-match requires a prop-filter"))?;
                    let negate = xml_attribute(&element, b"negate-condition")?
                        .is_some_and(|value| value.eq_ignore_ascii_case("yes"));
                    let match_type = match xml_attribute(&element, b"match-type")?.as_deref() {
                        None | Some("contains") => CalendarTextMatchType::Contains,
                        Some("equals") => CalendarTextMatchType::Equals,
                        Some("starts-with") => CalendarTextMatchType::StartsWith,
                        Some("ends-with") => CalendarTextMatchType::EndsWith,
                        Some(_) => return Err(anyhow!("CalDAV text match type is not supported")),
                    };
                    pending_text_filter = Some(CalendarTextFilter {
                        property,
                        value: String::new(),
                        negate,
                        match_type,
                    });
                }
                depth += 1;
            }
            Event::Empty(element) => {
                let namespace = resolved_namespace(resolution)?;
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                if root.is_none() {
                    root = Some((namespace.clone(), name.clone()));
                }
                if namespace == CALDAV_NAMESPACE && name == "comp-filter" {
                    for attribute in element.attributes() {
                        let attribute = attribute?;
                        if attribute.key.local_name().as_ref() == b"name" {
                            let value = attribute
                                .normalized_value(XmlVersion::Implicit1_0)?
                                .into_owned();
                            if value != "VCALENDAR" {
                                component = Some(value);
                            }
                        }
                    }
                }
                if namespace == CALDAV_NAMESPACE && name == "time-range" {
                    for attribute in element.attributes() {
                        let attribute = attribute?;
                        let value = attribute.normalized_value(XmlVersion::Implicit1_0)?;
                        match attribute.key.local_name().as_ref() {
                            b"start" => start = Some(parse_datetime(&value)?),
                            b"end" => end = Some(parse_datetime(&value)?),
                            _ => {}
                        }
                    }
                }
            }
            Event::Text(text) => {
                if let Some(filter) = pending_text_filter.as_mut() {
                    filter.value.push_str(&text.decode()?);
                }
            }
            Event::CData(text) => {
                if let Some(filter) = pending_text_filter.as_mut() {
                    filter.value.push_str(&text.decode()?);
                }
            }
            Event::End(element) => {
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                if name == "text-match"
                    && let Some(filter) = pending_text_filter.take()
                {
                    text_filters.push(filter);
                }
                if name == "prop-filter" {
                    property_filter = None;
                }
                depth = depth.saturating_sub(1);
            }
            Event::DocType(_) => return Err(anyhow!("CalDAV XML document types are forbidden")),
            Event::Eof => break,
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) | Event::GeneralRef(_) => {}
        }
    }
    if depth != 0 {
        return Err(anyhow!("CalDAV REPORT XML is malformed"));
    }
    match root
        .as_ref()
        .map(|(namespace, name)| (namespace.as_str(), name.as_str()))
    {
        Some(("DAV:", "version-tree")) => Ok(ReportRequest::VersionTree),
        Some((CALDAV_NAMESPACE, "calendar-query")) => Ok(ReportRequest::CalendarQuery {
            component,
            start,
            end,
            text_filters,
        }),
        Some((CALDAV_NAMESPACE, "free-busy-query")) => {
            let start = start.ok_or_else(|| anyhow!("free-busy-query requires start"))?;
            let end = end.ok_or_else(|| anyhow!("free-busy-query requires end"))?;
            if end <= start {
                return Err(anyhow!("free-busy-query end must follow start"));
            }
            Ok(ReportRequest::FreeBusy { start, end })
        }
        _ => Err(anyhow!("unsupported WebDAV REPORT type")),
    }
}

#[derive(Debug)]
struct BasicSearchQuery {
    scope: ResourceId,
    depth: usize,
    predicate: SearchPredicate,
}

#[derive(Debug)]
enum SearchPredicate {
    All,
    IsCollection,
    Contains(String),
    PropertyEquals {
        namespace: String,
        name: String,
        value: String,
    },
}

fn parse_basic_search(body: &[u8], max_depth: usize) -> Result<BasicSearchQuery> {
    reject_unsafe_xml(body)?;
    let document = std::str::from_utf8(body)?;
    let mut reader = NsReader::from_str(document);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::<(String, String)>::new();
    let mut href = None;
    let mut depth = None;
    let mut literal = None;
    let mut contains = None;
    let mut property = None;
    let mut is_collection = false;
    let mut saw_basicsearch = false;
    let mut saw_where = false;
    let mut operator_count = 0usize;
    loop {
        let (resolution, event) = reader.read_resolved_event()?;
        match event {
            Event::Start(element) => {
                let namespace = resolved_namespace(resolution)?;
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                if namespace == "DAV:" && name == "basicsearch" {
                    saw_basicsearch = true;
                }
                if namespace == "DAV:" && name == "where" {
                    saw_where = true;
                }
                if namespace == "DAV:" && name == "is-collection" {
                    is_collection = true;
                }
                if stack
                    .last()
                    .is_some_and(|(namespace, name)| namespace == "DAV:" && name == "where")
                {
                    if namespace != "DAV:"
                        || !matches!(name.as_str(), "eq" | "contains" | "is-collection")
                    {
                        return Err(anyhow!("DAV:basicsearch operator is not supported"));
                    }
                    operator_count += 1;
                }
                let parent_is_prop = stack
                    .last()
                    .is_some_and(|(namespace, name)| namespace == "DAV:" && name == "prop");
                if parent_is_prop {
                    property = Some((namespace.clone(), name.clone()));
                }
                stack.push((namespace, name));
            }
            Event::Empty(element) => {
                let namespace = resolved_namespace(resolution)?;
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                if namespace == "DAV:" && name == "is-collection" {
                    is_collection = true;
                    if stack
                        .last()
                        .is_some_and(|(namespace, name)| namespace == "DAV:" && name == "where")
                    {
                        operator_count += 1;
                    }
                } else if stack
                    .last()
                    .is_some_and(|(namespace, name)| namespace == "DAV:" && name == "prop")
                {
                    property = Some((namespace, name));
                }
            }
            Event::Text(text) => {
                let value = text.decode()?.trim().to_owned();
                if value.is_empty() {
                    continue;
                }
                match stack.last().map(|(_, name)| name.as_str()) {
                    Some("href") => href = Some(value),
                    Some("depth") => depth = Some(value),
                    Some("literal") => literal = Some(value),
                    Some("contains") => contains = Some(value),
                    _ => {}
                }
            }
            Event::CData(text) => {
                let value = text.decode()?.trim().to_owned();
                if value.is_empty() {
                    continue;
                }
                match stack.last().map(|(_, name)| name.as_str()) {
                    Some("href") => href = Some(value),
                    Some("depth") => depth = Some(value),
                    Some("literal") => literal = Some(value),
                    Some("contains") => contains = Some(value),
                    _ => {}
                }
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::DocType(_) => return Err(anyhow!("WebDAV XML document types are forbidden")),
            Event::Eof => break,
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) | Event::GeneralRef(_) => {}
        }
    }
    if !saw_basicsearch || !stack.is_empty() {
        return Err(anyhow!("DAV:basicsearch document is malformed"));
    }
    if saw_where && operator_count != 1 {
        return Err(anyhow!(
            "DAV:basicsearch requires exactly one supported where operator"
        ));
    }
    let scope = ResourceId::parse(
        href.as_deref()
            .ok_or_else(|| anyhow!("DAV:basicsearch scope href is required"))?,
    )?;
    let depth = match depth.as_deref() {
        Some("0") => 0,
        Some("1") => 1,
        Some("infinity") | None => max_depth,
        Some(_) => return Err(anyhow!("DAV:basicsearch scope depth is invalid")),
    };
    let predicate = if is_collection {
        SearchPredicate::IsCollection
    } else if let Some(needle) = contains {
        SearchPredicate::Contains(needle)
    } else if let (Some((namespace, name)), Some(value)) = (property, literal) {
        SearchPredicate::PropertyEquals {
            namespace,
            name,
            value,
        }
    } else {
        SearchPredicate::All
    };
    Ok(BasicSearchQuery {
        scope,
        depth,
        predicate,
    })
}

fn resource_contains(parent: &ResourceId, child: &ResourceId) -> bool {
    parent == &ResourceId::root()
        || child == parent
        || child
            .as_str()
            .starts_with(&format!("{}/", parent.as_str().trim_end_matches('/')))
}

fn is_calendar_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/calendar"))
}

fn if_header_tokens(header: &str) -> impl Iterator<Item = &str> {
    header
        .split('<')
        .skip(1)
        .filter_map(|remainder| remainder.split_once('>').map(|(token, _)| token))
}

fn calendar_text_filter_matches(body: &[u8], filter: &CalendarTextFilter) -> bool {
    let text = String::from_utf8_lossy(body).replace("\r\n", "\n");
    let mut unfolded = Vec::<String>::new();
    for line in text.lines() {
        if (line.starts_with(' ') || line.starts_with('\t')) && !unfolded.is_empty() {
            unfolded.last_mut().unwrap().push_str(&line[1..]);
        } else {
            unfolded.push(line.to_owned());
        }
    }
    let expected = filter.value.to_lowercase();
    let matched = unfolded.iter().any(|line| {
        let Some((name_and_parameters, value)) = line.split_once(':') else {
            return false;
        };
        let name = name_and_parameters
            .split(';')
            .next()
            .unwrap_or(name_and_parameters);
        if !name.eq_ignore_ascii_case(&filter.property) {
            return false;
        }
        let actual = value.to_lowercase();
        match filter.match_type {
            CalendarTextMatchType::Equals => actual == expected,
            CalendarTextMatchType::StartsWith => actual.starts_with(&expected),
            CalendarTextMatchType::EndsWith => actual.ends_with(&expected),
            CalendarTextMatchType::Contains => actual.contains(&expected),
        }
    });
    matched != filter.negate
}

struct BindingRequest {
    segment: String,
    href: Option<String>,
}

fn parse_binding_request(body: &[u8], expected_root: &str) -> Result<BindingRequest> {
    reject_unsafe_xml(body)?;
    let mut reader = NsReader::from_reader(body);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::new();
    let mut root = None;
    let mut segment = None;
    let mut href = None;
    loop {
        let (resolution, event) = reader.read_resolved_event()?;
        match event {
            Event::Start(element) => {
                let namespace = resolved_namespace(resolution)?;
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                if namespace != "DAV:" {
                    return Err(anyhow!("WebDAV binding elements must use DAV: namespace"));
                }
                if stack.is_empty() {
                    root = Some(name.clone());
                }
                stack.push(name);
            }
            Event::Text(text) => {
                let value = text.decode()?.trim().to_owned();
                match stack.last().map(String::as_str) {
                    Some("segment") => segment = Some(value),
                    Some("href") => href = Some(value),
                    _ if !value.is_empty() => {
                        return Err(anyhow!("unexpected WebDAV binding text"));
                    }
                    _ => {}
                }
            }
            Event::CData(text) => {
                let value = text.decode()?.trim().to_owned();
                match stack.last().map(String::as_str) {
                    Some("segment") => segment = Some(value),
                    Some("href") => href = Some(value),
                    _ if !value.is_empty() => {
                        return Err(anyhow!("unexpected WebDAV binding text"));
                    }
                    _ => {}
                }
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Empty(_) => return Err(anyhow!("WebDAV binding element must not be empty")),
            Event::DocType(_) => return Err(anyhow!("WebDAV XML document types are forbidden")),
            Event::Eof => break,
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) | Event::GeneralRef(_) => {}
        }
    }
    if root.as_deref() != Some(expected_root) || !stack.is_empty() {
        return Err(anyhow!("WebDAV binding request root is invalid"));
    }
    let segment = segment.ok_or_else(|| anyhow!("WebDAV binding segment is required"))?;
    if segment.is_empty()
        || matches!(segment.as_str(), "." | "..")
        || segment.contains('/')
        || segment.contains('\\')
        || segment.chars().any(char::is_control)
    {
        return Err(anyhow!("WebDAV binding segment is invalid"));
    }
    Ok(BindingRequest { segment, href })
}

fn binding_child(collection: &ResourceId, segment: &str) -> Result<ResourceId> {
    ResourceId::parse(&format!(
        "{}/{}",
        collection.as_str().trim_end_matches('/'),
        segment
    ))
}

#[derive(Default)]
struct PropertyPatch {
    set: Vec<DeadProperty>,
    remove: Vec<(String, String)>,
}

impl PropertyPatch {
    fn names(&self) -> Vec<(String, String)> {
        self.set
            .iter()
            .map(|property| (property.namespace.clone(), property.name.clone()))
            .chain(self.remove.iter().cloned())
            .collect()
    }
}

#[derive(Clone, Copy)]
enum PropertyPatchMode {
    Set,
    Remove,
}

struct PendingProperty {
    namespace: String,
    name: String,
    value: String,
    stack_depth: usize,
    mode: PropertyPatchMode,
}

fn parse_property_update(body: &[u8]) -> Result<PropertyPatch> {
    parse_property_update_inner(body, false)
}

fn parse_property_update_allow_empty(body: &[u8]) -> Result<PropertyPatch> {
    parse_property_update_inner(body, true)
}

fn parse_property_update_inner(body: &[u8], allow_empty: bool) -> Result<PropertyPatch> {
    reject_unsafe_xml(body)?;
    let document = std::str::from_utf8(body)?;
    let mut reader = NsReader::from_str(document);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::<(String, String)>::new();
    let mut mode = None;
    let mut pending: Option<PendingProperty> = None;
    let mut patch = PropertyPatch::default();
    loop {
        let (resolution, event) = reader.read_resolved_event()?;
        match event {
            Event::Start(element) => {
                let namespace = resolved_namespace(resolution)?;
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_string();
                let parent_is_prop = stack
                    .last()
                    .is_some_and(|(namespace, name)| namespace == "DAV:" && name == "prop");
                if namespace == "DAV:" && name == "set" {
                    mode = Some(PropertyPatchMode::Set);
                } else if namespace == "DAV:" && name == "remove" {
                    mode = Some(PropertyPatchMode::Remove);
                } else if parent_is_prop {
                    pending = Some(PendingProperty {
                        namespace: namespace.clone(),
                        name: name.clone(),
                        value: String::new(),
                        stack_depth: stack.len() + 1,
                        mode: mode
                            .ok_or_else(|| anyhow!("WebDAV property has no set/remove mode"))?,
                    });
                }
                stack.push((namespace, name));
            }
            Event::Empty(element) => {
                let namespace = resolved_namespace(resolution)?;
                let name = std::str::from_utf8(element.local_name().as_ref())?.to_string();
                let parent_is_prop = stack
                    .last()
                    .is_some_and(|(namespace, name)| namespace == "DAV:" && name == "prop");
                if parent_is_prop {
                    finish_property(
                        &mut patch,
                        PendingProperty {
                            namespace,
                            name,
                            value: String::new(),
                            stack_depth: stack.len() + 1,
                            mode: mode
                                .ok_or_else(|| anyhow!("WebDAV property has no set/remove mode"))?,
                        },
                    );
                }
            }
            Event::Text(text) => {
                if let Some(property) = pending.as_mut() {
                    property.value.push_str(&text.decode()?);
                }
            }
            Event::CData(text) => {
                if let Some(property) = pending.as_mut() {
                    property.value.push_str(&text.decode()?);
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(property) = pending.as_mut() {
                    let character = if let Some(character) = reference.resolve_char_ref()? {
                        character
                    } else {
                        match reference.decode()?.as_ref() {
                            "lt" => '<',
                            "gt" => '>',
                            "amp" => '&',
                            "apos" => '\'',
                            "quot" => '"',
                            _ => return Err(anyhow!("WebDAV property contains an unknown entity")),
                        }
                    };
                    property.value.push(character);
                }
            }
            Event::End(_) => {
                if pending
                    .as_ref()
                    .is_some_and(|property| property.stack_depth == stack.len())
                    && let Some(property) = pending.take()
                {
                    finish_property(&mut patch, property);
                }
                if let Some((namespace, name)) = stack.pop()
                    && namespace == "DAV:"
                    && (name == "set" || name == "remove")
                {
                    mode = None;
                }
            }
            Event::DocType(_) => return Err(anyhow!("WebDAV XML document types are forbidden")),
            Event::Eof => break,
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
        }
    }
    if !stack.is_empty()
        || pending.is_some()
        || !allow_empty && patch.set.is_empty() && patch.remove.is_empty()
    {
        return Err(anyhow!("WebDAV property update is empty or malformed"));
    }
    Ok(patch)
}

fn resolved_namespace(resolution: ResolveResult<'_>) -> Result<String> {
    match resolution {
        ResolveResult::Bound(namespace) => Ok(std::str::from_utf8(namespace.as_ref())?.to_string()),
        ResolveResult::Unbound => Ok(String::new()),
        ResolveResult::Unknown(prefix) => Err(anyhow!(
            "WebDAV XML namespace prefix is not bound: {}",
            String::from_utf8_lossy(prefix.as_ref())
        )),
    }
}

fn is_xml_local_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn finish_property(patch: &mut PropertyPatch, property: PendingProperty) {
    match property.mode {
        PropertyPatchMode::Set => {
            patch.remove.retain(|(namespace, name)| {
                namespace != &property.namespace || name != &property.name
            });
            patch.set.retain(|existing| {
                existing.namespace != property.namespace || existing.name != property.name
            });
            patch.set.push(DeadProperty {
                namespace: property.namespace,
                name: property.name,
                value_xml: property.value,
            });
        }
        PropertyPatchMode::Remove => {
            patch.set.retain(|existing| {
                existing.namespace != property.namespace || existing.name != property.name
            });
            if !patch
                .remove
                .iter()
                .any(|(namespace, name)| namespace == &property.namespace && name == &property.name)
            {
                patch.remove.push((property.namespace, property.name));
            }
        }
    }
}

fn is_protected_live_property(property: &DeadProperty) -> bool {
    is_protected_property_name(&property.namespace, &property.name)
}

fn is_protected_property_name(namespace: &str, name: &str) -> bool {
    namespace == "DAV:"
        && matches!(
            name,
            "acl"
                | "creationdate"
                | "getcontentlength"
                | "getetag"
                | "getlastmodified"
                | "lockdiscovery"
                | "resourcetype"
                | "supportedlock"
        )
}

fn multistatus_property_response(
    resource: &ResourceId,
    names: Vec<(String, String)>,
) -> Result<Response<Vec<u8>>> {
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>{}</D:href><D:propstat><D:prop>"#,
        escape_xml(resource.as_str())
    );
    for (namespace, name) in names {
        xml.push_str("<Q:property xmlns:Q=\"");
        xml.push_str(&escape_xml(&namespace));
        xml.push_str("\" name=\"");
        xml.push_str(&escape_xml(&name));
        xml.push_str("\"/>");
    }
    xml.push_str(
        "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>",
    );
    Response::builder()
        .status(StatusCode::MULTI_STATUS)
        .header(http::header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(xml.into_bytes())
        .map_err(Into::into)
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn lock_response(
    lock: &LockRecord,
    timeout_seconds: u64,
    status: StatusCode,
) -> Result<Response<Vec<u8>>> {
    let scope = match lock.scope {
        LockScope::Exclusive => "exclusive",
        LockScope::Shared => "shared",
    };
    let depth = match lock.depth {
        LockDepth::Zero => "0",
        LockDepth::Infinity => "infinity",
    };
    let body = format!(
        r#"<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:lockscope><D:{scope}/></D:lockscope><D:depth>{depth}</D:depth><D:locktoken><D:href>{}</D:href></D:locktoken><D:timeout>Second-{timeout_seconds}</D:timeout></D:activelock></D:lockdiscovery></D:prop>"#,
        escape_xml(&lock.token)
    );
    Response::builder()
        .status(status)
        .header("lock-token", format!("<{}>", lock.token))
        .header(http::header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(body.into_bytes())
        .map_err(Into::into)
}

fn response(status: StatusCode, body: Vec<u8>) -> Result<Response<Vec<u8>>> {
    Response::builder()
        .status(status)
        .body(body)
        .map_err(Into::into)
}

fn locked_status() -> StatusCode {
    StatusCode::from_u16(423).expect("423 is a valid HTTP status")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FileSystemDataStore, PersistentWebDavStore, RedbMetadataStore, WebDavDataStore,
        WebDavMetadataStore,
    };
    use tempfile::tempdir;

    #[test]
    fn real_filesystem_and_redb_support_dav_lifecycle() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        let context = WebDavRequestContext::default();

        let mkcol = Request::builder()
            .method("MKCOL")
            .uri("/docs")
            .body(Vec::new())
            .unwrap();
        assert_eq!(service.handle(mkcol, &context).unwrap().status(), 201);

        let put = Request::builder()
            .method("PUT")
            .uri("/docs/report.txt")
            .body(b"report".to_vec())
            .unwrap();
        assert_eq!(service.handle(put, &context).unwrap().status(), 201);

        let propfind = Request::builder()
            .method("PROPFIND")
            .uri("/docs")
            .header("depth", "1")
            .body(Vec::new())
            .unwrap();
        let response = service.handle(propfind, &context).unwrap();
        assert_eq!(response.status(), 207);
        let body = String::from_utf8(response.into_body()).unwrap();
        assert!(body.contains("report.txt"));
        assert!(body.contains("current-user-principal"));
        assert!(body.contains("calendar-home-set"));

        let proppatch = Request::builder()
            .method("PROPPATCH")
            .uri("/docs/report.txt")
            .body(
                br#"<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Q="urn:qpx:test"><D:set><D:prop><Q:classification>internal</Q:classification></D:prop></D:set></D:propertyupdate>"#.to_vec(),
            )
            .unwrap();
        assert_eq!(service.handle(proppatch, &context).unwrap().status(), 207);
        assert_eq!(
            service
                .store
                .properties(&ResourceId::parse("/docs/report.txt").unwrap())
                .unwrap()[0]
                .value_xml,
            "internal"
        );
    }

    #[test]
    fn property_update_rejects_entities_and_protected_live_properties() {
        assert!(
            parse_property_update(
                br#"<!DOCTYPE x [<!ENTITY e "x">]><D:propertyupdate xmlns:D="DAV:"/>"#
            )
            .is_err()
        );
        let patch = parse_property_update(
            br#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><D:getetag>x</D:getetag></D:prop></D:set></D:propertyupdate>"#,
        )
        .unwrap();
        assert!(patch.set.iter().any(is_protected_live_property));
    }

    #[test]
    fn verified_acl_context_can_deny_before_store_access() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)))
            .with_authorizer(|context, _, _| {
                if context.entitlements.iter().any(|value| value == "dav:read") {
                    AclDecision::Allow
                } else {
                    AclDecision::Deny
                }
            });
        let request = Request::builder()
            .method("GET")
            .uri("/secret")
            .body(Vec::new())
            .unwrap();
        assert_eq!(
            service
                .handle(request, &WebDavRequestContext::default())
                .unwrap()
                .status(),
            403
        );
    }

    #[test]
    fn extended_mkcol_creates_collection_with_dead_properties() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        let request = Request::builder()
            .method("MKCOL")
            .uri("/calendar")
            .header(http::header::CONTENT_TYPE, "application/xml")
            .body(br#"<D:mkcol xmlns:D="DAV:" xmlns:X="urn:test"><D:set><D:prop><X:kind>calendar</X:kind></D:prop></D:set></D:mkcol>"#.to_vec())
            .unwrap();
        assert_eq!(
            service
                .handle(request, &WebDavRequestContext::default())
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            service
                .store
                .properties(&ResourceId::parse("/calendar").unwrap())
                .unwrap()[0]
                .value_xml,
            "calendar"
        );
    }

    #[test]
    fn put_and_mkcol_require_an_existing_parent_collection() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        let context = WebDavRequestContext::default();

        for method in ["PUT", "MKCOL", "MKCALENDAR"] {
            let request = Request::builder()
                .method(method)
                .uri(format!("/missing/{method}"))
                .body(Vec::new())
                .unwrap();
            assert_eq!(
                service.handle(request, &context).unwrap().status(),
                StatusCode::CONFLICT
            );
        }
    }

    #[test]
    fn copy_honors_overwrite_parent_and_depth_preconditions() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        let context = WebDavRequestContext::default();
        for path in ["/source", "/destination"] {
            service
                .handle(
                    Request::builder()
                        .method("MKCOL")
                        .uri(path)
                        .body(Vec::new())
                        .unwrap(),
                    &context,
                )
                .unwrap();
        }
        service
            .handle(
                Request::builder()
                    .method("PUT")
                    .uri("/source/child")
                    .body(b"child".to_vec())
                    .unwrap(),
                &context,
            )
            .unwrap();

        let conflict = service
            .handle(
                Request::builder()
                    .method("COPY")
                    .uri("/source")
                    .header("destination", "/destination")
                    .header("overwrite", "F")
                    .body(Vec::new())
                    .unwrap(),
                &context,
            )
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::PRECONDITION_FAILED);

        let missing_parent = service
            .handle(
                Request::builder()
                    .method("COPY")
                    .uri("/source")
                    .header("destination", "/missing/copy")
                    .body(Vec::new())
                    .unwrap(),
                &context,
            )
            .unwrap();
        assert_eq!(missing_parent.status(), StatusCode::CONFLICT);

        let shallow = service
            .handle(
                Request::builder()
                    .method("COPY")
                    .uri("/source")
                    .header("destination", "/shallow")
                    .header("depth", "0")
                    .body(Vec::new())
                    .unwrap(),
                &context,
            )
            .unwrap();
        assert_eq!(shallow.status(), StatusCode::CREATED);
        assert!(
            service
                .store
                .metadata(&ResourceId::parse("/shallow/child").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn if_header_requires_exact_lock_token_and_accepts_matching_etag() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        let resource = ResourceId::parse("/locked").unwrap();
        service.store.put(&resource, b"data", None).unwrap();
        let lock = LockRecord {
            token: "opaquelocktoken:test".to_owned(),
            resource: resource.clone(),
            owner_xml: None,
            depth: LockDepth::Zero,
            scope: LockScope::Exclusive,
            expires_unix_seconds: u64::MAX,
        };
        service.store.put_lock(&lock).unwrap();
        let etag = service.store.metadata(&resource).unwrap().unwrap().etag;
        let locks = service.store.locks(&resource, true).unwrap();
        assert!(
            service
                .if_header_satisfied(
                    &resource,
                    &format!("(<opaquelocktoken:test> [{etag}]) (Not <DAV:no-lock>)"),
                    &locks,
                )
                .unwrap()
        );
        assert!(!if_header_tokens("(<opaquelocktoken:testx>)").any(|token| token == lock.token));
    }

    #[test]
    fn basicsearch_filters_by_dead_property_and_stays_within_scope() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        let context = WebDavRequestContext::default();
        for path in ["/docs", "/private"] {
            service
                .handle(
                    Request::builder()
                        .method("MKCOL")
                        .uri(path)
                        .body(Vec::new())
                        .unwrap(),
                    &context,
                )
                .unwrap();
        }
        for path in [
            "/docs/report.txt",
            "/docs/public.txt",
            "/private/secret.txt",
        ] {
            service
                .handle(
                    Request::builder()
                        .method("PUT")
                        .uri(path)
                        .body(b"content".to_vec())
                        .unwrap(),
                    &context,
                )
                .unwrap();
        }
        service
            .store
            .set_properties(
                &ResourceId::parse("/docs/report.txt").unwrap(),
                &[DeadProperty {
                    namespace: "urn:test".to_owned(),
                    name: "classification".to_owned(),
                    value_xml: "internal".to_owned(),
                }],
            )
            .unwrap();
        let request = Request::builder()
            .method("SEARCH")
            .uri("/docs")
            .body(br#"<D:searchrequest xmlns:D="DAV:" xmlns:X="urn:test"><D:basicsearch><D:select><D:allprop/></D:select><D:from><D:scope><D:href>/docs</D:href><D:depth>infinity</D:depth></D:scope></D:from><D:where><D:eq><D:prop><X:classification/></D:prop><D:literal>internal</D:literal></D:eq></D:where></D:basicsearch></D:searchrequest>"#.to_vec())
            .unwrap();
        let response = service.handle(request, &context).unwrap();
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        let body = String::from_utf8(response.into_body()).unwrap();
        assert!(body.contains("/docs/report.txt"));
        assert!(!body.contains("/docs/public.txt"));
        assert!(!body.contains("/private/secret.txt"));
        assert!(
            parse_basic_search(
                br#"<D:searchrequest xmlns:D="DAV:"><D:basicsearch><D:from><D:scope><D:href>/docs</D:href></D:scope></D:from><D:where><D:like/></D:where></D:basicsearch></D:searchrequest>"#,
                32,
            )
            .is_err()
        );
    }

    #[test]
    fn dav_acl_uses_verified_identity_and_deny_precedence() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        service
            .handle(
                Request::builder()
                    .method("PUT")
                    .uri("/report.txt")
                    .body(b"report".to_vec())
                    .unwrap(),
                &WebDavRequestContext::default(),
            )
            .unwrap();
        let acl = Request::builder()
            .method("ACL")
            .uri("/report.txt")
            .body(br#"<D:acl xmlns:D="DAV:"><D:ace><D:principal><D:href>alice</D:href></D:principal><D:grant><D:privilege><D:read/></D:privilege></D:grant></D:ace><D:ace><D:principal><D:all/></D:principal><D:deny><D:privilege><D:write/></D:privilege></D:deny></D:ace></D:acl>"#.to_vec())
            .unwrap();
        assert_eq!(
            service
                .handle(acl, &WebDavRequestContext::default())
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let alice = WebDavRequestContext {
            subject: Some("alice".to_owned()),
            ..Default::default()
        };
        let bob = WebDavRequestContext {
            subject: Some("bob".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("GET")
                        .uri("/report.txt")
                        .body(Vec::new())
                        .unwrap(),
                    &alice,
                )
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("GET")
                        .uri("/report.txt")
                        .body(Vec::new())
                        .unwrap(),
                    &bob,
                )
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("PUT")
                        .uri("/report.txt")
                        .body(b"changed".to_vec())
                        .unwrap(),
                    &alice,
                )
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn delta_v_version_control_checkout_checkin_and_update_restore_content() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        let context = WebDavRequestContext {
            subject: Some("alice".to_owned()),
            ..Default::default()
        };
        service
            .handle(
                Request::builder()
                    .method("PUT")
                    .uri("/versioned.txt")
                    .body(b"version one".to_vec())
                    .unwrap(),
                &context,
            )
            .unwrap();
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("VERSION-CONTROL")
                        .uri("/versioned.txt")
                        .body(Vec::new())
                        .unwrap(),
                    &context,
                )
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let first = service
            .store
            .versions(&ResourceId::parse("/versioned.txt").unwrap())
            .unwrap()[0]
            .version_name
            .clone();
        service
            .handle(
                Request::builder()
                    .method("CHECKOUT")
                    .uri("/versioned.txt")
                    .body(Vec::new())
                    .unwrap(),
                &context,
            )
            .unwrap();
        service
            .handle(
                Request::builder()
                    .method("PUT")
                    .uri("/versioned.txt")
                    .body(b"version two".to_vec())
                    .unwrap(),
                &context,
            )
            .unwrap();
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("CHECKIN")
                        .uri("/versioned.txt")
                        .body(Vec::new())
                        .unwrap(),
                    &context,
                )
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            service
                .store
                .versions(&ResourceId::parse("/versioned.txt").unwrap())
                .unwrap()
                .len(),
            2
        );
        service
            .handle(
                Request::builder()
                    .method("UPDATE")
                    .uri("/versioned.txt")
                    .header("version-name", first)
                    .body(Vec::new())
                    .unwrap(),
                &context,
            )
            .unwrap();
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("GET")
                        .uri("/versioned.txt")
                        .body(Vec::new())
                        .unwrap(),
                    &context,
                )
                .unwrap()
                .into_body(),
            b"version one"
        );
    }

    #[test]
    fn caldav_validates_objects_and_answers_query_and_free_busy_reports() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        let context = WebDavRequestContext::default();
        let calendar = Request::builder()
            .method("MKCALENDAR")
            .uri("/events")
            .body(Vec::new())
            .unwrap();
        assert_eq!(
            service.handle(calendar, &context).unwrap().status(),
            StatusCode::CREATED
        );
        let invalid = Request::builder()
            .method("PUT")
            .uri("/events/wrong.ics")
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(b"invalid".to_vec())
            .unwrap();
        assert_eq!(
            service.handle(invalid, &context).unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let event = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nDTSTART:20260711T010000Z\r\nDTEND:20260711T020000Z\r\nCATEGORIES:Hands,Feet\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let put = Request::builder()
            .method("PUT")
            .uri("/events/meeting.ics")
            .header(http::header::CONTENT_TYPE, "text/calendar; charset=utf-8")
            .body(event.to_vec())
            .unwrap();
        assert_eq!(
            service.handle(put, &context).unwrap().status(),
            StatusCode::CREATED
        );
        let query = Request::builder()
            .method("REPORT")
            .uri("/events")
            .body(br#"<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:time-range start="20260711T000000Z" end="20260712T000000Z"/><C:prop-filter name="CATEGORIES"><C:text-match collation="i;octet">hands</C:text-match></C:prop-filter></C:comp-filter></C:comp-filter></C:filter></C:calendar-query>"#.to_vec())
            .unwrap();
        let response = service.handle(query, &context).unwrap();
        assert_eq!(response.status(), StatusCode::MULTI_STATUS);
        let query_body = String::from_utf8(response.into_body()).unwrap();
        assert!(query_body.contains("meeting.ics"), "{query_body}");
        assert!(query_body.contains("C:calendar-data"), "{query_body}");
        assert!(query_body.contains("BEGIN:VCALENDAR"), "{query_body}");
        let free_busy = Request::builder()
            .method("REPORT")
            .uri("/events")
            .body(br#"<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav"><C:time-range start="20260711T000000Z" end="20260712T000000Z"/></C:free-busy-query>"#.to_vec())
            .unwrap();
        let response = service.handle(free_busy, &context).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(response.into_body()).unwrap();
        assert!(body.contains("FREEBUSY:20260711T010000Z/20260711T020000Z"));
    }

    #[test]
    fn bind_rebind_unbind_resolve_logical_aliases_without_symlinks() {
        let directory = tempdir().unwrap();
        let data = FileSystemDataStore::open(directory.path().join("data")).unwrap();
        let metadata = RedbMetadataStore::open(directory.path().join("metadata.redb")).unwrap();
        let service = WebDavService::new(Arc::new(PersistentWebDavStore::new(data, metadata)));
        let context = WebDavRequestContext::default();
        for path in ["/links", "/targets"] {
            service
                .handle(
                    Request::builder()
                        .method("MKCOL")
                        .uri(path)
                        .body(Vec::new())
                        .unwrap(),
                    &context,
                )
                .unwrap();
        }
        for (path, body) in [
            ("/targets/one", b"one".as_slice()),
            ("/targets/two", b"two".as_slice()),
        ] {
            service
                .handle(
                    Request::builder()
                        .method("PUT")
                        .uri(path)
                        .body(body.to_vec())
                        .unwrap(),
                    &context,
                )
                .unwrap();
        }
        let bind_body = |root: &str, href: &str| {
            format!(
                "<D:{root} xmlns:D=\"DAV:\"><D:segment>current</D:segment><D:href>{href}</D:href></D:{root}>"
            )
            .into_bytes()
        };
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("BIND")
                        .uri("/links")
                        .body(bind_body("bind", "/targets/one"))
                        .unwrap(),
                    &context,
                )
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("GET")
                        .uri("/links/current")
                        .body(Vec::new())
                        .unwrap(),
                    &context,
                )
                .unwrap()
                .into_body(),
            b"one"
        );
        service
            .handle(
                Request::builder()
                    .method("REBIND")
                    .uri("/links")
                    .body(bind_body("rebind", "/targets/two"))
                    .unwrap(),
                &context,
            )
            .unwrap();
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("GET")
                        .uri("/links/current")
                        .body(Vec::new())
                        .unwrap(),
                    &context,
                )
                .unwrap()
                .into_body(),
            b"two"
        );
        assert_eq!(
            service
                .handle(
                    Request::builder()
                        .method("UNBIND")
                        .uri("/links")
                        .body(br#"<D:unbind xmlns:D="DAV:"><D:segment>current</D:segment></D:unbind>"#.to_vec())
                        .unwrap(),
                    &context,
                )
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        service
            .store
            .put_binding(
                &ResourceId::parse("/a").unwrap(),
                &ResourceId::parse("/b").unwrap(),
                false,
            )
            .unwrap();
        assert!(
            service
                .store
                .put_binding(
                    &ResourceId::parse("/b").unwrap(),
                    &ResourceId::parse("/a").unwrap(),
                    false,
                )
                .is_err()
        );
    }
}
