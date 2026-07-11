use crate::WebDavRequestContext;
use anyhow::{Result, anyhow};
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DavPrivilege {
    Read,
    Write,
    ReadAcl,
    WriteAcl,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclPrincipal {
    All,
    Authenticated,
    Href(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ace {
    pub principal: AclPrincipal,
    pub grant: bool,
    pub privileges: Vec<DavPrivilege>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclPolicy {
    pub entries: Vec<Ace>,
}

impl AclPolicy {
    pub fn allows(&self, context: &WebDavRequestContext, required: DavPrivilege) -> bool {
        let mut granted = false;
        for ace in &self.entries {
            if !principal_matches(&ace.principal, context)
                || !ace
                    .privileges
                    .iter()
                    .any(|privilege| *privilege == required || *privilege == DavPrivilege::All)
            {
                continue;
            }
            if !ace.grant {
                return false;
            }
            granted = true;
        }
        granted
    }

    pub fn parse(xml: &[u8]) -> Result<Self> {
        if xml.len() > 64 * 1024 {
            return Err(anyhow!("WebDAV ACL XML exceeds 64 KiB"));
        }
        let upper = String::from_utf8_lossy(xml).to_ascii_uppercase();
        if upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY") {
            return Err(anyhow!("WebDAV ACL entity declarations are forbidden"));
        }
        let mut reader = NsReader::from_reader(xml);
        reader.config_mut().trim_text(true);
        let mut stack = Vec::<String>::new();
        let mut entries = Vec::new();
        let mut principal = None;
        let mut href = None;
        let mut grant = None;
        let mut privileges = Vec::new();
        loop {
            let (resolution, event) = reader.read_resolved_event()?;
            match event {
                Event::Start(element) => {
                    require_dav_namespace(resolution)?;
                    let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                    match name.as_str() {
                        "ace" => {
                            principal = None;
                            href = None;
                            grant = None;
                            privileges.clear();
                        }
                        "all" if stack.last().is_some_and(|name| name == "principal") => {
                            principal = Some(AclPrincipal::All)
                        }
                        "authenticated" if stack.last().is_some_and(|name| name == "principal") => {
                            principal = Some(AclPrincipal::Authenticated)
                        }
                        "grant" => grant = Some(true),
                        "deny" => grant = Some(false),
                        "read" if stack.last().is_some_and(|name| name == "privilege") => {
                            privileges.push(DavPrivilege::Read)
                        }
                        "write" if stack.last().is_some_and(|name| name == "privilege") => {
                            privileges.push(DavPrivilege::Write)
                        }
                        "read-acl" if stack.last().is_some_and(|name| name == "privilege") => {
                            privileges.push(DavPrivilege::ReadAcl)
                        }
                        "write-acl" if stack.last().is_some_and(|name| name == "privilege") => {
                            privileges.push(DavPrivilege::WriteAcl)
                        }
                        "all" if stack.last().is_some_and(|name| name == "privilege") => {
                            privileges.push(DavPrivilege::All)
                        }
                        _ => {}
                    }
                    stack.push(name);
                }
                Event::Empty(element) => {
                    require_dav_namespace(resolution)?;
                    let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                    match name.as_str() {
                        "all" if stack.last().is_some_and(|name| name == "principal") => {
                            principal = Some(AclPrincipal::All)
                        }
                        "authenticated" if stack.last().is_some_and(|name| name == "principal") => {
                            principal = Some(AclPrincipal::Authenticated)
                        }
                        "read" => privileges.push(DavPrivilege::Read),
                        "write" => privileges.push(DavPrivilege::Write),
                        "read-acl" => privileges.push(DavPrivilege::ReadAcl),
                        "write-acl" => privileges.push(DavPrivilege::WriteAcl),
                        "all" => privileges.push(DavPrivilege::All),
                        _ => return Err(anyhow!("unsupported DAV ACL element")),
                    }
                }
                Event::Text(text) => {
                    if stack.last().is_some_and(|name| name == "href") {
                        href = Some(text.decode()?.trim().to_owned());
                    }
                }
                Event::CData(text) => {
                    if stack.last().is_some_and(|name| name == "href") {
                        href = Some(text.decode()?.trim().to_owned());
                    }
                }
                Event::End(element) => {
                    let name = std::str::from_utf8(element.local_name().as_ref())?.to_owned();
                    if name == "principal" && principal.is_none() {
                        principal = href.take().map(AclPrincipal::Href);
                    }
                    if name == "ace" {
                        entries.push(Ace {
                            principal: principal
                                .take()
                                .ok_or_else(|| anyhow!("DAV ACE principal is required"))?,
                            grant: grant
                                .ok_or_else(|| anyhow!("DAV ACE grant or deny is required"))?,
                            privileges: (!privileges.is_empty())
                                .then(|| std::mem::take(&mut privileges))
                                .ok_or_else(|| anyhow!("DAV ACE privilege is required"))?,
                        });
                    }
                    stack.pop();
                }
                Event::DocType(_) => return Err(anyhow!("WebDAV ACL document type is forbidden")),
                Event::Eof => break,
                Event::Decl(_) | Event::PI(_) | Event::Comment(_) | Event::GeneralRef(_) => {}
            }
        }
        if entries.is_empty() || !stack.is_empty() {
            return Err(anyhow!("DAV ACL is empty or malformed"));
        }
        Ok(Self { entries })
    }
}

fn principal_matches(principal: &AclPrincipal, context: &WebDavRequestContext) -> bool {
    match principal {
        AclPrincipal::All => true,
        AclPrincipal::Authenticated => context.subject.is_some(),
        AclPrincipal::Href(value) => {
            context.subject.as_deref() == Some(value)
                || context.groups.iter().any(|item| item == value)
                || context.roles.iter().any(|item| item == value)
                || context.entitlements.iter().any(|item| item == value)
        }
    }
}

fn require_dav_namespace(resolution: ResolveResult<'_>) -> Result<()> {
    match resolution {
        ResolveResult::Bound(namespace) if namespace.as_ref() == b"DAV:" => Ok(()),
        _ => Err(anyhow!("DAV ACL elements must use the DAV: namespace")),
    }
}
