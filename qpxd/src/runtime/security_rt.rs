use crate::policy_context::{CompiledExtAuthz, CompiledIdentitySource};
use crate::runtime::auth::Authenticator;
use anyhow::Result;
use qpx_core::tls::CaStore;
#[cfg(feature = "mitm")]
use qpx_core::tls::{MitmConfig, load_or_generate_ca};
use std::collections::HashMap;
use std::ops::Deref;
#[cfg(feature = "mitm")]
use std::path::PathBuf;
use std::sync::Arc;

use super::RuntimeResources;

#[derive(Clone)]
pub struct SecurityRuntime {
    pub auth: AuthRuntime,
    pub identity_sources: IdentitySourceRuntime,
    pub decisions: DecisionRuntime,
    pub destination: DestinationPolicyRuntime,
}

#[derive(Clone)]
pub struct AuthRuntime {
    pub authenticator: Arc<Authenticator>,
}

impl Deref for AuthRuntime {
    type Target = Authenticator;

    fn deref(&self) -> &Self::Target {
        &self.authenticator
    }
}

#[derive(Clone)]
pub struct IdentitySourceRuntime {
    pub(crate) sources: HashMap<String, Arc<CompiledIdentitySource>>,
}

#[derive(Clone)]
pub struct DecisionRuntime {
    pub(crate) ext_authz: HashMap<String, Arc<CompiledExtAuthz>>,
}

#[derive(Clone)]
pub struct DestinationPolicyRuntime {
    pub tls: TlsSecurityRuntime,
}

#[derive(Clone)]
pub struct TlsSecurityRuntime {
    pub ca: Option<CaStore>,
    #[cfg(feature = "mitm")]
    pub mitm: Option<MitmConfig>,
    #[cfg(feature = "mitm")]
    tls_verify_exception_sets: HashMap<String, globset::GlobSet>,
}

impl SecurityRuntime {
    pub(super) fn build(config: &RuntimeResources) -> Result<Self> {
        let identity_sources = config
            .operational
            .security
            .identity_sources
            .iter()
            .map(|source| {
                Ok((
                    source.name.clone(),
                    Arc::new(CompiledIdentitySource::from_config(source)?),
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        let ext_authz = config
            .operational
            .security
            .decisions
            .ext_authz
            .iter()
            .map(|cfg| {
                Ok((
                    cfg.name.clone(),
                    Arc::new(CompiledExtAuthz::from_config(cfg)?),
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let auth_audit_redact_query_keys = auth_audit_redact_query_keys(config);

        let auth = AuthRuntime {
            authenticator: Arc::new(Authenticator::new_with_audit_redaction(
                &config.operational.security.auth,
                config.operational.identity.auth_realm.as_str(),
                &auth_audit_redact_query_keys,
            )?),
        };

        #[cfg(feature = "mitm")]
        let mut tls_verify_exception_sets = HashMap::new();
        #[cfg(feature = "mitm")]
        {
            for listener in config.operational.ingress_edge_configs() {
                if let Some(tls) = listener.tls_inspection.as_ref()
                    && !tls.verify_exceptions.is_empty()
                {
                    let mut builder = globset::GlobSetBuilder::new();
                    for pattern in &tls.verify_exceptions {
                        builder.add(globset::Glob::new(pattern)?);
                    }
                    tls_verify_exception_sets.insert(listener.name.clone(), builder.build()?);
                }
            }
        }

        #[cfg(feature = "mitm")]
        let state_dir = config
            .operational
            .state_dir
            .as_deref()
            .map(expand_tilde)
            .unwrap_or_else(|| PathBuf::from(".qpx"));

        #[cfg(feature = "mitm")]
        let (ca, mitm) = if any_tls_inspection_enabled(config.operational.ingress_edges()) {
            let ca = load_or_generate_ca(&state_dir)?;
            let mitm = Some(ca.mitm_config()?);
            (Some(ca), mitm)
        } else {
            (None, None)
        };

        #[cfg(not(feature = "mitm"))]
        let ca = None;

        let tls = TlsSecurityRuntime {
            ca,
            #[cfg(feature = "mitm")]
            mitm,
            #[cfg(feature = "mitm")]
            tls_verify_exception_sets,
        };

        Ok(Self {
            auth,
            identity_sources: IdentitySourceRuntime {
                sources: identity_sources,
            },
            decisions: DecisionRuntime { ext_authz },
            destination: DestinationPolicyRuntime { tls },
        })
    }

    #[cfg(feature = "mitm")]
    pub(super) fn tls_verify_exception_matches(&self, listener: &str, host: &str) -> bool {
        self.destination
            .tls
            .tls_verify_exception_sets
            .get(listener)
            .map(|set| set.is_match(host))
            .unwrap_or(false)
    }
}

fn auth_audit_redact_query_keys(config: &RuntimeResources) -> Vec<String> {
    config.access_log.redact.query_keys.clone()
}

#[cfg(feature = "mitm")]
fn any_tls_inspection_enabled<'a>(
    forward_edges: impl IntoIterator<Item = &'a qpx_core::config::IngressEdgeConfig>,
) -> bool {
    forward_edges.into_iter().any(|l| {
        l.tls_inspection
            .as_ref()
            .map(|t| t.enabled)
            .unwrap_or(false)
    })
}

#[cfg(feature = "mitm")]
fn expand_tilde(input: &str) -> PathBuf {
    if let Some(stripped) = input.strip_prefix("~/")
        && let Some(home) = dirs_next::home_dir()
    {
        return home.join(stripped);
    }
    PathBuf::from(input)
}
