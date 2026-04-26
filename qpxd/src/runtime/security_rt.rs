use crate::policy_context::{CompiledExtAuthz, CompiledIdentitySource};
use anyhow::Result;
use qpx_auth::Authenticator;
use qpx_core::tls::CaStore;
#[cfg(feature = "mitm")]
use qpx_core::tls::{load_or_generate_ca, MitmConfig};
use std::collections::HashMap;
#[cfg(feature = "mitm")]
use std::path::PathBuf;
use std::sync::Arc;

use super::ConfigRuntime;

#[derive(Clone)]
pub struct SecurityRuntime {
    pub auth: Arc<Authenticator>,
    pub ca: Option<CaStore>,
    #[cfg(feature = "mitm")]
    pub mitm: Option<MitmConfig>,
    pub(crate) identity_sources: HashMap<String, Arc<CompiledIdentitySource>>,
    pub(crate) ext_authz: HashMap<String, Arc<CompiledExtAuthz>>,
    #[cfg(feature = "mitm")]
    tls_verify_exception_sets: HashMap<String, globset::GlobSet>,
}

impl SecurityRuntime {
    pub(super) fn build(config: &ConfigRuntime) -> Result<Self> {
        let identity_sources = config
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
            .ext_authz
            .iter()
            .map(|cfg| {
                Ok((
                    cfg.name.clone(),
                    Arc::new(CompiledExtAuthz::from_config(cfg)?),
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let auth = Arc::new(Authenticator::new(
            &config.auth,
            config.identity.auth_realm.as_str(),
        )?);

        #[cfg(feature = "mitm")]
        let mut tls_verify_exception_sets = HashMap::new();
        #[cfg(feature = "mitm")]
        {
            for listener in &config.listeners {
                if let Some(tls) = listener.tls_inspection.as_ref() {
                    if !tls.verify_exceptions.is_empty() {
                        let mut builder = globset::GlobSetBuilder::new();
                        for pattern in &tls.verify_exceptions {
                            builder.add(globset::Glob::new(pattern)?);
                        }
                        tls_verify_exception_sets.insert(listener.name.clone(), builder.build()?);
                    }
                }
            }
        }

        #[cfg(feature = "mitm")]
        let state_dir = config
            .state_dir
            .as_deref()
            .map(expand_tilde)
            .unwrap_or_else(|| PathBuf::from(".qpx"));

        #[cfg(feature = "mitm")]
        let (ca, mitm) = if any_tls_inspection_enabled(&config.listeners) {
            let ca = Some(load_or_generate_ca(&state_dir)?);
            let mitm = Some(ca.as_ref().expect("ca").mitm_config()?);
            (ca, mitm)
        } else {
            (None, None)
        };

        #[cfg(not(feature = "mitm"))]
        let ca = None;

        Ok(Self {
            auth,
            ca,
            #[cfg(feature = "mitm")]
            mitm,
            identity_sources,
            ext_authz,
            #[cfg(feature = "mitm")]
            tls_verify_exception_sets,
        })
    }

    #[cfg(feature = "mitm")]
    pub(super) fn tls_verify_exception_matches(&self, listener: &str, host: &str) -> bool {
        self.tls_verify_exception_sets
            .get(listener)
            .map(|set| set.is_match(host))
            .unwrap_or(false)
    }
}

#[cfg(feature = "mitm")]
fn any_tls_inspection_enabled(listeners: &[qpx_core::config::ListenerConfig]) -> bool {
    listeners.iter().any(|l| {
        l.tls_inspection
            .as_ref()
            .map(|t| t.enabled)
            .unwrap_or(false)
    })
}

#[cfg(feature = "mitm")]
fn expand_tilde(input: &str) -> PathBuf {
    if let Some(stripped) = input.strip_prefix("~/") {
        if let Some(home) = dirs_next::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(input)
}
