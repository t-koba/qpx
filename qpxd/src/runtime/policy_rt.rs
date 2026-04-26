use crate::connection_filter::compile_connection_filter;
use crate::destination::{CompiledDestinationResolutionPolicy, DestinationClassifier};
use crate::http::guard::{compile_http_guard_profiles, CompiledHttpGuardProfile};
use crate::http::response_policy::HttpResponseRuleEngine;
use crate::rate_limit::RateLimiters;
use anyhow::Result;
use qpx_core::rules::RuleEngine;
use std::collections::HashMap;
use std::sync::Arc;

use super::ConfigRuntime;

#[derive(Clone)]
pub struct PolicyRuntime {
    pub rules_by_listener: HashMap<String, RuleEngine>,
    pub(crate) response_rules_by_listener: HashMap<String, Arc<HttpResponseRuleEngine>>,
    pub connection_filters_by_listener: HashMap<String, RuleEngine>,
    pub connection_filters_by_reverse: HashMap<String, RuleEngine>,
    pub(crate) rate_limiters: RateLimiters,
    pub(crate) destination_classifier: DestinationClassifier,
    pub(crate) destination_resolution_defaults: CompiledDestinationResolutionPolicy,
    pub(crate) http_guard_profiles: HashMap<String, Arc<CompiledHttpGuardProfile>>,
}

impl PolicyRuntime {
    pub(super) fn build(config: &ConfigRuntime) -> Result<Self> {
        let mut rules_by_listener = HashMap::new();
        let mut response_rules_by_listener = HashMap::new();
        let mut connection_filters_by_listener = HashMap::new();
        let mut connection_filters_by_reverse = HashMap::new();
        for listener in &config.listeners {
            let engine = RuleEngine::new(listener.rules.clone(), listener.default_action.clone())?;
            rules_by_listener.insert(listener.name.clone(), engine);
            if let Some(http) = listener.http.as_ref() {
                if let Some(engine) = HttpResponseRuleEngine::new(http.response_rules.as_slice())? {
                    response_rules_by_listener.insert(listener.name.clone(), Arc::new(engine));
                }
            }
            if let Some(engine) = compile_connection_filter(listener.connection_filter.clone())? {
                connection_filters_by_listener.insert(listener.name.clone(), engine);
            }
        }
        for reverse in &config.reverse {
            if let Some(engine) = compile_connection_filter(reverse.connection_filter.clone())? {
                connection_filters_by_reverse.insert(reverse.name.clone(), engine);
            }
        }

        let rate_limiters = RateLimiters::from_config(
            config.listeners.as_slice(),
            config.rate_limit_profiles.as_slice(),
        );
        let destination_classifier = DestinationClassifier::from_config(config.raw.as_ref())?;
        let destination_resolution_defaults = CompiledDestinationResolutionPolicy::from_config(
            &config.destination_resolution.defaults,
        );
        let http_guard_profiles =
            compile_http_guard_profiles(config.http_guard_profiles.as_slice());

        Ok(Self {
            rules_by_listener,
            response_rules_by_listener,
            connection_filters_by_listener,
            connection_filters_by_reverse,
            rate_limiters,
            destination_classifier,
            destination_resolution_defaults,
            http_guard_profiles,
        })
    }
}
