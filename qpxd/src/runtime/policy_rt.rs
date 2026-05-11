use crate::connection_filter::compile_connection_filter;
use crate::destination::{CompiledDestinationResolutionPolicy, DestinationClassifier};
use crate::rate_limit::RateLimiters;
use anyhow::Result;
use qpx_core::rules::RuleEngine;
use std::collections::HashMap;

use super::RuntimeResources;

#[derive(Clone)]
pub struct PolicyRuntime {
    pub rules_by_listener: HashMap<String, RuleEngine>,
    pub connection_filters_by_listener: HashMap<String, RuleEngine>,
    pub connection_filters_by_reverse: HashMap<String, RuleEngine>,
    pub(crate) rate_limiters: RateLimiters,
    pub(crate) destination_classifier: DestinationClassifier,
    pub(crate) destination_resolution_defaults: CompiledDestinationResolutionPolicy,
}

impl PolicyRuntime {
    pub(super) fn build(config: &RuntimeResources) -> Result<Self> {
        let mut rules_by_listener = HashMap::new();
        let mut connection_filters_by_listener = HashMap::new();
        let mut connection_filters_by_reverse = HashMap::new();
        for listener in config.operational.ingress_edge_configs() {
            let engine = RuleEngine::new(listener.rules.clone(), listener.default_action.clone())?;
            rules_by_listener.insert(listener.name.clone(), engine);
            if let Some(engine) = compile_connection_filter(listener.connection_filter.clone())? {
                connection_filters_by_listener.insert(listener.name.clone(), engine);
            }
        }
        for reverse_edges in config.operational.reverse_edge_configs() {
            if let Some(engine) =
                compile_connection_filter(reverse_edges.connection_filter.clone())?
            {
                connection_filters_by_reverse.insert(reverse_edges.name.clone(), engine);
            }
        }

        let rate_limiters = RateLimiters::from_config(
            config.operational.ingress_edge_configs(),
            config.operational.traffic.rate_limit_profiles.as_slice(),
        );
        let destination_classifier =
            DestinationClassifier::from_config(config.operational.as_ref())?;
        let destination_resolution_defaults = CompiledDestinationResolutionPolicy::from_config(
            &config.operational.security.destination.defaults,
        );
        Ok(Self {
            rules_by_listener,
            connection_filters_by_listener,
            connection_filters_by_reverse,
            rate_limiters,
            destination_classifier,
            destination_resolution_defaults,
        })
    }
}
