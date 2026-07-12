use super::{CacheRuntime, ObsRuntime, RuntimePlan, RuntimeState};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct AcceptorView {
    pub plan: Arc<RuntimePlan>,
    pub connection_semaphore: Arc<Semaphore>,
    pub observability: ObsRuntime,
}

#[derive(Clone)]
pub struct CacheView {
    pub plan: Arc<RuntimePlan>,
    pub cache: CacheRuntime,
    pub observability: ObsRuntime,
}

#[derive(Clone)]
pub struct ObservabilityView {
    pub plan: Arc<RuntimePlan>,
    pub observability: ObsRuntime,
}

impl AcceptorView {
    pub fn from_state(state: Arc<RuntimeState>) -> Self {
        Self {
            plan: state.plan.clone(),
            connection_semaphore: state.connection_semaphore.clone(),
            observability: state.observability.clone(),
        }
    }
}

impl CacheView {
    pub fn from_state(state: Arc<RuntimeState>) -> Self {
        Self {
            plan: state.plan.clone(),
            cache: state.cache.clone(),
            observability: state.observability.clone(),
        }
    }
}

impl ObservabilityView {
    pub fn from_state(state: Arc<RuntimeState>) -> Self {
        Self {
            plan: state.plan.clone(),
            observability: state.observability.clone(),
        }
    }
}
