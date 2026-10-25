use super::CgiExecutor;
use crate::executor::CgiRequest;
use std::collections::HashMap;

pub(crate) use qpx_core::execution::cgi_env_passthrough_is_reserved;

impl CgiExecutor {
    pub(super) fn build_env(&self, req: &CgiRequest) -> HashMap<String, String> {
        let mut env = req.cgi_environment().into_variables();
        for var in &self.env_passthrough {
            if cgi_env_passthrough_is_reserved(var) {
                continue;
            }
            if let Ok(value) = std::env::var(var) {
                env.entry(var.clone()).or_insert(value);
            }
        }
        env
    }
}
