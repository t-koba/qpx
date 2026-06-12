/// Request-body observations required by one or more candidate rules.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CandidateRequestObservationRequirements {
    /// A request size value is needed.
    pub needs_size: bool,
    /// Request body bytes must be inspected.
    pub needs_body: bool,
    /// Request RPC metadata or frames must be inspected.
    pub needs_rpc: bool,
}

impl CandidateRequestObservationRequirements {
    /// Returns true when no request observation is required.
    pub fn is_empty(self) -> bool {
        !self.needs_size && !self.needs_body && !self.needs_rpc
    }

    /// Merges another requirement set into this one.
    pub fn include(&mut self, other: Self) {
        self.needs_size |= other.needs_size;
        self.needs_body |= other.needs_body;
        self.needs_rpc |= other.needs_rpc;
    }
}
