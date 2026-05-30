#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CandidateRequestObservationRequirements {
    pub needs_size: bool,
    pub needs_body: bool,
    pub needs_rpc: bool,
}

impl CandidateRequestObservationRequirements {
    pub fn is_empty(self) -> bool {
        !self.needs_size && !self.needs_body && !self.needs_rpc
    }

    pub fn include(&mut self, other: Self) {
        self.needs_size |= other.needs_size;
        self.needs_body |= other.needs_body;
        self.needs_rpc |= other.needs_rpc;
    }
}
