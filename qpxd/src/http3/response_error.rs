#[derive(Debug)]
pub(crate) struct H3ResponseSendError {
    stage: ResponseSendStage,
    source: anyhow::Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseSendStage {
    BeforeResponseHead,
    AfterResponseHead,
    AfterBodyStarted,
    AfterTrailersStarted,
}

impl H3ResponseSendError {
    pub(crate) fn new(stage: ResponseSendStage, source: anyhow::Error) -> Self {
        Self { stage, source }
    }

    pub(crate) fn before_response_head(source: impl Into<anyhow::Error>) -> Self {
        Self::new(ResponseSendStage::BeforeResponseHead, source.into())
    }

    pub(crate) fn after_response_head(source: impl Into<anyhow::Error>) -> Self {
        Self::new(ResponseSendStage::AfterResponseHead, source.into())
    }

    pub(crate) fn after_body_started(source: impl Into<anyhow::Error>) -> Self {
        Self::new(ResponseSendStage::AfterBodyStarted, source.into())
    }

    pub(crate) fn for_body(body_started: bool, source: anyhow::Error) -> Self {
        if body_started {
            Self::after_body_started(source)
        } else {
            Self::after_response_head(source)
        }
    }

    pub(crate) fn after_trailers_started(source: impl Into<anyhow::Error>) -> Self {
        Self::new(ResponseSendStage::AfterTrailersStarted, source.into())
    }

    pub(crate) fn stage(&self) -> ResponseSendStage {
        self.stage
    }

    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    pub(crate) fn can_send_error_response(&self) -> bool {
        self.stage == ResponseSendStage::BeforeResponseHead
    }

    pub(crate) fn into_inner(self) -> anyhow::Error {
        self.source
    }
}

impl ResponseSendStage {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::BeforeResponseHead => "before_response_head",
            Self::AfterResponseHead => "after_response_head",
            Self::AfterBodyStarted => "after_body_started",
            Self::AfterTrailersStarted => "after_trailers_started",
        }
    }
}

impl std::fmt::Display for H3ResponseSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stage.as_str(), self.source)
    }
}

impl std::error::Error for H3ResponseSendError {}

pub(crate) fn emit_h3_response_send_error(backend: &'static str, error: &H3ResponseSendError) {
    tracing::warn!(backend, stage = error.stage().as_str(), error = %error, "HTTP/3 response send failed");
    crate::http3::metrics::h3_response_send_error(backend, error.stage().as_str());
}

#[cfg(test)]
mod tests {
    use super::{H3ResponseSendError, ResponseSendStage};

    #[derive(Debug, PartialEq, Eq, thiserror::Error)]
    #[error("body source {0}")]
    struct BodySource(u8);

    #[test]
    fn for_body_preserves_stage_and_source() {
        for (body_started, expected_stage) in [
            (false, ResponseSendStage::AfterResponseHead),
            (true, ResponseSendStage::AfterBodyStarted),
        ] {
            let error = H3ResponseSendError::for_body(body_started, BodySource(42).into());
            assert_eq!(error.stage(), expected_stage);
            assert_eq!(
                error.into_inner().downcast::<BodySource>().unwrap(),
                BodySource(42)
            );
        }
    }
}
