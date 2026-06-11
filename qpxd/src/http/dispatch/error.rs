use hyper::Response;
use qpx_http::body::Body;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum DispatchError {
    #[error("rate limited")]
    RateLimited { response: Box<Response<Body>> },

    #[cfg(feature = "auth-basic")]
    #[error("policy denied: {reason}")]
    PolicyDenied {
        reason: String,
        response: Box<Response<Body>>,
    },

    #[cfg(feature = "auth-basic")]
    #[error("authentication required: {method}")]
    AuthRequired {
        method: String,
        response: Box<Response<Body>>,
    },

    #[error("ext-authz denied")]
    ExtAuthzDenied { response: Box<Response<Body>> },

    #[error("upstream unavailable: {0}")]
    UpstreamUnavailable(String),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl DispatchError {
    pub(crate) fn into_response_result(self) -> anyhow::Result<Response<Body>> {
        match self {
            Self::RateLimited { response } => Ok(*response),
            #[cfg(feature = "auth-basic")]
            Self::PolicyDenied { response, .. } => Ok(*response),
            #[cfg(feature = "auth-basic")]
            Self::AuthRequired { response, .. } => Ok(*response),
            Self::ExtAuthzDenied { response } => Ok(*response),
            Self::UpstreamUnavailable(message) => Err(anyhow::anyhow!(message)),
            Self::Internal(err) => Err(err),
        }
    }
}
