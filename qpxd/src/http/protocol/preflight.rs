use crate::http::protocol::l7::finalize_response_for_request;
use hyper::{Method, Response, StatusCode};
use qpx_core::http_message::{Request, Response as OwnerResponse};
use qpx_http::body::Body;
use qpx_http::protocol::semantics::validate_incoming_request_with_metadata;

pub(crate) enum ConnectPolicy<'a> {
    Allow,
    Reject { status: StatusCode, body: &'a str },
}

pub(crate) struct PreflightOptions<'a> {
    pub(crate) trace_enabled: bool,
    pub(crate) trace_disabled_message: &'a str,
    pub(crate) connect_policy: ConnectPolicy<'a>,
}

impl<'a> PreflightOptions<'a> {
    pub(crate) fn allow_connect(trace_enabled: bool, trace_disabled_message: &'a str) -> Self {
        Self {
            trace_enabled,
            trace_disabled_message,
            connect_policy: ConnectPolicy::Allow,
        }
    }

    pub(crate) fn reject_connect(
        trace_enabled: bool,
        trace_disabled_message: &'a str,
        status: StatusCode,
        body: &'a str,
    ) -> Self {
        Self {
            trace_enabled,
            trace_disabled_message,
            connect_policy: ConnectPolicy::Reject { status, body },
        }
    }
}

pub(crate) enum PreflightOutcome {
    Continue(qpx_http::protocol::semantics::ValidatedIncomingRequest),
    Reject(Box<OwnerResponse<Body>>),
}

pub(crate) fn preflight_validate<B>(
    req: &Request<B>,
    proxy_name: &str,
    options: PreflightOptions<'_>,
    rejection: Option<Response<Body>>,
) -> PreflightOutcome {
    let response = if let Some(response) = rejection {
        OwnerResponse::from_http(response)
    } else {
        let (status, body) = match validate_incoming_request_with_metadata(req) {
            Err(err) => (err.http_status(), err.to_string()),
            Ok(validated) => {
                if req.method() == Method::TRACE && !options.trace_enabled {
                    (
                        StatusCode::METHOD_NOT_ALLOWED,
                        options.trace_disabled_message.to_owned(),
                    )
                } else if req.method() == Method::CONNECT
                    && let ConnectPolicy::Reject { status, body } = options.connect_policy
                {
                    (status, body.to_owned())
                } else {
                    return PreflightOutcome::Continue(validated);
                }
            }
        };
        let mut response = OwnerResponse::new(Body::from(body));
        *response.status_mut() = status;
        response
    };
    PreflightOutcome::Reject(Box::new(finalize_response_for_request(
        req.method(),
        req.version(),
        proxy_name,
        response,
        false,
    )))
}
