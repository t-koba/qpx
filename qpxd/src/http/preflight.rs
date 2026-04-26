use crate::http::body::Body;
use crate::http::common::bad_request_response as bad_request;
use crate::http::l7::finalize_response_for_request;
use crate::http::semantics::validate_incoming_request;
use hyper::{Method, Request, Response, StatusCode};

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
    Continue,
    Reject(Box<Response<Body>>),
}

pub(crate) fn preflight_validate<B>(
    req: &Request<B>,
    proxy_name: &str,
    options: PreflightOptions<'_>,
) -> PreflightOutcome {
    if let Err(err) = validate_incoming_request(req) {
        return PreflightOutcome::Reject(Box::new(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(err.http_status())
                .body(Body::from(err.to_string()))
                .unwrap_or_else(|_| bad_request(err.to_string())),
            false,
        )));
    }

    if req.method() == Method::TRACE && !options.trace_enabled {
        return PreflightOutcome::Reject(Box::new(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from(options.trace_disabled_message.to_owned()))
                .unwrap_or_else(|_| bad_request("trace disabled")),
            false,
        )));
    }

    if req.method() == Method::CONNECT {
        if let ConnectPolicy::Reject { status, body } = options.connect_policy {
            return PreflightOutcome::Reject(Box::new(finalize_response_for_request(
                &Method::CONNECT,
                req.version(),
                proxy_name,
                Response::builder()
                    .status(status)
                    .body(Body::from(body.to_owned()))
                    .unwrap_or_else(|_| bad_request(body)),
                false,
            )));
        }
    }

    PreflightOutcome::Continue
}
