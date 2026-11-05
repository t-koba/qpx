use crate::http::protocol::l7::finalize_response_for_request;
use hyper::{Method, StatusCode};
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
    rejection: Option<OwnerResponse<Body>>,
) -> PreflightOutcome {
    let response = if let Some(response) = rejection {
        response
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::protocol::common::bad_request_response;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn owner_rejection_is_finalized_without_framing_import() {
        let request = Request::from_http(
            hyper::Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .expect("request"),
        );
        let PreflightOutcome::Reject(response) = preflight_validate(
            &request,
            "qpx",
            PreflightOptions::allow_connect(false, "TRACE disabled"),
            Some(bad_request_response("invalid FTP request")),
        ) else {
            panic!("explicit rejection must reject");
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.version(), http::Version::HTTP_11);
        assert_eq!(response.headers().declared_content_length(), Ok(None));
        assert_eq!(
            response
                .into_head_and_body()
                .1
                .collect()
                .await
                .expect("body")
                .to_bytes(),
            "invalid FTP request"
        );
    }
}
