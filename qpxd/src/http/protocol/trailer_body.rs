use bytes::Bytes;
use http_body::{Body as HttpBody, Frame};
use qpx_http::body::{Body, BodyError};
use std::future::Future as _;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Sleep;
use tracing::warn;

const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum TrailerPolicy {
    ValidateRequest,
    SanitizeResponse,
}

pub(super) fn validating_request(body: Body) -> Body {
    Body::wrap(TrailerBody::new(body, TrailerPolicy::ValidateRequest))
}

pub(super) fn sanitizing_response(body: Body) -> Body {
    Body::wrap(TrailerBody::new(body, TrailerPolicy::SanitizeResponse))
}

struct TrailerBody {
    inner: Body,
    policy: TrailerPolicy,
    read_timer: Option<Pin<Box<Sleep>>>,
    done: bool,
}

impl TrailerBody {
    fn new(inner: Body, policy: TrailerPolicy) -> Self {
        Self {
            inner,
            policy,
            read_timer: None,
            done: false,
        }
    }

    fn timeout_message(&self) -> &'static str {
        match self.policy {
            TrailerPolicy::ValidateRequest => "request body trailer wrapper timed out while idle",
            TrailerPolicy::SanitizeResponse => "response body trailer wrapper timed out while idle",
        }
    }

    fn body_error_message(&self) -> &'static str {
        match self.policy {
            TrailerPolicy::ValidateRequest => "request body stream failed",
            TrailerPolicy::SanitizeResponse => "response body stream failed",
        }
    }

    fn process_trailers(
        &mut self,
        mut trailers: http::HeaderMap,
    ) -> Result<http::HeaderMap, BodyError> {
        match self.policy {
            TrailerPolicy::ValidateRequest => {
                if let Err(err) =
                    qpx_http::protocol::semantics::validate_request_trailers(&trailers)
                {
                    warn!(error = ?err, "rejecting forbidden request trailers");
                    return Err(BodyError::aborted());
                }
            }
            TrailerPolicy::SanitizeResponse => {
                let removed =
                    qpx_http::protocol::semantics::sanitize_response_trailers(&mut trailers);
                if removed > 0 {
                    warn!(removed, "dropping forbidden response trailers");
                }
            }
        }
        Ok(trailers)
    }
}

impl HttpBody for TrailerBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.done {
            return Poll::Ready(None);
        }

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.read_timer = None;
                match frame.into_trailers() {
                    Ok(trailers) => {
                        this.done = true;
                        Poll::Ready(Some(this.process_trailers(trailers).map(Frame::trailers)))
                    }
                    Err(frame) => Poll::Ready(Some(Ok(frame))),
                }
            }
            Poll::Ready(Some(Err(err))) => {
                this.read_timer = None;
                this.done = true;
                warn!(error = ?err, "{}", this.body_error_message());
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                this.read_timer = None;
                this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => {
                let timer = this
                    .read_timer
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(BODY_IDLE_TIMEOUT)));
                if timer.as_mut().poll(cx).is_ready() {
                    this.read_timer = None;
                    this.done = true;
                    warn!("{}", this.timeout_message());
                    Poll::Ready(Some(Err(BodyError::aborted())))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}
