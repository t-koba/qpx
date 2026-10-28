use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::{Method, StatusCode};
use hyper::body::{Body as HttpBody, Frame};
use qpx_http::body::{Body, BodyError};
use std::pin::Pin;
use std::task::{Context, Poll};

pub(super) fn expected_body_length(
    method: &Method,
    status: StatusCode,
    headers: &qpx_core::http_message::Headers,
) -> Result<Option<u64>> {
    let declared = headers
        .declared_content_length()
        .map_err(|err| anyhow!("cache response Content-Length: {err}"))?;
    // Match qpx_http's no-body response normalization. HEAD's length describes
    // the corresponding GET representation, not bytes in this stream.
    if method == Method::HEAD
        || status.is_informational()
        || matches!(status.as_u16(), 204 | 205 | 304)
        || (method == Method::CONNECT && status.is_success())
    {
        return Ok(None);
    }
    Ok(declared)
}

pub(super) fn validate_body_length(body: Body, expected: Option<u64>) -> Body {
    match expected {
        Some(expected) => Body::wrap(LengthCheckedBody {
            source: body,
            expected,
            observed: 0,
            finished: false,
        }),
        None => body,
    }
}

// Only wrap the cache mirror: a validation error must not alter client bytes.
// Do not advertise a size hint or source end-of-stream before validation; the
// backend must poll the terminal frame before it can publish the object.
struct LengthCheckedBody {
    source: Body,
    expected: u64,
    observed: u64,
    finished: bool,
}

impl HttpBody for LengthCheckedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        let frame = match Pin::new(&mut this.source).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(frame) => frame,
        };
        if let Some(Ok(frame)) = &frame
            && let Some(bytes) = frame.data_ref()
        {
            // Subtract before adding to avoid overflowing the observed count.
            if bytes.len() as u64 > this.expected - this.observed {
                this.finished = true;
                return Poll::Ready(Some(Err(BodyError::new(
                    "cache response body exceeds declared Content-Length",
                ))));
            }
            this.observed += bytes.len() as u64;
        }
        // A trailers frame is terminal in qpx_http::Body: reject a short body
        // before forwarding trailers, rather than waiting for another poll.
        let terminal = frame.is_none() || matches!(&frame, Some(Ok(frame)) if frame.is_trailers());
        if terminal {
            this.finished = true;
            if this.observed != this.expected {
                return Poll::Ready(Some(Err(BodyError::new(
                    "cache response body shorter than declared Content-Length",
                ))));
            }
        } else if matches!(&frame, Some(Err(_))) {
            this.finished = true;
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }
}
