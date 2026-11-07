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
        Some(expected) => {
            let sanitized = body.trailers_are_sanitized();
            let checked = Body::wrap(LengthCheckedBody {
                source: body,
                expected,
                observed: 0,
                finished: false,
            });
            if sanitized {
                checked.mark_trailers_sanitized()
            } else {
                checked
            }
        }
        None => body,
    }
}

// Validate cache mirrors and cached replays, never the live origin response.
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

#[derive(Clone, Copy)]
pub(super) enum Delivery {
    Complete,
    Abandoned,
    Failed,
}

type Finalizer =
    Box<dyn FnOnce(Delivery) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send>;

/// Never run backend mutations while a source producer can still hold an
/// operation permit or use the object being deleted. Dropping the source first
/// also wakes producers blocked on their bounded output channel.
pub(super) fn after_delivery<F, Fut>(
    source: Body,
    producer_done: tokio::sync::oneshot::Receiver<()>,
    finalize: F,
) -> Body
where
    F: FnOnce(Delivery) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let sanitized = source.trailers_are_sanitized();
    let body = Body::wrap(PostDeliveryBody {
        source: Some(source),
        producer_done: Some(producer_done),
        finalize: Some(Box::new(move |delivery| Box::pin(finalize(delivery)))),
    });
    if sanitized {
        body.mark_trailers_sanitized()
    } else {
        body
    }
}

struct PostDeliveryBody {
    source: Option<Body>,
    producer_done: Option<tokio::sync::oneshot::Receiver<()>>,
    finalize: Option<Finalizer>,
}

impl PostDeliveryBody {
    fn finish(&mut self, delivery: Delivery) {
        drop(self.source.take());
        if let Some(finalize) = self.finalize.take()
            && let Some(done) = self.producer_done.take()
        {
            tokio::spawn(async move {
                let delivery = if done.await.is_ok() {
                    delivery
                } else {
                    Delivery::Failed
                };
                finalize(delivery).await;
            });
        }
    }
}

impl HttpBody for PostDeliveryBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        let Some(source) = this.source.as_mut() else {
            return Poll::Ready(None);
        };
        let frame = match Pin::new(&mut *source).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(frame) => frame,
        };
        if matches!(&frame, Some(Err(_))) {
            this.finish(Delivery::Failed);
        } else if frame.is_none()
            || matches!(&frame, Some(Ok(frame)) if frame.is_trailers())
            || source.is_end_stream()
        {
            this.finish(Delivery::Complete);
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.source.is_none()
    }
}

impl Drop for PostDeliveryBody {
    fn drop(&mut self) {
        self.finish(Delivery::Abandoned);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn finalizer_waits_for_producer_and_distinguishes_delivery_from_drop() {
        for (consume, producer_ok) in [(true, true), (false, true), (true, false)] {
            let (done, producer_done) = oneshot::channel();
            let (finalize, mut finalized) = oneshot::channel();
            let mut body = after_delivery(
                Body::from("cached"),
                producer_done,
                move |delivery| async move {
                    let _ = finalize.send(delivery);
                },
            );
            if consume {
                while let Some(chunk) = body.data().await {
                    chunk.expect("data");
                }
            }
            drop(body);
            tokio::task::yield_now().await;
            assert!(matches!(
                finalized.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            if producer_ok {
                done.send(()).unwrap();
            } else {
                drop(done);
            }
            let delivery = tokio::time::timeout(std::time::Duration::from_secs(1), finalized)
                .await
                .expect("finalizer timed out")
                .expect("finalizer must settle");
            assert!(matches!(
                (consume, producer_ok, delivery),
                (_, false, Delivery::Failed)
                    | (true, true, Delivery::Complete)
                    | (false, true, Delivery::Abandoned)
            ));
        }
    }
}
