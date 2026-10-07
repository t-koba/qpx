use super::BodyError;
use bytes::Bytes;
use http_body::Frame;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub(super) struct ChannelSender {
    pub frames: mpsc::Sender<Frame<Bytes>>,
    pub error: oneshot::Sender<BodyError>,
}

pub(super) struct Channel {
    frames: mpsc::Receiver<Frame<Bytes>>,
    error: Option<oneshot::Receiver<BodyError>>,
}

impl Channel {
    pub fn new(capacity: usize) -> (ChannelSender, Self) {
        let (frames_tx, frames_rx) = mpsc::channel(capacity);
        let (error_tx, error_rx) = oneshot::channel();
        (
            ChannelSender {
                frames: frames_tx,
                error: error_tx,
            },
            Self {
                frames: frames_rx,
                error: Some(error_rx),
            },
        )
    }
}

impl http_body::Body for Channel {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match self.frames.poll_recv(cx) {
            Poll::Ready(Some(frame)) => Poll::Ready(Some(Ok(frame))),
            Poll::Pending => Poll::Pending,
            // Only a drained frame queue may expose the terminal result. A sender can
            // enqueue its final frame and close while an earlier receive poll is pending.
            Poll::Ready(None) => {
                let Some(error) = self.error.as_mut() else {
                    return Poll::Ready(None);
                };
                match Pin::new(error).poll(cx) {
                    Poll::Ready(result) => {
                        self.error = None;
                        Poll::Ready(result.ok().map(Err))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}
