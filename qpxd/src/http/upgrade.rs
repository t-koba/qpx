use crate::http::body::Body;
use anyhow::{anyhow, Result};
use http::Request;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

pub trait DownstreamIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> DownstreamIo for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub type DownstreamUpgraded = Box<dyn DownstreamIo>;

pub struct PendingDownstreamUpgrade {
    inner: oneshot::Receiver<Result<DownstreamUpgraded>>,
}

#[derive(Clone)]
struct DownstreamUpgradeRequest {
    inner: Arc<Mutex<Option<oneshot::Receiver<Result<DownstreamUpgraded>>>>>,
}

pub(crate) struct DownstreamUpgradeCommit {
    inner: Option<oneshot::Sender<Result<DownstreamUpgraded>>>,
}

pub(crate) fn install(req: &mut Request<Body>) -> DownstreamUpgradeCommit {
    let (tx, rx) = oneshot::channel();
    req.extensions_mut().insert(DownstreamUpgradeRequest {
        inner: Arc::new(Mutex::new(Some(rx))),
    });
    DownstreamUpgradeCommit { inner: Some(tx) }
}

pub fn on(req: &mut Request<Body>) -> PendingDownstreamUpgrade {
    let receiver = req
        .extensions_mut()
        .remove::<DownstreamUpgradeRequest>()
        .and_then(|request| request.inner.lock().ok().and_then(|mut inner| inner.take()))
        .unwrap_or_else(|| {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(Err(anyhow!("downstream upgrade not available")));
            rx
        });
    PendingDownstreamUpgrade { inner: receiver }
}

impl DownstreamUpgradeCommit {
    pub(crate) fn resolve_with_io<I>(mut self, io: I)
    where
        I: DownstreamIo,
    {
        if let Some(sender) = self.inner.take() {
            let _ = sender.send(Ok(Box::new(io)));
        }
    }
}

impl Drop for DownstreamUpgradeCommit {
    fn drop(&mut self) {
        if let Some(sender) = self.inner.take() {
            let _ = sender.send(Err(anyhow!("downstream upgrade canceled")));
        }
    }
}

impl Future for PendingDownstreamUpgrade {
    type Output = Result<DownstreamUpgraded>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.inner).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(anyhow!("downstream upgrade canceled"))),
            Poll::Pending => Poll::Pending,
        }
    }
}
