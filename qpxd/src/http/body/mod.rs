//! Daemon-local HTTP body helpers. The body core (`Body`, `Sender`,
//! `BodyError`, `to_bytes`, `tee`, `metrics`) lives in the shared `qpx-http`
//! crate and is imported directly from there. The `observation` and `size`
//! submodules stay in `qpxd` because they depend on `http::policy` /
//! `http::rpc`.

use anyhow::Result;
use bytes::Bytes;
use hyper::header::HeaderMap;
use qpx_http::body::Body;
use std::future::{Future, poll_fn};
use std::task::Poll;

/// Poll body data once without waiting for a pending body.
pub(crate) async fn poll_body_data_now(body: &mut Body) -> Result<Poll<Option<Bytes>>> {
    poll_fn(|cx| {
        let future = body.data();
        let mut future = std::pin::pin!(future);
        match Future::poll(future.as_mut(), cx) {
            Poll::Ready(chunk) => {
                Poll::Ready(chunk.transpose().map(Poll::Ready).map_err(Into::into))
            }
            Poll::Pending => Poll::Ready(Ok(Poll::Pending)),
        }
    })
    .await
}

/// Poll body trailers once without waiting for a pending body.
pub(crate) async fn poll_body_trailers_now(body: &mut Body) -> Result<Option<HeaderMap>> {
    poll_fn(|cx| {
        let future = body.trailers();
        let mut future = std::pin::pin!(future);
        match Future::poll(future.as_mut(), cx) {
            Poll::Ready(trailers) => Poll::Ready(trailers.map_err(Into::into)),
            Poll::Pending => Poll::Ready(Ok(None)),
        }
    })
    .await
}

pub mod observation;
pub mod size;

#[cfg(test)]
mod poll_tests {
    use super::*;
    use hyper::header::HeaderValue;
    use std::time::Duration;

    #[tokio::test]
    async fn pending_body_data_returns_pending() {
        let (_sender, mut body) = Body::channel();
        let result = tokio::time::timeout(Duration::from_secs(1), poll_body_data_now(&mut body))
            .await
            .expect("nonblocking body-data poll must not wait");
        assert_eq!(result.expect("body-data poll"), Poll::Pending);
    }

    #[tokio::test]
    async fn ready_body_data_is_preserved() {
        let (mut sender, mut body) = Body::channel();
        let expected = Bytes::from_static(b"data");
        sender
            .try_send_data(expected.clone())
            .expect("send body data");
        assert_eq!(
            poll_body_data_now(&mut body).await.expect("body-data poll"),
            Poll::Ready(Some(expected)),
        );
    }

    #[tokio::test]
    async fn pending_trailers_return_none() {
        let (_sender, mut body) = Body::channel();
        let trailers =
            tokio::time::timeout(Duration::from_secs(1), poll_body_trailers_now(&mut body))
                .await
                .expect("nonblocking trailer poll must not wait")
                .expect("trailer poll");
        assert!(trailers.is_none());
    }

    #[tokio::test]
    async fn ready_trailers_are_preserved() {
        let (mut sender, mut body) = Body::channel();
        let mut expected = HeaderMap::new();
        expected.insert("x-test", HeaderValue::from_static("value"));
        sender
            .try_send_trailers(expected.clone())
            .expect("send trailers");
        assert_eq!(
            poll_body_trailers_now(&mut body)
                .await
                .expect("trailer poll"),
            Some(expected),
        );
    }
}
