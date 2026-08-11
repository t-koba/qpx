use std::future::Future;
use std::pin::Pin;

/// Minimal async request handler trait.
pub trait RequestHandler<Request>: Send + Sync {
    /// Response produced by the handler.
    type Response;
    /// Error returned by the handler.
    type Error;

    /// Handles one request.
    fn call(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send;

    /// Handles one request from a multiplexed transport with stable storage.
    ///
    /// Implementations with large request futures can override this method to
    /// construct the future directly in its pinned allocation. Sequential
    /// transports should use [`Self::call`] so small futures stay allocation-free.
    fn call_pinned<'a>(
        &'a self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'a>>
    where
        Request: 'a,
    {
        Box::pin(self.call(request))
    }
}

/// [`RequestHandler`] implementation backed by a closure.
#[derive(Clone)]
pub struct HandlerFn<F> {
    inner: F,
}

/// Wraps a closure as a [`RequestHandler`].
pub fn handler_fn<F>(inner: F) -> HandlerFn<F> {
    HandlerFn { inner }
}

impl<F, Request, Response, Error, Fut> RequestHandler<Request> for HandlerFn<F>
where
    F: Fn(Request) -> Fut + Clone + Send + Sync,
    Fut: Future<Output = Result<Response, Error>> + Send,
{
    type Response = Response;
    type Error = Error;

    fn call(&self, request: Request) -> impl Future<Output = Result<Response, Error>> + Send {
        (self.inner)(request)
    }
}
