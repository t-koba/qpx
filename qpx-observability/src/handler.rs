use std::future::Future;

/// Minimal async request handler trait.
pub trait RequestHandler<Request>: Send + Sync {
    /// Response produced by the handler.
    type Response;
    /// Error returned by the handler.
    type Error;
    /// Future returned by [`RequestHandler::call`].
    type Future: Future<Output = Result<Self::Response, Self::Error>> + Send;

    /// Handles one request.
    fn call(&self, request: Request) -> Self::Future;
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
    type Future = Fut;

    fn call(&self, request: Request) -> Self::Future {
        (self.inner)(request)
    }
}
