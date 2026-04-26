use std::future::Future;

pub trait RequestHandler<Request>: Send + Sync {
    type Response;
    type Error;
    type Future: Future<Output = Result<Self::Response, Self::Error>> + Send;

    fn call(&self, request: Request) -> Self::Future;
}

#[derive(Clone)]
pub struct HandlerFn<F> {
    inner: F,
}

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
