//! Closed capabilities for shared response finalization, not message conversion.
//!
//! Ordinary fields use the core mutation vocabulary. Content-Length can only
//! be removed here; its stored values remain private to the message owner.
use http::{Extensions, HeaderMap, StatusCode};
use qpx_core::http_message::{Headers, OrdinaryHeaderMut, Response as OwnerResponse};

mod sealed {
    pub trait Headers {}
    impl Headers for http::HeaderMap {}
    impl Headers for qpx_core::http_message::Headers {}
    pub trait Response {}
    impl<B> Response for http::Response<B> {}
    impl<B> Response for qpx_core::http_message::Response<B> {}
}

pub trait FinalizationHeaders: sealed::Headers + OrdinaryHeaderMut {
    fn remove_content_length(&mut self);
}

impl FinalizationHeaders for HeaderMap {
    fn remove_content_length(&mut self) {
        self.remove(http::header::CONTENT_LENGTH);
    }
}

impl FinalizationHeaders for Headers {
    fn remove_content_length(&mut self) {
        self.remove_content_length();
    }
}

/// Only the operations needed by normalization and the finalizer. There is no
/// raw head, conversion, routing, or general message-building API. The closed
/// implementations cover standard library boundaries and core-owned messages;
/// adopting the owner in a caller does not migrate other callers implicitly.
///
/// An owned finalization head cannot be projected as a raw map:
/// ```compile_fail,E0308
/// use qpx_core::http_message::Response;
/// use qpx_http::protocol::finalization::FinalizeResponse;
/// let mut response = Response::new(());
/// let _: &mut http::HeaderMap = FinalizeResponse::headers_mut(&mut response);
/// ```
pub trait FinalizeResponse: sealed::Response {
    type Body: Default;
    type Headers: FinalizationHeaders;
    fn status(&self) -> StatusCode;
    fn status_mut(&mut self) -> &mut StatusCode;
    fn headers(&self) -> &Self::Headers;
    fn headers_mut(&mut self) -> &mut Self::Headers;
    fn body(&self) -> &Self::Body;
    fn body_mut(&mut self) -> &mut Self::Body;
    fn extensions(&self) -> &Extensions;
    fn extensions_mut(&mut self) -> &mut Extensions;
}

macro_rules! impl_finalization {
    ($response:ty, $headers:ty) => {
        impl<B: Default> FinalizeResponse for $response {
            type Body = B;
            type Headers = $headers;
            fn status(&self) -> StatusCode {
                self.status()
            }
            fn status_mut(&mut self) -> &mut StatusCode {
                self.status_mut()
            }
            fn headers(&self) -> &Self::Headers {
                self.headers()
            }
            fn headers_mut(&mut self) -> &mut Self::Headers {
                self.headers_mut()
            }
            fn body(&self) -> &B {
                self.body()
            }
            fn body_mut(&mut self) -> &mut B {
                self.body_mut()
            }
            fn extensions(&self) -> &Extensions {
                self.extensions()
            }
            fn extensions_mut(&mut self) -> &mut Extensions {
                self.extensions_mut()
            }
        }
    };
}
impl_finalization!(http::Response<B>, HeaderMap);
impl_finalization!(OwnerResponse<B>, Headers);

#[cfg(test)]
mod tests;
