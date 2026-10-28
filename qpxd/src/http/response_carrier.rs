//! Private observation/capture seam for terminal owned responses and legacy paths.
//! No raw heads or maps cross this interface.
use http::{Extensions, StatusCode, Version};
use qpx_core::http_message::Response as OwnerResponse;
use qpx_http::body::Body;

pub(crate) trait ResponseCarrier: Send + Sized {
    fn status(&self) -> StatusCode;
    fn version(&self) -> Version;
    fn extensions(&self) -> &Extensions;
    fn extensions_mut(&mut self) -> &mut Extensions;
    fn body(&self) -> &Body;
    fn body_mut(&mut self) -> &mut Body;
    fn preview_fields(&self, out: &mut String, include: fn(&str) -> bool);
    fn drop_length_over(&mut self, max: usize);
    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    fn into_owner(self) -> OwnerResponse<Body>;
    #[cfg(feature = "http3-backend-qpx")]
    fn into_qpx_codec_response(
        self,
    ) -> Result<http::Response<Body>, qpx_core::http_content_length::ContentLengthError>;
}

macro_rules! common {
    () => {
        fn status(&self) -> StatusCode {
            self.status()
        }
        fn version(&self) -> Version {
            self.version()
        }
        fn extensions(&self) -> &Extensions {
            self.extensions()
        }
        fn extensions_mut(&mut self) -> &mut Extensions {
            self.extensions_mut()
        }
        fn body(&self) -> &Body {
            self.body()
        }
        fn body_mut(&mut self) -> &mut Body {
            self.body_mut()
        }
    };
}

impl ResponseCarrier for OwnerResponse<Body> {
    common!();
    fn preview_fields(&self, out: &mut String, include: fn(&str) -> bool) {
        self.headers()
            .write_textual_http_field_lines(out, |name| include(name.as_str()));
    }
    fn drop_length_over(&mut self, max: usize) {
        if self
            .headers()
            .declared_content_length()
            .ok()
            .flatten()
            .is_some_and(|len| len > max as u64)
        {
            self.headers_mut().remove_content_length();
        }
    }
    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    fn into_owner(self) -> OwnerResponse<Body> {
        self
    }
    #[cfg(feature = "http3-backend-qpx")]
    fn into_qpx_codec_response(
        mut self,
    ) -> Result<http::Response<Body>, qpx_core::http_content_length::ContentLengthError> {
        // The qpx H3 codec's established head preparation removes malformed or
        // conflicting Content-Length values. Do that at this codec boundary
        // before the owner's otherwise-strict export validates the field.
        if self.headers().declared_content_length().is_err() {
            self.headers_mut().remove_content_length();
        }
        self.into_http_for_codec()
    }
}

impl ResponseCarrier for http::Response<Body> {
    common!();
    fn preview_fields(&self, out: &mut String, include: fn(&str) -> bool) {
        for (name, value) in self.headers() {
            if include(name.as_str()) {
                out.push_str(name.as_str());
                out.push_str(": ");
                out.push_str(value.to_str().unwrap_or(""));
                out.push_str("\r\n");
            }
        }
    }
    fn drop_length_over(&mut self, max: usize) {
        if qpx_core::http_content_length::declared_content_length(self.headers())
            .ok()
            .flatten()
            .is_some_and(|len| len > max as u64)
        {
            self.headers_mut().remove(http::header::CONTENT_LENGTH);
        }
    }
    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    fn into_owner(self) -> OwnerResponse<Body> {
        OwnerResponse::from_http(self)
    }
    #[cfg(feature = "http3-backend-qpx")]
    fn into_qpx_codec_response(
        self,
    ) -> Result<http::Response<Body>, qpx_core::http_content_length::ContentLengthError> {
        Ok(self)
    }
}

#[cfg(all(test, feature = "http3-backend-qpx"))]
mod qpx_codec_tests {
    use super::*;
    use http::Method;
    use http::header::CONTENT_LENGTH;

    #[test]
    fn owner_qpx_codec_export_preserves_h3_content_length_sanitizer_for_get_and_head() {
        for values in [vec!["invalid"], vec!["3", "4"]] {
            for request_method in [Method::GET, Method::HEAD] {
                let mut response = http::Response::new(Body::empty());
                for value in &values {
                    response
                        .headers_mut()
                        .append(CONTENT_LENGTH, value.parse().expect("header value"));
                }
                let owner = OwnerResponse::from_http(response);
                let response = owner
                    .into_qpx_codec_response()
                    .expect("H3 codec boundary sanitizes malformed framing");
                let (parts, _) = response.into_parts();
                let prepared =
                    crate::http3::codec::prepare_h3_response_head(&parts, &request_method)
                        .expect("prepare response head");

                assert_eq!(prepared.body_allowed, request_method != Method::HEAD);
                assert_eq!(prepared.content_length, None);
                assert!(!prepared.head.headers().contains_key(CONTENT_LENGTH));
            }
        }
    }
}
