use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Full};
use std::convert::Infallible;

pub fn full_body(data: impl Into<Bytes>) -> BoxBody<Bytes, Infallible> {
    Full::new(data.into()).boxed()
}
