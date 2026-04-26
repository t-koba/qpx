use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Empty};
use std::convert::Infallible;

pub fn empty_body() -> BoxBody<Bytes, Infallible> {
    Empty::<Bytes>::new().boxed()
}
