use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use std::convert::Infallible;

pub fn test_client() -> Client<HttpConnector, BoxBody<Bytes, Infallible>> {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}
