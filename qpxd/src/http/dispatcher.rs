use crate::http::body::Body;
use crate::upstream::raw_http1::InterimResponseHead;
use hyper::Response;

pub(crate) type InterimList = Vec<InterimResponseHead>;

pub(crate) fn attach_interim_response_heads(response: &mut Response<Body>, interim: InterimList) {
    if !interim.is_empty() {
        response.extensions_mut().insert(interim);
    }
}
