use crate::upstream::raw_http1::InterimResponseHead;

pub(crate) type InterimList = Vec<InterimResponseHead>;

pub(crate) fn attach_interim_response_heads<R: crate::http::response_carrier::ResponseCarrier>(
    response: &mut R,
    interim: InterimList,
) {
    if !interim.is_empty() {
        response.extensions_mut().insert(interim);
    }
}
