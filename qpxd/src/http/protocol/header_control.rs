use qpx_core::rules::CompiledHeaderControl;

pub(crate) trait HeaderTransform {
    fn apply_request_transform(&self, headers: &mut qpx_core::http_message::Headers);
}

impl HeaderTransform for CompiledHeaderControl {
    fn apply_request_transform(&self, headers: &mut qpx_core::http_message::Headers) {
        for name in self.apply_request_owned(headers) {
            crate::http::metrics::header_regex_replace_invalid(crate::runtime::metric_names());
            tracing::warn!(
                header = %name,
                "header regex_replace produced invalid HeaderValue; mutation skipped"
            );
        }
    }
}

// The two closed finalization header stores select the existing mutation
// engine; diagnostics and execution order are shared below.
pub(crate) trait ResponseHeaderControl:
    qpx_http::protocol::finalization::FinalizationHeaders
{
    fn apply_control(&mut self, control: &CompiledHeaderControl) -> Vec<http::HeaderName>;
}

impl ResponseHeaderControl for http::HeaderMap {
    fn apply_control(&mut self, control: &CompiledHeaderControl) -> Vec<http::HeaderName> {
        control.apply_response(self)
    }
}

impl ResponseHeaderControl for qpx_core::http_message::Headers {
    fn apply_control(&mut self, control: &CompiledHeaderControl) -> Vec<http::HeaderName> {
        control.apply_response_owned(self)
    }
}

pub(crate) fn set_proxy_authorization_header(
    headers: &mut qpx_core::http_message::Headers,
    value: Option<&http::HeaderValue>,
) {
    let name =
        qpx_core::http_message::OrdinaryHeaderName::try_from(http::header::PROXY_AUTHORIZATION)
            .expect("proxy-authorization is an ordinary field");
    headers.remove(&name);
    if let Some(value) = value {
        headers.insert(name, value.clone());
    }
}

pub(crate) fn apply_request_headers(
    headers: &mut qpx_core::http_message::Headers,
    control: Option<&CompiledHeaderControl>,
) {
    let Some(control) = control else {
        return;
    };
    control.apply_request_transform(headers);
}

pub(crate) fn apply_response_headers(
    headers: &mut impl ResponseHeaderControl,
    control: Option<&CompiledHeaderControl>,
) {
    let Some(control) = control else {
        return;
    };
    for name in headers.apply_control(control) {
        crate::http::metrics::header_regex_replace_invalid(crate::runtime::metric_names());
        tracing::warn!(
            header = %name,
            "header regex_replace produced invalid HeaderValue; mutation skipped"
        );
    }
}
