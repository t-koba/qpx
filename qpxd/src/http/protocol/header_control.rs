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
    headers: &mut qpx_core::http_message::Headers,
    control: Option<&CompiledHeaderControl>,
) {
    let Some(control) = control else {
        return;
    };
    for name in control.apply_response_owned(headers) {
        crate::http::metrics::header_regex_replace_invalid(crate::runtime::metric_names());
        tracing::warn!(
            header = %name,
            "header regex_replace produced invalid HeaderValue; mutation skipped"
        );
    }
}
