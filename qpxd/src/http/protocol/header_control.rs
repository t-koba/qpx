use qpx_core::rules::{CompiledHeaderControl, CompiledRegexReplace};

pub(crate) trait HeaderTransform {
    fn apply_request_transform(&self, headers: &mut http::HeaderMap);
    fn apply_response_transform(&self, headers: &mut http::HeaderMap);
}

impl HeaderTransform for CompiledHeaderControl {
    fn apply_request_transform(&self, headers: &mut http::HeaderMap) {
        apply_header_mutations(
            headers,
            self.request_set(),
            self.request_add(),
            self.request_remove(),
            self.request_regex_replace(),
        );
    }

    fn apply_response_transform(&self, headers: &mut http::HeaderMap) {
        apply_header_mutations(
            headers,
            self.response_set(),
            self.response_add(),
            self.response_remove(),
            self.response_regex_replace(),
        );
    }
}

pub(crate) fn set_proxy_authorization_header(
    headers: &mut http::HeaderMap,
    value: Option<&http::HeaderValue>,
) {
    headers.remove(http::header::PROXY_AUTHORIZATION);
    let _ = value.map(|value| headers.insert(http::header::PROXY_AUTHORIZATION, value.clone()));
}

pub(crate) fn apply_request_headers(
    headers: &mut http::HeaderMap,
    control: Option<&CompiledHeaderControl>,
) {
    let Some(control) = control else {
        return;
    };
    control.apply_request_transform(headers);
}

pub(crate) fn apply_response_headers(
    headers: &mut http::HeaderMap,
    control: Option<&CompiledHeaderControl>,
) {
    let Some(control) = control else {
        return;
    };
    control.apply_response_transform(headers);
}

fn apply_header_mutations(
    headers: &mut http::HeaderMap,
    set: &[(http::header::HeaderName, http::HeaderValue)],
    add: &[(http::header::HeaderName, http::HeaderValue)],
    remove: &[http::header::HeaderName],
    regex_replace: &[CompiledRegexReplace],
) {
    for (name, value) in set {
        headers.insert(name.clone(), value.clone());
    }

    for (name, value) in add {
        headers.append(name.clone(), value.clone());
    }

    for name in remove {
        headers.remove(name);
    }

    for replace in regex_replace {
        let Some(value) = headers.get(replace.header()).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        let replaced = replace.pattern().replace_all(value, replace.replace());
        if let Ok(new_value) = http::HeaderValue::from_str(replaced.as_ref()) {
            headers.insert(replace.header().clone(), new_value);
        } else {
            crate::http::metrics::header_regex_replace_invalid(crate::runtime::metric_names());
            tracing::warn!(
                header = %replace.header(),
                "header regex_replace produced invalid HeaderValue; mutation skipped"
            );
        }
    }
}
