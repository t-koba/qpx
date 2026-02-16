use qpx_core::rules::{CompiledHeaderControl, CompiledRegexReplace};

pub fn apply_request_headers(
    headers: &mut http::HeaderMap,
    control: Option<&CompiledHeaderControl>,
) {
    let Some(control) = control else {
        return;
    };
    apply_header_mutations(
        headers,
        control.request_set(),
        control.request_add(),
        control.request_remove(),
        control.request_regex_replace(),
    );
}

pub fn apply_response_headers(
    headers: &mut http::HeaderMap,
    control: Option<&CompiledHeaderControl>,
) {
    let Some(control) = control else {
        return;
    };
    apply_header_mutations(
        headers,
        control.response_set(),
        control.response_add(),
        control.response_remove(),
        control.response_regex_replace(),
    );
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
        }
    }
}
