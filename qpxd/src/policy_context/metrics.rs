use metrics::{counter, histogram};

pub(super) fn signed_assertion_verification_failed(source: &str) {
    counter!(
        "qpx_signed_assertion_verification_failed_total",
        "source" => source.to_owned(),
    )
    .increment(1);
}

pub(super) fn ext_authz_response_body_bytes(scheme: &str, bytes: usize) {
    histogram!(
        "qpx_ext_authz_response_body_bytes",
        "scheme" => scheme.to_owned(),
    )
    .record(bytes as f64);
}
