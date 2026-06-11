use metrics::counter;

pub(super) fn probe_success() {
    counter!(
        crate::runtime::metric_names()
            .forward_upstream_proxy_probe_success_total
            .clone()
    )
    .increment(1);
}

pub(super) fn ejection(reason: &str) {
    counter!(
        crate::runtime::metric_names()
            .forward_upstream_proxy_ejections_total
            .clone(),
        "reason" => reason.to_owned()
    )
    .increment(1);
}
