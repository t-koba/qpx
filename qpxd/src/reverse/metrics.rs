use metrics::{Gauge, counter, gauge};

pub(super) fn unhealthy_upstreams_gauge(
    metric_name: &str,
    reverse_name: &str,
    route_kind: &'static str,
    route_idx: &str,
) -> Gauge {
    gauge!(
        metric_name.to_owned(),
        "reverse" => reverse_name.to_owned(),
        "route_kind" => route_kind,
        "route_idx" => route_idx.to_owned()
    )
}

pub(super) fn draining_upstreams_gauge(
    reverse_name: &str,
    route_kind: &'static str,
    route_idx: &str,
) -> Gauge {
    gauge!(
        crate::runtime::metric_names().reverse_upstreams_draining.clone(),
        "reverse" => reverse_name.to_owned(),
        "route_kind" => route_kind,
        "route_idx" => route_idx.to_owned()
    )
}

pub(super) fn upstream_probe_success() {
    counter!(
        crate::runtime::metric_names()
            .reverse_upstream_probe_success_total
            .clone()
    )
    .increment(1);
}

pub(super) fn upstream_ejection(reason: &str) {
    counter!(
        crate::runtime::metric_names()
            .reverse_upstream_ejections_total
            .clone(),
        "reason" => reason.to_owned()
    )
    .increment(1);
}
