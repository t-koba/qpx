use crate::runtime::MetricNames;
use metrics::{counter, histogram};
use std::time::Duration;

pub(crate) fn forward_request(metrics: &MetricNames, result: &'static str) {
    request_result(metrics.forward_requests_total.as_str(), result)
}

pub(crate) fn forward_request_with_latency(metrics: &MetricNames, result: &str, elapsed: Duration) {
    request_result(metrics.forward_requests_total.as_str(), result);
    request_latency_ms(metrics.forward_latency_ms.as_str(), elapsed);
}

pub(crate) fn transparent_request(metrics: &MetricNames, result: &str, elapsed: Duration) {
    request_result(metrics.transparent_requests_total.as_str(), result);
    request_latency_ms(metrics.transparent_latency_ms.as_str(), elapsed);
}

pub(crate) fn request_result(metric_name: &str, result: &str) {
    counter!(metric_name.to_owned(), "result" => result.to_owned()).increment(1);
}

pub(crate) fn header_regex_replace_invalid(metrics: &MetricNames) {
    counter!(metrics.header_regex_replace_invalid_total.clone()).increment(1);
}

fn request_latency_ms(metric_name: &str, elapsed: Duration) {
    histogram!(metric_name.to_owned()).record(elapsed.as_secs_f64() * 1000.0);
}
