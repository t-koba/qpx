"""Required performance evaluations shared by CI validation and reporting."""

import re

CATEGORIES = {
    "protocol": {
        "criterion_streaming_throughput_bench": "criterion streaming throughput bench",
        "h3_crate_protocol_perf_benchmarks": "h3 crate protocol perf benchmarks",
        "qpx_http3_protocol_perf_benchmarks": "qpx http3 protocol perf benchmarks",
        "advanced_transport_perf_benchmarks": "advanced transport perf benchmarks",
    },
    "proxy": {
        "external_proxy_comparison_bench": "external proxy comparison bench",
        "enforce_cache_origin_feature_rich_performance_objectives": "enforce cache origin and feature-rich performance objectives",
        "compare_proxy_baseline": "compare proxy baseline",
    },
    "http2": {
        "external_http2_comparison_bench": "external http2 comparison bench",
        "enforce_http2_performance_objectives": "enforce http2 performance objectives",
    },
    "streaming": {
        "external_long_streaming_comparison_bench": "external long streaming comparison bench",
        "enforce_streaming_performance_objectives": "enforce streaming performance objectives",
    },
    "allocation": {
        "allocation_profile": "allocation profile",
        "enforce_allocation_budget": "enforce allocation budget",
    },
    "netem": {"netem_proxy_comparison_bench": "netem proxy comparison bench"},
    "interop": {"http3_interop_matrix": "http3 interop matrix"},
    "callgrind": {"callgrind_hot_path_profile": "callgrind hot path profile"},
}


def evaluation_name(label):
    return re.sub(r"[^a-zA-Z0-9_-]", "-", label)
