use super::*;

#[test]
fn canonical_schema_accepts_null_for_optional_root_state_dir() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({"state_dir": null, "edges": []});
    assert!(validator.is_valid(&config));
    assert!(serde_json::from_value::<crate::config::Config>(config).is_ok());
}

#[test]
fn canonical_schema_runtime_accepts_serde_values_and_defaults() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    for runtime in [
        serde_json::json!({}),
        serde_json::json!({
            "worker_threads": null,
            "max_blocking_threads": null,
            "acceptor_tasks_per_listener": null,
            "max_concurrent_connections": 0,
            "upstream_http_timeout_ms": 0,
            "h2_server_max_concurrent_streams": u32::MAX,
            "tcp_backlog": i32::MIN,
            "h3_allow_connection_migration": true,
            "trace_enabled": false,
            "trace_reflect_all_headers": true,
            "reuse_port": false,
            "unknown_length_exact_size": "buffer",
            "datagram_overflow_strategy": "drop_newest",
            "h3_request_body_drain": {
                "mode": "best_effort", "max_concurrent": 0, "timeout_ms": 0
            },
            "sse": {"flush_policy": "batched", "disable_compression": true},
            "future_runtime_field": {"enabled": true}
        }),
        serde_json::json!({
            "worker_threads": 0,
            "max_blocking_threads": usize::MAX,
            "acceptor_tasks_per_listener": 1,
            "tcp_backlog": i32::MAX,
            "unknown_length_exact_size": "reject",
            "h3_request_body_drain": {"mode": "abort"},
            "sse": {}
        }),
        serde_json::json!({"h3_request_body_drain": {"mode": "bounded"}}),
    ] {
        let config = serde_json::json!({"edges": [], "runtime": runtime});
        assert!(validator.is_valid(&config), "schema rejected {config}");
        assert!(serde_json::from_value::<crate::config::Config>(config).is_ok());
    }
}

#[test]
fn canonical_schema_runtime_rejects_malformed_known_fields() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    for runtime in [
        serde_json::json!({"worker_threads": "auto"}),
        serde_json::json!({"max_concurrent_connections": null}),
        serde_json::json!({"max_concurrent_connections": -1}),
        serde_json::json!({"upstream_http_timeout_ms": 1.5}),
        serde_json::json!({"h2_server_max_concurrent_streams": u64::from(u32::MAX) + 1}),
        serde_json::json!({"tcp_backlog": i64::from(i32::MIN) - 1}),
        serde_json::json!({"tcp_backlog": i64::from(i32::MAX) + 1}),
        serde_json::json!({"trace_enabled": "yes"}),
        serde_json::json!({"unknown_length_exact_size": "ignore"}),
        serde_json::json!({"datagram_overflow_strategy": "drop_oldest"}),
        serde_json::json!({"h3_request_body_drain": null}),
        serde_json::json!({"h3_request_body_drain": {"mode": "unbounded"}}),
        serde_json::json!({"h3_request_body_drain": {"max_concurrent": -1}}),
        serde_json::json!({"h3_request_body_drain": {"timeout_ms": "fast"}}),
        serde_json::json!({"h3_request_body_drain": {"future_field": true}}),
        serde_json::json!({"sse": null}),
        serde_json::json!({"sse": {"flush_policy": "immediate"}}),
        serde_json::json!({"sse": {"future_field": true}}),
    ] {
        let config = serde_json::json!({"edges": [], "runtime": runtime});
        assert!(!validator.is_valid(&config), "schema accepted {config}");
        assert!(serde_json::from_value::<crate::config::Config>(config).is_err());
    }
}

#[test]
fn canonical_schema_telemetry_matches_serde_contract() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let valid = serde_json::json!({
        "edges": [],
        "telemetry": {
            "system_log": {"format": "json"},
            "access_log": {
                "path": null,
                "redact": {"headers": ["authorization"], "future_field": true}
            },
            "audit_log": {"include": ["subject", "matched_route"]},
            "metrics": null,
            "otel": {
                "endpoint": null,
                "service_name": null,
                "redact": {"query_keys": ["token"]}
            },
            "exporter": {
                "capture": {
                    "plaintext": true,
                    "max_chunk_bytes": 4096,
                    "redact": {"json_paths": ["$.secret"]},
                    "future_field": true
                }
            }
        }
    });
    assert!(validator.is_valid(&valid));
    assert!(serde_json::from_value::<crate::config::Config>(valid).is_ok());

    let unknown_root_field = serde_json::json!({
        "edges": [],
        "telemetry": {"typo": true}
    });
    assert!(!validator.is_valid(&unknown_root_field));
    assert!(serde_json::from_value::<crate::config::Config>(unknown_root_field).is_err());

    let unknown_access_log_field = serde_json::json!({
        "edges": [],
        "telemetry": {"access_log": {"typo": true}}
    });
    assert!(!validator.is_valid(&unknown_access_log_field));
    assert!(serde_json::from_value::<crate::config::Config>(unknown_access_log_field).is_err());

    let missing_metrics_listener = serde_json::json!({
        "edges": [],
        "telemetry": {"metrics": {}}
    });
    assert!(!validator.is_valid(&missing_metrics_listener));
    assert!(serde_json::from_value::<crate::config::Config>(missing_metrics_listener).is_err());

    let malformed_nested_values = [
        serde_json::json!({
            "edges": [],
            "telemetry": {"access_log": {"redact": {"headers": false}}}
        }),
        serde_json::json!({
            "edges": [],
            "telemetry": {"otel": {"redact": {"headers": false}}}
        }),
        serde_json::json!({
            "edges": [],
            "telemetry": {"exporter": {"capture": {"plaintext": "yes"}}}
        }),
    ];
    for malformed in malformed_nested_values {
        assert!(!validator.is_valid(&malformed));
        assert!(serde_json::from_value::<crate::config::Config>(malformed).is_err());
    }
}

#[test]
fn canonical_schema_security_matches_serde_root_contract() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let valid = serde_json::json!({
        "edges": [],
        "security": {
            "auth": {},
            "identity_sources": [],
            "decisions": {},
            "destination": {},
            "named_sets": [],
            "upstream_trust_profiles": []
        }
    });
    assert!(validator.is_valid(&valid));
    assert!(serde_json::from_value::<crate::config::Config>(valid).is_ok());

    let unknown_root_field = serde_json::json!({
        "edges": [],
        "security": {"typo": true}
    });
    assert!(!validator.is_valid(&unknown_root_field));
    assert!(serde_json::from_value::<crate::config::Config>(unknown_root_field).is_err());

    let null_non_optional_field = serde_json::json!({
        "edges": [],
        "security": {"auth": null}
    });
    assert!(!validator.is_valid(&null_non_optional_field));
    assert!(serde_json::from_value::<crate::config::Config>(null_non_optional_field).is_err());
}

#[test]
fn canonical_schema_exposes_acme_dns_hook_deadline() {
    let schema = canonical_schema_value();
    assert_eq!(
        schema
            .pointer("/properties/acme/anyOf/0/$ref")
            .and_then(serde_json::Value::as_str),
        Some("#/$defs/acmeConfig")
    );
    assert_eq!(
        schema
            .pointer("/$defs/acmeConfig/properties/dns_hook/properties/timeout_secs/minimum")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        schema
            .pointer("/$defs/acmeConfig/properties/dns_hook/properties/timeout_secs/default")
            .and_then(serde_json::Value::as_u64),
        Some(60)
    );
}

#[test]
fn canonical_schema_accepts_null_for_optional_acme_fields() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({
        "edges": [],
        "acme": {
            "enabled": false,
            "directory_url": null,
            "email": null,
            "http01_listen": null,
            "dns_hook": null
        }
    });
    assert!(validator.is_valid(&config));
    assert!(validator.is_valid(&serde_json::json!({"edges": [], "acme": null})));
}

#[test]
fn canonical_schema_accepts_null_for_optional_api_metadata_fields() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({
        "edges": [{
            "kind": "forward",
            "name": "front",
            "listen": "127.0.0.1:0",
            "default_action": {},
            "http": {
                "api_metadata": {
                    "deprecation_unix_seconds": null,
                    "sunset_unix_seconds": null,
                    "links": [{
                        "target": "/docs",
                        "relation": "describedby",
                        "media_type": null
                    }]
                }
            }
        }]
    });
    assert!(validator.is_valid(&config));

    let null_container = serde_json::json!({
        "edges": [{
            "kind": "forward",
            "name": "front",
            "listen": "127.0.0.1:0",
            "default_action": {},
            "http": {"api_metadata": null}
        }]
    });
    assert!(validator.is_valid(&null_container));
}

#[test]
fn canonical_schema_accepts_null_for_optional_http_policy_containers() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({
        "edges": [
            {
                "kind": "forward",
                "name": "front-null-http",
                "listen": "127.0.0.1:0",
                "default_action": {},
                "http": null
            },
            {
                "kind": "forward",
                "name": "front-null-settings",
                "listen": "127.0.0.1:1",
                "default_action": {},
                "http": {
                    "forwarded": null,
                    "hsts": null,
                    "cors": null,
                    "client_certificate": null,
                    "cookies": null,
                    "fetch_metadata": null,
                    "browser_security": null,
                    "reporting_collector": null
                }
            },
            {
                "kind": "reverse",
                "name": "reverse-null-route-http",
                "listen": "127.0.0.1:2",
                "routes": [{
                    "match": {},
                    "target": {"type": "upstream", "upstreams": []},
                    "http": null
                }]
            }
        ]
    });
    assert!(validator.is_valid(&config));
}

#[test]
fn canonical_schema_accepts_null_for_optional_http_policy_scalar_fields() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({
        "edges": [{
            "kind": "forward",
            "name": "front",
            "listen": "127.0.0.1:0",
            "default_action": {},
            "http": {
                "cookies": {"same_site": null},
                "browser_security": {
                    "content_security_policy": null,
                    "content_security_policy_report_only": null,
                    "referrer_policy": null,
                    "permissions_policy": null,
                    "permissions_policy_report_only": null,
                    "cross_origin_opener_policy": null,
                    "cross_origin_opener_policy_report_only": null,
                    "cross_origin_embedder_policy": null,
                    "cross_origin_embedder_policy_report_only": null,
                    "cross_origin_resource_policy": null,
                    "x_content_type_options": null,
                    "origin_agent_cluster": null,
                    "clear_site_data": null,
                    "reporting_endpoints": null,
                    "timing_allow_origin": null,
                    "accept_ch": null,
                    "critical_ch": null
                }
            }
        }]
    });
    assert!(validator.is_valid(&config));
}

#[test]
fn canonical_schema_accepts_null_for_optional_reverse_edge_fields() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({
        "edges": [{
            "kind": "reverse",
            "name": "back",
            "listen": "127.0.0.1:2",
            "tls": null,
            "http3": null,
            "xdp": null,
            "policy_context": null,
            "destination_resolution": null,
            "streaming": null,
            "grpc": null,
            "sse": null
        }]
    });
    assert!(validator.is_valid(&config));
    assert!(serde_json::from_value::<crate::config::Config>(config).is_ok());
}

#[test]
fn canonical_schema_accepts_null_for_optional_reverse_route_fields() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({
        "edges": [{
            "kind": "reverse",
            "name": "back",
            "listen": "127.0.0.1:2",
            "routes": [{
                "match": {},
                "target": {"type": "upstream", "upstreams": ["origin"]},
                "name": null,
                "headers": null,
                "timeout_ms": null,
                "health_check": null,
                "resilience": null,
                "cache": null,
                "capture": null,
                "rate_limit": null,
                "path_rewrite": null,
                "upstream_trust_profile": null,
                "upstream_trust": null,
                "lifecycle": null,
                "affinity": null,
                "policy_context": null,
                "destination_resolution": null,
                "http": null,
                "http_guard_profile": null,
                "streaming": null,
                "grpc": null,
                "sse": null,
                "streaming_requirement": null
            }]
        }]
    });
    assert!(validator.is_valid(&config));
    assert!(serde_json::from_value::<crate::config::Config>(config).is_ok());
}

#[test]
fn canonical_schema_accepts_null_for_optional_ingress_edge_fields() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({
        "edges": [
            {
                "kind": "forward",
                "name": "front",
                "listen": "127.0.0.1:0",
                "default_action": {"type": "inspect"},
                "upstream_proxy": null,
                "tls_inspection": null,
                "http3": null,
                "xdp": null,
                "cache": null,
                "capture": null,
                "rate_limit": null,
                "policy_context": null,
                "destination_resolution": null,
                "http_guard_profile": null,
                "streaming": null,
                "grpc": null,
                "sse": null,
                "streaming_requirement": null
            },
            {
                "kind": "transparent",
                "name": "intercept",
                "listen": "127.0.0.1:1",
                "default_action": {"type": "inspect"},
                "original_dst": null,
                "tls_inspection": null,
                "http3": null,
                "xdp": null,
                "cache": null,
                "capture": null,
                "rate_limit": null,
                "policy_context": null,
                "destination_resolution": null,
                "http_guard_profile": null,
                "streaming": null,
                "grpc": null,
                "sse": null,
                "streaming_requirement": null
            }
        ]
    });
    assert!(validator.is_valid(&config));
    let parsed = serde_json::from_value::<crate::config::Config>(config.clone());
    assert!(parsed.is_ok(), "serde rejected explicit nulls: {parsed:?}");
}

#[test]
fn canonical_schema_accepts_null_for_optional_http_module_metadata() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({
        "edges": [{
            "kind": "forward",
            "name": "front",
            "listen": "127.0.0.1:0",
            "default_action": {},
            "http_modules": [{
                "type": "response_compression",
                "id": null,
                "order": null,
                "settings": {}
            }]
        }]
    });
    assert!(validator.is_valid(&config));
}

#[test]
fn canonical_schema_http_module_matches_serde_envelope() {
    let schema = canonical_schema_value();
    assert_eq!(
        schema.pointer("/required"),
        Some(&serde_json::json!(["edges"]))
    );
    let http_module = schema
        .pointer("/$defs/httpModule")
        .expect("httpModule schema");
    assert_eq!(
        http_module
            .get("additionalProperties")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert!(http_module.pointer("/properties/settings").is_some());

    let fields = http_module
        .pointer("/properties")
        .and_then(serde_json::Value::as_object)
        .expect("httpModule properties")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fields,
        ["id", "order", "settings", "type"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>()
    );

    let minimal = serde_yaml::from_str::<HttpModuleConfig>(
        r#"type: response_compression
settings:
  min_body_bytes: 1"#,
    )
    .expect("minimal settings module");
    assert_eq!(minimal.r#type, "response_compression");
    assert!(minimal.settings.get("min_body_bytes").is_some());
}

#[test]
fn canonical_schema_exposes_streaming_grpc_and_sse_knobs() {
    let schema = canonical_schema_value();
    assert!(
        schema
            .pointer("/$defs/streamingConfig/properties/body_channel_capacity")
            .is_some()
    );
    assert!(
        schema
            .pointer("/$defs/grpcConfig/properties/max_web_trailer_bytes")
            .is_some()
    );
    assert_eq!(
        schema
            .pointer("/$defs/grpcConfig/properties/max_web_trailer_bytes/maximum")
            .and_then(serde_json::Value::as_u64),
        Some(MAX_GRPC_WEB_TRAILER_BYTES)
    );
    assert_eq!(
        schema
            .pointer("/$defs/grpcConfig/properties/max_stream_duration_ms/maximum")
            .and_then(serde_json::Value::as_u64),
        Some(MAX_GRPC_STREAM_DURATION_MS)
    );
    assert!(
        schema
            .pointer("/$defs/sseStreamingPolicy/properties/flush_policy")
            .is_some()
    );
    assert_eq!(
        schema
            .pointer("/$defs/sseStreamingPolicy/properties/max_stream_duration_ms/maximum")
            .and_then(serde_json::Value::as_u64),
        Some(MAX_SSE_STREAM_DURATION_MS)
    );
    assert_eq!(
        schema
            .pointer("/$defs/sseStreamingPolicy/properties/max_line_bytes/maximum")
            .and_then(serde_json::Value::as_u64),
        Some(MAX_SSE_LINE_BYTES as u64)
    );
    assert_eq!(
        schema
            .pointer("/$defs/sseStreamingPolicy/properties/max_event_id_bytes/maximum")
            .and_then(serde_json::Value::as_u64),
        Some(MAX_SSE_EVENT_ID_BYTES as u64)
    );

    let edges = schema
        .pointer("/properties/edges/items/oneOf")
        .and_then(serde_json::Value::as_array)
        .expect("edge schemas");
    let forward = &edges[0]["allOf"][1]["properties"];
    assert!(forward.get("streaming").is_some());
    assert!(forward.get("grpc").is_some());
    assert!(forward.get("sse").is_some());

    let reverse = &edges[1]["properties"];
    assert!(reverse.get("streaming").is_some());
    assert!(reverse.get("grpc").is_some());
    assert!(reverse.get("sse").is_some());
    let route = &reverse["routes"]["items"]["properties"];
    assert!(route.get("streaming").is_some());
    assert!(route.get("grpc").is_some());
    assert!(route.get("sse").is_some());
    assert!(route.get("streaming_requirement").is_some());
}

#[test]
fn canonical_schema_exposes_browser_origin_policies() {
    let schema = canonical_schema_value();
    let properties = schema
        .pointer("/$defs/httpPolicy/properties")
        .and_then(serde_json::Value::as_object)
        .expect("HTTP policy properties");
    for name in [
        "cors",
        "client_certificate",
        "cookies",
        "fetch_metadata",
        "browser_security",
        "reporting_collector",
    ] {
        assert!(properties.contains_key(name), "missing {name} schema");
    }
    assert_eq!(
        schema
            .pointer("/$defs/httpPolicy/properties/client_certificate/properties/max_certificate_bytes/minimum")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        schema
            .pointer(
                "/$defs/httpPolicy/properties/reporting_collector/properties/max_reports/minimum"
            )
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
}

#[test]
fn canonical_schema_accepts_hsts_max_age_zero() {
    let validator =
        jsonschema::validator_for(&canonical_schema_value()).expect("canonical schema compiles");
    let config = serde_json::json!({
        "edges": [{
            "kind": "reverse",
            "name": "hsts-zero",
            "listen": "127.0.0.1:0",
            "routes": [{
                "match": {},
                "target": {"type": "upstream", "upstreams": []},
                "http": {"hsts": {"max_age_seconds": 0}}
            }]
        }]
    });
    assert!(validator.is_valid(&config));
}
