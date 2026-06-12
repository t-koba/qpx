use super::*;

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
