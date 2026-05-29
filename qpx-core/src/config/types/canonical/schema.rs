use crate::config::{
    MAX_GRPC_STREAM_DURATION_MS, MAX_GRPC_WEB_TRAILER_BYTES, MAX_SSE_STREAM_DURATION_MS,
};
use serde_json::json;

pub fn canonical_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "qpxd canonical configuration",
        "type": "object",
        "required": ["edges"],
        "additionalProperties": false,
        "$defs": {
            "capturePolicy": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "encrypted": {"type": "boolean", "default": false},
                    "plaintext": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "enabled": {"type": "boolean", "default": false},
                            "headers": {"type": "boolean", "default": false},
                            "body": {"enum": ["disabled", "full", "stream_sample"], "default": "disabled"},
                            "body_sample_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576},
                            "sample_percent": {"type": "integer", "minimum": 0, "maximum": 100},
                            "max_body_bytes": {"type": "integer", "minimum": 1},
                            "redact": {"$ref": "#/$defs/captureRedaction"}
                        }
                    }
                }
            },
            "captureRedaction": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "headers": {"type": "array", "items": {"type": "string"}},
                    "query_keys": {"type": "array", "items": {"type": "string"}},
                    "json_paths": {"type": "array", "items": {"type": "string"}}
                }
            },
            "routeTarget": {
                "oneOf": [
                    {"type": "object", "required": ["type", "upstreams"], "additionalProperties": false, "properties": {"type": {"const": "upstream"}, "upstreams": {"type": "array", "items": {"type": "string"}}, "lb": {"type": "string"}}},
                    {"type": "object", "required": ["type", "backends"], "additionalProperties": false, "properties": {"type": {"const": "weighted"}, "backends": {"type": "array", "items": {"type": "object"}}}},
                    {"type": "object", "required": ["type", "endpoint"], "additionalProperties": false, "properties": {"type": {"const": "ipc"}, "endpoint": {"type": "string"}, "mode": {"enum": ["shm", "tcp"]}, "timeout_ms": {"type": "integer", "minimum": 1}, "body": {"$ref": "#/$defs/ipcBodyLimit"}}},
                    {"type": "object", "required": ["type", "response"], "additionalProperties": false, "properties": {"type": {"const": "local_response"}, "response": {"type": "object"}}},
                    {"type": "object", "required": ["type", "upstreams"], "additionalProperties": false, "properties": {"type": {"const": "tls_passthrough"}, "upstreams": {"type": "array", "items": {"type": "string"}}, "lb": {"type": "string"}}}
                ]
            },
            "ipcBodyLimit": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "max_request_bytes": {"type": "integer", "minimum": 1},
                    "max_response_bytes": {"type": "integer", "minimum": 1}
                }
            },
            "originalDst": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "source": {"enum": ["linux_so_original_dst"], "default": "linux_so_original_dst"}
                }
            },
            "httpModule": {
                "type": "object",
                "required": ["type"],
                "additionalProperties": false,
                "properties": {
                    "type": {"type": "string"},
                    "id": {"type": "string"},
                    "order": {"type": "integer"},
                    "settings": true
                }
            },
            "httpPolicy": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "response_rules": {"type": "array", "items": {"type": "object"}}
                }
            },
            "streamingConfig": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "body_channel_capacity": {"type": "integer", "minimum": 1},
                    "body_read_timeout_ms": {"type": "integer", "minimum": 1},
                    "body_send_timeout_ms": {"type": "integer", "minimum": 1},
                    "max_request_body_bytes": {"type": "integer", "minimum": 1},
                    "max_response_body_bytes": {"type": "integer", "minimum": 1}
                }
            },
            "grpcConfig": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "max_message_bytes": {"type": "integer", "minimum": 1},
                    "max_web_trailer_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_GRPC_WEB_TRAILER_BYTES},
                    "max_stream_duration_ms": {"type": "integer", "minimum": 1, "maximum": MAX_GRPC_STREAM_DURATION_MS},
                    "observe_messages": {"type": "boolean"}
                }
            },
            "sseStreamingPolicy": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "disable_compression": {"type": "boolean"},
                    "flush_policy": {"enum": ["low_latency", "batched"]},
                    "idle_timeout_ms": {"type": "integer", "minimum": 1},
                    "max_stream_duration_ms": {"type": "integer", "minimum": 1, "maximum": MAX_SSE_STREAM_DURATION_MS}
                }
            },
            "commonEdgeFields": {
                "type": "object",
                "properties": {
                    "tls_inspection": {"type": "object"},
                    "connection_filter": {"type": "array", "items": {"type": "object"}},
                    "rules": {"type": "array", "items": {"type": "object"}},
                    "http3": {"type": "object"},
                    "ftp": {"type": "object"},
                    "xdp": {"type": "object"},
                    "cache": {"type": "object"},
                    "capture": {"$ref": "#/$defs/capturePolicy"},
                    "rate_limit": {"type": "object"},
                    "policy_context": {"type": "object"},
                    "destination_resolution": {"type": "object"},
                    "http": {"$ref": "#/$defs/httpPolicy"},
                    "http_guard_profile": {"type": "string"},
                    "modules": {"type": "array", "items": {"type": "string"}},
                    "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}},
                    "streaming": {"$ref": "#/$defs/streamingConfig"},
                    "grpc": {"$ref": "#/$defs/grpcConfig"},
                    "sse": {"$ref": "#/$defs/sseStreamingPolicy"}
                }
            }
        },
        "properties": {
            "state_dir": {"type": "string"},
            "identity": {"type": "object"},
            "messages": {"type": "object"},
            "runtime": {"type": "object"},
            "telemetry": {"type": "object"},
            "security": {"type": "object"},
            "http": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "guard_profiles": {"type": "array", "items": {"type": "object"}},
                    "module_chains": {"type": "array", "items": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}, "modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}}}}
                }
            },
            "traffic": {"type": "object"},
            "upstreams": {"type": "array"},
            "caches": {"type": "array"},
            "acme": {"type": "object"},
            "edges": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {
                            "allOf": [
                                {"$ref": "#/$defs/commonEdgeFields"},
                                {"type": "object", "required": ["kind", "name", "listen", "default_action"], "additionalProperties": false, "properties": {"kind": {"const": "forward"}, "name": {"type": "string"}, "listen": {"type": "string"}, "default_action": {"type": "object"}, "upstream_proxy": {"type": "string"}, "tls_inspection": {"type": "object"}, "connection_filter": {"type": "array", "items": {"type": "object"}}, "rules": {"type": "array", "items": {"type": "object"}}, "http3": {"type": "object"}, "ftp": {"type": "object"}, "xdp": {"type": "object"}, "cache": {"type": "object"}, "capture": {"$ref": "#/$defs/capturePolicy"}, "rate_limit": {"type": "object"}, "policy_context": {"type": "object"}, "destination_resolution": {"type": "object"}, "http": {"$ref": "#/$defs/httpPolicy"}, "http_guard_profile": {"type": "string"}, "modules": {"type": "array", "items": {"type": "string"}}, "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}, "streaming": {"$ref": "#/$defs/streamingConfig"}, "grpc": {"$ref": "#/$defs/grpcConfig"}, "sse": {"$ref": "#/$defs/sseStreamingPolicy"}, "streaming_requirement": {"enum": ["preferred", "required"]}}}
                            ]
                        },
                        {"type": "object", "required": ["kind", "name", "listen"], "additionalProperties": false, "properties": {"kind": {"const": "reverse"}, "name": {"type": "string"}, "listen": {"type": "string"}, "tls": {"type": "object"}, "http3": {"type": "object"}, "xdp": {"type": "object"}, "enforce_sni_host_match": {"type": "boolean"}, "sni_host_exceptions": {"type": "array", "items": {"type": "string"}}, "policy_context": {"type": "object"}, "destination_resolution": {"type": "object"}, "connection_filter": {"type": "array", "items": {"type": "object"}}, "streaming": {"$ref": "#/$defs/streamingConfig"}, "grpc": {"$ref": "#/$defs/grpcConfig"}, "sse": {"$ref": "#/$defs/sseStreamingPolicy"}, "routes": {"type": "array", "items": {"type": "object", "required": ["match", "target"], "additionalProperties": false, "properties": {"name": {"type": "string"}, "match": {"type": "object"}, "target": {"$ref": "#/$defs/routeTarget"}, "mirrors": {"type": "array", "items": {"type": "object"}}, "headers": {"type": "object"}, "timeout_ms": {"type": "integer", "minimum": 1}, "health_check": {"type": "object"}, "resilience": {"type": "object"}, "cache": {"type": "object"}, "capture": {"$ref": "#/$defs/capturePolicy"}, "rate_limit": {"type": "object"}, "path_rewrite": {"type": "object"}, "upstream_trust_profile": {"type": "string"}, "upstream_trust": {"type": "object"}, "lifecycle": {"type": "object"}, "affinity": {"type": "object"}, "policy_context": {"type": "object"}, "destination_resolution": {"type": "object"}, "http": {"$ref": "#/$defs/httpPolicy"}, "http_guard_profile": {"type": "string"}, "modules": {"type": "array", "items": {"type": "string"}}, "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}, "streaming": {"$ref": "#/$defs/streamingConfig"}, "grpc": {"$ref": "#/$defs/grpcConfig"}, "sse": {"$ref": "#/$defs/sseStreamingPolicy"}, "streaming_requirement": {"enum": ["preferred", "required"]}}}}, "tls_passthrough_routes": {"type": "array", "items": {"type": "object"}}}},
                        {
                            "allOf": [
                                {"$ref": "#/$defs/commonEdgeFields"},
                                {"type": "object", "required": ["kind", "name", "listen", "default_action"], "additionalProperties": false, "properties": {"kind": {"const": "transparent"}, "name": {"type": "string"}, "listen": {"type": "string"}, "default_action": {"type": "object"}, "original_dst": {"$ref": "#/$defs/originalDst"}, "tls_inspection": {"type": "object"}, "connection_filter": {"type": "array", "items": {"type": "object"}}, "rules": {"type": "array", "items": {"type": "object"}}, "http3": {"type": "object"}, "ftp": {"type": "object"}, "xdp": {"type": "object"}, "cache": {"type": "object"}, "capture": {"$ref": "#/$defs/capturePolicy"}, "rate_limit": {"type": "object"}, "policy_context": {"type": "object"}, "destination_resolution": {"type": "object"}, "http": {"$ref": "#/$defs/httpPolicy"}, "http_guard_profile": {"type": "string"}, "modules": {"type": "array", "items": {"type": "string"}}, "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}, "streaming": {"$ref": "#/$defs/streamingConfig"}, "grpc": {"$ref": "#/$defs/grpcConfig"}, "sse": {"$ref": "#/$defs/sseStreamingPolicy"}, "streaming_requirement": {"enum": ["preferred", "required"]}}}
                            ]
                        }
                    ]
                }
            }
        }
    })
}
