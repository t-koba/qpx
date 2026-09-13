use crate::config::{
    MAX_GRPC_STREAM_DURATION_MS, MAX_GRPC_WEB_TRAILER_BYTES, MAX_SSE_EVENT_ID_BYTES,
    MAX_SSE_LINE_BYTES, MAX_SSE_STREAM_DURATION_MS,
};
use serde_json::json;

pub fn canonical_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "qpxd canonical configuration",
        "type": "object",
        "required": ["edges"],
        "additionalProperties": false,
        "properties": {
            "state_dir": {"type": "string"},
            "identity": {"type": "object"},
            "messages": {"type": "object"},
            "runtime": {"type": "object"},
            "telemetry": {"type": "object"},
            "security": {"type": "object"},
            "http": {"type": "object"},
            "origins": {"type": "object"},
            "traffic": {"type": "object"},
            "upstreams": {"type": "array", "items": {"type": "object"}},
            "caches": {"type": "array", "items": {"type": "object"}},
            "acme": {"type": "object"},
            "edges": {"type": "array", "items": {"$ref": "#/$defs/edge"}}
        },
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
                    {"type": "object", "required": ["type", "origin"], "additionalProperties": false, "properties": {"type": {"const": "webdav"}, "origin": {"type": "string", "minLength": 1}}},
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
                    "response_rules": {"type": "array", "items": {"type": "object"}},
                    "require_precondition": {"type": "boolean"},
                    "capport": {"type": "boolean"},
                    "forwarded": {
                        "type": "object",
                        "required": ["trusted_peers", "by"],
                        "additionalProperties": false,
                        "properties": {
                            "trusted_peers": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                            "by": {"type": "string", "minLength": 1},
                            "untrusted_chain": {"enum": ["discard", "reject"]}
                        }
                    },
                    "api_metadata": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "deprecation_unix_seconds": {"type": "integer"},
                            "sunset_unix_seconds": {"type": "integer"},
                            "links": {"type": "array", "items": {
                                "type": "object",
                                "required": ["target", "relation"],
                                "additionalProperties": false,
                                "properties": {
                                    "target": {"type": "string", "minLength": 1},
                                    "relation": {"type": "string", "minLength": 1},
                                    "media_type": {"type": "string", "minLength": 1}
                                }
                            }}
                        }
                    },
                    "hsts": {
                        "type": "object",
                        "required": ["max_age_seconds"],
                        "additionalProperties": false,
                        "properties": {
                            "max_age_seconds": {"type": "integer", "minimum": 1},
                            "include_subdomains": {"type": "boolean"}
                        }
                    },
                    "cors": {
                        "type": "object",
                        "required": ["allowed_origins", "allowed_methods"],
                        "additionalProperties": false,
                        "properties": {
                            "allowed_origins": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
                            "allowed_methods": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
                            "allowed_headers": {"type": "array", "items": {"type": "string", "minLength": 1}},
                            "expose_headers": {"type": "array", "items": {"type": "string", "minLength": 1}},
                            "allow_credentials": {"type": "boolean"},
                            "max_age_seconds": {"type": "integer", "minimum": 0},
                            "allow_private_network": {"type": "boolean"}
                        }
                    },
                    "client_certificate": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "include_chain": {"type": "boolean"},
                            "reject_inbound": {"type": "boolean"},
                            "max_certificate_bytes": {"type": "integer", "minimum": 1},
                            "max_chain_certificates": {"type": "integer", "minimum": 1},
                            "max_field_bytes": {"type": "integer", "minimum": 1},
                            "max_total_field_bytes": {"type": "integer", "minimum": 1}
                        }
                    },
                    "cookies": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "require_secure": {"type": "boolean"},
                            "require_http_only": {"type": "boolean"},
                            "same_site": {"enum": ["strict", "lax", "none"]},
                            "require_partitioned": {"type": "boolean"},
                            "max_field_bytes": {"type": "integer", "minimum": 1}
                        }
                    },
                    "fetch_metadata": {
                        "type": "object",
                        "required": ["allowed_sites"],
                        "additionalProperties": false,
                        "properties": {
                            "allowed_sites": {"type": "array", "minItems": 1, "items": {"enum": ["same-origin", "same-site", "cross-site", "none"]}},
                            "allowed_modes": {"type": "array", "items": {"enum": ["navigate", "same-origin", "cors", "no-cors", "websocket"]}},
                            "allowed_destinations": {"type": "array", "items": {"type": "string", "minLength": 1}},
                            "allow_missing": {"type": "boolean"},
                            "require_user_activation_for_navigation": {"type": "boolean"}
                        }
                    },
                    "browser_security": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "content_security_policy": {"type": "string", "minLength": 1},
                            "content_security_policy_report_only": {"type": "string", "minLength": 1},
                            "referrer_policy": {"type": "string", "minLength": 1},
                            "permissions_policy": {"type": "string", "minLength": 1},
                            "permissions_policy_report_only": {"type": "string", "minLength": 1},
                            "cross_origin_opener_policy": {"type": "string", "minLength": 1},
                            "cross_origin_opener_policy_report_only": {"type": "string", "minLength": 1},
                            "cross_origin_embedder_policy": {"type": "string", "minLength": 1},
                            "cross_origin_embedder_policy_report_only": {"type": "string", "minLength": 1},
                            "cross_origin_resource_policy": {"type": "string", "minLength": 1},
                            "x_content_type_options": {"type": "string", "minLength": 1},
                            "origin_agent_cluster": {"type": "string", "minLength": 1},
                            "clear_site_data": {"type": "string", "minLength": 1},
                            "reporting_endpoints": {"type": "string", "minLength": 1},
                            "timing_allow_origin": {"type": "string", "minLength": 1},
                            "accept_ch": {"type": "string", "minLength": 1},
                            "critical_ch": {"type": "string", "minLength": 1}
                        }
                    },
                    "reporting_collector": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "max_body_bytes": {"type": "integer", "minimum": 1},
                            "max_reports": {"type": "integer", "minimum": 1},
                            "accept_legacy_csp_reports": {"type": "boolean"}
                        }
                    }
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
                    "max_stream_duration_ms": {"type": "integer", "minimum": 1, "maximum": MAX_SSE_STREAM_DURATION_MS},
                    "max_line_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_SSE_LINE_BYTES},
                    "max_event_id_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_SSE_EVENT_ID_BYTES}
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
            "origins": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "webdav": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["name", "root", "metadata"],
                            "properties": {
                                "name": {"type": "string", "minLength": 1},
                                "root": {"type": "string", "minLength": 1},
                                "metadata": {"type": "string", "minLength": 1},
                                "max_depth": {"type": "integer", "minimum": 1},
                                "max_multistatus_entries": {"type": "integer", "minimum": 1},
                                "max_lock_timeout_seconds": {"type": "integer", "minimum": 1}
                            }
                        }
                    }
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
