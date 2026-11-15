use crate::config::{
    MAX_GRPC_STREAM_DURATION_MS, MAX_GRPC_WEB_TRAILER_BYTES, MAX_SSE_EVENT_ID_BYTES,
    MAX_SSE_LINE_BYTES, MAX_SSE_STREAM_DURATION_MS,
};
use serde_json::json;

pub fn canonical_schema_value() -> serde_json::Value {
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "qpxd canonical configuration",
        "type": "object",
        "required": ["edges"],
        "additionalProperties": false,
        "$defs": {
            "runtimeConfig": {
                "type": "object",
                "additionalProperties": true,
                "properties": {
                    "worker_threads": {"type": ["integer", "null"], "minimum": 0, "maximum": usize::MAX},
                    "max_blocking_threads": {"type": ["integer", "null"], "minimum": 0, "maximum": usize::MAX},
                    "max_ftp_concurrency": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "max_concurrent_connections": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "max_h3_streams_per_connection": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "h3_max_uni_streams": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "h3_allow_connection_migration": {"type": "boolean"},
                    "h3_stream_receive_window_bytes": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "h3_connection_receive_window_bytes": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "h3_send_window_bytes": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "h3_origin_pool_max_connections_per_origin": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "h3_origin_pool_max_inflight_streams_per_connection": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "trace_enabled": {"type": "boolean"},
                    "trace_reflect_all_headers": {"type": "boolean"},
                    "acceptor_tasks_per_listener": {"type": ["integer", "null"], "minimum": 0, "maximum": usize::MAX},
                    "reuse_port": {"type": "boolean"},
                    "tcp_backlog": {"type": "integer", "minimum": i32::MIN, "maximum": i32::MAX},
                    "max_h3_request_body_bytes": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "max_h3_response_body_bytes": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "max_reverse_retry_template_body_bytes": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "max_observed_request_body_bytes": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "max_observed_response_body_bytes": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "unknown_length_exact_size": {"enum": ["reject", "buffer"]},
                    "upstream_http_timeout_ms": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "upstream_proxy_max_concurrent_per_endpoint": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "upstream_max_idle_connections_per_origin": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "h2_server_max_header_list_size_bytes": {"type": "integer", "minimum": 0, "maximum": u32::MAX},
                    "h2_server_max_concurrent_streams": {"type": "integer", "minimum": 0, "maximum": u32::MAX},
                    "h2_initial_stream_window_size_bytes": {"type": "integer", "minimum": 0, "maximum": u32::MAX},
                    "h2_initial_connection_window_size_bytes": {"type": "integer", "minimum": 0, "maximum": u32::MAX},
                    "tls_peek_timeout_ms": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "http_header_read_timeout_ms": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "upgrade_wait_timeout_ms": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "tunnel_idle_timeout_ms": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "h3_read_timeout_ms": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "h3_request_body_drain": {"$ref": "#/$defs/h3RequestBodyDrain"},
                    "body_channel_capacity": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "datagram_channel_capacity": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "webtransport_datagram_channel_capacity": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "webtransport_stream_channel_capacity": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "datagram_overflow_strategy": {"enum": ["drop_newest"]},
                    "max_grpc_message_bytes": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "max_grpc_web_trailer_bytes": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "max_grpc_stream_duration_ms": {"type": "integer", "minimum": 0, "maximum": u64::MAX},
                    "sse": {"$ref": "#/$defs/sseStreamingPolicy"}
                }
            },
            "h3RequestBodyDrain": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "mode": {"enum": ["bounded", "abort", "best_effort"]},
                    "max_concurrent": {"type": "integer", "minimum": 0, "maximum": usize::MAX},
                    "timeout_ms": {"type": "integer", "minimum": 0, "maximum": u64::MAX}
                }
            },
            "acmeConfig": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "enabled": {"type": "boolean", "default": false},
                    "challenge": {"enum": ["http-01", "tls-alpn-01", "dns-01"], "default": "http-01"},
                    "staging": {"type": "boolean", "default": false},
                    "directory_url": {"type": ["string", "null"]},
                    "email": {"type": ["string", "null"]},
                    "terms_of_service_agreed": {"type": "boolean", "default": false},
                    "http01_listen": {"type": ["string", "null"]},
                    "dns_hook": {
                        "type": ["object", "null"],
                        "additionalProperties": false,
                        "required": ["set_command", "clear_command"],
                        "properties": {
                            "set_command": {"type": "string"},
                            "clear_command": {"type": "string"},
                            "propagation_wait_secs": {"type": "integer", "minimum": 0, "default": 0},
                            "timeout_secs": {"type": "integer", "minimum": 1, "default": 60}
                        }
                    },
                    "renew_before_days": {"type": "integer", "minimum": 1, "default": 30}
                }
            },
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
                "properties": {
                    "headers": {"type": "array", "items": {"type": "string"}},
                    "query_keys": {"type": "array", "items": {"type": "string"}},
                    "json_paths": {"type": "array", "items": {"type": "string"}}
                }
            },
            "exporterCapture": {
                "type": "object",
                "properties": {
                    "plaintext": {"type": "boolean"},
                    "encrypted": {"type": "boolean"},
                    "max_chunk_bytes": {"type": "integer", "minimum": 0},
                    "redact": {"$ref": "#/$defs/captureRedaction"}
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
                    "id": {"type": ["string", "null"]},
                    "order": {"type": ["integer", "null"]},
                    "settings": true
                }
            },
            "httpPolicy": {
                "type": ["object", "null"],
                "additionalProperties": false,
                "properties": {
                    "response_rules": {"type": "array", "items": {"type": "object"}},
                    "require_precondition": {"type": "boolean"},
                    "capport": {"type": "boolean"},
                    "forwarded": {
                        "type": ["object", "null"],
                        "required": ["trusted_peers", "by"],
                        "additionalProperties": false,
                        "properties": {
                            "trusted_peers": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                            "by": {"type": "string", "minLength": 1},
                            "untrusted_chain": {"enum": ["discard", "reject"]}
                        }
                    },
                    "api_metadata": {
                        "type": ["object", "null"],
                        "additionalProperties": false,
                        "properties": {
                            "deprecation_unix_seconds": {"type": ["integer", "null"]},
                            "sunset_unix_seconds": {"type": ["integer", "null"]},
                            "links": {"type": "array", "items": {
                                "type": "object",
                                "required": ["target", "relation"],
                                "additionalProperties": false,
                                "properties": {
                                    "target": {"type": "string", "minLength": 1},
                                    "relation": {"type": "string", "minLength": 1},
                                    "media_type": {"type": ["string", "null"], "minLength": 1}
                                }
                            }}
                        }
                    },
                    "hsts": {
                        "type": ["object", "null"],
                        "required": ["max_age_seconds"],
                        "additionalProperties": false,
                        "properties": {
                            "max_age_seconds": {"type": "integer", "minimum": 1},
                            "include_subdomains": {"type": "boolean"}
                        }
                    },
                    "cors": {
                        "type": ["object", "null"],
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
                        "type": ["object", "null"],
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
                        "type": ["object", "null"],
                        "additionalProperties": false,
                        "properties": {
                            "require_secure": {"type": "boolean"},
                            "require_http_only": {"type": "boolean"},
                            "same_site": {"enum": ["strict", "lax", "none", null]},
                            "require_partitioned": {"type": "boolean"},
                            "max_field_bytes": {"type": "integer", "minimum": 1}
                        }
                    },
                    "fetch_metadata": {
                        "type": ["object", "null"],
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
                        "type": ["object", "null"],
                        "additionalProperties": false,
                        "properties": {
                            "content_security_policy": {"type": ["string", "null"], "minLength": 1},
                            "content_security_policy_report_only": {"type": ["string", "null"], "minLength": 1},
                            "referrer_policy": {"type": ["string", "null"], "minLength": 1},
                            "permissions_policy": {"type": ["string", "null"], "minLength": 1},
                            "permissions_policy_report_only": {"type": ["string", "null"], "minLength": 1},
                            "cross_origin_opener_policy": {"type": ["string", "null"], "minLength": 1},
                            "cross_origin_opener_policy_report_only": {"type": ["string", "null"], "minLength": 1},
                            "cross_origin_embedder_policy": {"type": ["string", "null"], "minLength": 1},
                            "cross_origin_embedder_policy_report_only": {"type": ["string", "null"], "minLength": 1},
                            "cross_origin_resource_policy": {"type": ["string", "null"], "minLength": 1},
                            "x_content_type_options": {"type": ["string", "null"], "minLength": 1},
                            "origin_agent_cluster": {"type": ["string", "null"], "minLength": 1},
                            "clear_site_data": {"type": ["string", "null"], "minLength": 1},
                            "reporting_endpoints": {"type": ["string", "null"], "minLength": 1},
                            "timing_allow_origin": {"type": ["string", "null"], "minLength": 1},
                            "accept_ch": {"type": ["string", "null"], "minLength": 1},
                            "critical_ch": {"type": ["string", "null"], "minLength": 1}
                        }
                    },
                    "reporting_collector": {
                        "type": ["object", "null"],
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
                    "tls_inspection": {"type": ["object", "null"]},
                    "connection_filter": {"type": "array", "items": {"type": "object"}},
                    "rules": {"type": "array", "items": {"type": "object"}},
                    "http3": {"type": ["object", "null"]},
                    "ftp": {"type": "object"},
                    "xdp": {"type": ["object", "null"]},
                    "cache": {"type": ["object", "null"]},
                    "capture": {"anyOf": [{"$ref": "#/$defs/capturePolicy"}, {"type": "null"}]},
                    "rate_limit": {"type": ["object", "null"]},
                    "policy_context": {"type": ["object", "null"]},
                    "destination_resolution": {"type": ["object", "null"]},
                    "http": {"$ref": "#/$defs/httpPolicy"},
                    "http_guard_profile": {"type": ["string", "null"]},
                    "modules": {"type": "array", "items": {"type": "string"}},
                    "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}},
                    "streaming": {"anyOf": [{"$ref": "#/$defs/streamingConfig"}, {"type": "null"}]},
                    "grpc": {"anyOf": [{"$ref": "#/$defs/grpcConfig"}, {"type": "null"}]},
                    "sse": {"anyOf": [{"$ref": "#/$defs/sseStreamingPolicy"}, {"type": "null"}]}
                }
            }
        },
        "properties": {
            "state_dir": {"type": ["string", "null"]},
            "identity": {"type": "object"},
            "messages": {"type": "object"},
            "runtime": {"$ref": "#/$defs/runtimeConfig"},
            "telemetry": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "system_log": {
                        "type": "object",
                        "properties": {
                            "level": {"type": "string"},
                            "format": {"type": "string"}
                        }
                    },
                    "access_log": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "enabled": {"type": "boolean"},
                            "path": {"type": ["string", "null"]},
                            "format": {"type": "string"},
                            "rotation": {"type": "string"},
                            "rotation_count": {"type": "integer", "minimum": 0},
                            "exclude": {"type": "array", "items": {"type": "string"}},
                            "redact": {"$ref": "#/$defs/captureRedaction"}
                        }
                    },
                    "audit_log": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "enabled": {"type": "boolean"},
                            "path": {"type": ["string", "null"]},
                            "format": {"type": "string"},
                            "rotation": {"type": "string"},
                            "rotation_count": {"type": "integer", "minimum": 0},
                            "include": {
                                "type": "array",
                                "items": {"enum": ["subject", "groups", "device_id", "posture", "tenant", "auth_strength", "idp", "identity_source", "policy_tags", "decision_service_policy_id", "matched_rule", "matched_route"]}
                            }
                        }
                    },
                    "metrics": {
                        "type": ["object", "null"],
                        "required": ["listen"],
                        "properties": {
                            "listen": {"type": "string"},
                            "path": {"type": "string"},
                            "allow": {"type": "array", "items": {"type": "string"}},
                            "max_concurrent_connections": {"type": "integer", "minimum": 0}
                        }
                    },
                    "otel": {
                        "type": ["object", "null"],
                        "additionalProperties": false,
                        "properties": {
                            "enabled": {"type": "boolean"},
                            "endpoint": {"type": ["string", "null"]},
                            "protocol": {"type": "string"},
                            "level": {"type": "string"},
                            "sample_percent": {"type": "integer", "minimum": 0},
                            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                            "service_name": {"type": ["string", "null"]},
                            "redact": {"$ref": "#/$defs/captureRedaction"}
                        }
                    },
                    "exporter": {
                        "type": ["object", "null"],
                        "properties": {
                            "enabled": {"type": "boolean"},
                            "shm_path": {"type": "string"},
                            "shm_size_mb": {"type": "integer", "minimum": 0},
                            "lossy": {"type": "boolean"},
                            "max_queue_events": {"type": "integer", "minimum": 0},
                            "capture": {"$ref": "#/$defs/exporterCapture"}
                        }
                    }
                }
            },
            "security": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "auth": {"type": "object"},
                    "identity_sources": {"type": "array", "items": {"type": "object"}},
                    "decisions": {"type": "object"},
                    "destination": {"type": "object"},
                    "named_sets": {"type": "array", "items": {"type": "object"}},
                    "upstream_trust_profiles": {"type": "array", "items": {"type": "object"}}
                }
            },
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
            "acme": {"anyOf": [{"$ref": "#/$defs/acmeConfig"}, {"type": "null"}]},
            "edges": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {
                            "allOf": [
                                {"$ref": "#/$defs/commonEdgeFields"},
                                {"type": "object", "required": ["kind", "name", "listen", "default_action"], "additionalProperties": false, "properties": {"kind": {"const": "forward"}, "name": {"type": "string"}, "listen": {"type": "string"}, "default_action": {"type": "object"}, "upstream_proxy": {"type": ["string", "null"]}, "tls_inspection": {"type": ["object", "null"]}, "connection_filter": {"type": "array", "items": {"type": "object"}}, "rules": {"type": "array", "items": {"type": "object"}}, "http3": {"type": ["object", "null"]}, "ftp": {"type": "object"}, "xdp": {"type": ["object", "null"]}, "cache": {"type": ["object", "null"]}, "capture": {"anyOf": [{"$ref": "#/$defs/capturePolicy"}, {"type": "null"}]}, "rate_limit": {"type": ["object", "null"]}, "policy_context": {"type": ["object", "null"]}, "destination_resolution": {"type": ["object", "null"]}, "http": {"$ref": "#/$defs/httpPolicy"}, "http_guard_profile": {"type": ["string", "null"]}, "modules": {"type": "array", "items": {"type": "string"}}, "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}, "streaming": {"anyOf": [{"$ref": "#/$defs/streamingConfig"}, {"type": "null"}]}, "grpc": {"anyOf": [{"$ref": "#/$defs/grpcConfig"}, {"type": "null"}]}, "sse": {"anyOf": [{"$ref": "#/$defs/sseStreamingPolicy"}, {"type": "null"}]}, "streaming_requirement": {"anyOf": [{"enum": ["preferred", "required"]}, {"type": "null"}]}}}
                            ]
                        },
                        {"type": "object", "required": ["kind", "name", "listen"], "additionalProperties": false, "properties": {"kind": {"const": "reverse"}, "name": {"type": "string"}, "listen": {"type": "string"}, "tls": {"type": ["object", "null"]}, "http3": {"type": ["object", "null"]}, "xdp": {"type": ["object", "null"]}, "enforce_sni_host_match": {"type": "boolean"}, "sni_host_exceptions": {"type": "array", "items": {"type": "string"}}, "policy_context": {"type": ["object", "null"]}, "destination_resolution": {"type": ["object", "null"]}, "connection_filter": {"type": "array", "items": {"type": "object"}}, "streaming": {"anyOf": [{"$ref": "#/$defs/streamingConfig"}, {"type": "null"}]}, "grpc": {"anyOf": [{"$ref": "#/$defs/grpcConfig"}, {"type": "null"}]}, "sse": {"anyOf": [{"$ref": "#/$defs/sseStreamingPolicy"}, {"type": "null"}]}, "routes": {"type": "array", "items": {"type": "object", "required": ["match", "target"], "additionalProperties": false, "properties": {"name": {"type": "string"}, "match": {"type": "object"}, "target": {"$ref": "#/$defs/routeTarget"}, "mirrors": {"type": "array", "items": {"type": "object"}}, "headers": {"type": "object"}, "timeout_ms": {"type": "integer", "minimum": 1}, "health_check": {"type": "object"}, "resilience": {"type": "object"}, "cache": {"type": "object"}, "capture": {"$ref": "#/$defs/capturePolicy"}, "rate_limit": {"type": "object"}, "path_rewrite": {"type": "object"}, "upstream_trust_profile": {"type": "string"}, "upstream_trust": {"type": "object"}, "lifecycle": {"type": "object"}, "affinity": {"type": "object"}, "policy_context": {"type": "object"}, "destination_resolution": {"type": "object"}, "http": {"$ref": "#/$defs/httpPolicy"}, "http_guard_profile": {"type": "string"}, "modules": {"type": "array", "items": {"type": "string"}}, "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}, "streaming": {"$ref": "#/$defs/streamingConfig"}, "grpc": {"$ref": "#/$defs/grpcConfig"}, "sse": {"$ref": "#/$defs/sseStreamingPolicy"}, "streaming_requirement": {"enum": ["preferred", "required"]}}}}, "tls_passthrough_routes": {"type": "array", "items": {"type": "object"}}}},
                        {
                            "allOf": [
                                {"$ref": "#/$defs/commonEdgeFields"},
                                {"type": "object", "required": ["kind", "name", "listen", "default_action"], "additionalProperties": false, "properties": {"kind": {"const": "transparent"}, "name": {"type": "string"}, "listen": {"type": "string"}, "default_action": {"type": "object"}, "original_dst": {"anyOf": [{"$ref": "#/$defs/originalDst"}, {"type": "null"}]}, "tls_inspection": {"type": ["object", "null"]}, "connection_filter": {"type": "array", "items": {"type": "object"}}, "rules": {"type": "array", "items": {"type": "object"}}, "http3": {"type": ["object", "null"]}, "ftp": {"type": "object"}, "xdp": {"type": ["object", "null"]}, "cache": {"type": ["object", "null"]}, "capture": {"anyOf": [{"$ref": "#/$defs/capturePolicy"}, {"type": "null"}]}, "rate_limit": {"type": ["object", "null"]}, "policy_context": {"type": ["object", "null"]}, "destination_resolution": {"type": ["object", "null"]}, "http": {"$ref": "#/$defs/httpPolicy"}, "http_guard_profile": {"type": ["string", "null"]}, "modules": {"type": "array", "items": {"type": "string"}}, "http_modules": {"type": "array", "items": {"$ref": "#/$defs/httpModule"}}, "streaming": {"anyOf": [{"$ref": "#/$defs/streamingConfig"}, {"type": "null"}]}, "grpc": {"anyOf": [{"$ref": "#/$defs/grpcConfig"}, {"type": "null"}]}, "sse": {"anyOf": [{"$ref": "#/$defs/sseStreamingPolicy"}, {"type": "null"}]}, "streaming_requirement": {"anyOf": [{"enum": ["preferred", "required"]}, {"type": "null"}]}}}
                            ]
                        }
                    ]
                }
            }
        }
    });

    let route_properties =
        schema["properties"]["edges"]["items"]["oneOf"][1]["properties"]["routes"]["items"]["properties"]
            .as_object_mut()
            .expect("reverse route schema properties");
    for field in [
        "name",
        "headers",
        "timeout_ms",
        "health_check",
        "resilience",
        "cache",
        "capture",
        "rate_limit",
        "path_rewrite",
        "upstream_trust_profile",
        "upstream_trust",
        "lifecycle",
        "affinity",
        "policy_context",
        "destination_resolution",
        "http_guard_profile",
        "streaming",
        "grpc",
        "sse",
        "streaming_requirement",
    ] {
        let field_schema = route_properties
            .get_mut(field)
            .expect("declared optional reverse route field");
        let non_null_schema = std::mem::replace(field_schema, serde_json::Value::Null);
        *field_schema = json!({
            "anyOf": [non_null_schema, {"type": "null"}]
        });
    }

    schema
}
