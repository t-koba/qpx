# Metrics Cardinality

Default metrics labels are intentionally low-cardinality:

- `listener`
- `route`
- `protocol`
- `direction`
- `reason`
- `status`
- `backend`
- `stage`

Avoid metric labels for:

- full path
- authority
- peer IP
- user id
- gRPC service
- gRPC method
- Connect procedure
- arbitrary header value

Use access logs, audit logs, or tracing attributes for high-cardinality
forensic detail. If `grpc_service`, `grpc_method`, or `connect_procedure`
metrics are added, they must be opt-in telemetry detail and disabled by
default.
