# Metrics Cardinality

Default metrics labels are intentionally low-cardinality:

- `listener`
- `route`
- `protocol`
- `direction`
- `reason`
- `status`

Avoid metric labels for full path, authority, user id, peer IP, arbitrary header values, gRPC method, or Connect procedure. Use access logs, audit logs, or tracing attributes for high-cardinality forensic detail.
