# Capture Pipeline

The capture pipeline is split across three binaries:

| Binary | Role |
|---|---|
| `qpxd` | Writes decrypted/encrypted capture events into a shared-memory ring. |
| `qpxr` | Reads the ring, writes PCAPNG files, and serves live/history streams. |
| `qpxc` | Connects to `qpxr` and relays PCAPNG to stdout, Wireshark, or extcap. |

Recommended topology: run `qpxd` and `qpxr` on the same host; connect remote
analysis machines through `qpxc` only.

## Local Debug Flow

```bash
# 1. Start the reader.
export QPX_EXPORTER_TOKEN='local-dev-token'
cargo run -p qpxr -- \
  --stream-listen 127.0.0.1:19101 \
  --token-env QPX_EXPORTER_TOKEN \
  --save-dir /tmp/qpx-pcapng

# 2. Start qpxd with exporter-enabled config.
cargo run -p qpxd -- run --config config/usecases/07-observability-debug/observability-high-detail.yaml

# 3. Stream PCAPNG via the client.
cargo run -p qpxc -- \
  --endpoint 127.0.0.1:19101 --mode live \
  --token-env QPX_EXPORTER_TOKEN \
  > /tmp/qpx-live.pcapng
```

`qpxd` and `qpxr` must agree on `shm_path` and `shm_size_mb`. If both are
omitted, both sides use the same platform-private default path.

## Security Profiles

- **Local debug**: loopback bind with `--token-env`.
- **Low-security lab**: loopback bind without auth only with
  `--unsafe-allow-insecure`.
- **Production**: TLS + token, optionally mTLS and CIDR allowlist.

`qpxr` refuses unauthenticated loopback listeners and refuses non-loopback
listeners without TLS unless `--unsafe-allow-insecure` is explicitly passed.

```bash
export QPX_EXPORTER_TOKEN='...'

cargo run -p qpxr -- \
  --stream-listen 0.0.0.0:19101 \
  --tls-cert /etc/qpxr/tls/server.crt --tls-key /etc/qpxr/tls/server.key \
  --token-env QPX_EXPORTER_TOKEN \
  --stream-allow 10.0.0.0/8

cargo run -p qpxc -- \
  --endpoint qpxr.example.internal:19101 --mode follow \
  --tls --tls-server-name qpxr.example.internal \
  --token-env QPX_EXPORTER_TOKEN \
  > /tmp/qpx-live.pcapng
```

For `tls-native` builds, use `qpxr --tls-pkcs12` and
`qpxc --tls-client-pkcs12` instead of PEM certificate/key options.

## qpxd Exporter Config

```yaml
telemetry:
  exporter:
    enabled: true
    shm_path: ""
    shm_size_mb: 16
    lossy: false
    max_queue_events: 4096
    capture:
      plaintext: true
      encrypted: true
      max_chunk_bytes: 16384
      redact:
        headers: [authorization, cookie, set-cookie, proxy-authorization]
        query_keys: [token, password, session, access_token]
        json_paths: ["$.password", "$.access_token"]
```

For targeted plaintext debugging, attach `capture` to an edge or reverse route.
Plaintext body capture is explicit and requires `max_body_bytes`:

```yaml
capture:
  plaintext:
    enabled: true
    headers: true
    body: full
    sample_percent: 10
    max_body_bytes: 16384
    redact:
      headers: [authorization, cookie, set-cookie]
      query_keys: [token, password, session]
      json_paths: ["$.password", "$.access_token"]
```

