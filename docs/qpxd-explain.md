# qpxd explain

`qpxd explain` renders the compiled runtime plan.

```bash
qpxd explain -c config/qpx.example.yaml --edge site --route app
qpxd explain -c config/qpx.example.yaml --format json
```

The JSON output is deterministic and includes:

- edge and route identity
- target type
- effective streaming limits
- module body mode
- buffering requirement and reasons
- cache, capture, response-rule, and local-response summaries

Use this in CI to reject unexpected buffering before a config is deployed.
