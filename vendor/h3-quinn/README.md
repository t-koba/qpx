# h3-quinn local patch

This is crates.io `h3-quinn` 0.0.10 with the fix from upstream commit
[`704b37a2e82cf4c8de379ec779dbc2a23bfcb9a1`](https://github.com/hyperium/h3/commit/704b37a2e82cf4c8de379ec779dbc2a23bfcb9a1)
extended so the requested QUIC stop code is applied when an in-flight receive
future is dropped. The upstream adapter unwraps an empty stream slot in
`stop_sending`; deferring the code alone loses it on cancellation, so this
local patch applies it from the read future's drop guard. Replace this copy
with a published fixed release when available.
