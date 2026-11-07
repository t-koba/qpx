# Cache representation publication

Each response writeback allocates a unique generation below its Vary variant
key. The metadata and body keys belong to that generation, not to the selector.
The existing variant index is published only after `put_response` succeeds;
this also applies to Vary-less responses. Replacing a selector removes its old
generation from the index, without reusing its storage keys.

This is address-based isolation, not a read/compare/write approximation to CAS:

- HTTP supports unconditional object PUT/DELETE; no conditional-write extension
  is required from its server.
- Redis stages and renames the body, then writes metadata. Neither object is
  discoverable through the new index until both writes finish.
- Disk renames a co-located body/envelope file before publishing the index.

A foreground 304 retains the generation returned by lookup. Delivery still
streams, with the original trailer, error and producer-completion handling.
Refresh writes only that generation's metadata; invalidation deletes only that
generation's metadata/body, never the primary index or other variants. Multiple
finalizers for an old generation consequently cannot mutate a replacement.
The metadata envelope format and Vary selector encoding are unchanged. Historical
canonical entries remain readable through ordinary lookup; the disk hot candidate
requires a single indexed representation rather than probing a superseded canonical
entry.

Superseded generations remain available to already-open remote body producers
until their writer-assigned retention TTL expires (disk also retains its normal
capacity eviction). This trades temporary retained objects and an index operation
for Vary-less writebacks for safe publication without backend-specific CAS.
Index updates retain their existing last-publisher behavior, and metadata updates
within the same body generation retain completion-order behavior; this mechanism
isolates representation replacement, not distributed transactions or origin-event
ordering. A metadata refresh does not extend the stored body's lifetime. Disk's hot LRU
also verifies the logical key: co-located metadata and body must not alias just
because their physical path (or byte length) is the same.
