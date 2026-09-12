# Negative fixture for proto-check.sh

Both schemas compile with protoc, and each has at least one request message that carries
`uint32 version = 1;` directly, so a per-file check would pass them (Phase 8 design §5.2, §14.1,
RC G18). `scripts/gates/self-test.sh` runs `proto-check.sh` with `GHOST_ROOT` pointed here and
requires exactly the eight unversioned request messages to be reported, by name, and none of the
versioned ones:

- `protocol/bad/v1/bad.proto`: `GoodRequest`, `InlineGoodRequest` (one line) and
  `GoodNextLineRequest` (its `{` on the next line) are versioned. Reported: no version, a wrong
  field number, no version in a message with a nested message, a version declared only by a nested
  message, and a header whose `{` is on the next line.
- `protocol/relay/v1/relay.proto`: `StoreBlobRequest` is versioned. Reported: `RedeemTokenRequest`
  (no version), `GetBlobRequest` (version only in a nested message) and `ListNamespaceRequest`
  (version only in a comment).

Nothing here is compiled or shipped.
