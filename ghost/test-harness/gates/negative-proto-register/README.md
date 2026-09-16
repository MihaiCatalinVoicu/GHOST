# Negative fixture for proto-check.sh: the key registration schema

`protocol/relay/v1/relay.proto` compiles with protoc and every request message in it is versioned,
so the per-request rule passes it. Its key registration schema is not the Phase 9 design's (§4.2):
`scripts/gates/self-test.sh` runs `proto-check.sh` with `GHOST_ROOT` pointed here and requires
exactly three violations, each by name: `enum KeyKind` (a value 2, the Write byte of capability
headers, and no `KEY_KIND_FETCH`), `enum RegisterResult` (a replacing result, which the
accumulation rule forbids) and the missing `message RegisterKeyRequest`.

Nothing here is compiled or shipped.
