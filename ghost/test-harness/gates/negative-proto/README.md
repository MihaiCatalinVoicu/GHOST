# Negative fixture for proto-check.sh

`protocol/bad/v1/bad.proto` compiles with protoc and carries `uint32 version = 1;` directly in three
request messages only (one written on a single line, one with its `{` on the next line).
`scripts/gates/self-test.sh` runs `proto-check.sh` with `GHOST_ROOT` pointed here and requires
exactly the five other request messages to be reported: no version, a wrong field number, no
version in a message with a nested message, a version declared only by a nested message, and a
header whose `{` is on the next line (Phase 8 design §5.2, §14.1). Nothing here is compiled or
shipped.
