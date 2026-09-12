# Negative fixture for proto-check.sh

`protocol/bad/v1/bad.proto` compiles with protoc and carries `uint32 version = 1;` in one request
message only. `scripts/gates/self-test.sh` runs `proto-check.sh` with `GHOST_ROOT` pointed here and
requires exactly the three unversioned request messages to be reported (Phase 8 design §5.2,
§14.1). Nothing here is compiled or shipped.
