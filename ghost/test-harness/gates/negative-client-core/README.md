# Negative fixture scoped to client-core/

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here, so a gate that stopped scanning `client-core/` would be caught even though other fixtures still fail.
