# Negative fixture: sync-no-catch-all without an entitlement module

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here. The sync source is clean and
`android/entitlement/src/main` is missing, so the gate must fail for exactly one reason: a moved or
renamed entitlement module would otherwise leave its sources unscanned (Phase 8 design §11.1). Nothing
here is compiled or shipped.
