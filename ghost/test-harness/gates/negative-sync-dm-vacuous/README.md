# Negative fixture: sync-no-catch-all with the DM modules moved away

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 9 design §22.33). The sync
source is clean, `android/messaging/src/main` exists with no source and `android/crypto-bridge` is
missing, so the gate must fail for exactly those two reasons rather than pass over modules it no
longer reads. Nothing here is compiled or shipped.
