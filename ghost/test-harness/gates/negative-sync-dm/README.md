# Negative fixture: sync-no-catch-all over the DM modules

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 9 design §16.1, §22.33).
The sync and entitlement sources are clean. `SwallowingStep.kt` holds two catch-alls, `DmNative.kt`
holds two `UnsatisfiedLinkError` catches where the fixture's own allowlist permits one (both are
reported), the `gate` source set holds one `Throwable` catch, and the allowlist has a stale entry, an
entry outside the DM modules and a malformed entry: 8 violations in all. Nothing here is compiled or
shipped.
