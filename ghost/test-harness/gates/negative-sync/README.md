# Negative fixture for the sync-no-catch-all gate

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here. Each line marked in
`CatchAll.kt` and `CatchAllJava.java` is a way the sync engine could swallow an injected process
death (a JVM `Error`); the gate must report every one of them. `CatchAllParticipant.kt`, under
`android/entitlement/src/main`, holds the same forms in the session participant's module (Phase 8
design §11.1): 3 more lines, 12 in all. Nothing here is compiled or shipped.
