# Negative fixture for the sync-no-catch-all gate

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here. Each line marked in
`CatchAll.kt` and `CatchAllJava.java` is a way the sync engine could swallow an injected process
death (a JVM `Error`); the gate must report every one of them. Nothing here is compiled or shipped.
