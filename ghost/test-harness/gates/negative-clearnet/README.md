# Negative fixture for the kotlin-clearnet gate

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here. Each line marked in
`Clearnet.kt` and `Clearnet.java` is a way Android code could open a clearnet connection outside
the Tor core; the gate must report every one of them (12 lines). Nothing here is compiled or
shipped.
