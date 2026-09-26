# Negative fixture for the messaging-no-network gate (G-DM1): network imports

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here (Phase 9 design §16.1 G-DM1, §22.33).
`NetworkedStep.kt` imports five network packages in `:messaging` (two of the lines also name a socket
class, so they count twice: 7 violations) beside a line of decoys the word boundaries must not match;
`Fetcher.kt` imports an HTTP client in `:crypto-bridge` (the package and the class: 2). A test source
that imports a server socket must not be read. 9 violations in all. Nothing here is compiled or shipped.
