# Negative fixture for the messaging-no-network gate (G-DM1): a wildcard import

Used by `scripts/gates/self-test.sh` (Phase 9 design §22.33). After `import java.net.*` the class that uses
it is left as a bare name on its own line; the gate reports the import and the bare `Socket`: 2
violations. `:crypto-bridge` is clean. Nothing here is compiled or shipped.
