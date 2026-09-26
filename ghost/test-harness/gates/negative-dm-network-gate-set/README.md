# Negative fixture for the messaging-no-network gate (G-DM1): the gate source set

Used by `scripts/gates/self-test.sh` (Phase 9 design §22.33). Both modules' `src/main` are clean; the
`gate` build type's source set of `:crypto-bridge`, installed on the gate devices, imports a
connectivity class: 1 violation. Nothing here is compiled or shipped.
