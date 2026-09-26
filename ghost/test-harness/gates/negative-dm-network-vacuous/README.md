# Negative fixture for the messaging-no-network gate (G-DM1): a module moved away

Used by `scripts/gates/self-test.sh` (Phase 9 design §22.33). `:messaging` is clean and
`android/crypto-bridge` is missing, so the gate must fail for that reason alone rather than pass over a
module it no longer reads: 1 violation. Nothing here is compiled or shipped.
