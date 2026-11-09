# Fixture roots for `release-records.sh` (G-D4)

Each root mirrors ghost/'s protocol/release layout plus a stub checker (`checker.sh`,
registered through the GHOST_D4_CHECKER hook - no records-check binary ships in the tree).
Run by `scripts/gates/self-test.sh`.

| Root | Expected |
|---|---|
| `clean` | passes: a stagenet chain under stagenet/, the stub checker green, allowed_signers present |
| `drill-root` | fails: a network-3 (drill) chain in a release build |
| `wrong-network` | fails: a mainnet-byte chain under protocol/release/stagenet |
| `checker-refused` | fails: the records checker exits non-zero |
| `missing-signers` | fails: root records without the allowed-signers file |
