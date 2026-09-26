# Negative fixture for the dm-no-replace gate (G-DM4): nothing to read

Used by `scripts/gates/self-test.sh` (Phase 9 design §22.33). The DM store holds no SQL string and the
schema lost its migration 5 markers, so the gate must fail for both reasons rather than read nothing:
2 violations. Nothing here is compiled or shipped.
