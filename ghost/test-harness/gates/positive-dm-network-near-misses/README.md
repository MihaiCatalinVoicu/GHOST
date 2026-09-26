# Positive fixture for G-DM1 (messaging-no-network.sh): near misses that must pass

Used by `scripts/gates/self-test.sh` (Phase 9 design §22.33 item 16). The whole-file reading must
not turn prose or identifiers into violations: the word suspend in a KDoc and in a string, the
identifiers `suspended` and `isSuspendable`, a qualified name of an allowed package written across
lines, and `kotlin.collections`.
