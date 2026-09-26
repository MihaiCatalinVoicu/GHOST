# Negative fixture for the dm-no-replace gate (G-DM4): REPLACE in a DM store

Used by `scripts/gates/self-test.sh` (Phase 9 design §16.1 G-DM4, §22.33). `ReplacingStore.kt` holds
the four refused forms on lines 19–21, 23 (an upsert split over two literals) and 26 (a clause chosen
by a template): 5 violations. Its comments, KDoc, a string holding `//`, a quote character, the
`replace()` function, `INSERT OR IGNORE` and `DO NOTHING` must not count. Nothing here is compiled or
shipped.
