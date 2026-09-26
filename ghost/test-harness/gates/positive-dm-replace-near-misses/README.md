# Positive fixture for G-DM4 (dm-no-replace.sh): near misses that must pass

Used by `scripts/gates/self-test.sh` (Phase 9 design §22.33 item 16). The `replace()` SQL function,
`INSERT OR IGNORE`, `DO NOTHING`, a boolean `OR` followed by a literal joined with `+`, a trigger
named `*_no_replace` whose message says "replaced", `String.replace`, and prose that names the
refused APIs: nothing here replaces a row.
