# Fixture roots for `entitlement-schedule.sh`

Each directory is a `GHOST_ROOT` for `scripts/gates/entitlement-schedule.sh`, run by
`scripts/gates/self-test.sh`. The schedules are edits of the committed test schedule
(`issuer/crates/entitlement/tests/fixtures/test_schedule.ghes`, regtest, signed with the test key
derived from `SHA-256("ghost/test/schedule-key")`, never pinned) and are verified here through the
gate's fixture-only hook `GHOST_ES_TEST_KEY`; the predecessor of the rule-5 cases is that test
schedule (`GHOST_ES_PREDECESSOR`), and the relay directory check runs in week 2960
(`GHOST_ES_NOW=1790557200`).

| Root | Expected |
|---|---|
| `absent` | passes: no schedule, never committed; fails with `GHOST_ES_PREDECESSOR` set (removed after a commit) |
| `positive` | passes: seq 2, a new slot from week 2983 (after coverage), directory with two operators; fails without the test key (the pinned-key path refuses every test schedule) |
| `tampered` | fails: one byte of the positive schedule flipped (signature) |
| `slot-set-changed` | fails: seq 2, a new slot from week 2970 (rule 5, slot set of a covered week) |
| `duplicated-key` | fails: one SPKI under two entries (rule 2) |
| `directory-missing-onion` | fails: slot 2's relay of week 2960 is not in the directory |
| `directory-single-operator` | fails: every relay under one operator |
| `directory-absent` | fails: a schedule without `relay-directory.txt` |
| `second-copy` | fails: a schedule copy under `infra/relay` |
| `infra-other-path` | fails: infrastructure copying the schedule from another repository path |
| `fixture-in-src` | fails: production source embedding a test fixture |
| `sealed-key-committed` | fails: a sealed key file outside `tests/fixtures` |

The binary files and directory lists are generated and checked byte for byte by
`issuer/crates/ops/tests/fixtures_check.rs` (`write_gate_fixtures` regenerates them). Nothing here
is compiled or shipped.
