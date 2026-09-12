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
| `resigned-slot-set-changed` | passes against `slot-set-changed` alone: seq 3, that schedule re-signed; the head of the history case below |
| `second-copy` | fails: a schedule copy under `infra/relay` |
| `infra-other-path` | fails: infrastructure copying the schedule from another repository path |
| `infra-fixtures-copy` | fails: a copy under `infra/relay/tests/fixtures`, and a Dockerfile copying it |
| `infra-build-copy` | fails: a copy under `infra/relay/build`, and a compose volume mounting it |
| `infra-variable-path` | fails: a Dockerfile naming the schedule through `${SRC}` |
| `infra-stage-path` | fails: an absolute build-stage path naming a schedule under `test-harness/gates` |
| `infra-one-path` | passes: infrastructure naming the one schedule by context, repository, file-relative and in-container paths |
| `fixture-in-src` | fails: production source embedding a test fixture |
| `sealed-key-committed` | fails: a sealed key file outside `tests/fixtures` |
| `sealed-key-hidden` | fails: sealed key files under `infra/issuer/build` and `infra/issuer/tests/fixtures` |
| `onion-key-committed` | fails twice: `infra/relay/tor-keys/hs_ed25519_secret_key` (by its name; its text is no key) and `infra/relay/slot-1.key` (by C Tor's secret key header, followed by 64 filler bytes, not a key) |

Rule 5 over the git history is exercised in throwaway repositories built by `self-test.sh`
(`GHOST_ES_GIT=1`): the versions test schedule, `slot-set-changed`, `resigned-slot-set-changed`
committed in turn fail on the middle version; the test schedule followed by `positive` passes; a
schedule committed and then removed fails.

The `build/` directories, the `*.ghks` files and `hs_ed25519_secret_key` are ignored by
`.gitignore` and committed with `git add -f`. The binary
files and directory lists are generated and checked byte for byte by
`issuer/crates/ops/tests/fixtures_check.rs` (`write_gate_fixtures` regenerates them). Nothing here
is compiled or shipped.
