# Fixture fragments for `update-report-check.sh`

Each directory's `build/update-mutants/report.txt` is a `report` argument for
`scripts/gates/update-report-check.sh`, run by `scripts/gates/self-test.sh` (the gate takes the
fragment's path, so these fixtures need no `GHOST_ROOT` layout beyond the file itself).

| Fragment | Expected |
|---|---|
| `consistent` | passes as `pr`: the copy of a real default-suite fragment (the 30-row killable registry, both headline sides equal, the twins equal, the named worlds, the PR-scale throughput line) |
| `inflated` | fails: the headline claims `30 run, 31 detected` — more detected than measured |
| `consistent` as `gate` | fails: a PR-scale fragment (1 world, no drill lines) cannot pass as the gate job's report |

The gate's registry and counts are pinned in the script, so the fixtures stay stand-ins: the
negative is synthesized by editing the headline, the gate-kind negative reuses the consistent
fragment under the `gate` kind.
