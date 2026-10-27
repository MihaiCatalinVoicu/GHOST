# Fixture roots for `wire-transcript.sh`

Each directory is a `GHOST_ROOT` for `scripts/gates/wire-transcript.sh`, run by
`scripts/gates/self-test.sh`. The committed transcripts are minimal stand-ins for the real
artifact: the gate's fixture-only hooks supply the "regenerated" sides, so the fixtures'
machines need no cargo, no git worktree build, and the generator never runs in the self-test.

| Root | Expected |
|---|---|
| `regenerated-equal` | passes: the committed transcript is byte-equal to the regenerated file; NI-U5's comparison against a byte-identical reference passes too |
| `mismatch` | fails: the committed transcript differs from the regenerated file |
| the repository itself | fails: the `GHOST_WIRE_TRANSCRIPT_REGEN` / `GHOST_WIRE_TRANSCRIPT_COMPARE` hooks are refused on the real root |

NI-U5's negative (the task asked for it explicitly) needs no third root: the compare-accept
case reuses `regenerated-equal` with the reference file equal to it, and the compare-refuse
case reuses `regenerated-equal`'s committed transcript against `mismatch`'s regenerated file
(one line different).
