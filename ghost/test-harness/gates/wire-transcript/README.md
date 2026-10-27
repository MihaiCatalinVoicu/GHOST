# Fixture roots for `wire-transcript.sh`

Each directory is a `GHOST_ROOT` for `scripts/gates/wire-transcript.sh`, run by
`scripts/gates/self-test.sh`. The committed transcripts are minimal stand-ins for the real
artifact: the gate's fixture-only hook `GHOST_WIRE_TRANSCRIPT_REGEN` supplies the "regenerated"
side, so the fixtures' machines need no cargo and the generator never runs in the self-test.

| Root | Expected |
|---|---|
| `regenerated-equal` | passes: the committed transcript is byte-equal to the regenerated file |
| `mismatch` | fails: the committed transcript differs from the regenerated file |
| the repository itself | fails: the `GHOST_WIRE_TRANSCRIPT_REGEN` hook is refused on the real root |
