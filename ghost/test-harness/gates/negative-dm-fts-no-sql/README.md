# Negative fixture for the dm-no-fts gate: nothing to scan

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here. The tree has an Android
production source and no SQL at all, so the gate finds files but no `CREATE TABLE`. A gate that
passed here would also pass on the day the schema moved out of `android/*/src/main`, which is the
one way G-DM6 could go quiet without anyone noticing; it must report the vacuity instead.
Nothing here is compiled or shipped.
