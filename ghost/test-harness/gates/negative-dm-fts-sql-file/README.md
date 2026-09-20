# Negative fixture for the dm-no-fts gate: a plain `.sql` file

Used by `scripts/gates/self-test.sh` with `GHOST_ROOT` pointing here. Every statement GHOST
writes today lives inside a Kotlin migration, so the `*.sql` half of G-DM6's corpus would be
scanned but never exercised. `relay/schema/search.sql` exercises it: the same forbidden statement,
outside `android/`, outside any Kotlin source, reported with its path and line. Exactly one line
is the violation. Nothing here is compiled or shipped.
