# no-declaration (gate G-L5 fixture)

This fixture root deliberately carries no `repository-visibility.txt`: `no-public-binaries.sh` must
fail with `scripts/gates/repository-visibility.txt missing`. Git keeps no empty directory, and the
gate resolves `GHOST_ROOT` before it looks for the declaration, so this file keeps the directory
in the tree; it plays no other part in the case.
