# anti-placeholder.sh over `*/src/gate/*`

Phase 9 design §21.13 point 7 (slice S12): `anti-placeholder.sh` scans the `gate` build type's
source sets as well as the production path. This tree holds one gate source and no production
source, so the gate can only fail here if it reads `src/gate`. Nothing here is compiled.
