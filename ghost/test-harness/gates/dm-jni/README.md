# Negative fixtures for G-R6 (`scripts/gates/dm-jni-surface.sh`)

The closed JNI surface of Phase 9 design §2.6 has one file per way to drift. Every fixture is a
**source excerpt**, not a compilable crate: the gate reads the closed-list constant, the macro
arms and the Kotlin `external fun` declarations as text, so an excerpt is exactly what it needs and
what keeps the fixture readable.

| File | Drift it reproduces |
|---|---|
| `undeclared-export.rs` | the crate exports a function that is not on the closed list |
| `missing-export.rs` | an entry is marked `Exported` but no entry point is emitted for it |
| `unmarked-export.rs` | an entry point is emitted for an entry still marked `Declared` |
| `stray/stray-export.rs` | an entry point written outside the file the closed list lives in |
| `DmNativeExtra.kt` | Kotlin declares an `external fun` the crate does not export |
| `DmNativeMissing.kt` | Kotlin does not declare a function the crate exports |
| `DmNativePublic.kt` | a native declaration is public, so `:messaging` could bypass the facade |
| `DmNativeMangled.kt` | an `internal` declaration without `@JvmName`, which Kotlin mangles |
| `nm/exact-nm` | a built library whose DM symbols are exactly the closed list (the positive case) |
| `nm/stray-nm` | a built library exporting a DM symbol that is not on the list |
| `nm/missing-nm` | a built library that does not export an entry marked `Exported` |
| `nm/unreadable-nm` | a symbol reader that cannot read the library and exits non-zero |

The four `nm/` files are **symbol readers**, named with `GHOST_DM_JNI_NM`, and they are the symbol
half's fixtures: the gate's other half needs a built `.so`, and a repository of source excerpts is
not the place for committed binaries. They print `nm -D --defined-only` lines, taking the names
from the closed list itself, so promoting a function to `Exported` needs no fixture change — what
they drill is the gate's symbol **diff** and its reader-failure path (review round 2, R2-05), on a
file that only has to begin with the ELF magic.

`stray/` is a directory of its own because the scan half takes a **root**: the gate is pointed at
it with `GHOST_DM_JNI_SCAN`, which is also how the CI jobs point the symbol half at a built
library.
