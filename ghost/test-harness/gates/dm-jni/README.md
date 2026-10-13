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
| `nm/exact-nm` | a built library whose DM symbols are exactly the closed list (the positive case); since slice S2 (G-M5) it prints the media surface `MEDIA_CLOSED_LIST` too, from the constant itself |
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

## Slice S12 additions

- `nm/entry-nm` prints the closed list plus `Java_org_ghost_crypto_bridge_DmEquivalence_run`, the
  one symbol a library built with the `test-vectors` feature adds (§15.9 item 7, §22.8.10 point 6):
  the gate accepts it for a library passed with `--test` and refuses it for a shipped one, and
  refuses `exact-nm` with `--test` (a test library without its entry point).
- `android-ref/` is an Android tree whose `:messaging` production source imports and calls
  `DmNative` directly; the source-set half (only `:crypto-bridge` `src/{main,gate}` may) reports
  the import and the call, not the comment.

## Slice S2 additions (G-M5, Phase 11 design §13.2)

- `nm/exact-nm` prints the media surface `MEDIA_CLOSED_LIST` of `jni_media.rs` beside the DM list
  (both read from the constants), and `nm/entry-nm` adds the two host-only media test entries
  (`MediaNative_testVectors`, `MediaNative_testSealBeginWithKey`) beside `DmEquivalence`'s four:
  a shipped library carries both closed surfaces and no test symbol, a `--test` library carries
  both plus exactly those six.

## Phase 9 review additions (GATES-3)

Every half of the gate used to name one class, `DmNative`, so a DM entry point exported under any
other class passed all of them. Now only `DmNative` (the closed list), `DmEquivalence.run` and the
network surface's three classes may carry a JNI entry point or a native declaration.

- `foreign/foreign-export.rs`: a `#[unsafe(no_mangle)]` entry point
  `Java_org_ghost_crypto_bridge_DmDebug_exportSessionState` — the source half refuses it.
- `nm/foreign-nm` and `nm/foreign-package-nm`: the closed list plus a symbol of another class
  (`DmDebug`) and of another package (`org.ghost.messaging`) — the symbol half refuses each.
  `nm/exact-nm` now prints a network-surface symbol beside the list, which the gate accepts.
- `android-native/`: a Kotlin `external fun` in a second `:crypto-bridge` class and a Java
  `native` method in `:messaging` — exactly two lines, the comment that says "native" not one.

## Review of S2b additions

- `DmNativeOneLine.kt`: a public declaration on the same line as its `@JvmName`, which the
  visibility check skipped (its `@JvmName` match ended the line's reading).
- The source half reads code through `common.sh`'s `jni_source_symbols`, shared with G-M6: the
  spellings it once missed (`pub unsafe extern`, no `pub`, `extern "C"`, a line break after `fn`, an
  `export_name` written by a macro, a module directory named `target` or `build` under `src/`) are
  G-M6's fixture `../mls-jni/evasions/`, which `self-test.sh` runs through both gates.
