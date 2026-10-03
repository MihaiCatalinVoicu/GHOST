# Fixtures of gate G-M6 (`scripts/gates/mls-jni-surface.sh`)

Phase 10 design `docs/design/faza10-forum.md` §10.2, §13.1; slice S2b. Each fixture breaks the closed
channel JNI surface in one way, and `scripts/gates/self-test.sh` checks the gate reports that way.

- `*.rs`: small closed lists (`ctxOpen`, `ctxClose` exported, `revealSeal` reserved for S9) with
  the entry points a crate would write: `good.rs` (passes with `MlsNativeSmall.kt`),
  `undeclared-export.rs` (a name not on the list), `early-reveal.rs` (the reserved function written
  early), `missing-export.rs` (an exported entry with no entry point).
- `MlsNative*.kt`: the Kotlin declarations — extra, reserved, public, mangled (no `@JvmName`),
  missing — against the real crate (`MlsNativeSmall.kt` against the small lists).
- `stray/`, `foreign/`: a scan root with an `MlsNative` entry point outside the list's file, and a
  JNI entry point of a class outside `common.sh`'s `GHOST_JNI_CLASSES`.
- `android-native/`: native methods outside the allowed files (Kotlin and Java); `android-ref/`:
  code that references `MlsNative` outside `:crypto-bridge`'s `src/main` (and prose that may).
- `nm/`: symbol readers that stand in for built libraries (the closed list read from the real
  `jni.rs`): `exact-nm` (a shipped library), `entry-nm` (the host library), `both-nm` (both surfaces:
  the DM and channel gates must both accept it), `stray-nm`, `missing-nm`, `reveal-nm` (function 16
  exported early), `entry-extra-nm`, `foreign-nm`, `unreadable-nm`.
