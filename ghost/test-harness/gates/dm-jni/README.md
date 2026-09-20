# Negative fixtures for G-R6 (`scripts/gates/dm-jni-surface.sh`)

The closed JNI surface of Phase 9 design §2.6 has four ways to drift, one file each. Every fixture
is a **source excerpt**, not a compilable crate: the gate reads the closed-list constant, the macro
arms and the Kotlin `external fun` declarations as text, so an excerpt is exactly what it needs and
what keeps the fixture readable.

| File | Drift it reproduces |
|---|---|
| `undeclared-export.rs` | the crate exports a function that is not on the closed list |
| `missing-export.rs` | an entry is marked `Exported` but no entry point is emitted for it |
| `unmarked-export.rs` | an entry point is emitted for an entry still marked `Declared` |
| `DmNativeExtra.kt` | Kotlin declares an `external fun` the crate does not export |
| `DmNativeMissing.kt` | Kotlin does not declare a function the crate exports |
