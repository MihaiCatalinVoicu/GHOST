package org.ghost.network

// Fixture for G-D5 (`scripts/gates/dm-jni-surface.sh`), negative case: one `external fun`
// UpdateNative does not export, so the gate's "declares X, which the crate does not export"
// half is drilled. The real declarations live in UpdateNative.kt.
object UpdateNative {
    @JvmStatic private external fun nativeEmbeddedChain(): ByteArray
    @JvmStatic private external fun nativeDebugDumpState(): ByteArray
}
