//! Fixture: an entry point of the DM surface written **outside** `client-core/dm/src/jni.rs`.
//! The closed list of §2.6 says nothing about it, and a read scoped to the list's own file would
//! not see it; G-R6 scans the workspace and rejects it.

/// A debug dump nobody may ship.
#[no_mangle]
pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_debugDumpState(handle: i64) -> i64 {
    handle
}
