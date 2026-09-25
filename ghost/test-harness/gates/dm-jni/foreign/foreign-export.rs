//! Fixture (Phase 9 review GATES-3): a JNI entry point of the DM crate under **another class**.
//! Every other half of G-R6 matched `DmNative` by name, so this passed all of them.

/// A debug dump nobody may ship.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_ghost_crypto_bridge_DmDebug_exportSessionState() {}
