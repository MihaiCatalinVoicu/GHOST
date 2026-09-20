//! Fixture: an export outside the closed list (G-R6 direction 1).
pub const CLOSED_LIST: &[(u8, &str, Availability)] = &[
    (1, "ctxOpen", Availability::Exported),
];
pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_ctxOpen() {}
pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_debugDumpState() {}
