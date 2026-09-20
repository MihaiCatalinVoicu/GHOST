//! Fixture: an entry marked Exported with no entry point (G-R6 direction 2).
pub const CLOSED_LIST: &[(u8, &str, Availability)] = &[
    (1, "ctxOpen", Availability::Exported),
    (7, "sessionOutbound", Availability::Exported),
];
pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_ctxOpen() {}
