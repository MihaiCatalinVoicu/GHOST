/// Fixture: a small closed list.
pub const CLOSED_LIST: &[(u8, &str, Availability)] = &[
    (1, "ctxOpen", Availability::Exported),
    (1, "ctxClose", Availability::Exported),
    (16, "revealSeal", Availability::Declared("S9")),
];
pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_ctxOpen() {}
pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_ctxClose() {}
pub extern "system" fn Java_org_ghost_crypto_bridge_MlsVectors_run() {}
