//! Fixture: a function of a later slice exported early (G-R6 keeps the list closed while filling).
pub const CLOSED_LIST: &[(u8, &str, Availability)] = &[
    (1, "ctxOpen", Availability::Exported),
    (9, "sealIntro", Availability::Declared("S7")),
];
pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_ctxOpen() {}
pub extern "system" fn Java_org_ghost_crypto_bridge_DmNative_sealIntro() {}
