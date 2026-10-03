// Fixture (G-M6, G-R6 source halves; review of S2b): spellings rustc exports that S2b's first
// readers did not see. Each MlsNative name here is off the closed list and must be reported; the
// one in the comment below must not: "fn Java_org_ghost_crypto_bridge_MlsNative_debugComment".
// fn Java_org_ghost_crypto_bridge_MlsNative_debugCommentToo
#[no_mangle]
pub unsafe extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_debugUnsafe() {}
#[no_mangle]
extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_debugPrivate() {}
#[no_mangle]
pub extern "C" fn Java_org_ghost_crypto_bridge_MlsNative_debugC() {}
#[no_mangle]
pub extern "system" fn
    Java_org_ghost_crypto_bridge_MlsNative_debugSplit() {}
pub extern "system" fn Java_org_ghost_crypto_bridge_MlsVectors_run() {}
