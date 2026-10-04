/// Fixture: a closed list with no reserved entry (slice S9 has exported function 16).
pub const CLOSED_LIST: &[(u8, &str, Availability)] = &[
    (1, "ctxOpen", Availability::Exported),
    (1, "ctxClose", Availability::Exported),
];
pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_ctxOpen<'l>(env: JNIEnv<'l>, class: JClass<'l>, a: JByteArray<'l>) -> jbyteArray {}
pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_ctxClose<'l>(env: JNIEnv<'l>, class: JClass<'l>, h: jlong) -> jbyteArray {}
pub extern "system" fn Java_org_ghost_crypto_bridge_MlsVectors_run() {}
