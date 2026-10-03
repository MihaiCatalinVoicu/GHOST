// Fixture: a name the export attribute takes from a macro argument.
macro_rules! export {
    ($sym:literal, $f:ident) => {
        #[export_name = $sym]
        pub extern "system" fn $f() {}
    };
}
export!("Java_org_ghost_crypto_bridge_MlsNative_debugMacro", hidden);
export!("Java_org_ghost_crypto_bridge_DmDebug_dump", hidden_dm);
