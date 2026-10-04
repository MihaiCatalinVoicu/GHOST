# Consumer rules for :crypto-bridge (Phase 9 design §2.7 "R8", graft G-14).
#
# The DM cryptography is in `libghost_client_net.so`, built from the Rust crate
# `client-core/dm` (`ghost-client-dm`) and exported through `ghost_client_dm::export_jni!()` in
# `client-core/net/src/jni_bridge.rs`. JNI resolves the native methods by their Java names, so R8
# must not rename or remove them; the class itself is reachable from Kotlin, the methods are not.
-keepclasseswithmembernames,includedescriptorclasses class org.ghost.crypto.bridge.DmNative {
    native <methods>;
}

# GHOST classes are not obfuscated (§2.7, ADR-38, §22.8.10 point 11): `-dontobfuscate` takes no
# class filter and would disable obfuscation for the whole APK, so the names are kept instead and
# G-DM5 asserts that `mapping.txt` maps every `org.ghost.` class to itself. The app module carries
# the project-wide `-keepnames class org.ghost.** { *; }`.

# The channel surface (Phase 10 design §10.1, §10.2; slice S2b) is in the same library, exported
# through `ghost_client_mls::export_jni!()` beside the DM export. The same rule: JNI resolves the
# native methods of `org.ghost.crypto.bridge.MlsNative` by their Java names, so R8 must not rename
# them (the test-only `MlsVectors` is in no release source set; G-DM5 refuses it in the mapping).
-keepclasseswithmembernames,includedescriptorclasses class org.ghost.crypto.bridge.MlsNative {
    native <methods>;
}
