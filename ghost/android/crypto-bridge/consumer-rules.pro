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
