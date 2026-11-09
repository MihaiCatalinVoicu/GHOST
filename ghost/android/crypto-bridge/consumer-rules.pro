# Consumer rules for :crypto-bridge (Phase 9 design §2.7 "R8", graft G-14).
#
# The DM cryptography is in `libghost_client_net.so`, built from the Rust crate
# `client-core/dm` (`ghost-client-dm`) and exported through `ghost_client_dm::export_jni!()` in
# `client-core/net/src/jni_bridge.rs`. JNI resolves the native methods by their Java names, so R8
# must not rename or remove them; the class itself is reachable from Kotlin, the methods are not.
-keepclasseswithmembernames,includedescriptorclasses class org.ghost.crypto.bridge.DmNative {
    native <methods>;
}

# H-01 (spec v2.2 §8, ADR-38 §9 amendat v2.2, design docs/design/h0-apk-hardening.md §2): GHOST's
# names ARE obfuscated in the release — there is no project-wide `-keepnames`. These JNI keeps are
# the whitelist: gate G-DM5 reads them and refuses any other `org.ghost.` class that keeps its
# source name in `mapping.txt`.

# The channel surface (Phase 10 design §10.1, §10.2; slice S2b) is in the same library, exported
# through `ghost_client_mls::export_jni!()` beside the DM export. The same rule: JNI resolves the
# native methods of `org.ghost.crypto.bridge.MlsNative` by their Java names, so R8 must not rename
# them (the test-only `MlsVectors` is in no release source set; G-DM5 refuses it in the mapping).
-keepclasseswithmembernames,includedescriptorclasses class org.ghost.crypto.bridge.MlsNative {
    native <methods>;
}

# The media surface (Phase 11 design §13.2, G-M5; slice S2) — same JNI rule as DmNative/MlsNative:
# `MediaNative`'s native methods are bound by name from `client-core/dm/src/jni_media.rs`. This keep
# predates H-01 only formally: until v2.2 the global `-keepnames` masked it (G-DM5 caught the gap
# on the first obfuscated build, 2026-11-09).
-keepclasseswithmembernames,includedescriptorclasses class org.ghost.crypto.bridge.MediaNative {
    native <methods>;
}
