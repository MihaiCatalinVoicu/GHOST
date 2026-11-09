# JNI: client-core/net/src/jni_bridge.rs throws this class by name ("org/ghost/network/NetworkException")
# and calls its (String) constructor; R8 must neither rename nor strip it.
-keep class org.ghost.network.NetworkException { <init>(java.lang.String); }
# JNI: native methods are bound by name (Java_org_ghost_network_<Class>_native*).
-keepclasseswithmembernames class org.ghost.network.TorRelayTransport { native <methods>; }
-keepclasseswithmembernames class org.ghost.network.TorIssuerTransport { native <methods>; }
-keepclasseswithmembernames class org.ghost.network.EntitlementCrypto { native <methods>; }
# JNI: the update surface (Phase 14 design §9.3, G-D5; slice S6) — `UpdateNative`/`TorMirrorTransport`
# native methods are bound by name from client-core/net/src/update.rs (`CLOSED_UPDATE`/`CLOSED_MIRROR`).
# Like MediaNative in :crypto-bridge, these keeps were masked by the pre-v2.2 global `-keepnames`
# and surfaced on the first obfuscated build (G-DM5, 2026-11-09). `UpdateMutants` needs no rule: it
# is compiled only into test libraries, which no release ships.
-keepclasseswithmembernames class org.ghost.network.UpdateNative { native <methods>; }
-keepclasseswithmembernames class org.ghost.network.TorMirrorTransport { native <methods>; }
