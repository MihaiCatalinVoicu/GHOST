# JNI: client-core/net/src/jni_bridge.rs throws this class by name ("org/ghost/network/NetworkException")
# and calls its (String) constructor; R8 must neither rename nor strip it.
-keep class org.ghost.network.NetworkException { <init>(java.lang.String); }
# JNI: native methods are bound by name (Java_org_ghost_network_TorRelayTransport_native*).
-keepclasseswithmembernames class org.ghost.network.TorRelayTransport { native <methods>; }
