# Release stays minified (spec section 11, application hardening). Add keep rules only with a
# comment naming the library and the reason.
-dontwarn org.ghost.**

# H-01 (spec v2.2 §8, ADR-38 §9 amendat v2.2, design docs/design/h0-apk-hardening.md §2): GHOST's
# names ARE obfuscated in the release. There is deliberately no global `-keepnames class
# org.ghost.**` here — that was the pre-v2.2 rule and it is gone. The only names that survive are
# the narrow JNI/reflection surfaces each module justifies in its own consumer-rules.pro (native
# methods resolve by Java name; classes thrown/looked-up by name from JNI). Gate G-DM5
# (scripts/gates/apk-no-debug-hooks.sh) reads those rules as its whitelist and refuses any other
# org.ghost. class that keeps its source name in mapping.txt.

# Manifest-referenced components (android/app/src/main/AndroidManifest.xml). AGP keeps them through
# the merged manifest anyway; these explicit rules make the intent self-documenting, immune to AGP
# behavior changes, and verifiable by G-DM5's whitelist (which reads exactly the tree's -keep rules).
-keep class org.ghost.app.GhostApp
-keep class org.ghost.app.MainActivity
-keep class org.ghost.app.UpdateInstallReceiver
-keep class org.ghost.media.sandbox.MediaDecodeService
-keep class org.ghost.messaging.android.ExpiryAlarmReceiver
-keep class org.ghost.sync.android.SyncJobService

# H-10 (design docs/design/h0-apk-hardening.md §9 item 7; decision 2026-11-11): the release smoke
# (ReleaseSmokeTest, app/src/androidTest) runs against the R8-shrunk release APK and calls the
# crypto-bridge seam BY NAME. H1's minification profile otherwise renames every member and inlines
# the DmNative singleton's INSTANCE away entirely (measured 2026-11-11: smoke failed with
# "No field INSTANCE"; mapping.txt showed isAvailable kept only as inlined copies). Names survive
# only for this exact test seam; mapping.txt is auditor-private (ADR-38), so the residual surface
# is the decompiled readability of one facade — accepted against §15.9 item 3's whole point (the
# smoke must exercise the shipped, shrunk library). G-DM5 reads these rules as its whitelist.
-keepclassmembers class org.ghost.crypto.bridge.DmNative {
    public static final org.ghost.crypto.bridge.DmNative INSTANCE;
    public final boolean isAvailable();
}
-keepclassmembers class org.ghost.crypto.bridge.DmSessions {
    public static final org.ghost.crypto.bridge.DmSessions INSTANCE;
    <methods>;
}
-keep class org.ghost.crypto.bridge.DmSessions$* {
    <fields>;
    <methods>;
}
