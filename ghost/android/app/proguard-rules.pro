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
