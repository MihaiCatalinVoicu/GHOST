# Release stays minified (spec section 11, application hardening). Add keep rules only with a
# comment naming the library and the reason.
-dontwarn org.ghost.**

# GHOST classes are shrunk but never renamed (Phase 9 design §2.7, §22.8.10 point 11, ADR-38;
# slice S12). `-dontobfuscate` takes no class filter and would switch obfuscation off for every
# library in the APK, so the names of GHOST's own classes and members are kept instead: a crash
# report, a reviewer reading the release APK and gate G-DM5 all see the source names. G-DM5
# (scripts/gates/apk-no-debug-hooks.sh) asserts that R8's mapping.txt maps every `org.ghost.` class
# to itself and holds no debug hook, harness, transport seam or equivalence entry point.
-keepnames class org.ghost.** { *; }
