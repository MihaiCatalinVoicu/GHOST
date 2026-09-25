# Fixture: the release-only source set (Phase 9 review GATES-2)

`android/app/src/release/.../ReleaseOnly.kt` is compiled into the release APK beside `src/main`.
It carries a logging call, a clearnet socket, a placeholder comment, a restricted DM call from a
file that may not make one and a full-text-search table: no-logging, kotlin-clearnet,
anti-placeholder, dm-enqueue-callers and dm-no-fts must each reject it. Until the review all five
read `src/main` alone and passed. `src/main` holds a clean file and the one allowed restricted
call, so neither gate is vacuous.
