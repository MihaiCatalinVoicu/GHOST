# Negative fixture for the dm-no-replace gate (G-DM4): table names in any case, and every source set of every module

Used by `scripts/gates/self-test.sh` (Phase 10 design `faza10-forum.md` section 9, "Migration 7"; review of slice S3).
Two holes of the gate's channel-table rule, each shown by violations the first version passed:

- **The table name is matched without regard to case**, as SQLite resolves it. `ShoutingStore.kt`, a store outside
  `:messaging`, holds an `INSERT OR REPLACE` on `CH_POST` (line 12), a `REPLACE INTO` on `Mls_Kv` (line 15) and an
  upsert on `MLS_GLOBAL_KV` (line 20); its UPDATE in capitals (line 23) is the writers' own form and must not count.
- **Every source set of every module is read**, `main`, `gate`, `debug` and `release`, as `common.sh`'s
  `android_main_files` reads `src/main` and `src/release` for the other gates (Phase 9 review GATES-2): a `REPLACE INTO mls_kv` in
  `android/sync/src/release` (`ReleaseStore.kt:11`), an upsert on `mls_global_kv` in `android/sync/src/gate`
  (`GateStore.kt:9`) and an `INSERT OR REPLACE` on `ch_post` in `android/storage/src/debug` (`DebugSeed.kt:9`).
  Only `:messaging` and `:crypto-bridge` were read beyond `src/main`.

6 violations in all. `Schema.kt` keeps the migration 5 markers with a `dm_` and a `ch_` table between them so that the
gate's vacuity checks pass; nothing here is compiled or shipped.
