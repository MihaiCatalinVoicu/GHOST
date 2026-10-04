package org.ghost.sync.store

/**
 * G-DM4 negative fixture (Phase 10, slice S3 review). Expected in this file: 1 violation, on line 11: a REPLACE
 * on a channel table in the `release` source set of a module that is not `:messaging` or `:crypto-bridge`.
 * `src/release` is compiled into the release APK beside `src/main` (Phase 9 review GATES-2: the gates that read
 * the production path read it, and `common.sh`'s `android_main_files` does); the first version of this gate
 * read the `gate`, `debug` and `release` source sets of the two DM modules only.
 */
internal object ReleaseStore {
    const val PUT_GROUP = "REPLACE INTO mls_kv(channel_id, k, env) VALUES (?, ?, ?)"
}
