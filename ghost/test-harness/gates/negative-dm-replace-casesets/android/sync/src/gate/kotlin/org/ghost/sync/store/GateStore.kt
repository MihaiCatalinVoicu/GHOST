package org.ghost.sync.store

/**
 * G-DM4 negative fixture (Phase 10, slice S3 review). Expected in this file: 1 violation, on line 9: an upsert
 * on a channel table in the `gate` source set (never released, installed on the gate devices) of a module that
 * is not `:messaging` or `:crypto-bridge`.
 */
internal object GateStore {
    const val PUT_GLOBAL = "INSERT INTO mls_global_kv(k, channel_id) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET channel_id = excluded.channel_id"
}
