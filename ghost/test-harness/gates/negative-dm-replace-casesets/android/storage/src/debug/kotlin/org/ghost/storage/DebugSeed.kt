package org.ghost.storage

/**
 * G-DM4 negative fixture (Phase 10, slice S3 review). Expected in this file: 1 violation, on line 9: an
 * INSERT OR REPLACE on a channel table in the `debug` source set of a module that is not `:messaging` or
 * `:crypto-bridge`.
 */
internal object DebugSeed {
    const val SEED_POST = "INSERT OR REPLACE INTO ch_post(op_id, channel_id) VALUES (?, ?)"
}
