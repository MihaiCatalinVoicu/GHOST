package org.ghost.sync.store

/**
 * G-DM4 negative fixture (Phase 10, slice S3 review). Expected in this file: 3 violations, on lines 12, 15 and
 * 20: a REPLACE and an upsert on channel tables whose names are written in capitals or in mixed case. SQLite
 * resolves a table name without regard to case, so `INSERT OR REPLACE INTO CH_POST` replaces a row of `ch_post`
 * as `insert or replace into ch_post` does; the first version of the gate matched the table name case-sensitively
 * and passed them. The lower-case writers' form (UPDATE, then INSERT guarded by WHERE NOT EXISTS) is no violation.
 */
internal object ShoutingStore {
    // Upper case, on the posts.
    const val PUT_POST = "INSERT OR REPLACE INTO CH_POST(op_id, channel_id) VALUES (?, ?)"

    // Mixed case, the SQLite alias of INSERT OR REPLACE, on the group rows.
    const val PUT_GROUP = "REPLACE INTO Mls_Kv(channel_id, k, env) VALUES (?, ?, ?)"

    // Upper case, an upsert on the global rows.
    const val PUT_GLOBAL =
        "INSERT INTO MLS_GLOBAL_KV(k, channel_id, env) VALUES (?, ?, ?) " +
            "ON CONFLICT(k) DO UPDATE SET env = excluded.env"

    // The writers' form, in capitals: an UPDATE, then an INSERT that waits for the key to be absent.
    const val UPDATE_GROUP = "UPDATE MLS_KV SET env = ? WHERE channel_id = ? AND k = ?"
}
