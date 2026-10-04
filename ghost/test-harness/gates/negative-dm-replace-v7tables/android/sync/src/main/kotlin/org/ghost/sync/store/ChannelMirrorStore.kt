package org.ghost.sync.store

/**
 * G-DM4 negative fixture (Phase 10, slice S3). Expected in this file: 3 violations, on lines 16, 19 and
 * 22: an upsert on `mls_global_kv`, an INSERT OR REPLACE on `ch_post` and a REPLACE INTO on `mls_kv`,
 * written outside `:messaging` (where every SQL string is read anyway). The channel tables of
 * migration 7 carry REPLACE guards, so their writers are an UPDATE followed by an INSERT guarded by
 * WHERE NOT EXISTS, which the file also shows and which must not count. Not violations either: a table
 * that only ends like a channel table (`launch_log`, `research_kv`), a longer word that merely starts
 * with `ch` (`chart_cache`) and prose in a comment (INSERT OR REPLACE INTO ch_channel).
 */
internal object ChannelMirrorStore {
    // Upsert on the global rows of GhostKv.
    const val PUT_GLOBAL =
        "INSERT INTO mls_global_kv(k, channel_id, env) VALUES (?, ?, ?) " +
            "ON CONFLICT(k) DO UPDATE SET env = excluded.env"

    // REPLACE on a post.
    const val PUT_POST = "INSERT OR REPLACE INTO ch_post(op_id, channel_id) VALUES (?, ?)"

    // The SQLite alias of INSERT OR REPLACE, on the group rows.
    const val PUT_GROUP = "REPLACE INTO mls_kv(channel_id, k, env) VALUES (?, ?, ?)"

    // The writers' form: an UPDATE, then an INSERT that waits for the key to be absent.
    const val UPDATE_GROUP = "UPDATE mls_kv SET env = ? WHERE channel_id = ? AND k = ?"
    const val INSERT_GROUP =
        "INSERT INTO mls_kv(channel_id, k, env) SELECT ?1, ?2, ?3 " +
            "WHERE NOT EXISTS (SELECT 1 FROM mls_kv WHERE channel_id = ?1 AND k = ?2)"

    // Tables that are not channel tables: not read against the rule.
    const val LAUNCH = "INSERT OR REPLACE INTO launch_log(id) VALUES (?)"
    const val RESEARCH = "INSERT OR REPLACE INTO research_kv(k, v) VALUES (?, ?)"
    const val CHART = "INSERT OR REPLACE INTO chart_cache(k, v) VALUES (?, ?)"
}
