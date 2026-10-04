package org.ghost.sync.store

/**
 * G-DM4 negative fixture (Phase 10, slice S1a). Expected: 2 violations, on lines 17 and 23: an upsert on
 * `relay_register_capability` and an INSERT OR REPLACE on `sync_namespace_fund`. Both tables are
 * guarded against REPLACE (design faza10-forum.md §9, migration 6), so their writers are an UPDATE
 * followed by an INSERT. Not violations: the upsert on `relay_capability` (a v2 table, upserted by
 * design), the writers' own form on the two tables, a longer table name that merely starts with one
 * of theirs, and prose in a comment (INSERT OR REPLACE INTO relay_register_capability).
 */
internal object CapabilityStore {
    // The v2 capability upsert: not read against the rule.
    const val PUT_V2 = "INSERT INTO relay_capability(relay_id, namespace_id, kind) VALUES (?, ?, ?) ON CONFLICT(relay_id, namespace_id, kind) DO UPDATE SET kind = excluded.kind"

    const val PUT_REGISTER =
        "INSERT INTO relay_register_capability(relay_id, namespace_id, token) VALUES (?, ?, ?) " +
            "ON CONFLICT(relay_id, namespace_id) DO UPDATE SET token = excluded.token"

    // The writers' form: an UPDATE, then an INSERT when it changed nothing.
    const val UPDATE_REGISTER = "UPDATE relay_register_capability SET token = ?, generation = generation + 1 WHERE relay_id = ? AND namespace_id = ?"
    const val INSERT_REGISTER = "INSERT INTO relay_register_capability(relay_id, namespace_id, token, generation) VALUES (?, ?, ?, 1)"

    const val FUND = "INSERT OR REPLACE INTO sync_namespace_fund(namespace_id) VALUES (?)"

    const val FUND_ONCE = "INSERT INTO sync_namespace_fund(namespace_id) SELECT ?1 WHERE NOT EXISTS (SELECT 1 FROM sync_namespace_fund WHERE namespace_id = ?1)"

    // A longer name that starts like one of the two: another table, not read against the rule.
    const val AUDIT = "INSERT OR REPLACE INTO relay_register_capability_audit(relay_id) VALUES (?)"
}
