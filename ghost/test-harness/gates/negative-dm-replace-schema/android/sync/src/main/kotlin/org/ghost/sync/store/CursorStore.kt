package org.ghost.sync.store

// Not DM SQL: the sync engine's own upsert. Must not be reported.
internal object CursorStore {
    const val PUT = "INSERT INTO relay_cursor(relay_id, cursor) VALUES (?, ?) ON CONFLICT(relay_id) DO UPDATE SET cursor = excluded.cursor"
}
