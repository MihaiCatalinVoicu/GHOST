package org.ghost.messaging.evasion

// The conflict action is whatever the function returns. Expected: line 6.
internal object ConflictFollowedByValue {
    fun sql(action: () -> String) =
        "INSERT INTO dm_message(message_id) VALUES (?) ON CONFLICT(message_id) " + action()
}
