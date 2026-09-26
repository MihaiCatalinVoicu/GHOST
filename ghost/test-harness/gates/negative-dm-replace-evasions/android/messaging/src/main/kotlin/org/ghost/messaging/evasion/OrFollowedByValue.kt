package org.ghost.messaging.evasion

// The algorithm is whatever the function returns. Expected: line 5.
internal object OrFollowedByValue {
    fun sql(verb: () -> String) = "INSERT OR " + verb() + " INTO dm_message(message_id) VALUES (?)"
}
