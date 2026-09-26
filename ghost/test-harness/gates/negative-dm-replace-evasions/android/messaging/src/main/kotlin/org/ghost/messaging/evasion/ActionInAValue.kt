package org.ghost.messaging.evasion

// The upsert action in a literal of its own. Expected: line 5.
internal object ActionInAValue {
    val action = "DO UPDATE SET message_id = excluded.message_id"
}
