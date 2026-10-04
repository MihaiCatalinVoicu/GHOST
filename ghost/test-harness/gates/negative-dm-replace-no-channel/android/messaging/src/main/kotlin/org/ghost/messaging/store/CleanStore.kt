package org.ghost.messaging.store

internal object CleanStore {
    const val READ = "SELECT message_id FROM dm_message WHERE conversation_id = ?"
}
