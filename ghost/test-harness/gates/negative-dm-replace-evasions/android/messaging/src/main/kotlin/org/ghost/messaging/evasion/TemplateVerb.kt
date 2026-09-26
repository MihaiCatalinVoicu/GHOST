package org.ghost.messaging.evasion

// The algorithm as a template. Expected: line 5.
internal object TemplateVerb {
    fun sql(verb: String) = "INSERT OR ${verb} INTO dm_message(message_id) VALUES (?)"
}
