package org.ghost.storage

object Schema {
    private fun migration4(): List<String> = listOf("CREATE TABLE sync_namespace (namespace_id BLOB PRIMARY KEY)")
}
