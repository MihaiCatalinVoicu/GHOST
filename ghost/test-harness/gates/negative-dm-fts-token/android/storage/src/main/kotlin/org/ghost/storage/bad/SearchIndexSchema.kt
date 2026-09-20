package org.ghost.storage.bad

/**
 * A full-text index reached without the statement G-DM6's other half looks for: the module is
 * named in a pragma and the shadow table is written by hand. The gate must reject the module's
 * three-letter token itself, or this route stays open (design §13.6 R-M4; mutant ME-18).
 *
 * Exactly three lines below carry the token; the decoys must not be reported, and this fixture
 * holds no other violation, so the token half is proven on its own.
 */
object SearchIndexSchema {
    val statements: List<String> = listOf(
        """CREATE TABLE dm_message_shadow (
                  message_id BLOB PRIMARY KEY NOT NULL,
                  body_env   BLOB NOT NULL
                ) WITHOUT ROWID""",
        "CREATE TABLE dm_message_fts_content (docid INTEGER PRIMARY KEY, c0 TEXT)",
        "PRAGMA module_list_add = 'FTS5'",
        "INSERT INTO ftsIndex(rowid, body) SELECT rowid, body FROM dm_message_shadow",
    )

    /** Words that merely end in those three letters are not the token. */
    val decoys: List<String> = listOf("shifts", "drafts", "lifts", "gifts", "crafts", "lofts")
}
