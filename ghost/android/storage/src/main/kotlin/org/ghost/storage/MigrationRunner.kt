package org.ghost.storage

/**
 * Applies [Schema.migrations] transactionally. Each migration runs in its own transaction and
 * bumps `PRAGMA user_version` inside that transaction, so an interruption (crash, disk full)
 * leaves the database at the previous version with no partial schema (§8.1: migrations have a
 * recovery path after interruption). Downgrades fail closed.
 *
 * Connection settings ([Schema.connectionPragmas]) are not applied here: the executor applies
 * them on every connection it opens (SQLCipher `onConfigure`, the JDBC test executor on open), and
 * [verifyIntegrity] asserts them.
 */
class MigrationRunner(private val db: SqlExecutor, private val migrations: List<Schema.Migration> = Schema.migrations) {

    class DowngradeException(installed: Int, supported: Int) :
        IllegalStateException("database version $installed is newer than supported $supported")

    private val target: Int get() = migrations.maxOfOrNull { it.version } ?: 0

    /** Returns the list of versions applied during this call. */
    fun migrate(): List<Int> {
        val installed = db.userVersion
        if (installed > target) throw DowngradeException(installed, target)
        val applied = ArrayList<Int>()
        for (m in migrations.sortedBy { it.version }) {
            if (m.version <= installed) continue
            db.transaction {
                for (statement in m.statements) db.exec(statement)
                db.userVersion = m.version
            }
            applied += m.version
        }
        return applied
    }

    /**
     * Applies every migration newer than [installed] inside the transaction the caller already
     * holds, without touching `user_version`. Used by the SQLCipher open helper, which calls
     * `onCreate`/`onUpgrade` inside its own transaction and sets `user_version` to the callback
     * version in that same transaction; a failure rolls every pending migration back together.
     * Returns the list of versions applied.
     */
    fun migrateWithinTransaction(installed: Int): List<Int> {
        check(db.inTransaction) { "migrateWithinTransaction needs the caller's transaction" }
        if (installed > target) throw DowngradeException(installed, target)
        val applied = ArrayList<Int>()
        for (m in migrations.sortedBy { it.version }) {
            if (m.version <= installed) continue
            for (statement in m.statements) db.exec(statement)
            applied += m.version
        }
        return applied
    }

    /**
     * Fails closed unless the schema and the connection are the expected ones: every expected
     * table and trigger exists, the connection pragmas are in force, and the version is current.
     * Run after [migrate] and on every open.
     */
    fun verifyIntegrity() {
        val tables = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table'") { tables += it.string(0) }
        val missingTables = Schema.expectedTables - tables
        check(missingTables.isEmpty()) { "schema integrity: missing tables $missingTables" }
        val triggers = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'trigger'") { triggers += it.string(0) }
        val missingTriggers = Schema.expectedTriggers - triggers
        check(missingTriggers.isEmpty()) { "schema integrity: missing triggers $missingTriggers" }
        for ((pragma, expected) in Schema.expectedPragmaValues) {
            val actual = db.queryLong("PRAGMA $pragma")
            check(actual == expected) { "connection integrity: PRAGMA $pragma is $actual, expected $expected" }
        }
        check(db.userVersion == Schema.CURRENT_VERSION) { "schema version mismatch: ${db.userVersion}" }
    }
}
