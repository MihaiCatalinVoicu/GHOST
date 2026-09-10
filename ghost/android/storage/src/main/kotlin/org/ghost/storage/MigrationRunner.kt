package org.ghost.storage

/**
 * Applies [Schema.migrations] transactionally. Each migration runs in its own transaction and
 * bumps `PRAGMA user_version` inside that transaction, so an interruption (crash, disk full)
 * leaves the database at the previous version with no partial schema (§8.1: migrations have a
 * recovery path after interruption). Downgrades fail closed.
 */
class MigrationRunner(private val db: SqlExecutor, private val migrations: List<Schema.Migration> = Schema.migrations) {

    class DowngradeException(installed: Int, supported: Int) :
        IllegalStateException("database version $installed is newer than supported $supported")

    /** Returns the list of versions applied during this call. */
    fun migrate(): List<Int> {
        val target = migrations.maxOfOrNull { it.version } ?: 0
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
        db.exec("PRAGMA foreign_keys = ON")
        return applied
    }

    /** Verifies every expected table exists; run after [migrate] and on every open. */
    fun verifyIntegrity() {
        val present = HashSet<String>()
        db.query("SELECT name FROM sqlite_master WHERE type = 'table'") { present += it.string(0) }
        val missing = Schema.expectedTables - present
        check(missing.isEmpty()) { "schema integrity: missing tables $missing" }
        check(db.userVersion == Schema.CURRENT_VERSION) { "schema version mismatch: ${db.userVersion}" }
    }
}
