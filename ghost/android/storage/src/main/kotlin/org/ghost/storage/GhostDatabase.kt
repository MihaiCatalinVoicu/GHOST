package org.ghost.storage

import android.content.Context
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

/**
 * Opens the encrypted local database (SQLCipher over androidx.sqlite) in the no-backup directory,
 * runs migrations and applies the hardening pragmas. The key comes from [DatabaseKeyProvider] and
 * is zeroized after SQLCipher has derived its own state from it.
 *
 * Open sequence (SQLCipher `SQLiteOpenHelper`):
 *  1. [OpenCallback.onConfigure] applies [Schema.connectionPragmas] on the connection;
 *  2. when `user_version` differs from [Schema.CURRENT_VERSION], the helper opens one transaction,
 *     calls `onCreate`/`onUpgrade` (which apply the pending migrations through
 *     [MigrationRunner.migrateWithinTransaction]) and sets `user_version` in that same transaction,
 *     so an interrupted upgrade leaves the previous version;
 *  3. [open] enables memory security and WAL, then [MigrationRunner.verifyIntegrity] refuses a
 *     database whose tables, triggers, pragmas or version are not the expected ones; a refused
 *     database is closed before the failure propagates.
 */
class GhostDatabase private constructor(private val helper: SupportSQLiteOpenHelper) {
    val executor: SqlExecutor by lazy { SupportSqlExecutor(helper.writableDatabase) }

    fun close() = helper.close()

    companion object {
        const val FILE_NAME = "ghost.db"

        fun open(context: Context, keyProvider: DatabaseKeyProvider): GhostDatabase {
            System.loadLibrary("sqlcipher")
            val key = keyProvider.getOrCreate()
            try {
                val factory = SupportOpenHelperFactory(key)
                val config = SupportSQLiteOpenHelper.Configuration.builder(context)
                    .name(FILE_NAME)
                    .noBackupDirectory(true)
                    .callback(OpenCallback)
                    .build()
                val db = GhostDatabase(factory.create(config))
                // First access opens the database: configure, then migrate inside the helper. A
                // failure there is closed by the helper itself.
                finishOpen(db.executor, db::close)
                return db
            } finally {
                key.fill(0)
            }
        }

        /**
         * The steps after the helper has opened the connection: memory security, WAL, then
         * [MigrationRunner.verifyIntegrity]. When any of them fails, [close] runs before the
         * failure propagates, so a refused database never leaves its connection open.
         */
        internal fun finishOpen(ex: SqlExecutor, close: () -> Unit) {
            var finished = false
            try {
                // Wipe key material from SQLCipher's page cache and memory on free.
                ex.exec("PRAGMA cipher_memory_security = ON")
                // journal_mode returns the resulting mode as a row, so it runs as a query.
                ex.query("PRAGMA journal_mode = WAL") { }
                MigrationRunner(ex).verifyIntegrity()
                finished = true
            } finally {
                if (!finished) close()
            }
        }
    }

    /**
     * Connection configuration and schema migration. The helper owns `user_version`: it sets it to
     * [Schema.CURRENT_VERSION] after `onCreate`/`onUpgrade` return, inside its transaction.
     */
    private object OpenCallback : SupportSQLiteOpenHelper.Callback(Schema.CURRENT_VERSION) {
        override fun onConfigure(db: SupportSQLiteDatabase) {
            // Recorded in the connection pool configuration, so every connection it opens or
            // reconfigures keeps foreign keys on; the pragma list below repeats it for the
            // current connection and adds the settings the pool does not manage.
            db.setForeignKeyConstraintsEnabled(true)
            // Some of these return a row (secure_delete), so they run as queries.
            for (pragma in Schema.connectionPragmas) db.query(pragma).use { it.moveToFirst() }
        }

        override fun onCreate(db: SupportSQLiteDatabase) {
            MigrationRunner(SupportSqlExecutor(db)).migrateWithinTransaction(installed = 0)
        }

        override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
            MigrationRunner(SupportSqlExecutor(db)).migrateWithinTransaction(installed = oldVersion)
        }

        override fun onDowngrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
            throw MigrationRunner.DowngradeException(oldVersion, newVersion)
        }
    }
}

/**
 * [SqlExecutor] over androidx.sqlite (SQLCipher on device).
 *
 * Threading: the underlying `SQLiteDatabase` keeps one session per thread. A transaction holds the
 * primary connection for its whole duration, so statements of other threads wait for it to end.
 * [inTransaction] and the reentrancy check read that per-thread session state, which also covers
 * the open helper's own upgrade transaction.
 */
class SupportSqlExecutor(private val db: SupportSQLiteDatabase) : SqlExecutor {
    override fun exec(sql: String, args: List<Any?>) {
        if (args.isEmpty()) db.execSQL(sql) else db.execSQL(sql, args.onEach(::requireBindable).toTypedArray())
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int =
        db.compileStatement(sql).use { statement ->
            args.forEachIndexed { i, arg ->
                val index = i + 1
                when (arg) {
                    null -> statement.bindNull(index)
                    is ByteArray -> statement.bindBlob(index, arg)
                    is Long -> statement.bindLong(index, arg)
                    is Int -> statement.bindLong(index, arg.toLong())
                    is String -> statement.bindString(index, arg)
                    else -> requireBindable(arg)
                }
            }
            statement.executeUpdateDelete()
        }

    /**
     * The bind types of the [SqlExecutor] contract, on every path (design faza8-issuer.md §19.20
     * point 1). A Double would be stored as a REAL, and a `% 60 = 0` CHECK casts it to INTEGER
     * first, so a sub-minute time would pass it.
     */
    private fun requireBindable(arg: Any?) {
        if (arg != null && arg !is ByteArray && arg !is Long && arg !is Int && arg !is String) {
            throw IllegalArgumentException("unsupported bind type ${arg::class}")
        }
    }

    override fun query(sql: String, args: List<Any?>, onRow: (SqlExecutor.Row) -> Unit) {
        db.query(sql, args.toTypedArray()).use { cursor ->
            val row = object : SqlExecutor.Row {
                override fun isNull(index: Int) = cursor.isNull(index)
                override fun long(index: Int) = cursor.getLong(index)
                override fun string(index: Int) = cursor.getString(index)
                override fun blob(index: Int) = cursor.getBlob(index)
            }
            while (cursor.moveToNext()) onRow(row)
        }
    }

    override fun <T> transaction(block: () -> T): T {
        check(!db.inTransaction()) { "nested transaction on the same thread" }
        db.beginTransaction()
        try {
            val result = block()
            db.setTransactionSuccessful()
            return result
        } finally {
            db.endTransaction()
        }
    }

    override val inTransaction: Boolean
        get() = db.inTransaction()

    override var userVersion: Int
        get() = db.version
        set(value) { db.version = value }
}
