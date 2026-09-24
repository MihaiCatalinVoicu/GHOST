package org.ghost.storage

import android.content.Context
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

/**
 * Opens the encrypted local database (SQLCipher over androidx.sqlite), runs migrations and applies
 * the hardening pragmas. The key comes from [DatabaseKeyProvider] and is zeroized after SQLCipher
 * has derived its own state from it.
 *
 * **Where the file is.** The configuration asks for the no-backup directory, and SQLCipher 4.19.0's
 * `SupportOpenHelperFactory` ignores that request: the file is `getDatabasePath(FILE_NAME)`, under
 * `databases/` (observed on the first emulator run with this exact configuration, Phase 9 design
 * §22.32, which records the question for the owner). Backup exclusion rests on the manifest's
 * backup and data-extraction rules, which exclude the `database` domain.
 *
 * Open sequence (SQLCipher `SQLiteOpenHelper`):
 *  1. [OpenCallback.onConfigure] applies [Schema.connectionPragmas] on the connection;
 *  2. when `user_version` differs from [Schema.CURRENT_VERSION], the helper opens one transaction,
 *     calls `onCreate`/`onUpgrade` (which apply the pending migrations through
 *     [MigrationRunner.migrateWithinTransaction]) and sets `user_version` in that same transaction,
 *     so an interrupted upgrade leaves the previous version;
 *  3. [open] enables memory security and WAL, runs the **open checkpoint** of Phase 9 design §10.7
 *     (R-K1), then [MigrationRunner.verifyIntegrity] refuses a database whose tables, triggers,
 *     pragmas or version are not the expected ones; a refused database is closed before the failure
 *     propagates.
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
         * The steps after the helper has opened the connection: memory security, WAL, the open
         * checkpoint of **R-K1**, then [MigrationRunner.verifyIntegrity]. When any of them fails,
         * [close] runs before the failure propagates, so a refused database never leaves its
         * connection open.
         *
         * **R-K1** (Phase 9 design §10.7, §7.2 SWEEP): "a checkpoint runs at every database open,
         * after migration and before the first read". The write-ahead log outlives the process, so
         * pages a SWEEP freed in the last session — expired `body_env`, held ciphertext, erased
         * pair keys — sit in `-wal` until something truncates it. Nothing else would: the in-memory
         * `checkpoint_due` flag a busy sweep keeps (§10.7) dies with the process, and the next
         * sweep only checkpoints when it deleted rows of its own. Without this call a device that
         * swept and was then killed keeps the freed pages until its next deletion, which is the
         * T25 physical bound broken for an unbounded time.
         *
         * The migration itself runs **before** this, inside the helper's own upgrade transaction,
         * so "after migration" holds by construction; this call is placed before
         * [MigrationRunner.verifyIntegrity] so that no read of this connection precedes it.
         *
         * Returns whether the log was truncated. A busy answer is not a failure of the open —
         * another connection held the log, and the next sweep retries (§10.7) — so the result is
         * reported rather than raised.
         */
        internal fun finishOpen(ex: SqlExecutor, close: () -> Unit): Boolean {
            var finished = false
            var checkpointed = false
            try {
                // Wipe key material from SQLCipher's page cache and memory on free.
                ex.exec("PRAGMA cipher_memory_security = ON")
                // journal_mode returns the resulting mode as a row, so it runs as a query.
                ex.query("PRAGMA journal_mode = WAL") { }
                checkpointed = Checkpoint.truncate(ex)
                MigrationRunner(ex).verifyIntegrity()
                finished = true
            } finally {
                if (!finished) close()
            }
            return checkpointed
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
        try {
            if (args.isEmpty()) db.execSQL(sql) else db.execSQL(sql, args.onEach(::requireBindable).toTypedArray())
        } catch (e: RuntimeException) {
            throw StorageFull.wrap(e)
        }
    }

    override fun execUpdate(sql: String, args: List<Any?>): Int =
        try {
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
        } catch (e: RuntimeException) {
            throw StorageFull.wrap(e)
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
        var failure: Throwable? = null
        try {
            val result = block()
            db.setTransactionSuccessful()
            // endTransaction issues the COMMIT, so it belongs inside the guarded region: a commit
            // that runs out of space fails here, not in a statement (§21.12 point 1).
            db.endTransaction()
            return result
        } catch (e: Throwable) {
            failure = e
            throw if (e is RuntimeException) StorageFull.wrap(e) else e
        } finally {
            // The driver leaves the frame open only when the work failed before the commit: the
            // commit itself pops it, successfully or not. Ending it here rolls the transaction back.
            if (db.inTransaction()) {
                try {
                    db.endTransaction()
                } catch (e: RuntimeException) {
                    // SQLite rolls its own transaction back on SQLITE_FULL, so this rollback can
                    // fail; what the caller must see is the failure that started it, with the
                    // second one attached (the JVM double does the same).
                    val started = failure
                    if (started != null) started.addSuppressed(e) else throw StorageFull.wrap(e)
                }
            }
        }
    }

    override val inTransaction: Boolean
        get() = db.inTransaction()

    override var userVersion: Int
        get() = db.version
        set(value) { db.version = value }
}
