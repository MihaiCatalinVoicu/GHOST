package org.ghost.storage

import android.content.Context
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

/**
 * Opens the encrypted local database (SQLCipher over androidx.sqlite) in the no-backup directory,
 * runs migrations and applies the hardening pragmas. The key comes from [DatabaseKeyProvider] and
 * is zeroized after SQLCipher has derived its own state from it.
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
                    .callback(NoopCallback)
                    .build()
                val db = GhostDatabase(factory.create(config))
                val ex = db.executor
                // Wipe key material from SQLCipher's page cache and memory on free.
                ex.exec("PRAGMA cipher_memory_security = ON")
                ex.exec("PRAGMA journal_mode = WAL")
                ex.exec("PRAGMA secure_delete = ON")
                val runner = MigrationRunner(ex)
                runner.migrate()
                runner.verifyIntegrity()
                return db
            } finally {
                key.fill(0)
            }
        }
    }

    /** Schema is owned by [MigrationRunner], not by the open-helper callbacks. */
    private object NoopCallback : SupportSQLiteOpenHelper.Callback(Schema.CURRENT_VERSION) {
        override fun onCreate(db: SupportSQLiteDatabase) = Unit
        override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
        override fun onDowngrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
            throw MigrationRunner.DowngradeException(oldVersion, newVersion)
        }
    }
}

/** [SqlExecutor] over androidx.sqlite (SQLCipher on device). */
class SupportSqlExecutor(private val db: SupportSQLiteDatabase) : SqlExecutor {
    override fun exec(sql: String, args: List<Any?>) {
        if (args.isEmpty()) db.execSQL(sql) else db.execSQL(sql, args.toTypedArray())
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
        db.beginTransaction()
        try {
            val result = block()
            db.setTransactionSuccessful()
            return result
        } finally {
            db.endTransaction()
        }
    }

    override var userVersion: Int
        get() = db.version
        set(value) { db.version = value }
}
