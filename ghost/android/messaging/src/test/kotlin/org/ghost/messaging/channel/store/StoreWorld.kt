package org.ghost.messaging.channel.store

import org.ghost.storage.ChannelFixture
import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.storage.chBytes
import org.ghost.storage.queryLong
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction

/**
 * A migrated v7 database with the channel stores over it, the way the engine will hold them: one
 * `SyncDatabase` whose `transaction` is the only way to write (§10.4), the stores stateless beside it.
 *
 * The rows the tests need are written through the stores themselves where a store has the operation, and
 * through [ChannelFixture] (plain SQL with valid defaults) where the test needs a state the store would
 * not produce (an expired row, a row at a bound).
 */
internal class StoreWorld(path: String = ":memory:") : AutoCloseable {
    val db = JdbcSqlExecutor(path).also { MigrationRunner(it).migrate() }
    val sync = SyncDatabase(db)
    val stores = ChannelStores()
    val fixture = ChannelFixture(db)

    /** The channel every default row belongs to. */
    val ch: ByteArray = ChannelFixture.CH

    fun <T> tx(block: (SyncTransaction) -> T): T = sync.transaction(block)

    /** A second channel id. */
    val ch2: ByteArray = chBytes(32, 0xC2)

    /** An active channel with the defaults of [ChannelFixture]; returns its id. */
    fun channel(id: ByteArray = ch, state: ChannelState = ChannelState.ACTIVE): ByteArray {
        tx {
            stores.channels.insert(
                it,
                ChannelStore.NewChannel(
                    channelId = id, state = state, generation = 0, epoch = 0, joinedEpoch = 0, sizeClass = 0,
                    timerCode = 4, myPseudonym = chBytes(32, 0x50), nameEnv = null,
                ),
            )
        }
        return id
    }

    fun count(table: String): Long = db.queryLong("SELECT count(*) FROM $table")!!

    override fun close() = db.close()
}

/** The text of every secret byte value a row could leak: its decimal list, its hex and its Base64. */
internal fun leaks(secret: ByteArray): List<String> = listOf(
    secret.joinToString(", "),
    secret.joinToString("") { "%02x".format(it) },
    java.util.Base64.getEncoder().encodeToString(secret),
)

/** Asserts that a row's `toString` shows none of the [secrets] (T3: no key, no pseudonym, no body in a log line). */
internal fun assertRedacted(row: Any, vararg secrets: ByteArray) {
    val text = row.toString()
    for (secret in secrets) {
        for (leak in leaks(secret)) {
            org.junit.Assert.assertFalse("${row::class.simpleName}.toString shows a secret: $text", text.contains(leak))
        }
    }
    org.junit.Assert.assertTrue("a toString that is a data class dump: $text", !text.contains("[B@"))
}
