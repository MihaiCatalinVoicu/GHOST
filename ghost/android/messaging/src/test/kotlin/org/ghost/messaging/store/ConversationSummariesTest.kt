package org.ghost.messaging.store

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.engine.KeyedRandomSources
import org.ghost.sync.port.SyncClock
import org.ghost.sync.store.SyncStores
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Phase 13 §3.6 (`conversationSummaries`): the list query is a pure read - live unread count and
 * the newest live incoming minute per conversation, the expiry filter riding it (an expired
 * unread row neither counts nor dates), and never a text (T33).
 */
class ConversationSummariesTest {
    private class Db {
        val sql = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
        private val stores = SyncStores(
            SyncDatabase(sql),
            object : SyncClock {
                override fun epochSeconds() = 1_800_000_000L
                override fun monotonicMillis() = 1_800_000_000_000L
            },
            KeyedRandomSources(ByteArray(32) { 3 }),
            { PrivacyMode.STANDARD },
        )
        val contact = ByteArray(16) { 7 }
        val conversation = ByteArray(16) { 9 }

        fun tx(block: (SyncTransaction) -> Unit) = stores.database.transaction(block)

        fun seed() {
            tx { t ->
                ContactStore().insertContact(
                    t, contact, ByteArray(32) { 5 }, ByteArray(159) { 1 }, 0,
                    ContactStore.Trust.UNVERIFIED, ContactStore.Source.LINK, null,
                )
            }
            sql.exec(
                "INSERT INTO dm_conversation(conversation_id, contact_id, timer_code, timer_version) VALUES (?1, ?2, 0, 0)",
                listOf(conversation, contact),
            )
        }

        fun insertMessage(id: Int, minute: Long, direction: String, state: String, deleteAt: Long?, timerCode: Int = 0) {
            sql.exec(
                "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, sort_minute, minute_index, timer_code, body_env, state, expire_at_minute, unread_deadline_minute, delete_at_minute) " +
                    "VALUES (?1, ?2, ?3, 1, ?4, ?4, 0, ?8, ?5, ?6, ?7, ?7, ?7)",
                listOf(ByteArray(16) { id.toByte() }, conversation, direction, minute, ByteArray(30), state, deleteAt, timerCode),
            )
        }
    }

    @Test
    fun unreadCountsAndNewestMinuteFollowLiveRowsOnly() {
        val db = Db()
        db.seed()
        val store = MessageStore()
        val now = 10_000L
        val contacts = listOf(db.contact)
        val of = { _: ByteArray -> db.conversation }

        val empty = store.conversationSummaries(db.sql, contacts, of, now)
        assertEquals(0, empty[db.contact]!!.first)
        assertNull(empty[db.contact]!!.second)

        db.insertMessage(1, 9_000, "in", "unread", null)
        db.insertMessage(2, 9_060, "in", "unread", null)
        db.insertMessage(3, 8_400, "in", "unread", 8_460, timerCode = 1) // expired: must not count or date
        db.insertMessage(4, 9_120, "out", "sent", null) // outgoing: never counts
        val live = store.conversationSummaries(db.sql, contacts, of, now)
        assertEquals(2, live[db.contact]!!.first)
        assertEquals(9_060L, live[db.contact]!!.second)

        db.sql.exec(
            "UPDATE dm_message SET state = 'read' WHERE conversation_id = ?1 AND direction = 'in' AND author_minute = 9060",
            listOf(db.conversation),
        )
        val after = store.conversationSummaries(db.sql, contacts, of, now)
        assertEquals(1, after[db.contact]!!.first)
        assertEquals(9_060L, after[db.contact]!!.second)
    }
}
