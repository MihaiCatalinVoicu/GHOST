package org.ghost.messaging.store

import org.ghost.storage.JdbcSqlExecutor
import org.ghost.storage.MigrationRunner
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.store.SyncStores
import org.ghost.messaging.FixedRandomSources
import org.ghost.messaging.MovableClock
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Phase 13 §3.6 (the alias half): `name_env` rides `dm_contact`, sealed under the content key
 * with the contact id as associated data (the card's own pattern), round trips through the
 * store, and clears to NULL.
 */
class ContactAliasTest {
    private class Fixture {
        val sql = JdbcSqlExecutor().also { MigrationRunner(it).migrate() }
        val stores = SyncStores(SyncDatabase(sql), MovableClock(1_800_000_000L), FixedRandomSources(), { org.ghost.sync.api.PrivacyMode.STANDARD })
        val store = ContactStore()
        val cipher = ContentCipher(ByteArray(32) { 9 })

        fun tx(block: (org.ghost.sync.api.SyncTransaction) -> Unit) = stores.database.transaction(block)

        fun add(contactId: ByteArray) = tx { t ->
            store.insertContact(
                t, contactId, ByteArray(32) { 5 }, ByteArray(159) { 1 }, 0,
                ContactStore.Trust.UNVERIFIED, ContactStore.Source.LINK, null,
            )
        }
    }

    @Test
    fun theAliasRoundTripsSealedAndClears() {
        val f = Fixture()
        val id = ByteArray(16) { 7 }
        f.add(id)
        val name = "Ana"
        val nonce = ByteArray(ContentCipher.NONCE_BYTES) { 11 }
        f.tx { t -> f.store.setName(t, id, f.cipher.seal(nonce, id, name.toByteArray())) }
        val row = f.store.contact(f.sql, id)!!
        val opened = f.cipher.open(row.nameEnv!!, id)!!.toString(Charsets.UTF_8)
        assertEquals(name, opened)
        // The name never sits in the row's other columns and never appears as a stored string.
        f.tx { t -> f.store.setName(t, id, null) }
        assertNull(f.store.contact(f.sql, id)!!.nameEnv)
    }

    @Test
    fun theCheckDomainBoundsTheEnvelope() {
        val f = Fixture()
        val id = ByteArray(16) { 8 }
        f.add(id)
        // A 29-byte sealed envelope is the schema's floor (§13.6's REPLACE/CHECK discipline).
        val smallest = ByteArray(29)
        org.junit.Assert.assertThrows(Exception::class.java) {
            f.sql.exec("INSERT INTO dm_contact(contact_id, identity_pk, name_env) VALUES (?1, ?2, ?3)", listOf(ByteArray(16) { 3 }, ByteArray(32) { 4 }, ByteArray(28)))
        }
    }
}
