package org.ghost.entitlement.store

import org.ghost.sync.api.SyncTransaction

/**
 * The device's append-only memory of accepted schedules (ES rule 5, design §3.1, §19.2, §19.20 point 2,
 * §19.21 point 4): `ent_key` maps (kind, epoch) to a key id; `ent_schedule_fact` holds the slot-set
 * digest of every covered week, the price digest of every covered price epoch, and every remembered
 * revocation (`revoked_<kind>`, digest = the revoked key's id). Rows are only ever inserted, with a
 * plain INSERT after a read (the schema refuses UPDATE, DELETE and REPLACE).
 */
internal class KeyStore {

    /** Remembered keys by (JNI kind, epoch). */
    fun keys(tx: SyncTransaction): Map<Pair<Int, Long>, ByteArray> =
        tx.sql.rows("SELECT kind, epoch, key_id FROM ent_key") { (Kinds.of(it.string(0)) to it.long(1)) to it.blob(2) }.toMap()

    /** Remembered facts by (fact, epoch). */
    fun facts(tx: SyncTransaction): Map<Pair<String, Long>, ByteArray> =
        tx.sql.rows("SELECT fact, epoch, digest FROM ent_schedule_fact") { (it.string(0) to it.long(1)) to it.blob(2) }.toMap()

    fun insertKey(tx: SyncTransaction, kind: Int, epoch: Long, keyId: ByteArray) {
        val code = Kinds.code(kind)
        check(tx.sql.single("SELECT 1 FROM ent_key WHERE kind = ?1 AND epoch = ?2", listOf(code, epoch)) { 1 } == null) { "key already remembered" }
        tx.sql.updateExactly(1, "INSERT INTO ent_key(kind, epoch, key_id) VALUES (?1, ?2, ?3)", listOf(code, epoch, keyId))
    }

    fun insertFact(tx: SyncTransaction, fact: String, epoch: Long, digest: ByteArray) {
        check(tx.sql.single("SELECT 1 FROM ent_schedule_fact WHERE fact = ?1 AND epoch = ?2", listOf(fact, epoch)) { 1 } == null) {
            "fact already remembered"
        }
        tx.sql.updateExactly(1, "INSERT INTO ent_schedule_fact(fact, epoch, digest) VALUES (?1, ?2, ?3)", listOf(fact, epoch, digest))
    }

    companion object {
        const val FACT_SLOTS = "slots"
        const val FACT_PRICE = "price"

        /** The revocation fact of a (JNI) token kind: access weeks, invite and credit epochs are separate indices. */
        fun revokedFact(kind: Int): String = "revoked_" + Kinds.code(kind)
    }
}
