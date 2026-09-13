package org.ghost.entitlement.engine

import org.ghost.entitlement.store.KeyStore
import org.ghost.entitlement.store.StateStore
import org.ghost.entitlement.store.sha256
import org.ghost.network.EntitlementCrypto.ScheduleSummary
import org.ghost.sync.api.SyncTransaction
import java.nio.ByteBuffer

/**
 * ES rule 5 on the device (design §3.1, §19.2, §19.20 point 2, §19.21 point 4). The schedule built
 * into the native library is accepted when, against the remembered facts:
 *  - its seq does not go backwards, and a remembered seq comes with the remembered digest;
 *  - every remembered (kind, epoch) keeps its key id, and no key id reappears under another (kind, epoch);
 *  - every covered week keeps its slot-number set and every covered price epoch its price;
 *  - every remembered revocation is still listed.
 * Then its new keys and facts are inserted (plain INSERT after a read) and `ent_state` records its seq
 * and digest (created with a fresh payout salt at the first acceptance). Otherwise nothing is written
 * but the persistent `SCHEDULE_CONFLICT` alarm, and the engine stays inert. The digests use the
 * issuer's `es_memory` encodings: slots = SHA-256 of the slot bytes in ascending order, price =
 * SHA-256 of the price as u64 big-endian, revocation = the revoked key's id.
 */
internal class ScheduleAcceptance(private val keys: KeyStore, private val state: StateStore) {

    enum class Result {
        ACCEPTED,
        CONFLICT,

        /** A regtest schedule: the production client refuses it (rule 6); no alarm. */
        REFUSED,
    }

    fun accept(tx: SyncTransaction, s: ScheduleSummary, freshSalt: () -> ByteArray): Result {
        if (s.network == REGTEST) return Result.REFUSED
        val st = state.read(tx)
        val rememberedKeys = keys.keys(tx)
        val facts = keys.facts(tx)
        if (conflicts(st?.scheduleSeq, st?.scheduleDigest(), rememberedKeys, facts, s)) {
            state.raiseAlarm(tx, StateStore.ALARM_SCHEDULE_CONFLICT)
            return Result.CONFLICT
        }
        for (k in s.keys) if (rememberedKeys[k.kind to k.epoch] == null) keys.insertKey(tx, k.kind, k.epoch, k.keyId())
        for (w in s.firstWeek..s.lastWeek) {
            if (facts[KeyStore.FACT_SLOTS to w] == null) keys.insertFact(tx, KeyStore.FACT_SLOTS, w, slotDigest(s.slotsInWeek(w)))
        }
        for (p in s.prices) {
            if (facts[KeyStore.FACT_PRICE to p.priceEpoch] == null) keys.insertFact(tx, KeyStore.FACT_PRICE, p.priceEpoch, priceDigest(p.packPriceAtomic))
        }
        for (r in s.revoked) {
            val fact = KeyStore.revokedFact(r.kind)
            if (facts[fact to r.epoch] == null) keys.insertFact(tx, fact, r.epoch, checkNotNull(keyIdOf(s, rememberedKeys, r.kind, r.epoch)))
        }
        when {
            st == null -> state.create(tx, s.seq, s.digest(), freshSalt())
            s.seq > st.scheduleSeq -> state.updateSchedule(tx, s.seq, s.digest())
        }
        return Result.ACCEPTED
    }

    private fun conflicts(
        seq: Long?,
        digest: ByteArray?,
        rememberedKeys: Map<Pair<Int, Long>, ByteArray>,
        facts: Map<Pair<String, Long>, ByteArray>,
        s: ScheduleSummary,
    ): Boolean {
        if (seq != null && (s.seq < seq || (s.seq == seq && !s.digest().contentEquals(digest)))) return true
        for (k in s.keys) {
            val id = k.keyId()
            val remembered = rememberedKeys[k.kind to k.epoch]
            if (remembered != null && !remembered.contentEquals(id)) return true
            if (rememberedKeys.any { (at, other) -> at != (k.kind to k.epoch) && other.contentEquals(id) }) return true
        }
        for (w in s.firstWeek..s.lastWeek) {
            val f = facts[KeyStore.FACT_SLOTS to w]
            if (f != null && !f.contentEquals(slotDigest(s.slotsInWeek(w)))) return true
        }
        for (p in s.prices) {
            val f = facts[KeyStore.FACT_PRICE to p.priceEpoch]
            if (f != null && !f.contentEquals(priceDigest(p.packPriceAtomic))) return true
        }
        for ((at, _) in facts) {
            val kind = REVOKED_KINDS[at.first] ?: continue
            if (s.revoked.none { it.kind == kind && it.epoch == at.second }) return true
        }
        // A revocation must name a key the device knows (an ES revokes only keys it lists): fail closed.
        return s.revoked.any { keyIdOf(s, rememberedKeys, it.kind, it.epoch) == null }
    }

    private fun keyIdOf(s: ScheduleSummary, remembered: Map<Pair<Int, Long>, ByteArray>, kind: Int, epoch: Long): ByteArray? =
        s.keys.firstOrNull { it.kind == kind && it.epoch == epoch }?.keyId() ?: remembered[kind to epoch]

    override fun toString(): String = "ScheduleAcceptance"

    companion object {
        private const val REGTEST = 3

        private val REVOKED_KINDS: Map<String, Int> = listOf(
            org.ghost.network.EntitlementCrypto.KIND_ACCESS,
            org.ghost.network.EntitlementCrypto.KIND_INVITE,
            org.ghost.network.EntitlementCrypto.KIND_CREDIT,
        ).associateBy { KeyStore.revokedFact(it) }

        /** SHA-256 of the week's slot numbers, one byte each, ascending (the issuer's `slot_digest`). */
        fun slotDigest(slots: List<Int>): ByteArray = sha256(ByteArray(slots.size) { slots.sorted()[it].toByte() })

        /** SHA-256 of the price as u64 big-endian (the issuer's `price_digest`). */
        fun priceDigest(price: Long): ByteArray = sha256(ByteBuffer.allocate(8).putLong(price).array())
    }
}
