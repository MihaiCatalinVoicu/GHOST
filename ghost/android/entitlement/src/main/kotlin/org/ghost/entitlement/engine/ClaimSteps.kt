package org.ghost.entitlement.engine

import org.ghost.entitlement.api.ClaimId
import org.ghost.entitlement.port.IssuerPort
import org.ghost.entitlement.store.ClaimRow
import org.ghost.entitlement.store.ClaimStore
import org.ghost.entitlement.store.StateStore
import org.ghost.entitlement.store.TokenStore
import org.ghost.network.EntitlementCrypto
import org.ghost.network.NetworkException
import org.ghost.network.TorIssuerTransport
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.store.Time
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Payout claims (design §9.4, §19.22 point 2): the address is validated locally (Rust) and must not
 * have been used before (salted hash in `ent_payout_used`); claim id, address and the reserved own
 * credits are written ahead; the `ClaimPayout` runs alone in a quiet run at a random time, at most one
 * claim per week, and retries once by the same claim id with identical bytes at a time drawn before the
 * first send (§19.11 applied to claims: an issuer that stalls gets two linked samples at most). The
 * address counts as used from the write-ahead of its first send, whatever the answers: a claim whose
 * answers were all lost may still be queued and paid, and the workstation refuses a repeated address.
 */
internal class ClaimSteps(private val c: EngineContext) {

    private class ClaimCall(val credits: List<ByteArray>, val address: String)

    fun create(address: String, now: Long): ClaimId? {
        val info = try {
            c.crypto.validateAddress(address, EntitlementCrypto.PURPOSE_PAYOUT)
        } catch (e: NetworkException) {
            null
        } ?: return null
        if (info.network != c.summary.network || address.length != ADDRESS_CHARS) return null
        val id = c.random.bytes(EngineContext.ID_BYTES)
        val jitter = (c.random.uniform() * CLAIM_SPREAD).toLong()
        val created = c.tx { tx -> insert(tx, id, address, now, jitter) }
        return if (created) ClaimId(id) else null
    }

    private fun insert(tx: SyncTransaction, id: ByteArray, address: String, now: Long, jitter: Long): Boolean {
        val st = c.state.read(tx) ?: return false
        if (c.claims.payoutUsed(tx, addressHash(st.payoutSalt(), address)) || c.claims.open(tx) != null) return false
        val week = Grid.week(now)
        val credits = c.tokens.freshCredits(tx).filter { Pricing.accepted(it.epoch, week) }.take(c.summary.constants.maxClaimCredits)
        if (credits.size < c.summary.constants.minClaimCredits) return false
        val earliest = maxOf(now, (c.claims.latestTerminalDay(tx)?.let { (it + CLAIM_INTERVAL_DAYS) * Grid.DAY } ?: now))
        c.claims.insert(tx, id, address, Time.ceilMinute(earliest + jitter))
        credits.forEach { c.tokens.reserveCredit(tx, it.nullifier(), TokenStore.FOR_CLAIM, id) }
        return true
    }

    /** One `ClaimPayout` attempt of claim [id]. */
    fun step(issuer: IssuerPort, id: ByteArray, now: Long) = c.memory.flight(id) {
        val call = c.tx { tx -> prepare(tx, id, now) } ?: return@flight
        val answer = try {
            issuer.claimPayout(id, call.credits, call.address)
        } catch (e: NetworkException) {
            c.tx { tx -> failed(tx, id, RetryPolicy.classify(e.category), now) }
            return@flight
        } catch (e: IllegalArgumentException) {
            c.tx { tx -> failed(tx, id, Failure.REJECTED, now) }
            return@flight
        }
        c.tx { tx -> apply(tx, id, call, answer, now) }
    }

    private fun prepare(tx: SyncTransaction, id: ByteArray, now: Long): ClaimCall? {
        val claim = c.claims.get(tx, id) ?: return null
        if (claim.state != ClaimStore.PREPARED) return null
        if (claim.attempt >= RetryPolicy.CALL_ATTEMPTS) {
            fail(tx, claim, now)
            return null
        }
        c.claims.countAttempt(tx, id, claim.attempt, checkNotNull(RetryPolicy.nextDueAfterSend(claim.attempt, claim.nextDueMinute, now, c.random::uniform)))
        val address = checkNotNull(claim.payoutAddress)
        // Written ahead with the send: once a ClaimPayout may have left the device, the issuer may queue
        // and pay it even if every answer is lost, so the address is used whatever the answers (§9.4).
        markUsed(tx, address, Grid.day(now))
        val credits = c.tokens.reservedCredits(tx, TokenStore.FOR_CLAIM, id).map { it.token() }
        return ClaimCall(credits, address)
    }

    /** The salted hash of [address] joins `ent_payout_used` for [ClaimStore.PAYOUT_USED_DAYS] (a no-op when present). */
    private fun markUsed(tx: SyncTransaction, address: String, today: Long) {
        val salt = checkNotNull(c.state.read(tx)).payoutSalt()
        c.claims.insertPayoutUsed(tx, addressHash(salt, address), today + ClaimStore.PAYOUT_USED_DAYS)
    }

    private fun apply(tx: SyncTransaction, id: ByteArray, call: ClaimCall, answer: TorIssuerTransport.ClaimAnswer, now: Long) {
        val claim = c.claims.get(tx, id) ?: return
        if (claim.state != ClaimStore.PREPARED) return
        val today = Grid.day(now)
        when (answer.result) {
            TorIssuerTransport.CLAIM_QUEUED -> {
                c.claims.queued(tx, id, answer.queuedAtomic, today)
                markUsed(tx, call.address, today)
                c.tokens.deleteReservedCredits(tx, TokenStore.FOR_CLAIM, id)
                c.memory.clearMalformed(id)
            }
            TorIssuerTransport.CLAIM_CREDITS_SPENT -> {
                val sent = c.tokens.reservedCredits(tx, TokenStore.FOR_CLAIM, id)
                c.claims.failed(tx, id, today)
                sent.forEachIndexed { i, t -> if (i < MASK_BITS && (answer.spentMask ushr i) and 1L == 1L) c.tokens.delete(tx, t.nullifier()) }
                c.tokens.releaseCredits(tx, TokenStore.FOR_CLAIM, id)
            }
            TorIssuerTransport.CLAIM_CONFLICT -> {
                c.alarm(tx, StateStore.ALARM_ISSUER_MISMATCH)
                fail(tx, claim, now)
            }
            // One pending claim per address, or an invalid address (§19.22 point 2): the credits are released.
            TorIssuerTransport.CLAIM_ADDRESS_REJECTED -> fail(tx, claim, now)
            else -> malformed(tx, claim, now)
        }
    }

    private fun failed(tx: SyncTransaction, id: ByteArray, failure: Failure, now: Long) {
        val claim = c.claims.get(tx, id) ?: return
        if (claim.state != ClaimStore.PREPARED) return
        when (failure) {
            Failure.TRANSIENT -> if (claim.attempt >= RetryPolicy.CALL_ATTEMPTS) fail(tx, claim, now)
            Failure.UNAUTHORIZED, Failure.REJECTED -> fail(tx, claim, now)
            Failure.MALFORMED -> malformed(tx, claim, now)
        }
    }

    private fun malformed(tx: SyncTransaction, claim: ClaimRow, now: Long) {
        if (c.memory.firstMalformed(claim.claimId())) return
        c.alarm(tx, StateStore.ALARM_ISSUER_MISMATCH)
        fail(tx, claim, now)
    }

    /** The claim fails and its credits return to fresh (the trigger allows it for a failed claim only). */
    private fun fail(tx: SyncTransaction, claim: ClaimRow, now: Long) {
        c.claims.failed(tx, claim.claimId(), Grid.day(now))
        c.tokens.releaseCredits(tx, TokenStore.FOR_CLAIM, claim.claimId())
    }

    override fun toString(): String = "ClaimSteps"

    companion object {
        private const val ADDRESS_CHARS = 95
        private const val CLAIM_SPREAD: Long = 24 * Grid.HOUR
        private const val CLAIM_INTERVAL_DAYS = 7L
        private const val MASK_BITS = 64

        /** HMAC-SHA256(payout_salt, address): the salted hash of `ent_payout_used` (RP V11). */
        fun addressHash(salt: ByteArray, address: String): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            return mac.doFinal(address.toByteArray(Charsets.US_ASCII))
        }
    }
}
