package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelContentFields
import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.ChannelStoreError
import org.ghost.messaging.channel.store.ChannelStoreException
import org.ghost.messaging.channel.store.Direction
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.engine.DmTimers
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.InsufficientReplicasException

/**
 * **`CH-REVEAL`** (Phase 10 design §6.9, §10.4), a user action: the member's opt-in reveal of its
 * pseudonym to **one chosen member M**, in one transaction.
 *
 * The native `revealSeal` (§10.2 fn 16) builds the `RevealPayload` — the own DM contact card v2
 * (the card `ownCard` hands out, so the recipient's `addContact` dedups against it, R-E3) and the
 * two signatures: `sig_id` under the `ghost1` identity key (made in Rust with the DM context's
 * key, ADR-35's X-21 rule — the `dmHandle` argument names that context; Kotlin never sees the
 * seed) and `sig_ps` under the channel's pseudonym key — and HPKE-seals it (RFC 9180 base,
 * KEM 0x0020, KDF 0x0001, AEAD 0x0003, through the provider's `hpke_seal`) to M's current
 * `box_pk` as M's current leaf publishes it. The result is a `REVEAL` post: a normal post of the
 * channel for the floor and the TTL of §5.7/§5.8 (not an administrative post — §19.21 names
 * `INVITE_ISSUED` and `LEAVE` only), encrypted and enqueued by [ChannelPostStep.compose], or kept
 * pending when the channel is not current (§6.3.1). The sender's `ch_reveal` row is written in the
 * same transaction, with the deletion deadline the REVEAL post's timer gives it (§8.5: the row
 * follows its post's timer, whatever the post's state).
 *
 * Gate G-M5: this file makes no restricted call; the enqueue is [ChannelPostStep.compose]'s, as
 * for CH-INVITE's post.
 */
internal class ChannelRevealStep(
    private val env: ChannelEnv,
    private val postStep: ChannelPostStep,
) {
    private val stores = env.stores

    /** What [reveal] did (§10.3's `Result` shape; the facade maps it in Phase 13). */
    enum class RevealResult {
        /** The REVEAL post is out (or pending) and the sender's `ch_reveal` row is written. */
        REVEALED,

        /** Nothing revealed: no active channel, the recipient is no current member or the member
         * itself, or the op could not be enqueued this turn. */
        NOTHING,

        /** The context, the content key or the DM context is not available. */
        UNAVAILABLE,
    }

    /**
     * The member reveals itself to [recipient] (a member pseudonym `P`). One transaction: the
     * `ch_reveal(direction = out, peer = P)` row (its only time the deletion deadline, §19.21) and,
     * through [ChannelPostStep.compose], the REVEAL post's op — the post itself carries no
     * `ch_post` row (a REVEAL derives only its `ch_reveal` row, §8.5, like an `INVITE_ISSUED`
     * derives only its invite record).
     */
    fun reveal(channelId: ByteArray, recipient: ByteArray): RevealResult {
        val now = env.now()
        val day = DmTime.day(now)
        val content = env.keys.content() ?: return RevealResult.UNAVAILABLE
        val row = env.database.transaction { tx -> stores.channels.channel(tx.sql, channelId) }
            ?: return RevealResult.NOTHING
        if (row.state != ChannelState.ACTIVE) return RevealResult.NOTHING
        val opened = env.contexts.open(channelId) ?: return RevealResult.UNAVAILABLE
        if (!opened.pseudonym.contentEquals(row.myPseudonym)) return RevealResult.UNAVAILABLE
        val dmHandle = env.dmContext.handleOrNull() ?: return RevealResult.UNAVAILABLE
        if (recipient.contentEquals(opened.pseudonym)) return RevealResult.NOTHING
        val rows = MlsRows.of(env.database.transaction { tx -> stores.mls.rows(tx.sql, channelId, day) })
        val member = opened.crypto.roster(channelId, rows, day.toInt()).valueOrNull()
            ?.members?.firstOrNull { it.pseudonym.contentEquals(recipient) }
            ?: return RevealResult.NOTHING
        // A member's current leaf always publishes a box key (§5.4); one without is a state that
        // cannot seal a reveal — refuse rather than encrypt to nothing.
        val recipientBoxPk = member.boxPk ?: return RevealResult.NOTHING
        val fields = ChannelContentFields(
            kind = ChannelPostStep.KIND_REVEAL,
            opId = env.random.bytes(ChannelPostStep.OP_ID_BYTES),
            authorMinute = Math.floorDiv(now, DmTime.MINUTE),
            timerCode = row.timerCode,
            hpkeEnc = null,
            ciphertext = null,
        )
        // The op id is the HPKE aad: the reveal binds to the post that carries it.
        val sealed = when (
            val s = opened.crypto.revealSeal(
                channelId, dmHandle, recipient, recipientBoxPk, fields.authorMinute.toInt(), fields.opId,
            )
        ) {
            is MlsOutcome.Ok -> s.value
            is MlsOutcome.Refused -> return when (s.code) {
                MlsCode.NON_CANONICAL -> RevealResult.NOTHING
                else -> RevealResult.UNAVAILABLE
            }
        }
        val withBody = ChannelContentFields(
            kind = fields.kind,
            opId = fields.opId,
            authorMinute = fields.authorMinute,
            timerCode = fields.timerCode,
            hpkeEnc = sealed.hpkeEnc,
            ciphertext = sealed.ciphertext,
        )
        val encoded = when (val e = ChannelCrypto.contentEncode(withBody)) {
            is MlsOutcome.Ok -> e.value
            is MlsOutcome.Refused -> return RevealResult.UNAVAILABLE
        }
        return try {
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                if (fresh == null || fresh.state != ChannelState.ACTIVE) return@transaction RevealResult.NOTHING
                postStep.compose(tx, fresh, opened, content, withBody, encoded, handshake = false, now = now)
                // The row follows the REVEAL post's timer from its author minute (§8.5), whatever
                // the post's state — pending posts encrypt at the first current transaction, and
                // the row's life is the post's, not the op's.
                stores.posts.putReveal(
                    tx, channelId, Direction.OUT, recipient,
                    DmTimers.senderExpireMinute(withBody.authorMinute * DmTime.MINUTE, fresh.timerCode),
                )
                RevealResult.REVEALED
            }
        } catch (e: InsufficientReplicasException) {
            RevealResult.NOTHING
        } catch (e: StorageFullException) {
            RevealResult.UNAVAILABLE
        } catch (e: ChannelStoreException) {
            if (e.error != ChannelStoreError.LIMIT) throw e
            // §6.3.5: the REVEAL post would be the 257th pending one; the transaction rolled the row back.
            RevealResult.NOTHING
        } finally {
            encoded.fill(0)
        }
    }

    override fun toString(): String = "ChannelRevealStep"
}
