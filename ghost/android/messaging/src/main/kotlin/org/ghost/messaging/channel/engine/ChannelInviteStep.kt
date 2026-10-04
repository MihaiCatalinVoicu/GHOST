package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelContentFields
import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.ChannelInvite
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.api.InviteResult
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.engine.DmTime
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.InsufficientReplicasException

/**
 * **`CH-INVITE`** (Phase 10 design §6.2.1, §10.4; the password rules of §19.28 and §19.29.3), a user action.
 *
 * A member may invite if `members_may_invite` (flag bit 0) or it is a committer; **in a password channel only a
 * committer** (Q46 (b), §5.3: a context with bit 0 and bit 2 both set is invalid). The native `inviteBuild` (§10.2 fn 14)
 * draws `invite_id`, the invite seed and the salt, computes the committers digest over the current context (S0-15),
 * signs `sponsor_sig` with the pseudonym key and, in a password channel, seals the link under `Argon2id(password)` —
 * a password **nothing can check** (§19.29.3): the facade asks for it twice, and a typo yields a link nobody opens.
 *
 * In **one transaction**: the sponsor's own record of its invite (`ch_invite_own`: the link wrapped under the content
 * key for an open invite, **nothing** for a password invite — the link is shown once and never kept, Q50 (a)), the
 * `INVITE_ISSUED` record every member keeps (`ch_invite_issued`), the committers digest of the context (amended
 * `ch_channel.committers_digest`, §19.37 F-S4-2: the one native output that carries it) and the `INVITE_ISSUED` post
 * itself, encrypted and enqueued by [ChannelPostStep.compose] with the handshake TTL (§5.8, §19.21) — or kept pending
 * when the channel is not current. The link goes back to the caller and to nothing else.
 *
 * **The password** arrives as the caller's `CharArray` and reaches the native call through `ChannelPassword`, which
 * builds the NFKD UTF-8 bytes and zeroes them after the call (§19.36 row 6); this step makes no copy of its own, and the
 * caller's array stays the caller's to zero. The residue `java.text.Normalizer` leaves for a non-ASCII password is
 * F-S2b-3's, recorded in §19.36 and unchanged here.
 */
internal class ChannelInviteStep(
    private val env: ChannelEnv,
    private val postStep: ChannelPostStep,
) {
    private val stores = env.stores

    fun invite(channelId: ByteArray, expiryDays: Int, password: CharArray?): InviteResult {
        if (expiryDays !in 1..MAX_EXPIRY_DAYS) return InviteResult(InviteResult.Status.INVALID, null)
        val now = env.now()
        val day = DmTime.day(now)
        val content = env.keys.content() ?: return unavailable()
        val row = env.database.transaction { tx -> stores.channels.channel(tx.sql, channelId) }
        if (row == null || row.state != ChannelState.ACTIVE) return InviteResult(InviteResult.Status.NOT_MEMBER, null)
        val opened = env.contexts.open(channelId) ?: return unavailable()
        val p = opened.pseudonym
        if (!p.contentEquals(row.myPseudonym)) return unavailable()
        val rows = MlsRows.of(env.database.transaction { tx -> stores.mls.rows(tx.sql, channelId, day) })
        val roster = opened.crypto.roster(channelId, rows, day.toInt()).valueOrNull() ?: return unavailable()
        val context = roster.context
        val committer = context.committers.any { it.contentEquals(p) }
        val passwordChannel = context.flags and ChannelEnv.FLAG_PASSWORD != 0
        val membersMayInvite = context.flags and ChannelEnv.FLAG_MEMBERS_MAY_INVITE != 0
        // §6.2.1 with Q46 (b): a member invites when members may, a committer always; in a password channel only a committer.
        if (!committer && (passwordChannel || !membersMayInvite)) return InviteResult(InviteResult.Status.NOT_ALLOWED, null)
        if (passwordChannel && password == null) return InviteResult(InviteResult.Status.PASSWORD_REQUIRED, null)
        if (!passwordChannel && password != null) return InviteResult(InviteResult.Status.INVALID, null)
        val generation = env.database.transaction { tx -> stores.generations.current(tx.sql, channelId, day) }
            ?: return unavailable()
        val expiryDay = day + expiryDays
        val built = when (
            val b = opened.crypto.inviteBuild(
                channelId, rows, generation.gEnv, generation.generation.toInt(), expiryDay.toInt(), password,
                carryName = false, day = day.toInt(),
            )
        ) {
            is MlsOutcome.Ok -> b.value
            is MlsOutcome.Refused -> return when (b.code) {
                MlsCode.PASSWORD_REQUIRED -> InviteResult(InviteResult.Status.PASSWORD_REQUIRED, null)
                MlsCode.INVALID_POLICY, MlsCode.NON_CANONICAL -> InviteResult(InviteResult.Status.INVALID, null)
                else -> unavailable()
            }
        }
        val link = ChannelInvite.toLink(built.invite).toByteArray(Charsets.US_ASCII)
        built.invite.fill(0)
        val issued = ChannelContentFields(
            kind = ChannelPostStep.KIND_INVITE_ISSUED,
            opId = env.random.bytes(ChannelPostStep.OP_ID_BYTES),
            authorMinute = Math.floorDiv(now, DmTime.MINUTE),
            timerCode = row.timerCode,
            inviteId = built.inviteId,
            invitePk = built.invitePk,
            expiryDay = built.expiryDay,
            sponsorSig = built.sponsorSig,
            committersDigest = built.committersDigest,
            pwVersion = built.pwVersion,
        )
        val encoded = ChannelCrypto.contentEncode(issued).valueOrNull() ?: return unavailable()
        return try {
            env.database.transaction { tx ->
                val fresh = stores.channels.channel(tx.sql, channelId)
                if (fresh == null || fresh.state != ChannelState.ACTIVE) {
                    return@transaction InviteResult(InviteResult.Status.NOT_MEMBER, null)
                }
                // Q50 (a): a password invite's link is not kept; an open one is, for the UI, until its expiry.
                val inviteEnv = if (password == null) env.seal(content, ChannelAd.ownInvite(built.inviteId), link) else null
                stores.invites.insertOwn(tx, built.inviteId, channelId, inviteEnv, built.expiryDay)
                stores.invites.insertIssued(
                    tx, channelId, built.inviteId, built.invitePk, p, built.sponsorSig, built.committersDigest,
                    built.pwVersion, built.expiryDay,
                )
                stores.channels.setCommittersDigest(tx, channelId, built.committersDigest)
                postStep.compose(tx, fresh, opened, content, issued, encoded, handshake = true, now = now)
                InviteResult(InviteResult.Status.CREATED, link)
            }
        } catch (e: InsufficientReplicasException) {
            InviteResult(InviteResult.Status.NO_REPLICAS, null)
        } catch (e: StorageFullException) {
            InviteResult(InviteResult.Status.STORAGE_FULL, null)
        } finally {
            encoded.fill(0)
        }
    }

    private fun unavailable() = InviteResult(InviteResult.Status.CRYPTO_UNAVAILABLE, null)

    override fun toString(): String = "ChannelInviteStep"

    companion object {
        /** §5.9: an invite expires at `expiry_day ≤ issue day + 7`. */
        const val MAX_EXPIRY_DAYS: Int = 7
    }
}
