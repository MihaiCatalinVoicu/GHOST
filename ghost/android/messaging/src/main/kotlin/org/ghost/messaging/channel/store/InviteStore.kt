package org.ghost.messaging.channel.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The invitation rows of schema v7 (Phase 10 design §6.2, §8.5, §9, §19.28, §19.29): `ch_invite_issued` (every
 * member's record of the `INVITE_ISSUED` posts of the channel, until `expiry_day`), `ch_invite_own` (the
 * sponsor's own link, for the UI, until `expiry_day`; **a password invite's link is never kept**,
 * `invite_env` is `NULL` for it, Q50 (a)) and `ch_sponsor` (the attribution of a member's admission, ADR-13,
 * kept while the member is in the channel).
 *
 * **Every read of `ch_invite_issued` and `ch_invite_own` applies the expiry filter** `expiry_day >= :today`
 * (a row lives **through** `expiry_day` and is swept from `expiry_day + 1`; the caller passes the day the
 * row must still reach, so the one-day slack for the clocks' skew is a day it chooses and not a number in
 * a query — §19.46 FIX 7): a committer must not admit an invite that expired, and the UI must not show a
 * link that did. Registered with `:storage`'s `ChannelExpiredRowLint`; the sweep's reads name the opposite
 * set. `ch_sponsor` has no deadline.
 *
 * **Voiding** (CO-5): a settle voids the unconsumed invites whose `committers_digest` no longer matches the new
 * committers (S0-15), those of an older `pw_version` when the password changed (§19.29.3) and those of a
 * sponsor who was removed (§19.7). The three are single statements here, each of them a one-way flag.
 *
 * **Every write goes through the caller's [SyncTransaction]**; no `REPLACE`, no upsert (G-DM4).
 */
internal class InviteStore {

    /** A `ch_invite_issued` row. Never shows a key or a signature (T3). */
    class IssuedRow(
        val channelId: ByteArray,
        val inviteId: ByteArray,
        val invitePk: ByteArray,
        val sponsor: ByteArray,
        val sponsorSig: ByteArray,
        val committersDigest: ByteArray,
        /** TLV 0x0015: the context's `pw_version` when the sponsor issued in a password channel; `null` for an open invite. */
        val pwVersion: Int?,
        val consumed: Boolean,
        val void: Boolean,
        val expiryDay: Long,
    ) {
        override fun toString(): String = "IssuedRow(consumed=$consumed, void=$void)"
    }

    /** A `ch_invite_own` row: the sponsor's link, wrapped under the content key; `null` for a password invite (Q50 (a)). */
    class OwnRow(val inviteId: ByteArray, val channelId: ByteArray, val inviteEnv: ByteArray?, val expiryDay: Long) {
        override fun toString(): String = "OwnRow(kept=${inviteEnv != null})"
    }

    /** A `ch_sponsor` row: who admitted the member and by which invite (ADR-13's attribution and age weighting). */
    class SponsorRow(val channelId: ByteArray, val member: ByteArray, val sponsor: ByteArray, val inviteId: ByteArray, val admittedDay: Long) {
        override fun toString(): String = "SponsorRow(redacted)"
    }

    // ------------------------------------------------------------------------------- ch_invite_issued

    /** One issued invite, if it has not expired. */
    fun issued(sql: SqlExecutor, channelId: ByteArray, inviteId: ByteArray, today: Long): IssuedRow? {
        var row: IssuedRow? = null
        sql.query(ISSUED, listOf(channelId, inviteId, today)) { r -> row = readIssued(r) }
        return row
    }

    /** The invites of a channel that have not expired, by invite id. */
    fun issuedOf(sql: SqlExecutor, channelId: ByteArray, today: Long): List<IssuedRow> {
        val out = ArrayList<IssuedRow>()
        sql.query(ISSUED_OF, listOf(channelId, today)) { r -> out += readIssued(r) }
        return out
    }

    /** Records an `INVITE_ISSUED` (`CH-INVITE`, `CH-RECV`). A repeat is [ChannelStoreError.ROW_EXISTS]. */
    fun insertIssued(
        tx: SyncTransaction,
        channelId: ByteArray,
        inviteId: ByteArray,
        invitePk: ByteArray,
        sponsor: ByteArray,
        sponsorSig: ByteArray,
        committersDigest: ByteArray,
        pwVersion: Int?,
        expiryDay: Long,
    ) {
        Fields.bytes("ch_invite_issued.invite_id", inviteId, 16)
        Fields.bytes("ch_invite_issued.invite_pk", invitePk, 32)
        Fields.bytes("ch_invite_issued.sponsor", sponsor, 32)
        Fields.bytes("ch_invite_issued.sponsor_sig", sponsorSig, 64)
        Fields.bytes("ch_invite_issued.committers_digest", committersDigest, 32)
        if (pwVersion != null) Fields.rangeInt("ch_invite_issued.pw_version", pwVersion, 1, 65_535)
        Fields.nonNegative("ch_invite_issued.expiry_day", expiryDay)
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_invite_issued(channel_id, invite_id, invite_pk, sponsor, sponsor_sig, committers_digest, pw_version, " +
                "expiry_day) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS " +
                "(SELECT 1 FROM ch_invite_issued WHERE channel_id = ? AND invite_id = ?)",
            listOf(
                channelId, inviteId, invitePk, sponsor, sponsorSig, committersDigest, pwVersion?.toLong(), expiryDay,
                channelId, inviteId,
            ),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_invite_issued")
    }

    /**
     * [insertIssued] for an `INVITE_ISSUED` that arrived (`CH-RECV`): false, with nothing written, when the channel already
     * records that invite id — the sponsor's own record of `CH-INVITE`, a replay that re-sealed the post, or a member
     * that reused an id it read (the first record stays; nothing about a record is rewritten, `ch_invite_issued_identity`).
     */
    fun recordIssued(
        tx: SyncTransaction,
        channelId: ByteArray,
        inviteId: ByteArray,
        invitePk: ByteArray,
        sponsor: ByteArray,
        sponsorSig: ByteArray,
        committersDigest: ByteArray,
        pwVersion: Int?,
        expiryDay: Long,
    ): Boolean {
        Fields.bytes("ch_invite_issued.invite_id", inviteId, 16)
        Fields.bytes("ch_invite_issued.invite_pk", invitePk, 32)
        Fields.bytes("ch_invite_issued.sponsor", sponsor, 32)
        Fields.bytes("ch_invite_issued.sponsor_sig", sponsorSig, 64)
        Fields.bytes("ch_invite_issued.committers_digest", committersDigest, 32)
        if (pwVersion != null) Fields.rangeInt("ch_invite_issued.pw_version", pwVersion, 1, 65_535)
        Fields.nonNegative("ch_invite_issued.expiry_day", expiryDay)
        return tx.sql.execUpdate(
            "INSERT INTO ch_invite_issued(channel_id, invite_id, invite_pk, sponsor, sponsor_sig, committers_digest, pw_version, " +
                "expiry_day) SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS " +
                "(SELECT 1 FROM ch_invite_issued WHERE channel_id = ? AND invite_id = ?)",
            listOf(
                channelId, inviteId, invitePk, sponsor, sponsorSig, committersDigest, pwVersion?.toLong(), expiryDay,
                channelId, inviteId,
            ),
        ) == 1
    }

    /** Set at the settle from the `GhostCommitAad` of a merged Add (CO-5): once, never undone. */
    fun markConsumed(tx: SyncTransaction, channelId: ByteArray, inviteId: ByteArray): Boolean =
        tx.sql.execUpdate(
            "UPDATE ch_invite_issued SET consumed = 1 WHERE channel_id = ? AND invite_id = ? AND consumed = 0",
            listOf(channelId, inviteId),
        ) == 1

    /** CO-5 (S0-15): the committers changed, so the unconsumed invites that name the old set are void; returns how many. */
    fun voidByDigest(tx: SyncTransaction, channelId: ByteArray, currentDigest: ByteArray): Int {
        Fields.bytes("ch_invite_issued.committers_digest", currentDigest, 32)
        return tx.sql.execUpdate(
            "UPDATE ch_invite_issued SET void = 1 WHERE channel_id = ? AND consumed = 0 AND void = 0 AND committers_digest <> ?",
            listOf(channelId, currentDigest),
        )
    }

    /**
     * CO-5 (§19.29.3): the password changed to [pwVersion], so the unconsumed invites of an older version are void;
     * with [includeOpen] the open ones too (the channel became a password channel, so an open link no longer
     * admits). Returns how many.
     */
    fun voidByPassword(tx: SyncTransaction, channelId: ByteArray, pwVersion: Int, includeOpen: Boolean): Int {
        Fields.rangeInt("ch_invite_issued.pw_version", pwVersion, 1, 65_535)
        return tx.sql.execUpdate(
            "UPDATE ch_invite_issued SET void = 1 WHERE channel_id = ? AND consumed = 0 AND void = 0 " +
                "AND ((pw_version IS NOT NULL AND pw_version < ?) OR (? = 1 AND pw_version IS NULL))",
            listOf(channelId, pwVersion.toLong(), Fields.flag(includeOpen)),
        )
    }

    /** §19.7: a merged commit that removed [sponsor] voids its unconsumed invites. Returns how many. */
    fun voidOfSponsor(tx: SyncTransaction, channelId: ByteArray, sponsor: ByteArray): Int {
        Fields.bytes("ch_invite_issued.sponsor", sponsor, 32)
        return tx.sql.execUpdate(
            "UPDATE ch_invite_issued SET void = 1 WHERE channel_id = ? AND sponsor = ? AND consumed = 0 AND void = 0",
            listOf(channelId, sponsor),
        )
    }

    /** SWEEP's read: the records of invites past their day. */
    fun expiredIssued(sql: SqlExecutor, today: Long, batch: Int): List<IssuedRow> {
        val out = ArrayList<IssuedRow>()
        sql.query(EXPIRED_ISSUED, listOf(today, batch.toLong())) { r -> out += readIssued(r) }
        return out
    }

    fun deleteIssued(tx: SyncTransaction, channelId: ByteArray, inviteId: ByteArray): Boolean =
        tx.sql.execUpdate(
            "DELETE FROM ch_invite_issued WHERE channel_id = ? AND invite_id = ?",
            listOf(channelId, inviteId),
        ) == 1

    private fun readIssued(r: SqlExecutor.Row) = IssuedRow(
        channelId = r.blob(0),
        inviteId = r.blob(1),
        invitePk = r.blob(2),
        sponsor = r.blob(3),
        sponsorSig = r.blob(4),
        committersDigest = r.blob(5),
        pwVersion = if (r.isNull(6)) null else r.long(6).toInt(),
        consumed = r.long(7) == 1L,
        void = r.long(8) == 1L,
        expiryDay = r.long(9),
    )

    // --------------------------------------------------------------------------------- ch_invite_own

    /** The sponsor's links of a channel that have not expired, for the UI. */
    fun ownInvites(sql: SqlExecutor, channelId: ByteArray, today: Long): List<OwnRow> {
        val out = ArrayList<OwnRow>()
        sql.query(OWN_OF, listOf(channelId, today)) { r -> out += readOwn(r) }
        return out
    }

    fun ownInvite(sql: SqlExecutor, inviteId: ByteArray, today: Long): OwnRow? {
        var row: OwnRow? = null
        sql.query(OWN, listOf(inviteId, today)) { r -> row = readOwn(r) }
        return row
    }

    /** `CH-INVITE`: the link wrapped under the content key, or `null` for a password invite (Q50 (a): no password oracle at rest). */
    fun insertOwn(tx: SyncTransaction, inviteId: ByteArray, channelId: ByteArray, inviteEnv: ByteArray?, expiryDay: Long) {
        Fields.bytes("ch_invite_own.invite_id", inviteId, 16)
        Fields.bytesBetweenOrNull("ch_invite_own.invite_env", inviteEnv, 29, 1024)
        Fields.nonNegative("ch_invite_own.expiry_day", expiryDay)
        val changed = tx.sql.execUpdate(
            "INSERT INTO ch_invite_own(invite_id, channel_id, invite_env, expiry_day) SELECT ?, ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_invite_own WHERE invite_id = ?)",
            listOf(inviteId, channelId, inviteEnv, expiryDay, inviteId),
        )
        if (changed != 1) throw ChannelStoreException(ChannelStoreError.ROW_EXISTS, "ch_invite_own")
    }

    /** SWEEP: the sponsor's links past their day. */
    fun deleteExpiredOwn(tx: SyncTransaction, today: Long): Int =
        tx.sql.execUpdate("DELETE FROM ch_invite_own WHERE expiry_day < ?", listOf(today))

    /** SWEEP's read of the same set, for the lint's mirror contract. */
    fun expiredOwn(sql: SqlExecutor, today: Long, batch: Int): List<OwnRow> {
        val out = ArrayList<OwnRow>()
        sql.query(EXPIRED_OWN, listOf(today, batch.toLong())) { r -> out += readOwn(r) }
        return out
    }

    private fun readOwn(r: SqlExecutor.Row) =
        OwnRow(r.blob(0), r.blob(1), if (r.isNull(2)) null else r.blob(2), r.long(3))

    // ----------------------------------------------------------------------------------- ch_sponsor

    fun sponsor(sql: SqlExecutor, channelId: ByteArray, member: ByteArray): SponsorRow? {
        var row: SponsorRow? = null
        sql.query(SPONSOR, listOf(channelId, member)) { r -> row = readSponsor(r) }
        return row
    }

    fun sponsors(sql: SqlExecutor, channelId: ByteArray): List<SponsorRow> {
        val out = ArrayList<SponsorRow>()
        sql.query(SPONSORS, listOf(channelId)) { r -> out += readSponsor(r) }
        return out
    }

    /**
     * Records who admitted [member] (from the admitting commit's `GhostCommitAad`, so every member and every
     * joiner records the same): once; a member admitted again (a rejoin, a restore) keeps its first record
     * and the call returns false.
     */
    fun putSponsor(tx: SyncTransaction, channelId: ByteArray, member: ByteArray, sponsor: ByteArray, inviteId: ByteArray, admittedDay: Long): Boolean {
        Fields.bytes("ch_sponsor.member", member, 32)
        Fields.bytes("ch_sponsor.sponsor", sponsor, 32)
        Fields.bytes("ch_sponsor.invite_id", inviteId, 16)
        Fields.nonNegative("ch_sponsor.admitted_day", admittedDay)
        return tx.sql.execUpdate(
            "INSERT INTO ch_sponsor(channel_id, member, sponsor, invite_id, admitted_day) SELECT ?, ?, ?, ?, ? " +
                "WHERE NOT EXISTS (SELECT 1 FROM ch_sponsor WHERE channel_id = ? AND member = ?)",
            listOf(channelId, member, sponsor, inviteId, admittedDay, channelId, member),
        ) == 1
    }

    /** The record is deleted at the member's removal (§8.5). */
    fun deleteSponsor(tx: SyncTransaction, channelId: ByteArray, member: ByteArray): Boolean =
        tx.sql.execUpdate("DELETE FROM ch_sponsor WHERE channel_id = ? AND member = ?", listOf(channelId, member)) == 1

    private fun readSponsor(r: SqlExecutor.Row) = SponsorRow(r.blob(0), r.blob(1), r.blob(2), r.blob(3), r.long(4))

    companion object {

        const val ISSUED: String =
            "SELECT channel_id, invite_id, invite_pk, sponsor, sponsor_sig, committers_digest, pw_version, consumed, void, " +
                "expiry_day FROM ch_invite_issued WHERE channel_id = ? AND invite_id = ? AND expiry_day >= ?"

        const val ISSUED_OF: String =
            "SELECT channel_id, invite_id, invite_pk, sponsor, sponsor_sig, committers_digest, pw_version, consumed, void, " +
                "expiry_day FROM ch_invite_issued WHERE channel_id = ? AND expiry_day >= ? ORDER BY invite_id"

        /** SWEEP's own batch. */
        const val EXPIRED_ISSUED: String =
            "SELECT channel_id, invite_id, invite_pk, sponsor, sponsor_sig, committers_digest, pw_version, consumed, void, " +
                "expiry_day FROM ch_invite_issued WHERE expiry_day < ? ORDER BY expiry_day, channel_id, invite_id LIMIT ?"

        const val OWN_OF: String =
            "SELECT invite_id, channel_id, invite_env, expiry_day FROM ch_invite_own WHERE channel_id = ? AND expiry_day >= ? " +
                "ORDER BY expiry_day, invite_id"

        const val OWN: String =
            "SELECT invite_id, channel_id, invite_env, expiry_day FROM ch_invite_own WHERE invite_id = ? AND expiry_day >= ?"

        const val EXPIRED_OWN: String =
            "SELECT invite_id, channel_id, invite_env, expiry_day FROM ch_invite_own WHERE expiry_day < ? " +
                "ORDER BY expiry_day, invite_id LIMIT ?"

        const val SPONSOR: String =
            "SELECT channel_id, member, sponsor, invite_id, admitted_day FROM ch_sponsor WHERE channel_id = ? AND member = ?"

        const val SPONSORS: String =
            "SELECT channel_id, member, sponsor, invite_id, admitted_day FROM ch_sponsor WHERE channel_id = ? ORDER BY member"
    }
}
