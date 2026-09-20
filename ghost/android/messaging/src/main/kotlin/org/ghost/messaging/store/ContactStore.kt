package org.ghost.messaging.store

import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.SyncTransaction

/**
 * The contact-side rows of schema v5 (Phase 9 design §13.6 step 5): `dm_contact`,
 * `dm_conversation`, `dm_bundle_candidate`, `dm_pair_key`, `dm_pair_offer`, `dm_peer_pq` and
 * `dm_orphan_namespace`.
 *
 * **Every write goes through the caller's [SyncTransaction]**, like [OwnerStore]: the steps of
 * §7.2 are each exactly one `SyncDatabase.transaction`, and a DAO that opened one of its own
 * would break the atomicity SEND and RECV rest on.
 *
 * **No `REPLACE`, no upsert** (gate G-DM4): a row that may or may not exist is a guarded `UPDATE`
 * whose changed-row count decides whether an `INSERT` follows.
 *
 * **No read of an expiring table.** None of these tables carries `delete_at_minute`; the reads of
 * `dm_message` are [MessageStore]'s, and they are registered with `:storage`'s `DmExpiredRowLint`
 * (§22.10 item 3).
 */
internal class ContactStore {

    /** `dm_contact.trust_state` (§8.3). */
    enum class Trust(val wire: String) {
        /** An unknown card holder wrote first and the user has not decided (§12.3). */
        REQUEST("request"),

        /** A card that arrived as a link, or an accepted request (§12.1). */
        UNVERIFIED("unverified"),

        /** A card scanned in person, or a compared safety number (§8.4). */
        VERIFIED("verified"),

        /** A key change is pending a user decision; sending is refused (§8.3, slice S8). */
        CHANGED("changed"),

        /** Locally blocked: no send, no display, the card erased (§12.4). */
        BLOCKED("blocked"),

        /** A valid revocation certificate arrived; terminal (§8.5, slice S8). */
        REVOKED("revoked"),
        ;

        internal companion object {
            fun of(wire: String): Trust = entries.first { it.wire == wire }
        }
    }

    /** `dm_contact.source` (§12.1). */
    enum class Source(val wire: String) {
        /** Scanned in person: starts `verified` (§8.4). */
        QR_IN_PERSON("qr_in_person"),

        /** A `ghost://contact/` link through another channel: starts `unverified`. */
        LINK("link"),

        /** The card inside an intro envelope from an unknown holder (§12.3). */
        REQUEST("request"),
        ;

        internal companion object {
            fun of(wire: String): Source = entries.first { it.wire == wire }
        }
    }

    /** `dm_contact.establishment` (§13.5). */
    enum class Establishment(val wire: String) {
        /** A card and nothing else: no fetch has run (rule R-E1). */
        CARD_ONLY("card_only"),

        /** A bundle fetch is under way (§5.5, §21.7). */
        FETCHING("fetching"),

        /** A session exists: `EST-READY` ran (§21.7 point 4). */
        READY("ready"),

        /** Three attempts failed; the user may retry (§21.7 point 5). */
        UNREACHABLE("unreachable"),
        ;

        internal companion object {
            fun of(wire: String): Establishment = entries.first { it.wire == wire }
        }
    }

    /** A `dm_contact` row. */
    class ContactRow(
        val contactId: ByteArray,
        val identityPk: ByteArray,
        val cardEnv: ByteArray?,
        val cardIndex: Int,
        val pinnedIdentity: ByteArray?,
        val pendingIdentity: ByteArray?,
        val bundleWeekSeen: Long?,
        val trust: Trust,
        val source: Source,
        val establishment: Establishment,
        val fetchAttempts: Int,
        val fetchListenUntilMinute: Long?,
        val resetNeeded: Boolean,
        val requestUntilDay: Long?,
    ) {
        /** Never shows the card: it is a bearer secret for "may message me" (§3.3). */
        override fun toString(): String = "ContactRow(trust=$trust, establishment=$establishment)"
    }

    /** A `dm_pair_key` row (§6.3). */
    class PairKeyRow(
        val direction: String,
        val rootGen: Int,
        val week: Long,
        val recognitionKey: ByteArray,
        val openEnv: ByteArray,
    ) {
        override fun toString(): String = "PairKeyRow($direction, gen=$rootGen, week=$week)"
    }

    /** A `dm_pair_offer` row: a root this device offered for `c → me` (§6.3). */
    class PairOfferRow(
        val rootGen: Int,
        val rootEnv: ByteArray?,
        val offerEnv: ByteArray?,
        val baseWeek: Long,
        val acknowledged: Boolean,
    ) {
        override fun toString(): String = "PairOfferRow(gen=$rootGen, acknowledged=$acknowledged)"
    }

    /** A `dm_peer_pq` row: a peer's X-Wing key (§9.4; Phase 9 stores the bundle one). */
    class PeerPqRow(
        val genId: Int,
        val bundleWeek: Long,
        val source: String,
        val xwingPublic: ByteArray,
    ) {
        override fun toString(): String = "PeerPqRow(gen=$genId, week=$bundleWeek)"
    }

    /** A `dm_bundle_candidate` row: the best verified bundle of an attempt (§21.7 point 3). */
    class BundleCandidateRow(
        val bundleEnv: ByteArray,
        val bundleWeek: Long,
        val bundleRank: Int,
    ) {
        override fun toString(): String = "BundleCandidateRow(week=$bundleWeek, rank=$bundleRank)"
    }

    // ---------------------------------------------------------------- dm_contact

    private val contactColumns =
        "contact_id, identity_pk, card_env, card_index, pinned_identity, pending_identity, " +
            "bundle_week_seen, trust_state, source, establishment, fetch_attempts, " +
            "fetch_listen_until_minute, reset_needed, request_until_day"

    fun contact(sql: SqlExecutor, contactId: ByteArray): ContactRow? =
        contactBy(sql, "contact_id = ?", listOf(contactId))

    fun contactByIdentity(sql: SqlExecutor, identityPk: ByteArray): ContactRow? =
        contactBy(sql, "identity_pk = ?", listOf(identityPk))

    private fun contactBy(sql: SqlExecutor, where: String, args: List<Any?>): ContactRow? {
        var row: ContactRow? = null
        sql.query("SELECT $contactColumns FROM dm_contact WHERE $where", args) { r ->
            row = readContact(r)
        }
        return row
    }

    fun contacts(sql: SqlExecutor): List<ContactRow> {
        val out = ArrayList<ContactRow>()
        sql.query("SELECT $contactColumns FROM dm_contact ORDER BY contact_id") { r ->
            out += readContact(r)
        }
        return out
    }

    /** The contacts whose establishment is `fetching`, for the time-triggered EST steps. */
    fun fetching(sql: SqlExecutor): List<ContactRow> {
        val out = ArrayList<ContactRow>()
        sql.query(
            "SELECT $contactColumns FROM dm_contact WHERE establishment = 'fetching' " +
                "ORDER BY contact_id",
        ) { r -> out += readContact(r) }
        return out
    }

    /** How many contacts are in `request` (the `MAX_PENDING_REQUESTS` cap of §12.3). */
    fun requestCount(sql: SqlExecutor): Int {
        var count = 0
        sql.query("SELECT count(*) FROM dm_contact WHERE trust_state = 'request'") { r ->
            count = r.long(0).toInt()
        }
        return count
    }

    /** How many contacts exist at all (`MAX_CONTACTS`, §12.6). */
    fun contactCount(sql: SqlExecutor): Int {
        var count = 0
        sql.query("SELECT count(*) FROM dm_contact") { r -> count = r.long(0).toInt() }
        return count
    }

    @Suppress("LongParameterList")
    fun insertContact(
        tx: SyncTransaction,
        contactId: ByteArray,
        identityPk: ByteArray,
        cardEnv: ByteArray,
        cardIndex: Int,
        trust: Trust,
        source: Source,
        requestUntilDay: Long?,
    ) {
        tx.sql.exec(
            "INSERT INTO dm_contact($contactColumns) " +
                "VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?, ?, 'card_only', 0, NULL, 0, ?)",
            listOf(
                contactId,
                identityPk,
                cardEnv,
                cardIndex.toLong(),
                trust.wire,
                source.wire,
                requestUntilDay,
            ),
        )
    }

    /** Pins the contact's Olm identity. Only ever from NULL (the `dm_contact_pin` trigger). */
    fun pinIdentity(tx: SyncTransaction, contactId: ByteArray, olmIdentity: ByteArray): Boolean =
        tx.sql.execUpdate(
            "UPDATE dm_contact SET pinned_identity = ? WHERE contact_id = ? AND pinned_identity IS NULL",
            listOf(olmIdentity, contactId),
        ) == 1

    fun setTrust(tx: SyncTransaction, contactId: ByteArray, trust: Trust) {
        tx.sql.exec(
            "UPDATE dm_contact SET trust_state = ?, request_until_day = NULL WHERE contact_id = ?",
            listOf(trust.wire, contactId),
        )
    }

    /**
     * `block` (§12.4): the card and the request deadline go with the trust state, because
     * unblocking must not silently restore an address the user gave up.
     */
    fun block(tx: SyncTransaction, contactId: ByteArray) {
        tx.sql.exec(
            "UPDATE dm_contact SET trust_state = 'blocked', card_env = NULL, " +
                "request_until_day = NULL, establishment = 'card_only', fetch_attempts = 0, " +
                "fetch_listen_until_minute = NULL WHERE contact_id = ?",
            listOf(contactId),
        )
    }

    fun deleteContact(tx: SyncTransaction, contactId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM dm_contact WHERE contact_id = ?", listOf(contactId))

    fun setEstablishment(
        tx: SyncTransaction,
        contactId: ByteArray,
        establishment: Establishment,
        fetchAttempts: Int,
        listenUntilMinute: Long?,
    ) {
        tx.sql.exec(
            "UPDATE dm_contact SET establishment = ?, fetch_attempts = ?, " +
                "fetch_listen_until_minute = ? WHERE contact_id = ?",
            listOf(establishment.wire, fetchAttempts.toLong(), listenUntilMinute, contactId),
        )
    }

    /** `dm_contact.bundle_week_seen`: the rollback guard of §5.5. */
    fun setBundleWeekSeen(tx: SyncTransaction, contactId: ByteArray, week: Long) {
        tx.sql.exec(
            "UPDATE dm_contact SET bundle_week_seen = ? WHERE contact_id = ? " +
                "AND (bundle_week_seen IS NULL OR bundle_week_seen < ?)",
            listOf(week, contactId, week),
        )
    }

    fun setResetNeeded(tx: SyncTransaction, contactId: ByteArray, needed: Boolean) {
        tx.sql.exec(
            "UPDATE dm_contact SET reset_needed = ? WHERE contact_id = ?",
            listOf(if (needed) 1L else 0L, contactId),
        )
    }

    private fun readContact(r: SqlExecutor.Row) = ContactRow(
        contactId = r.blob(0),
        identityPk = r.blob(1),
        cardEnv = if (r.isNull(2)) null else r.blob(2),
        cardIndex = r.long(3).toInt(),
        pinnedIdentity = if (r.isNull(4)) null else r.blob(4),
        pendingIdentity = if (r.isNull(5)) null else r.blob(5),
        bundleWeekSeen = if (r.isNull(6)) null else r.long(6),
        trust = Trust.of(r.string(7)),
        source = Source.of(r.string(8)),
        establishment = Establishment.of(r.string(9)),
        fetchAttempts = r.long(10).toInt(),
        fetchListenUntilMinute = if (r.isNull(11)) null else r.long(11),
        resetNeeded = r.long(12) != 0L,
        requestUntilDay = if (r.isNull(13)) null else r.long(13),
    )

    // ----------------------------------------------------------- dm_conversation

    /** The conversation of a contact: its id, timer code and timer version (§10.5). */
    class ConversationRow(
        val conversationId: ByteArray,
        val timerCode: Int,
        val timerVersion: Long,
    ) {
        override fun toString(): String =
            "ConversationRow(timer=$timerCode, version=$timerVersion)"
    }

    fun conversation(sql: SqlExecutor, contactId: ByteArray): ConversationRow? {
        var row: ConversationRow? = null
        sql.query(
            "SELECT conversation_id, timer_code, timer_version FROM dm_conversation WHERE contact_id = ?",
            listOf(contactId),
        ) { r -> row = ConversationRow(r.blob(0), r.long(1).toInt(), r.long(2)) }
        return row
    }

    fun insertConversation(tx: SyncTransaction, conversationId: ByteArray, contactId: ByteArray) {
        tx.sql.exec(
            "INSERT INTO dm_conversation(conversation_id, contact_id) VALUES (?, ?)",
            listOf(conversationId, contactId),
        )
    }

    /** R-T9 (§10.5): a greater version is adopted; equal versions take the shorter timer. */
    fun adoptTimer(tx: SyncTransaction, conversationId: ByteArray, code: Int, version: Long) {
        tx.sql.exec(
            "UPDATE dm_conversation SET timer_code = ?, timer_version = ? " +
                "WHERE conversation_id = ? AND timer_version <= ?",
            listOf(code.toLong(), version, conversationId, version),
        )
    }

    // ------------------------------------------------------- dm_bundle_candidate

    fun bundleCandidate(sql: SqlExecutor, contactId: ByteArray): BundleCandidateRow? {
        var row: BundleCandidateRow? = null
        sql.query(
            "SELECT bundle_env, bundle_week, bundle_rank FROM dm_bundle_candidate WHERE contact_id = ?",
            listOf(contactId),
        ) { r -> row = BundleCandidateRow(r.blob(0), r.long(1), r.long(2).toInt()) }
        return row
    }

    /** Keeps the better candidate: `(bundle_week, bundle_rank)` descending (§5.3, §21.7). */
    fun putBundleCandidate(
        tx: SyncTransaction,
        contactId: ByteArray,
        bundleEnv: ByteArray,
        bundleWeek: Long,
        bundleRank: Int,
    ) {
        val changed = tx.sql.execUpdate(
            "UPDATE dm_bundle_candidate SET bundle_env = ?, bundle_week = ?, bundle_rank = ? " +
                "WHERE contact_id = ? AND (bundle_week < ? OR (bundle_week = ? AND bundle_rank < ?))",
            listOf(
                bundleEnv, bundleWeek, bundleRank.toLong(), contactId, bundleWeek, bundleWeek,
                bundleRank.toLong(),
            ),
        )
        if (changed == 0 && bundleCandidate(tx.sql, contactId) == null) {
            tx.sql.exec(
                "INSERT INTO dm_bundle_candidate(contact_id, bundle_env, bundle_week, bundle_rank) " +
                    "VALUES (?, ?, ?, ?)",
                listOf(contactId, bundleEnv, bundleWeek, bundleRank.toLong()),
            )
        }
    }

    fun deleteBundleCandidate(tx: SyncTransaction, contactId: ByteArray) {
        tx.sql.exec("DELETE FROM dm_bundle_candidate WHERE contact_id = ?", listOf(contactId))
    }

    // ---------------------------------------------------------------- dm_pair_key

    fun pairKeys(sql: SqlExecutor, contactId: ByteArray, direction: String): List<PairKeyRow> {
        val out = ArrayList<PairKeyRow>()
        sql.query(
            "SELECT direction, root_gen, week, recog_key, open_env FROM dm_pair_key " +
                "WHERE contact_id = ? AND direction = ? ORDER BY root_gen DESC, week DESC",
            listOf(contactId, direction),
        ) { r ->
            out += PairKeyRow(r.string(0), r.long(1).toInt(), r.long(2), r.blob(3), r.blob(4))
        }
        return out
    }

    fun pairKey(
        sql: SqlExecutor,
        contactId: ByteArray,
        direction: String,
        rootGen: Int,
        week: Long,
    ): PairKeyRow? {
        var row: PairKeyRow? = null
        sql.query(
            "SELECT direction, root_gen, week, recog_key, open_env FROM dm_pair_key " +
                "WHERE contact_id = ? AND direction = ? AND root_gen = ? AND week = ?",
            listOf(contactId, direction, rootGen.toLong(), week),
        ) { r ->
            row = PairKeyRow(r.string(0), r.long(1).toInt(), r.long(2), r.blob(3), r.blob(4))
        }
        return row
    }

    /** An UPDATE-then-INSERT pair, never a REPLACE (§13.6 step 6, gate G-DM4). */
    @Suppress("LongParameterList")
    fun putPairKey(
        tx: SyncTransaction,
        contactId: ByteArray,
        direction: String,
        rootGen: Int,
        week: Long,
        recognitionKey: ByteArray,
        openEnv: ByteArray,
    ) {
        val changed = tx.sql.execUpdate(
            "UPDATE dm_pair_key SET recog_key = ?, open_env = ? " +
                "WHERE contact_id = ? AND direction = ? AND root_gen = ? AND week = ?",
            listOf(recognitionKey, openEnv, contactId, direction, rootGen.toLong(), week),
        )
        if (changed == 0) {
            tx.sql.exec(
                "INSERT INTO dm_pair_key(contact_id, direction, root_gen, week, recog_key, open_env) " +
                    "VALUES (?, ?, ?, ?, ?, ?)",
                listOf(contactId, direction, rootGen.toLong(), week, recognitionKey, openEnv),
            )
        }
    }

    /**
     * Deletes every **out** key of a contact: the renewal rule of §21.3 point 2, so the next root
     * TLV from that contact is accepted whatever its generation.
     */
    fun deleteOutPairKeys(tx: SyncTransaction, contactId: ByteArray): Int = tx.sql.execUpdate(
        "DELETE FROM dm_pair_key WHERE contact_id = ? AND direction = 'out'",
        listOf(contactId),
    )

    // -------------------------------------------------------------- dm_pair_offer

    fun pairOffers(sql: SqlExecutor, contactId: ByteArray): List<PairOfferRow> {
        val out = ArrayList<PairOfferRow>()
        sql.query(
            "SELECT root_gen, root_env, offer_env, base_week, acknowledged FROM dm_pair_offer " +
                "WHERE contact_id = ? ORDER BY root_gen DESC",
            listOf(contactId),
        ) { r ->
            out += PairOfferRow(
                rootGen = r.long(0).toInt(),
                rootEnv = if (r.isNull(1)) null else r.blob(1),
                offerEnv = if (r.isNull(2)) null else r.blob(2),
                baseWeek = r.long(3),
                acknowledged = r.long(4) != 0L,
            )
        }
        return out
    }

    @Suppress("LongParameterList")
    fun insertPairOffer(
        tx: SyncTransaction,
        contactId: ByteArray,
        rootGen: Int,
        rootEnv: ByteArray,
        offerEnv: ByteArray,
        baseWeek: Long,
    ) {
        tx.sql.exec(
            "INSERT INTO dm_pair_offer(contact_id, root_gen, root_env, offer_env, base_week, acknowledged) " +
                "VALUES (?, ?, ?, ?, ?, 0)",
            listOf(contactId, rootGen.toLong(), rootEnv, offerEnv, baseWeek),
        )
    }

    /**
     * §6.3: a root's secret is erased as soon as a pair envelope under its generation opens. The
     * row stays, so the generation counter never repeats on a device that kept the contact
     * (§21.3 point 3), and `acknowledged` only goes 0 → 1 (the `dm_pair_offer_root` trigger).
     */
    fun acknowledgeOffer(tx: SyncTransaction, contactId: ByteArray, rootGen: Int): Boolean =
        tx.sql.execUpdate(
            "UPDATE dm_pair_offer SET acknowledged = 1, root_env = NULL, offer_env = NULL " +
                "WHERE contact_id = ? AND root_gen = ? AND acknowledged = 0",
            listOf(contactId, rootGen.toLong()),
        ) == 1

    // ----------------------------------------------------------------- dm_peer_pq

    fun peerPq(sql: SqlExecutor, contactId: ByteArray): List<PeerPqRow> {
        val out = ArrayList<PeerPqRow>()
        sql.query(
            "SELECT gen_id, bundle_week, source, xwing_pk FROM dm_peer_pq WHERE contact_id = ? " +
                "ORDER BY bundle_week DESC, gen_id DESC",
            listOf(contactId),
        ) { r -> out += PeerPqRow(r.long(0).toInt(), r.long(1), r.string(2), r.blob(3)) }
        return out
    }

    /** At most three rows per contact (the `dm_peer_pq_limit` trigger, CS-8). */
    @Suppress("LongParameterList")
    fun putPeerPq(
        tx: SyncTransaction,
        contactId: ByteArray,
        genId: Int,
        bundleWeek: Long,
        source: String,
        xwingPublic: ByteArray,
    ) {
        val changed = tx.sql.execUpdate(
            "UPDATE dm_peer_pq SET bundle_week = ?, source = ?, xwing_pk = ? " +
                "WHERE contact_id = ? AND gen_id = ?",
            listOf(bundleWeek, source, xwingPublic, contactId, genId.toLong()),
        )
        if (changed != 0) return
        // The trigger refuses a fourth row, so the oldest goes first — the newest bundle week is
        // the one a first flight will be addressed to (§5.4 step 3).
        val existing = peerPq(tx.sql, contactId)
        if (existing.size >= PEER_PQ_MAX) {
            val oldest = existing.last()
            tx.sql.exec(
                "DELETE FROM dm_peer_pq WHERE contact_id = ? AND gen_id = ?",
                listOf(contactId, oldest.genId.toLong()),
            )
        }
        tx.sql.exec(
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) " +
                "VALUES (?, ?, ?, ?, ?)",
            listOf(contactId, genId.toLong(), bundleWeek, source, xwingPublic),
        )
    }

    // -------------------------------------------------------- dm_orphan_namespace

    /** Records a namespace of a blocked or deleted contact, for SWEEP to remove (§21.12 point 3). */
    fun addOrphan(tx: SyncTransaction, namespace: ByteArray) {
        val changed = tx.sql.execUpdate(
            "UPDATE dm_orphan_namespace SET namespace_id = ? WHERE namespace_id = ?",
            listOf(namespace, namespace),
        )
        if (changed == 0) {
            tx.sql.exec(
                "INSERT INTO dm_orphan_namespace(namespace_id) VALUES (?)",
                listOf(namespace),
            )
        }
    }

    fun orphans(sql: SqlExecutor): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query("SELECT namespace_id FROM dm_orphan_namespace") { r -> out += r.blob(0) }
        return out
    }

    fun deleteOrphan(tx: SyncTransaction, namespace: ByteArray) {
        tx.sql.exec("DELETE FROM dm_orphan_namespace WHERE namespace_id = ?", listOf(namespace))
    }

    companion object {
        /** `dm_peer_pq_limit`: at most three peer X-Wing keys per contact (CS-8). */
        const val PEER_PQ_MAX: Int = 3

        /** `dm_pair_key.direction` for the keys this device accepts envelopes under. */
        const val DIRECTION_IN: String = "in"

        /** `dm_pair_key.direction` for the key this device seals with. */
        const val DIRECTION_OUT: String = "out"

        /** `dm_peer_pq.source` for a key that came out of a bundle (§5.5). */
        const val PQ_SOURCE_BUNDLE: String = "bundle"
    }
}
