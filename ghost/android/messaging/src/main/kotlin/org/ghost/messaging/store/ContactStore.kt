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
        /** `SHA-256(displayed digits)` of the safety number the user compared (§8.4). */
        val verifiedFp: ByteArray?,
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
            "fetch_listen_until_minute, reset_needed, request_until_day, verified_fp"

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
                "VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?, ?, 'card_only', 0, NULL, 0, ?, NULL)",
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
     *
     * `pending_identity` goes too, and it has to: the schema's
     * `CHECK ((trust_state = 'changed') = (pending_identity IS NOT NULL))` makes "blocked with a
     * pending identity" an aborted transaction, and §7.2 routes exactly that case — "`block` of a
     * changed contact" — through KEYDEC. §21.4 rule 5 says a CHECK abort inside a DM transaction
     * is a bug and never an expected path, so the block clears the column rather than meeting it.
     * Nothing sets `changed` before slice S8, so this is armed rather than exercised.
     */
    fun block(tx: SyncTransaction, contactId: ByteArray) {
        tx.sql.exec(
            "UPDATE dm_contact SET trust_state = 'blocked', card_env = NULL, " +
                "pending_identity = NULL, request_until_day = NULL, establishment = 'card_only', " +
                "fetch_attempts = 0, fetch_listen_until_minute = NULL WHERE contact_id = ?",
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
        verifiedFp = if (r.isNull(14)) null else r.blob(14),
    )

    // --------------------------------------------------- key change (§8.3, KEYDEC)

    /**
     * §8.3: a classified key change. The trust state and `pending_identity` move in **one**
     * statement, because the schema's `CHECK ((trust_state = 'changed') = (pending_identity IS NOT
     * NULL))` makes either half on its own an aborted transaction — and §21.4 rule 5 says a CHECK
     * abort inside a DM transaction is a bug, never an expected path.
     *
     * A contact already in `changed` under another pending key takes the new one (the newest valid
     * binding wins); its held rows of the superseded key go with it, in the caller's transaction
     * (`HeldStore.deleteHeldOtherThan`).
     */
    fun setChanged(tx: SyncTransaction, contactId: ByteArray, pendingIdentity: ByteArray): Boolean =
        tx.sql.execUpdate(
            "UPDATE dm_contact SET trust_state = 'changed', pending_identity = ?, " +
                "request_until_day = NULL WHERE contact_id = ? AND pinned_identity IS NOT NULL " +
                "AND pinned_identity IS NOT ?",
            listOf(pendingIdentity, contactId, pendingIdentity),
        ) == 1

    /**
     * KEYDEC's acceptance (§8.3 "Unblock"): `pinned := pending`, `pending := NULL`, the trust state
     * to `unverified` (acknowledge) or `verified` (verify), and `verified_fp` set only by the
     * second.
     *
     * One statement again, and for a second reason beside the CHECK: the `dm_contact_pin` trigger
     * admits a new pinned identity only while `OLD.trust_state = 'changed' AND NEW.pinned_identity
     * IS OLD.pending_identity`, so the move has to be read against the row as it was before it.
     */
    fun acceptPendingIdentity(
        tx: SyncTransaction,
        contactId: ByteArray,
        trust: Trust,
        verifiedFp: ByteArray?,
    ): Boolean = tx.sql.execUpdate(
        "UPDATE dm_contact SET pinned_identity = pending_identity, pending_identity = NULL, " +
            "trust_state = ?, verified_fp = ? " +
            "WHERE contact_id = ? AND trust_state = 'changed' AND pending_identity IS NOT NULL",
        listOf(trust.wire, verifiedFp, contactId),
    ) == 1

    /**
     * §8.4: what the user compared, recorded. Any change of the pinned key clears it, which is
     * [acceptPendingIdentity]'s `verified_fp` argument and not a second statement.
     */
    fun setVerifiedFp(tx: SyncTransaction, contactId: ByteArray, fingerprint: ByteArray?) {
        tx.sql.exec(
            "UPDATE dm_contact SET verified_fp = ? WHERE contact_id = ?",
            listOf(fingerprint, contactId),
        )
    }

    /**
     * §8.5: a valid revocation certificate. Terminal — only `deleteContact` leaves it.
     *
     * The card **stays**. Blocking erases it because unblocking must not silently restore an
     * address the user gave up (§12.4); a revoked contact has no unblock, and the card is what
     * `X_c` and `P_c` are derived from when the user finally deletes the row, so erasing it here
     * would leave two `:sync` namespaces nothing on the device could name (§21.12 point 3).
     * `pending_identity` goes, because the schema's CHECK ties it to `trust_state = 'changed'`.
     *
     * **The establishment state stays**, and that is deliberate. A revocation is applied inside
     * `RECV`, which may not call `Namespaces.setListening` (§21.7 point 7, gate G-DM2), so it
     * cannot close an open `P_c` window itself; and the actor only ever visits contacts whose
     * establishment is `fetching`, so moving this one to `card_only` would leave `P_c` listening
     * with its FETCH credentials installed and nothing left that could ever close it — the
     * unbounded-attempts half of mutant PM-31, which §22.12 item 18(a) fixed for `block`. Left
     * `fetching`, the contact is still visited: `EST-READY` refuses it (its guard admits only
     * `unverified` and `verified`), `EST-END` closes the window at its own minute, and after the
     * third attempt the namespace is removed and the pending items fail — the bound L7-D6 already
     * declares. The user's way out is `deleteContact`, which records the orphan namespaces.
     */
    fun revoke(tx: SyncTransaction, contactId: ByteArray): Boolean = tx.sql.execUpdate(
        "UPDATE dm_contact SET trust_state = 'revoked', pending_identity = NULL, " +
            "request_until_day = NULL, verified_fp = NULL " +
            "WHERE contact_id = ? AND trust_state <> 'revoked'",
        listOf(contactId),
    ) == 1

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
     * SWEEP's erasure of one (direction, generation, week) key: the opening key and the recognition
     * key go **together**, because they are one row (rule R-S6, §6.3 "both are erased together").
     */
    fun deletePairKey(
        tx: SyncTransaction,
        contactId: ByteArray,
        direction: String,
        rootGen: Int,
        week: Long,
    ): Int = tx.sql.execUpdate(
        "DELETE FROM dm_pair_key WHERE contact_id = ? AND direction = ? AND root_gen = ? AND week = ?",
        listOf(contactId, direction, rootGen.toLong(), week),
    )

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

    /**
     * §8.3 and §22.8.6 rule 1: a KEYDEC acceptance or a renewal **discards** this device's
     * unacknowledged root offers for a contact — the bytes go, the row stays.
     *
     * The row stays because `root_gen` is a per-contact counter and §21.3 point 3 needs
     * `1 + max(root_gen)` never to repeat on a device that kept the contact; a peer ignores a
     * generation "not greater than the stored out generation" (§6.3), so a repeated number would
     * be a root the peer silently drops. The `dm_pair_offer_root` trigger admits exactly this
     * direction: a root is erased, never replaced, and `acknowledged` never goes back.
     */
    fun discardOfferSecrets(tx: SyncTransaction, contactId: ByteArray): Int = tx.sql.execUpdate(
        "UPDATE dm_pair_offer SET root_env = NULL, offer_env = NULL " +
            "WHERE contact_id = ? AND acknowledged = 0 " +
            "AND (root_env IS NOT NULL OR offer_env IS NOT NULL)",
        listOf(contactId),
    )

    /**
     * §6.3 and §21.3 point 3, SWEEP's half: an offered root whose window has closed loses its
     * **secrets**, and a row whose secrets are gone is deleted only when a **higher** generation
     * exists.
     *
     * The row is what makes `1 + max(root_gen)` never repeat on a device that kept the contact
     * (§21.3 point 3); a peer ignores a generation not greater than the one it stored, so a reused
     * number would be a root the peer silently drops. Deleting only below a higher generation keeps
     * the counter intact while removing the rows nothing reads.
     */
    fun eraseOfferSecrets(tx: SyncTransaction, contactId: ByteArray, rootGen: Int): Int =
        tx.sql.execUpdate(
            "UPDATE dm_pair_offer SET root_env = NULL, offer_env = NULL " +
                "WHERE contact_id = ? AND root_gen = ? AND (root_env IS NOT NULL OR offer_env IS NOT NULL)",
            listOf(contactId, rootGen.toLong()),
        )

    fun deleteOffer(tx: SyncTransaction, contactId: ByteArray, rootGen: Int): Int =
        tx.sql.execUpdate(
            "DELETE FROM dm_pair_offer WHERE contact_id = ? AND root_gen = ? AND root_env IS NULL",
            listOf(contactId, rootGen.toLong()),
        )

    // -------------------------------------------------------------- requests

    /**
     * §12.3 and §10.6: the requests whose `request_until_day` has passed. Deleting the contact
     * cascades its conversation, messages, sessions, pair keys and rows.
     */
    fun expiredRequests(sql: SqlExecutor, today: Long, batch: Int): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        sql.query(
            "SELECT contact_id FROM dm_contact WHERE trust_state = 'request' " +
                "AND request_until_day <= ? ORDER BY request_until_day, contact_id LIMIT ?",
            listOf(today, batch.toLong()),
        ) { r -> out += r.blob(0) }
        return out
    }

    /**
     * §21.9 rule 1's "next EST timer": the end of the next open bundle-fetch window. It is a wake
     * and not a deletion, but it is the same timer (§10.7 trigger 1), and a device whose only live
     * deadline is a fetch window would otherwise sleep through `EST-END`.
     */
    fun nextFetchDeadline(sql: SqlExecutor, nowMinute: Long): Long? {
        var next: Long? = null
        sql.query(
            "SELECT min(fetch_listen_until_minute) FROM dm_contact " +
                "WHERE fetch_listen_until_minute > ?",
            listOf(nowMinute),
        ) { r -> if (!r.isNull(0)) next = r.long(0) }
        return next
    }

    // ----------------------------------------------------------------- dm_peer_pq

    /**
     * §22.8.6 rule 1: a renewal or a KEYDEC acceptance deletes the contact's in-band X-Wing keys
     * and every bundle key no live session names. After a KEYDEC acceptance **both** sessions are
     * gone (R-SS0), so no `peer_gen_id` names anything and the whole set goes: a PQ offer
     * encapsulated to a pre-change key is one the contact's new device could never open, and
     * re-attaching it would block pair mode from that contact for up to `start(b + 1) + 45 d`.
     */
    fun deletePeerPq(tx: SyncTransaction, contactId: ByteArray): Int =
        tx.sql.execUpdate("DELETE FROM dm_peer_pq WHERE contact_id = ?", listOf(contactId))

    /**
     * §22.8.6 rule 1 on a **renewal** from the contact (R-SS1 made a new inbound session
     * `current`): every in-band key goes, and every bundle key except the one [keepGenId] names —
     * the `peer_gen_id` of the new `current`, which a responder session does not have, so after a
     * renewal the whole set goes in practice. The contact restored, reset or reconnected, and a
     * key announced before that is one its new state may not hold: an offer encapsulated to it
     * could never be opened, and would block pair mode from the contact for up to
     * `start(b + 1) + 45 d` (CRY-6).
     */
    fun deletePeerPqOnRenewal(tx: SyncTransaction, contactId: ByteArray, keepGenId: Int?): Int =
        if (keepGenId == null) {
            deletePeerPq(tx, contactId)
        } else {
            tx.sql.execUpdate(
                "DELETE FROM dm_peer_pq WHERE contact_id = ? AND (source = ? OR gen_id <> ?)",
                listOf(contactId, PQ_SOURCE_IN_BAND, unsigned(keepGenId)),
            )
        }

    /**
     * §22.8.2 rule 4: a key the crate refused at encapsulation (`INVALID_KEY`) is deleted, and the
     * offer falls back to the classical `seal_root`. Validation happens on receipt already
     * (§22.8.2 rule 3), so this is the defence behind it, not a path a valid peer reaches.
     */
    fun deletePeerPqKey(tx: SyncTransaction, contactId: ByteArray, genId: Int): Int =
        tx.sql.execUpdate(
            "DELETE FROM dm_peer_pq WHERE contact_id = ? AND gen_id = ?",
            listOf(contactId, unsigned(genId)),
        )

    /**
     * §22.8.6 rule 1: a renewal from the contact discards this device's **unacknowledged PQ-C**
     * offers — `root_env` and `offer_env` to NULL, the row and its generation number kept (§21.3
     * point 3). A PQ offer is the one whose stored TLV is the 1 166-byte `seal_root_pq`
     * (`offer_env` of 1 194 bytes, §13.6); a classical offer carries no key of the peer's and
     * stays live. The next send then mints a new offer, classical unless a fresh key of the
     * contact has arrived since.
     */
    fun discardPqOffers(tx: SyncTransaction, contactId: ByteArray): Int = tx.sql.execUpdate(
        "UPDATE dm_pair_offer SET root_env = NULL, offer_env = NULL " +
            "WHERE contact_id = ? AND acknowledged = 0 AND length(offer_env) = ?",
        listOf(contactId, PQ_OFFER_ENV_BYTES.toLong()),
    )

    /**
     * §21.3 point 2(b) and §22.8.6 rule 1: the contact's state changed under this device's roots —
     * a renewal from it, a KEYDEC acceptance, or a new session of this device's own, after which
     * the contact drops its out keys for this device (§21.3 point 2(a) on its side) — so the next
     * send must offer a **new** root "unless an unacknowledged one exists".
     *
     * An unacknowledged newest offer is left as it is: with its bytes it is re-attached, and
     * without them (erased, or discarded by §22.8.6 rule 1) the next send mints anyway. An
     * **acknowledged** newest offer is superseded by a row of the next generation with no root and
     * no offer bytes — the state an offer is in once SWEEP erased it unacknowledged — which the
     * planning read of SEND answers with `1 + max(root_gen)`, exactly as it answers an erased
     * offer. The row is a counter, not a root: nothing derives from it, `dm_pair_offer_root` lets
     * its NULLs stay NULL, and SWEEP deletes it once a higher generation exists (§21.3 point 3).
     *
     * Its `base_week` is the superseded offer's: the row carries no root, so no week key is derived
     * from it, and the planning read mints on seeing it whatever its week.
     *
     * Returns whether a row was inserted. Until slice S13 no path did this, and the engine offered a
     * new root after **every** acknowledgement instead, which hid the missing rule (§22.18).
     */
    fun supersedeOffers(tx: SyncTransaction, contactId: ByteArray): Boolean {
        val newest = pairOffers(tx.sql, contactId).maxByOrNull { it.rootGen } ?: return false
        if (!newest.acknowledged) return false
        val next = newest.rootGen + 1
        if (next > MAX_ROOT_GEN) return false
        tx.sql.exec(
            "INSERT INTO dm_pair_offer(contact_id, root_gen, root_env, offer_env, base_week, acknowledged) " +
                "VALUES (?, ?, NULL, NULL, ?, 0)",
            listOf(contactId, next.toLong(), newest.baseWeek),
        )
        return true
    }

    /**
     * `dm_contact.pq_announced_week` (§9.4): the `bundle_week` of the generation whose `pq_key` this
     * device last sent the contact — a period index, so the announcement rides on the first
     * slack-eligible send after each new generation and on no other (at most one per ISO week;
     * §22.18 records why the index is the generation's week and not the send's). Null before the
     * first, and again after a renewal or a KEYDEC acceptance, when the contact's device may have
     * lost it.
     */
    fun pqAnnouncedWeek(sql: SqlExecutor, contactId: ByteArray): Long? {
        var week: Long? = null
        sql.query(
            "SELECT pq_announced_week FROM dm_contact WHERE contact_id = ?",
            listOf(contactId),
        ) { r -> week = if (r.isNull(0)) null else r.long(0) }
        return week
    }

    /** Sets or clears `dm_contact.pq_announced_week` (§9.4). */
    fun setPqAnnouncedWeek(tx: SyncTransaction, contactId: ByteArray, week: Long?): Int =
        tx.sql.execUpdate(
            "UPDATE dm_contact SET pq_announced_week = ? WHERE contact_id = ?",
            listOf(week, contactId),
        )

    /**
     * §10.6's "surplus `dm_peer_pq` rows", read through §22.8.6 rule 2: a stored X-Wing key is
     * usable only while `now < start(bundle_week + 5)`, so a row past that week can never be
     * encapsulated to again and is a public key kept for nothing.
     *
     * It is a public key, so this is hygiene rather than secrecy — but it is also the rule that
     * keeps the three-row cap (`dm_peer_pq_limit`, CS-8) from being filled with dead weeks and
     * evicting a live one.
     */
    fun deleteStalePeerPq(tx: SyncTransaction, week: Long): Int =
        tx.sql.execUpdate(
            "DELETE FROM dm_peer_pq WHERE bundle_week + ? <= ?",
            listOf(PQ_KEY_WEEKS, week),
        )

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
            listOf(bundleWeek, source, xwingPublic, contactId, unsigned(genId)),
        )
        if (changed != 0) return
        // The trigger refuses a fourth row, so the oldest goes first — the newest bundle week is
        // the one a first flight will be addressed to (§5.4 step 3).
        val existing = peerPq(tx.sql, contactId)
        if (existing.size >= PEER_PQ_MAX) {
            val oldest = existing.last()
            tx.sql.exec(
                "DELETE FROM dm_peer_pq WHERE contact_id = ? AND gen_id = ?",
                listOf(contactId, unsigned(oldest.genId)),
            )
        }
        tx.sql.exec(
            "INSERT INTO dm_peer_pq(contact_id, gen_id, bundle_week, source, xwing_pk) " +
                "VALUES (?, ?, ?, ?, ?)",
            listOf(contactId, unsigned(genId), bundleWeek, source, xwingPublic),
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

        /**
         * §22.8.6 rule 2 and §5.4 step 3: a peer's X-Wing key of week `b` is usable while
         * `now < start(b + 5)`, so a row is stale from week `b + 5` on.
         */
        const val PQ_KEY_WEEKS: Long = 5

        /** `dm_pair_key.direction` for the keys this device accepts envelopes under. */
        const val DIRECTION_IN: String = "in"

        /** `dm_pair_key.direction` for the key this device seals with. */
        const val DIRECTION_OUT: String = "out"

        /** `dm_peer_pq.source` for a key that came out of a bundle (§5.5). */
        const val PQ_SOURCE_BUNDLE: String = "bundle"

        /** `dm_peer_pq.source` for a key the contact announced in a `pq_key` TLV (§9.4). */
        const val PQ_SOURCE_IN_BAND: String = "in_band"

        /** `dm_pair_offer.offer_env` of a `seal_root_pq` offer: 1 166 + 28 bytes (§13.6). */
        const val PQ_OFFER_ENV_BYTES: Int = 1_194

        /** `dm_pair_offer.root_gen` is a `u16` (§13.6). */
        const val MAX_ROOT_GEN: Int = 65_535

        /**
         * `gen_id` is a **`u32`** (§13.6: `CHECK (gen_id BETWEEN 0 AND 4294967295)`) and crosses
         * the bridge as a signed `Int`, so the top half of the range arrives negative. Widening it
         * as unsigned is the same convention `PeekOrder` and `ReceiveStep` use; binding
         * `Int.toLong()` instead would fail the CHECK on roughly half the generations a peer
         * publishes — which is a bug nothing but a run of bundles would ever show.
         */
        private const val U32 = 0xffff_ffffL

        internal fun unsigned(genId: Int): Long = genId.toLong() and U32
    }
}
