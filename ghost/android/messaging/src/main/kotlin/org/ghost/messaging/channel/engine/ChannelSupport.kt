package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.MlsChange
import org.ghost.crypto.bridge.MlsRow
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.ChannelStores
import org.ghost.messaging.channel.store.MlsKvStore
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.engine.DmTimers
import org.ghost.messaging.engine.RelaySetResolver
import org.ghost.messaging.engine.SelfContexts
import org.ghost.messaging.port.DmClock
import org.ghost.messaging.port.DmRandom
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots
import org.ghost.messaging.store.ContentCipher
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.Capabilities
import org.ghost.sync.api.Funding
import org.ghost.sync.api.Inbox
import org.ghost.sync.api.Namespaces
import org.ghost.sync.api.Outbox
import org.ghost.sync.api.Registrations
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.TtlBucket

/**
 * What the channel engine needs from `:sync` (Phase 10 design §7, §10.1), gathered so the steps take one argument and a
 * world can supply one set. The restricted calls on these ports — `Outbox.enqueue`, `Namespaces.register`/`remove`,
 * `Capabilities.put`, `Registrations.*`, `Funding.set` — are made only from the transactions §13.1's gate G-M5 names
 * (`ch-enqueue-callers.sh`), never from `CH-RECV` or `CH-JOIN`; the inbox calls (`peek`, `claimOne`, `markConsumed`,
 * `defer`, `reofferDeferred`) cause no relay call and are every step's.
 */
internal class ChannelSyncPorts(
    val namespaces: Namespaces,
    val capabilities: Capabilities,
    val registrations: Registrations,
    val outbox: Outbox,
    val inbox: Inbox,
    val funding: Funding,
) {
    override fun toString(): String = "ChannelSyncPorts"
}

/**
 * The local keys a channel row is written under (§9: "plaintext content columns are wrapped under the content key (F9
 * §13.8)"): the content key of `dm_self`, which seals every `*_env` column that holds the user's text or bytes Kotlin
 * keeps for itself, and the random seen key of F9 §7.6, which keys the dedup tags (`ch_seen`, `ch_kp_seen`). Production
 * reads both from the DM's `SelfContexts`; null while the identity is locked or not activated (`CRYPTO_UNAVAILABLE`).
 */
internal interface ChannelLocalKeys {
    /** The content cipher, or null. */
    fun content(): ContentCipher?

    /** A copy of the seen key the caller zeroes, or null. */
    fun seenKey(): ByteArray?
}

/**
 * [ChannelLocalKeys] from the DM layer's [SelfContexts] (production): the content key and the seen key of `dm_self`,
 * available while the DM context is open and the identity activated, and zeroised with it at lock.
 */
internal class SelfChannelKeys(private val contexts: SelfContexts) : ChannelLocalKeys {
    override fun content(): ContentCipher? = contexts.get()?.content

    override fun seenKey(): ByteArray? = contexts.get()?.seenKey

    override fun toString(): String = "SelfChannelKeys"
}

/** What the channel engine counts (counts only, never a value or a time, T3): drops and refusals by reason. */
internal class ChannelCounters {
    enum class Reason {
        /** A blob whose hint matched no key and whose relay copy expired (§6.3.2 "no match"). */
        UNOPENABLE,

        /** A blob whose hint matched and whose seal did not open: a forgery (CS-S5). */
        FORGED_SEAL,

        /** A seal that opened onto a non-canonical body, or an `order` that disagrees with the MLS header (CS-S2, CS-S7). */
        NON_CANONICAL,

        /** An MLS proposal, dropped before `process_message` (§6.3.2, §19.16). */
        PROPOSAL,

        /** A message OpenMLS reports as the member's own that is not one of its ops (§6.3.2, §19.13; FORGE_OWN). */
        FORGED_OWN,

        /** A commit that fails CO-2. */
        INVALID_COMMIT,

        /** A commit refused with `LifetimeError`: a non-canonical KeyPackage — invalid for every member (§19.29.1). */
        INVALID_LIFETIME,

        /** An unconsumed invite the winner's context voided (its committers changed or its pw_version is older). */
        INVITE_VOIDED,

        /** A commit of a settled epoch with another hash: a fork signal (CO-6). */
        LATE_CANDIDATE,

        /** A commit of a settled epoch with the winner's hash: a resurrected copy (§6.3.4 layer 2). */
        RESURRECTED_COMMIT,

        /** An application message that did not decrypt (a replay, layer 2), or that MLS refused. */
        UNDECRYPTABLE,

        /** A post whose op id was already shown (§6.3.4 layer 4). */
        DUPLICATE,

        /** A post that reuses another member's op id (§19.35 F-10, recorded): the first stays. */
        OP_ID_CLASH,

        /** A post whose relay copy expired while it waited on the device (§19.38; the DM's): not inserted. */
        EXPIRED_WHILE_HELD,

        /** A reaction whose post is not on this device yet (§19.38): held in memory until the post lands. */
        REACTION_HELD,

        /** A held reaction dropped before its post came (§19.35 F-4, §19.38: the bound of the held ones). */
        REACTION_ORPHAN,

        /** An `INVITE_ISSUED` no admission could use (§19.38): its sender may not invite, or its expiry is too far. */
        INVITE_REFUSED,

        /** An application message deferred behind a gap while its namespace is under pressure (§19.38). */
        GAP_DEFERRED,

        /** A `REVEAL` addressed to another member's box key: one HPKE open, nothing inside, counted and
         * dropped (§6.9 "what members learn": the author revealed to someone — no recipient identity). */
        REVEAL_NOT_FOR_ME,

        /** A `REVEAL` whose box key opened but a binding failed: bad card, `sig_id`, `sig_ps`, `P_author`
         * not the MLS sender, or `P_M` not the opener — a forgery, refused with nothing kept (§6.9). */
        REVEAL_FORGED,

        /** A `REVEAL` of an epoch whose box key this member no longer holds within retention: the attempt
         * fails closed (§19.17) — counted, nothing learned of the payload. */
        REVEAL_NO_KEY,

        /** A reveal whose offer the DM context refused (`addContact` answered `NOT_ACTIVATED` or
         * `CRYPTO_UNAVAILABLE` — a locked or wiped DM library at the offer): the opened card is
         * lost with the offer, counted (§19.48 FIX 3); the author can reveal again, the same loss
         * shape as the crash-between edge (§19.47). */
        REVEAL_OFFER_FAILED,

        /** A Welcome that fails the committers anchor, OpenMLS, §5.3's validity or the bootstrap (§6.2.5). */
        INVALID_WELCOME,

        /** A Welcome of another joiner's KeyPackage. */
        NOT_FOR_ME,

        /** A join request whose KeyPackage, purpose or binding is refused, or that names a spent invite. */
        JOIN_REFUSED,

        /** A join request no held invite verifies; deferred until its relay expiry (the `INVITE_ISSUED` may come later). */
        JOIN_UNKNOWN_INVITE,

        /** A join request the committer's policy refuses at its pass (§6.2.4 (B)). */
        ADMISSION_REFUSED,

        /** A blob of a namespace no listened generation or pending join names. */
        UNROUTED,

        /** A batch or a blob whose stored state did not load (`STATE_CORRUPT`): deferred, never consumed. */
        STATE_CORRUPT,

        /** A blob offered for the fourth time, consumed unprocessed (the poison guard, F9 §7.8 R2). */
        POISONED,

        /** An own commit whose op failed (no copy can exist, CO-4): its pending commit cleared. */
        OWN_COMMIT_CLEARED,

        /** A settle whose winner the native side refused at the settle (CO-2 re-run): the candidate dropped. */
        SETTLE_REFUSED,
    }

    private val counts = HashMap<Reason, Int>()

    fun count(reason: Reason) {
        counts[reason] = (counts[reason] ?: 0) + 1
    }

    operator fun get(reason: Reason): Int = counts[reason] ?: 0

    fun snapshot(): Map<Reason, Int> = HashMap(counts)

    override fun toString(): String = "ChannelCounters"
}

/** The size, TTL and deadline arithmetic of §5.7, §5.8 and §8.3, on the DM time grid (T13). */
internal object ChannelTime {
    const val SMALL_FLOOR: Int = 4096
    const val LARGE_FLOOR: Int = 16384
    private val BUCKETS = intArrayOf(4096, 16384, 65536)

    /** `C(B) = B − 68` (§5.6). */
    fun capacity(bucket: Int): Int = bucket - 68

    /** The class floor (§5.7): 4 KiB small, 16 KiB large. */
    fun floor(sizeClass: Int): Int = if (sizeClass == 0) SMALL_FLOOR else LARGE_FLOOR

    /** `bucket(len)` (§5.7): the smallest bucket at or above the floor that holds the body; null for `NO_FIT`. */
    fun bucket(length: Int, sizeClass: Int): Int? =
        BUCKETS.firstOrNull { it >= floor(sizeClass) && capacity(it) >= length }

    /** The class cap (§5.3): 32 members small, 100 large. */
    fun cap(sizeClass: Int): Int = if (sizeClass == 0) 32 else 100

    /** The post TTL of §5.8, which is ADR-27 point 11 and the DM's (`DmTimers.bucketOf`). */
    fun postTtl(timerCode: Int): TtlBucket = DmTimers.bucketOf(timerCode)

    /** The handshake TTL of §5.8 (X-7): 30 days for a timer off or of 30 days, 7 days otherwise. */
    fun handshakeTtl(timerCode: Int): TtlBucket =
        if (timerCode == DmTimers.TIMER_OFF || timerCode == 5) TtlBucket.DAYS_30 else TtlBucket.DAYS_7

    /** A post's op deadline (§5.8): `author + min(bucket, 7 d)`. */
    fun postDeadline(authorSeconds: Long, timerCode: Int): Long = DmTimers.deadlineSeconds(authorSeconds, postTtl(timerCode))

    /** A handshake op's deadline (§5.8): `author + 7 d`. */
    fun handshakeDeadline(authorSeconds: Long): Long = authorSeconds + 7 * DmTime.DAY

    /** The settle window of CO-4: 20 minutes. */
    const val SETTLE_WINDOW_SECONDS: Long = 20 * DmTime.MINUTE

    /** The gap hold of §6.3.3: 12 minutes (F9's measured hold). */
    const val GAP_HOLD_SECONDS: Long = 12 * DmTime.MINUTE

    /** The retention R of §8.3, in days: 1 for timers of 5 minutes, 1 hour and 1 day, 2 otherwise. */
    fun retentionDays(timerCode: Int): Long = if (timerCode in 1..3) 1 else 2

    /**
     * The PCS cadence of CO-8 and §6.8: a committer's empty PCS commit when its last commit is at least this many
     * days old — 7 days, or 1 day in channels with timers ≤ 1 d (timer codes 1 … 3; Q36, §19.19: the daily cadence
     * of short-timer channels is rank 0's alone).
     */
    fun pcsDays(timerCode: Int): Long = if (timerCode in 1..3) 1 else 7

    /**
     * The shorter of two timers (§5.5 "a receiver deletes a post after min(its timer_code, the channel timer of the post's
     * epoch)"): the codes grow with the duration, and 0 is "off", the longest of all.
     */
    fun shorterTimer(a: Int, b: Int): Int = when {
        a == DmTimers.TIMER_OFF -> b
        b == DmTimers.TIMER_OFF -> a
        else -> minOf(a, b)
    }
}

/**
 * The associated data of the content-key envelopes this engine writes (§9; F9 §13.8's rule that an envelope belongs to
 * the row it was written for). A one-byte domain and the row's key: no envelope moved to another row, table or channel
 * opens. Local storage formats, never on the wire; no `ghost/v1/ch…` literal is needed (G-M3 rule 4).
 */
internal object ChannelAd {
    private fun of(domain: Int, vararg parts: ByteArray): ByteArray {
        var out = byteArrayOf(domain.toByte())
        for (p in parts) out += p
        return out
    }

    fun name(channelId: ByteArray): ByteArray = of(1, channelId)
    fun postBody(opId: ByteArray): ByteArray = of(2, opId)
    fun pending(opId: ByteArray): ByteArray = of(3, opId)
    fun candidate(channelId: ByteArray, epoch: Long, hash: ByteArray): ByteArray = of(4, channelId, u64(epoch), hash)
    fun welcomes(channelId: ByteArray, epoch: Long, hash: ByteArray): ByteArray = of(5, channelId, u64(epoch), hash)
    fun ownInvite(inviteId: ByteArray): ByteArray = of(6, inviteId)
    fun joinRequest(channelId: ByteArray, hash: ByteArray): ByteArray = of(7, channelId, hash)
    fun grapheme(target: ByteArray, author: ByteArray): ByteArray = of(8, target, author)
    fun liveness(channelId: ByteArray): ByteArray = of(9, channelId)

    fun u64(value: Long): ByteArray = ByteArray(8) { i -> (value ushr (56 - 8 * i)).toByte() }
}

/**
 * The committers digest of a channel's current context (S0-15), **returned by `roster`** (§19.37 F-S4-2, closed
 * in S5a: fn 18 outputs the context's digest, so the engine no longer learns it from a throwaway open `inviteBuild` —
 * which a password channel could never call, leaving its committers unable to admit until their own next invite).
 * Null only when the call is refused (the state does not load).
 */
internal object ChannelDigest {
    fun learn(crypto: org.ghost.crypto.bridge.ChannelCrypto, channelId: ByteArray, rows: List<MlsRow>, day: Long): ByteArray? =
        crypto.roster(channelId, rows, day.toInt()).valueOrNull()?.committersDigest
}

/** The bridge between the store's rows and the facade's (§3.4: Kotlin moves bytes and interprets none). */
internal object MlsRows {
    fun of(rows: List<MlsKvStore.KvRow>): List<MlsRow> = rows.map { MlsRow(it.scope.tag, it.key, it.env) }

    fun changes(changes: List<MlsChange>): List<MlsKvStore.KvChange> =
        changes.map { MlsKvStore.KvChange(MlsKvStore.Scope.of(it.scope), it.key, it.env) }

    /** [rows] with [changes] applied in memory: what the next native call of the same transaction must see. */
    fun applied(rows: List<MlsRow>, changes: List<MlsChange>): List<MlsRow> {
        val byKey = LinkedHashMap<String, MlsRow>()
        for (r in rows) byKey[key(r.scope, r.key)] = r
        for (c in changes) {
            val k = key(c.scope, c.key)
            val env = c.env
            if (env == null) byKey.remove(k) else byKey[k] = MlsRow(c.scope, c.key, env)
        }
        return byKey.values.toList()
    }

    private fun key(scope: Int, key: ByteArray): String = "$scope:" + key.joinToString("") { "%02x".format(it) }
}

/**
 * Seeds `ch_schedule` for a channel that has just become `active` (`CH-CREATE`, `CH-JOIN`): the PCS clock's
 * `last_own_commit_day` is [day] (the member's leaf is fresh), the self-update slot is [day]'s period's
 * ([ChannelSchedule]). False when `K_sched` is unavailable — the DM context is closed; the caller's
 * transaction is unaffected; the session-start scheduler seeds lazily then.
 */
internal fun seedSchedule(env: ChannelEnv, tx: org.ghost.sync.api.SyncTransaction, channelId: ByteArray, day: Long): Boolean {
    // CO-9's slot is keyed by `K_sched` (§6.4, owner decision Q-F5-6, slice S13b), the DM context's
    // MESSAGING-branch derivation — not the seen key.
    val scheduleKey = env.dmContext.channelScheduleKey() ?: return false
    try {
        env.stores.channels.putSchedule(
            tx, channelId, ChannelSchedule.slotDay(channelId, ChannelSchedule.period(day), scheduleKey), day, null,
        )
        return true
    } finally {
        scheduleKey.fill(0)
    }
}

/**
 * Everything the channel steps share: the database, the stores, the native context, the local keys, the clock, the
 * randomness, the relay sets and the counters. One instance per engine; no state of its own.
 */
internal class ChannelEnv(
    val database: SyncDatabase,
    val stores: ChannelStores,
    val contexts: ChannelContexts,
    val keys: ChannelLocalKeys,
    val clock: DmClock,
    val random: DmRandom,
    private val esSlots: EsSlots,
    val counters: ChannelCounters,
    /**
     * The DM context (§6.9's `revealSeal` takes its handle: the identity key that signs `sig_id`
     * and the own card the reveal carries stay native, ADR-35's X-21 rule). Null-handle while the
     * DM context is closed — a reveal then answers `CRYPTO_UNAVAILABLE`, like a post.
     */
    val dmContext: org.ghost.messaging.port.DmContext,
    /**
     * What an opened reveal (§6.9) does with the author's verified card: the DM layer's
     * `addContact(card, source)` — the engine names [org.ghost.messaging.store.ContactStore.Source.LINK]
     * (§19.17: the existing source for a card received through another channel; there is no
     * `CHANNEL_REVEAL` and its dm_contact CHECK is frozen), trust `unverified`. Called on the
     * actor thread after the receive transaction commits (it opens a transaction of its own);
     * the card is a bearer secret the caller zeroes once offered. The result is what `addContact`
     * answered: a DM context that is not there (`NOT_ACTIVATED`/`CRYPTO_UNAVAILABLE` — a locked
     * or wiped DM library) loses the card with the offer, and the receive counts it
     * [ChannelCounters.Reason.REVEAL_OFFER_FAILED] (§19.48 FIX 3).
     */
    val contactOffer: (ByteArray, org.ghost.messaging.store.ContactStore.Source) -> org.ghost.messaging.engine.ContactSteps.AddResult,
) {
    private val resolver = RelaySetResolver(esSlots)

    /** `set(ns, w)` (§7.2: F9 §5.2's permutation, unchanged for channel namespaces), or null when the week has none. */
    fun relaySet(ns: ByteArray, week: Long): List<EsSlot>? = resolver.forNamespace(ns, week)

    /** Every slot of the week's table, for an invite whose namespace is not known before it is parsed. */
    fun weekSlots(week: Long): List<EsSlot> = esSlots.slotsInWeek(week)

    fun now(): Long = clock.nowEpochSeconds()

    /** Seals [plain] under the content key for the row [ad] names, with a fresh nonce. */
    fun seal(content: ContentCipher, ad: ByteArray, plain: ByteArray): ByteArray = content.seal(random.bytes(12), ad, plain)

    /** The channels that count against the P0 limit of 9 (§19.8 (e), Q4): every one still listened to or joining. */
    fun liveChannels(sql: SqlExecutor): Int =
        stores.channels.channels(sql).count { it.state != ChannelState.LEFT && it.state != ChannelState.JOIN_EXPIRED }

    override fun toString(): String = "ChannelEnv"

    companion object {
        /** §19.8 (e), Q4: at most 9 channels per client. */
        const val MAX_CHANNELS: Int = 9

        /** `GhostChannelContext.flags` bit 0: members may invite (§5.3). */
        const val FLAG_MEMBERS_MAY_INVITE: Int = 1

        /** Bit 2: joining needs a password (§19.28). */
        const val FLAG_PASSWORD: Int = 4

        /** The default idle-eviction days (§19.4). */
        const val IDLE_EVICT_DAYS: Int = 63
    }
}
