package org.ghost.messaging.engine

import java.util.EnumMap

/**
 * The in-memory counters of Phase 9 design §7.4 R-P2 and §13.2 `status`.
 *
 * > A `drop` is `markConsumed` plus one in-memory counter increment (`MessagingStatus`, counts
 * > only, no persisted rejection history, T33) and nothing else.
 *
 * **In memory, and nowhere else.** A persisted rejection history would say who wrote, when and
 * how often — which is exactly what a seized device must not carry (T33, R-M1) — and it would
 * also be a relay-visible behaviour difference if a counter ever drove a decision. Nothing here
 * drives one: the counters are read by `status()` and by the test oracles, and by nothing else.
 *
 * They reset at every process start, which is what "in memory" means and what the facade's
 * documentation says.
 */
internal class DmCounters {

    /** Why a blob was dropped, or what was seen and deliberately ignored. */
    enum class Reason {
        /** The blob arrived in a namespace that is not this device's inbox (R3). */
        FOREIGN_NS,

        /** No candidate recognition key matched (§6.5 step 2). */
        UNKNOWN_SEAL,

        /** A hint matched but the AEAD failed: a forgery (rule R-S5). */
        NOT_OPEN,

        /** It opened but did not parse exactly (rule R-S2, R-C4). */
        NON_CANONICAL,

        /** Binding v3 did not verify under the sender card's key (E-1). */
        BAD_BINDING,

        /** The generation the envelope names is gone (§5.4's erasure, §21.4 point 4). */
        UNKNOWN_GENERATION,

        /** The contact is blocked or revoked (§12.4, §8.5). */
        BLOCKED,

        /** `MAX_PENDING_REQUESTS` or `MAX_CONTACTS` (§12.3, §12.6). */
        REQUEST_OVERFLOW,

        /** A `request` contact sent a second Olm identity (§21.4 point 5). */
        REQUEST_KEY_MISMATCH,

        /** An identity that is not the pinned one, and never a key change on its own (E-1). */
        UNTRUSTED,

        /** A MAC, padding, gap or key failure inside the session layer. */
        UNDECRYPTABLE,

        /** The message key is gone, or D3 already held this `message_id` (D2a, D3). */
        DUPLICATE,

        /** A replayed first flight of a live generation (D2b, §7.6). */
        REPLAY,

        /** An older first flight of a contact that has since restored or reset (§22.8.4 rule 2). */
        STALE_SESSION,

        /** Content older than `FRESH(bucket)`, from the future, or of the wrong pair week (R9). */
        STALE,

        /** The L0 did not decode (R8). */
        BAD_CONTENT,

        /** A stored envelope did not open under its binding (§22.8.3). */
        STATE_CORRUPT,

        /** A `seal_root` whose generation is not newer than the stored one (§6.3). */
        ROOT_NOT_NEWER,

        /** A PQ-C TLV: counted and ignored in Phase 9 (§9.4, slice S13). */
        PQ_TLV_IGNORED,

        /** A revocation certificate: slice S8 acts on it, S7 counts it (§8.5). */
        REVOCATION_DEFERRED,

        /** A `session_reset` notice: slice S8 acts on it, S7 counts it (§8.6). */
        SESSION_RESET_DEFERRED,
    }

    private val drops = EnumMap<Reason, Int>(Reason::class.java)

    @Volatile
    private var poisoned: Int = 0

    /** One drop, of one reason. */
    @Synchronized
    fun drop(reason: Reason) {
        drops[reason] = (drops[reason] ?: 0) + 1
    }

    /** A blob consumed unprocessed after three process deaths on it (§7.8 R2). */
    @Synchronized
    fun poisoned() {
        poisoned += 1
    }

    /** How many blobs were dropped for [reason] since this process started. */
    @Synchronized
    fun count(reason: Reason): Int = drops[reason] ?: 0

    /** The whole set, for `status()`. */
    @Synchronized
    fun snapshot(): Map<Reason, Int> = EnumMap(drops)

    /** How many blobs the poison guard consumed unprocessed. */
    @Synchronized
    fun poisonedCount(): Int = poisoned

    /** Never shows anything but counts (T3, T33). */
    override fun toString(): String = "DmCounters(drops=${drops.values.sum()}, poisoned=$poisoned)"
}
