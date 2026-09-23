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

        /**
         * A `seal_root` TLV carried by a **PreKey** message, which §21.3 rule 1 names and ignores.
         *
         * This device's own sender side never attaches one ([SendStep] refuses an offer on an
         * unacknowledged session), but the rule is about **receipt**: a peer running a modified or
         * older client can put a root in the L0 of its first flight, and installing out pair keys
         * from it would let the root ride inside an Olm PreKey message whose decryption keys — the
         * seed-derived identity plus the generation's retained secrets — live until
         * `superseded_day + 91`. That is mutant PM-29 and the P-7 / T34 violation the rule exists
         * to prevent, so the drop is the defence and not a formality.
         */
        ROOT_IN_PREKEY,

        /**
         * A PQ-C TLV that is ignored: a `seal_root_pq` beside a classical `seal_root` in one L0,
         * which no sender following §9.4 writes (the PQ form replaces the classical one; slice S13
         * narrowed this counter, which before PQ-C counted every PQ-C TLV).
         */
        PQ_TLV_IGNORED,

        /**
         * §22.8.6 rule 3: a `seal_root_pq` that does not open — it names a generation this device
         * does not hold (never had, or erased), or its ciphertext does not decapsulate. Ignored and
         * counted; the rest of the L0 applies.
         */
        PQ_ROOT_UNOPENABLE,

        /** §22.8.2 rule 3: an in-band `pq_key` whose X-Wing key is not valid whole. Ignored. */
        BAD_PQ_KEY,

        /**
         * §8.3: an intro PreKey message under a **new** Olm identity, bound by a signature valid
         * under the contact's pinned Ed25519 key, was held undecrypted. The contact is `changed`
         * and waits for the user; nothing is shown and nothing is sent (CS-5, T28).
         */
        KEY_CHANGE_HELD,

        /** §8.3: `MAX_HELD_PER_CONTACT` was reached and the oldest held row was evicted. */
        HOLD_OVERFLOW,

        /**
         * §21.10 point 5: a held message replayed after the user's decision whose unread deadline,
         * computed from the row's own `relay_expiry_hour` and `consume_minute`, has already
         * passed. It is not inserted; the ciphertext is deleted with its row.
         */
        EXPIRED_WHILE_HELD,

        /** §8.5: a valid revocation certificate v2 was applied; the contact is terminal. */
        REVOKED,

        /** §8.5: a `revocation` TLV that did not parse, verify, or named another identity. */
        BAD_REVOCATION,

        /**
         * §8.6: a `session_reset` notice — a content-free contact event, no message row. It is
         * counted because that is the only record §7.4's "no persisted rejection history" allows,
         * and because the renewal it announces is R-SS1's work and not this TLV's.
         */
        SESSION_RENEWED,
    }

    /**
     * The **sending** side of PQ-C (§9.4; slice S13 review): what a send did instead of the PQ-C
     * step it could have taken. None of it moves or drops a blob, so it is not a [Reason]; but a
     * conversation whose offers stay classical, or whose announcements never ride, heals in no
     * direction, and before these counts nothing showed it.
     */
    enum class PqEvent {
        /** A root offer went out classical: no fresh X-Wing key of the contact was held (§22.18). */
        OFFER_CLASSICAL_NO_KEY,

        /**
         * A root offer went out classical: the crate refused the contact's key at encapsulation
         * (§22.8.2 rule 4, and the key is deleted) or could not seal the PQ-C form.
         */
        OFFER_CLASSICAL_REFUSED,

        /**
         * A root offer went out classical: the PQ-C form did not fit the slack of the message's
         * bucket (R-C5), and the classical form replaced it in the same send (§9.4's fallback).
         */
        OFFER_CLASSICAL_NO_SLACK,

        /** A `pq_key` was due and did not fit the slack of the message's bucket (R-C5): it waits. */
        PQ_KEY_DEFERRED,

        /** A `pq_key` could not be built from its stored generation, and the L0 went without it. */
        PQ_KEY_DROPPED,
    }

    private val drops = EnumMap<Reason, Int>(Reason::class.java)

    private val pqEvents = EnumMap<PqEvent, Int>(PqEvent::class.java)

    @Volatile
    private var poisoned: Int = 0

    /** One drop, of one reason. */
    @Synchronized
    fun drop(reason: Reason) {
        drops[reason] = (drops[reason] ?: 0) + 1
    }

    /** One PQ-C sending event. */
    @Synchronized
    fun pq(event: PqEvent) {
        pqEvents[event] = (pqEvents[event] ?: 0) + 1
    }

    /** How many times [event] happened since this process started. */
    @Synchronized
    fun pqCount(event: PqEvent): Int = pqEvents[event] ?: 0

    /** Every PQ-C sending count, for `status()`. */
    @Synchronized
    fun pqSnapshot(): Map<PqEvent, Int> = EnumMap(pqEvents)

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
