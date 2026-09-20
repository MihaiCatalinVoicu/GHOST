package org.ghost.messaging.api

import org.ghost.messaging.engine.ContactSteps
import org.ghost.messaging.engine.DmCounters
import org.ghost.messaging.engine.OwnerSteps
import org.ghost.messaging.engine.SendStep
import org.ghost.messaging.store.ContactStore

/**
 * The UI-less DM facade of Phase 9 design §13.2, **as far as slices S6 and S7 build it**.
 *
 * §13.2 gives the whole interface Phase 13 will call. S6 was the **owner side**: the identity's
 * own card and the activation hooks. S7 is **contacts, sending and receiving**: `addContact`,
 * `contacts`, `conversation`, `send`, `react`, `setTimer`, `retry`, the request decisions, and
 * `block`/`unblock`/`deleteContact`. What is left arrives with its own slice — trust, safety
 * numbers, key-change decisions, reset, reconnect and revocation with **S8**, `markDisplayed` and
 * the notification port with **S9** — and each signature lands **with** its slice rather than
 * ahead of it: a method that compiled and answered nothing would be refused by the static gates,
 * and a caller written against one would be written against a promise.
 *
 * The contract §13.2 states holds for everything here: **every method posts to the DM actor** and
 * returns after its transaction commits (§13.7), none performs network I/O (gate G-DM1), and
 * `toString()` of every value type is redacted (T3).
 */
interface Messaging {

    /**
     * The owner's contact card v2 and its `ghost://contact/` link (§3.3, §12.1). No network, no
     * transaction: the card is a pure function of the seed and the card index, so a restored
     * device shows the same card and every contact keeps working.
     *
     * Null means `CRYPTO_UNAVAILABLE`: the DM context is closed (locked, wiped) or
     * `libghost_client_net.so` could not be loaded (§13.2).
     */
    fun myCard(): CardExport?

    /**
     * The K20 activation hook (§13.4, RS K20): `:entitlement` calls it after the activation
     * finalization of a trial or a genesis identity, through `:app`. Runs **ACTIVATE** (§7.2).
     *
     * It is safe to call more than once and from any state: ACTIVATE is idempotent per identity,
     * and §21.12 point 2 has the actor run it again at every start and database open, which is
     * what covers a crash between the identity's creation and this commit.
     */
    fun onActivated(): ActivationOutcome

    /**
     * The restore half of the same hook (§13.4, §8.6). Runs ACTIVATE with the restore semantics:
     * `dm_self.accept_after_minute` is this minute, so content authored before the restore is
     * refused at `RECV` R9 — `dm_seen` and the pair keys did not survive, so it could not be
     * deduplicated (§7.6 "Restore").
     */
    fun onRestored(): ActivationOutcome

    /**
     * The owner-side time-triggered steps of §7.2 — OWNER-WEEK, KEEPER and REGROWS — run in the
     * order §13.7 gives them, from a relay session start, a database open or the actor timer
     * (§21.9 rule 1). It is **never** called from an `INBOX` hint or a user send: that is the
     * whole of PM-30, and gate G-DM2 refuses a call from any other file.
     *
     * Returns counts only (T3).
     */
    fun runOwnerMaintenance(): MaintenanceReport

    // ------------------------------------------------------------------ contacts

    /**
     * §12.1, §12.2 step 1: a card becomes a contact, **locally**.
     *
     * Rule R-E1: adding a card never registers, fetches or stores anything until the user sends.
     * A card scanned in person starts `verified` — the scanned `identity_pk` authenticates the
     * Olm identity transitively through the bundle signature and binding v3 (§8.4) — and a card
     * that arrived as a link starts `unverified`, because a substituted link is a MITM.
     */
    fun addContact(card: ByteArray, source: CardSource): AddContactResult

    /** §13.2 `contacts`: ids and enums only, never a time (T33). */
    fun contacts(): List<ContactView>

    /**
     * §13.2 `conversation`: a page of one conversation, newest first, in the order R-O1 fixes —
     * `(sort_minute, minute_index, message_id)`, a pure function of stored content, with no
     * arrival-order column anywhere (§7.7).
     *
     * Every read carries the expiry filter of §10.7 point 4, so a message whose timer has passed
     * is never shown even before SWEEP has physically deleted it (mutant ME-16).
     */
    fun conversation(contact: ContactId, limit: Int, before: MessageCursor?): List<MessageView>

    /** §12.3: an unknown card holder's request becomes a contact the user may write to. */
    fun acceptRequest(contact: ContactId): Boolean

    /** §12.3: the request, its session, its pair keys and its rows go in one transaction. */
    fun rejectRequest(contact: ContactId): Boolean

    /** §12.3: the identity is kept, so later requests from it are dropped at `RECV` R5. */
    fun blockRequest(contact: ContactId): Boolean

    /**
     * §12.4: local, and the card goes with it. The contact's deposits still land in this inbox
     * and are dropped when they arrive; nothing is sent, the contact is not told, and copies on
     * its device are not touched — the Phase 13 UI says all three (FR-4.7).
     */
    fun block(contact: ContactId): Boolean

    /** §12.4: the blocked row is deleted, and the user must add the card again. */
    fun unblock(contact: ContactId): Boolean

    /** §12.4: every row of the contact; its two namespaces wait for SWEEP (§21.12 point 3). */
    fun deleteContact(contact: ContactId): Boolean

    // --------------------------------------------------------------------- send

    /** §7.3: one text message. The result is the send's, not the delivery's (D10, FR-4.3). */
    fun send(contact: ContactId, text: String, quote: MessageId?): SendResult

    /** §7.1: a reaction to a message of the same conversation; an empty grapheme removes it. */
    fun react(contact: ContactId, target: MessageId, grapheme: String?): SendResult

    /** §10.5: the conversation timer, as a TIMER_SET message both sides see (ADR-27 C.8). */
    fun setTimer(contact: ContactId, timer: Timer): SendResult

    /**
     * §7.5: the user retry of a FAILED message. It re-encrypts the **same** L0 — same
     * `message_id`, author minute, minute index and timer fields — under the next ratchet step,
     * while `now` is before the original deadline; after it, `DEADLINE_PASSED`.
     */
    fun retry(message: MessageId): SendResult

    // ------------------------------------------------------------------- status

    /** §13.2 `status`: counts only, never an identity, a time or a rejection history (T33). */
    fun status(): MessagingStatus
}

/** The owner's own card: 131 bytes and the 226-character link (§3.3). */
class CardExport(card: ByteArray, val link: String) {
    private val bytes: ByteArray = card.copyOf()

    val card: ByteArray get() = bytes.copyOf()

    /** Never shows the card: it is a bearer secret for "may message me" (§3.3). */
    override fun toString(): String = "CardExport(redacted)"
}

/** A contact, by its local random id (§8.1: Olm never sees it). */
class ContactId(bytes: ByteArray) {
    private val raw: ByteArray = bytes.copyOf()

    init {
        require(bytes.size == SIZE) { "a contact id is 16 bytes" }
    }

    fun toByteArray(): ByteArray = raw.copyOf()

    override fun equals(other: Any?): Boolean = other is ContactId && other.raw.contentEquals(raw)

    override fun hashCode(): Int = raw.contentHashCode()

    override fun toString(): String = "ContactId(redacted)"

    companion object {
        const val SIZE: Int = 16
    }
}

/** A message, by its end-to-end `message_id` (§7.1). */
class MessageId(bytes: ByteArray) {
    private val raw: ByteArray = bytes.copyOf()

    init {
        require(bytes.size == SIZE) { "a message id is 16 bytes" }
    }

    fun toByteArray(): ByteArray = raw.copyOf()

    override fun equals(other: Any?): Boolean = other is MessageId && other.raw.contentEquals(raw)

    override fun hashCode(): Int = raw.contentHashCode()

    override fun toString(): String = "MessageId(redacted)"

    companion object {
        const val SIZE: Int = 16
    }
}

/**
 * Where a page of a conversation continues (§13.2 `before`): the R-O1 order key of the oldest
 * message the caller already has.
 */
class MessageCursor(val sortMinute: Long, val minuteIndex: Int, val messageId: MessageId) {
    override fun toString(): String = "MessageCursor(redacted)"
}

/** How a card reached this device (§12.1). */
enum class CardSource {
    /** Scanned in person: starts `verified` (§8.4). */
    QR_IN_PERSON,

    /** A `ghost://contact/` link through another channel: starts `unverified`. */
    LINK,
    ;

    internal fun toStore(): ContactStore.Source = when (this) {
        QR_IN_PERSON -> ContactStore.Source.QR_IN_PERSON
        LINK -> ContactStore.Source.LINK
    }
}

/** The trust states of §8.3, as the facade shows them. */
enum class TrustState { REQUEST, UNVERIFIED, VERIFIED, CHANGED, BLOCKED, REVOKED }

/** The establishment states of §13.5. */
enum class Establishment { CARD_ONLY, FETCHING, READY, UNREACHABLE }

/** A contact as §13.2 renders it: no times, no keys. */
class ContactView(
    val id: ContactId,
    val trust: TrustState,
    val establishment: Establishment,
    val source: CardSource?,
    val resetNeeded: Boolean,
) {
    override fun toString(): String = "ContactView($trust, $establishment)"
}

/** One message, with its text decrypted **into memory only** (§13.2). */
class MessageView(
    val id: MessageId,
    val outgoing: Boolean,
    val kind: MessageKind,
    val authorMinute: Long,
    val state: MessageState,
    val text: String?,
    val quote: MessageId?,
    val cursor: MessageCursor,
) {
    /** Never shows the text (T3). */
    override fun toString(): String = "MessageView($kind, $state)"
}

/** What a message row is (§7.1's kinds, as far as a row exists for one). */
enum class MessageKind { TEXT, TIMER_SET }

/** The message state machines of §13.5. */
enum class MessageState { QUEUED, SENT, DEGRADED, FAILED, INDETERMINATE, UNREAD, READ }

/** The timer codes of §7.1 and ADR-27 C.7. */
enum class Timer(val code: Int) {
    OFF(0),
    MIN_5(1),
    HOUR_1(2),
    DAY_1(3),

    /** The default (ADR-27 point 7). */
    DAYS_7(4),
    DAYS_30(5),
    ;

    internal companion object {
        fun ofCode(code: Int): Timer = entries.first { it.code == code }
    }
}

/** What [Messaging.addContact] did (§13.2). */
enum class AddContactResult {
    ADDED,
    INVALID_CARD,
    OWN_CARD,
    ALREADY_KNOWN,

    /** A different card for a known identity: Phase 9 has no card rotation (C-16, §12.5). */
    CARD_CHANGED,
    REVOKED_IDENTITY,
    LIMIT_REACHED,
    CRYPTO_UNAVAILABLE,

    /** ACTIVATE has not run: there is no identity to add a contact to. */
    NOT_ACTIVATED,
    ;

    internal companion object {
        fun of(result: ContactSteps.AddResult): AddContactResult = when (result) {
            ContactSteps.AddResult.ADDED -> ADDED
            ContactSteps.AddResult.INVALID_CARD -> INVALID_CARD
            ContactSteps.AddResult.OWN_CARD -> OWN_CARD
            ContactSteps.AddResult.ALREADY_KNOWN -> ALREADY_KNOWN
            ContactSteps.AddResult.CARD_CHANGED -> CARD_CHANGED
            ContactSteps.AddResult.REVOKED_IDENTITY -> REVOKED_IDENTITY
            ContactSteps.AddResult.LIMIT_REACHED -> LIMIT_REACHED
            ContactSteps.AddResult.CRYPTO_UNAVAILABLE -> CRYPTO_UNAVAILABLE
            ContactSteps.AddResult.NOT_ACTIVATED -> NOT_ACTIVATED
        }
    }
}

/** What a send did (§13.2). It is the **send's** result, never the delivery's (D10). */
enum class SendResult {
    /** Stored, and either enqueued or waiting for establishment. */
    QUEUED,
    KEY_CHANGED,
    BLOCKED,
    REVOKED,
    REQUEST_NOT_ACCEPTED,
    TOO_LARGE,
    NO_REPLICAS,
    STORAGE_FULL,
    CRYPTO_UNAVAILABLE,

    /** No such contact, or no message to retry. */
    UNKNOWN,

    /** A retry past the original deadline (§7.5). */
    DEADLINE_PASSED,
    ;

    internal companion object {
        fun of(outcome: SendStep.Outcome): SendResult = when (outcome) {
            SendStep.Outcome.QUEUED -> QUEUED
            SendStep.Outcome.KEY_CHANGED -> KEY_CHANGED
            SendStep.Outcome.BLOCKED -> BLOCKED
            SendStep.Outcome.REVOKED -> REVOKED
            SendStep.Outcome.REQUEST_NOT_ACCEPTED -> REQUEST_NOT_ACCEPTED
            SendStep.Outcome.TOO_LARGE -> TOO_LARGE
            SendStep.Outcome.NO_REPLICAS -> NO_REPLICAS
            SendStep.Outcome.STORAGE_FULL -> STORAGE_FULL
            SendStep.Outcome.CRYPTO_UNAVAILABLE -> CRYPTO_UNAVAILABLE
            SendStep.Outcome.UNKNOWN_CONTACT -> UNKNOWN
            SendStep.Outcome.DEADLINE_PASSED -> DEADLINE_PASSED
        }
    }
}

/**
 * §13.2 `status`: **counts only**.
 *
 * No identity, no time and no persisted rejection history (T33, R-P2): the counters live in
 * memory and reset at every process start, which is what makes them safe to expose at all.
 */
class MessagingStatus(
    /** Drops by reason since this process started (§7.4 R-P2). */
    val drops: Map<String, Int>,
    /** Blobs consumed unprocessed after three process deaths on them (§7.8 R2). */
    val poisoned: Int,
    /** Contacts in each trust state. */
    val contactsByTrust: Map<TrustState, Int>,
    /** Contacts waiting for a bundle (§21.7). */
    val establishing: Int,
    /** Items stored and waiting for establishment (§5.5). */
    val pendingSends: Int,
) {
    override fun toString(): String =
        "MessagingStatus(drops=${drops.values.sum()}, poisoned=$poisoned, establishing=$establishing)"

    internal companion object {
        fun reasonName(reason: DmCounters.Reason): String = reason.name.lowercase()
    }
}

/** What [Messaging.onActivated] or [Messaging.onRestored] did. Enums only. */
enum class ActivationOutcome {
    /** `dm_self`, the own namespaces and the first bundle generation were created. */
    ACTIVATED,

    /** An identity was already activated here: ACTIVATE is idempotent per identity (§7.2). */
    ALREADY_ACTIVE,

    /** The DM context is closed or the native library is missing (§13.2). */
    CRYPTO_UNAVAILABLE,

    /**
     * This week's ES slot table yields no relay set, so no namespace could be registered (§5.2).
     * Nothing was written; §21.12 point 2's resumable activation runs it again.
     */
    NO_RELAYS,
    ;

    internal companion object {
        fun of(result: OwnerSteps.Result): ActivationOutcome = when (result) {
            OwnerSteps.Result.DONE -> ACTIVATED
            OwnerSteps.Result.UNCHANGED, OwnerSteps.Result.NOT_ACTIVATED -> ALREADY_ACTIVE
            OwnerSteps.Result.CRYPTO_UNAVAILABLE -> CRYPTO_UNAVAILABLE
            OwnerSteps.Result.NO_RELAYS -> NO_RELAYS
        }
    }
}

/** What one maintenance pass did. Counts and enums only, never a time (T3, §13.2 `status`). */
class MaintenanceReport(
    val ownerWeek: OwnerSteps.Result,
    val keeper: OwnerSteps.Result,
    val regrows: OwnerSteps.Result,
) {
    /** True when any of the three changed something. */
    val changed: Boolean
        get() = ownerWeek == OwnerSteps.Result.DONE ||
            keeper == OwnerSteps.Result.DONE ||
            regrows == OwnerSteps.Result.DONE

    override fun toString(): String = "MaintenanceReport($ownerWeek, $keeper, $regrows)"
}
