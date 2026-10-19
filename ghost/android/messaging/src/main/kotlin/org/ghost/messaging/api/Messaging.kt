package org.ghost.messaging.api

import org.ghost.crypto.bridge.DmRevocations
import org.ghost.messaging.engine.ContactSteps
import org.ghost.messaging.engine.DmCounters
import org.ghost.messaging.engine.KeyDecision
import org.ghost.messaging.engine.OwnerSteps
import org.ghost.messaging.engine.SendStep
import org.ghost.messaging.store.ContactStore

/**
 * The UI-less DM facade of Phase 9 design §13.2, **as far as slices S6 and S7 build it**.
 *
 * §13.2 gives the whole interface Phase 13 will call. S6 was the **owner side**: the identity's
 * own card and the activation hooks. S7 is **contacts, sending and receiving**. S8 is **trust and
 * restore**: safety numbers, the two key-change decisions, `markVerified`, `resetSession`,
 * `reconnect` and the two revocation calls. S9 is **ephemeral**: `markDisplayed`, which starts the
 * recipient's countdown, and `setNotificationPort`. What is left arrives with its own slice, and
 * each signature lands **with** its slice rather than ahead of it: a method that compiled and
 * answered nothing would be refused by the static gates, and a caller written against one would be
 * written against a promise. `setListener` (the coarse content-free change hints of §13.2) is
 * still one of those.
 *
 * The contract §13.2 states holds for everything here: **every method posts to the DM actor** and
 * returns after its transaction commits (§13.7), none performs network I/O (gate G-DM1), and
 * `toString()` of every value type is redacted (T3).
 */
/** §6.5's `PreparationId`: random, local, no row before `MEDIA-COMMIT` (T33). Redacted. */
class PreparationId(internal val id: String) {
    override fun equals(other: Any?): Boolean = other is PreparationId && other.id == id
    override fun hashCode(): Int = id.hashCode()
    override fun toString(): String = "PreparationId(redacted)"
}

/**
 * §6.5's `sendMedia` answer. The design words it `QUEUED(preparation) | TOO_LARGE | …`: the
 * refusal values are [SendResult]'s (the F9 enum, extended with [SendResult.LIMIT_REACHED] and
 * [SendResult.NOT_RETRYABLE]); `QUEUED` carries the [PreparationId] the UI polls with
 * [Messaging.preparationState]. (A wrapper rather than a carrier on `SendResult.QUEUED` itself:
 * 158 F9 call sites read the plain value; §22.8 records the reading.)
 */
sealed class MediaSendResult {
    /** The preparation runs on the media worker; poll [Messaging.preparationState]. */
    class Queued(val preparation: PreparationId) : MediaSendResult()

    /** A check made before any work refused the send (a local refusal, visible to nobody else). */
    class Refused(val result: SendResult) : MediaSendResult()
}

/** §6.5's `preparationState` answer; null for an unknown id or after the final state was read once. */
sealed class PreparationView {
    /** Work is running; [progress] is 0–99, a UI hint. */
    data class Preparing(val progress: Int) : PreparationView()

    /** `MEDIA-COMMIT` committed; the message id is the item the UI follows. */
    class Committed(val message: MessageId) : PreparationView()

    /** The typed refusal (§6.2's list). */
    class Failed(val failure: org.ghost.media.send.PrepFailure) : PreparationView()
}

/**
 * §6.5's `mediaPreview` answer: decoded pixels from the RAM cache or the sandbox. ARGB_8888,
 * row-major, `pixels.size == width * height * 4`; the UI wraps them in a Bitmap (Phase 13).
 * Every value type's `toString()` is redacted (T3).
 */
class MediaPreview(
    val width: Int,
    val height: Int,
    val pixels: ByteArray,
) {
    init {
        require(width > 0 && height > 0 && pixels.size == width * height * 4) { "not ARGB_8888 pixels" }
    }

    override fun toString(): String = "MediaPreview(${width}x$height)"
}

/**
 * §6.5/§10.2's `openMedia` answer (slice S7): one open native reader over one object, the
 * metadata the UI shows, and the [org.ghost.media.play.MediaPlayable] the player reads
 * through. The UI builds its player with [org.ghost.media.play.GhostPlayer.create] and
 * closes the handle when the screen closes: closing zeroises the native reader (§13.2 M8),
 * a lock closes every open handle (§13.7), and reads after either end in a typed playback
 * error, never a crash. Every value type's `toString()` is redacted (T3).
 */
class MediaHandle(
    val kind: org.ghost.media.store.MediaKind,
    val classCode: Int,
    val width: Int,
    val height: Int,
    /** The manifest's duration (§10.2: the fMP4 carries none; the UI and the seek tests use this). */
    val durationMs: Long,
    /** The object's exact content length. */
    val contentLength: Long,
    /** The player's data path; consumed only by [org.ghost.media.play.GhostMediaDataSource]. */
    val playable: org.ghost.media.play.MediaPlayable,
) : AutoCloseable {

    /** Close the native reader and zeroise what it holds; idempotent in effect. */
    override fun close() = playable.close()

    override fun toString(): String = "MediaHandle(kind=$kind, class=$classCode, ${width}x$height, ${durationMs}ms)"
}

/**
 * §6.5's `mediaState` answer: the object's kind, class, state and held/F progress — no times.
 * [NOT_KEPT] is the request rule's answer (D28): the message is there, the object is not, and
 * nothing on the device can open it.
 */
class MediaStateView(
    /**
     * The store's state (the sender's uploads show the outgoing states, §7.6); **null exactly for
     * [NOT_KEPT]** — a message whose object the request rule (D28) never created has no state.
     */
    val state: org.ghost.media.store.ObjectState?,
    val kind: org.ghost.media.store.MediaKind?,
    val classCode: Int,
    /** The fragments the device holds bound, of [totalFragments] (the manifest excluded). */
    val heldFragments: Int,
    val totalFragments: Int,
) {
    override fun toString(): String = "MediaStateView(state=$state, kind=$kind, class=$classCode, $heldFragments/$totalFragments)"

    companion object {
        /** A kind-5 message whose descriptor arrived in a request (D28): stored, never openable. */
        val NOT_KEPT: MediaStateView = MediaStateView(
            state = null,
            kind = null,
            classCode = -1,
            heldFragments = 0,
            totalFragments = 0,
        )
    }
}

/**
 * §6.5's `MediaSource`: the picked source and nothing else. The app builds it — the bytes for an
 * image (read straight into memory, §6.1's no-copy rule is the app's contract), or the video
 * source port plus its first 64 bytes for the sniff. No platform content-handle package name
 * crosses into the DM modules (G-DM1; §22.8 F-S5-3's pattern).
 */
class MediaSource private constructor(
    internal val imageBytes: ByteArray?,
    internal val videoSource: org.ghost.media.send.VideoSource?,
    internal val videoFirst64: ByteArray?,
) {
    init {
        require((imageBytes != null) != (videoSource != null)) { "exactly one of image or video" }
        if (imageBytes != null) require(imageBytes.size >= 64) { "the sniff needs the first 64 bytes" }
        if (videoSource != null) require(videoFirst64 != null && videoFirst64.size >= 8) { "the sniff needs the ftyp" }
    }

    companion object {
        /** A picked still image: its full encoded bytes (the engine sniffs the head). */
        fun image(bytes: ByteArray): MediaSource = MediaSource(bytes, null, null)

        /** A picked video: the opaque source port and its first bytes for the sniff. */
        fun video(source: org.ghost.media.send.VideoSource, first64: ByteArray): MediaSource =
            MediaSource(null, source, first64)
    }
}

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
    /** §13.2's add, with the §3.6 alias applied when the add succeeds. */
    fun addContact(card: ByteArray, source: CardSource, name: String?): AddContactResult

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
    /** Phase 13 §3.6: the conversation list's rows - contact id, live unread count, newest live
     * message minute; no text, ever (T33). */
    fun conversationSummaries(): List<ConversationSummary>

    /** Phase 13 §3.6 (`conversationTimer`): the conversation's timer, or null when off. */
    fun conversationTimer(contact: ContactId): Timer?

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
    /** Phase 13 §3.6: renames (or clears, null) the contact's alias. False when no such contact. */
    fun rename(contact: ContactId, name: String?): Boolean

    fun deleteContact(contact: ContactId): Boolean

    // --------------------------------------------------------------------- send

    /** §7.3: one text message. The result is the send's, not the delivery's (D10, FR-4.3). */
    fun send(contact: ContactId, text: String, quote: MessageId?): SendResult

    /**
     * §7.1: a reaction to a message of the same conversation; an empty grapheme removes it. A
     * grapheme over 32 bytes is [SendResult.TOO_LARGE]; a target that is not a live message of the
     * conversation is [SendResult.UNKNOWN].
     */
    fun react(contact: ContactId, target: MessageId, grapheme: String?): SendResult

    /** §10.5: the conversation timer, as a TIMER_SET message both sides see (ADR-27 C.8). */
    fun setTimer(contact: ContactId, timer: Timer): SendResult

    /**
     * §10.3, §21.10 point 6: the recipient's countdown starts **here**, at the first display, and
     * not at receipt (mutant ME-7).
     *
     * `expire_at_minute` becomes `ceil_minute(now + timer)` for each id that names a live incoming
     * unread message of this device, and only if that is **earlier** than a value already there
     * (R-T6). Ids that name nothing, an outgoing row, an already-displayed one, or a message whose
     * `delete_at_minute` has passed are ignored: a stale call cannot resurrect a message the unread
     * cap already took.
     *
     * Returns how many rows moved to `read` — a count, never a time or an id (T3).
     */
    fun markDisplayed(ids: List<MessageId>): Int

    /**
     * §10.7 (Q19), §13.2: the only channel from the DM layer to a notifier, and it carries a
     * **count**.
     *
     * The count is published after every transaction that can change it (`RECV`, `HELD`,
     * `markDisplayed`, SWEEP), and only when it differs from the last one published, so an
     * implementation that reposts is not turned into a heartbeat. `0` means cancel.
     *
     * Phase 9 posts no notification of its own (§21.10 point 9); what it ships is this port and the
     * guarantee that nothing else ever crosses it.
     */
    /**
     * Phase 13 §3.6 (`setListener`): the UI's live-update hook — content-free kinds, emitted on
     * the actor thread AFTER the committing pass. The listener must not block the actor (the UI
     * hands it to a conflated hub; §13.7's rule for the hand-off). Enums only, so the UI-side
     * surface is testable without engine types.
     */
    fun setListener(listener: MessagingListener?)

    fun setNotificationPort(port: NotificationPort?)

    /**
     * §7.5: the user retry of a FAILED message. It re-encrypts the **same** L0 — same
     * `message_id`, author minute, minute index and timer fields — under the next ratchet step,
     * while `now` is before the original deadline; after it, `DEADLINE_PASSED`.
     */
    fun retry(message: MessageId): SendResult

    /**
     * Phase 11 §6.5: send a photo or a video. The checks before any work — the contact's state,
     * the sniff, the header limits, the free-space floor — refuse locally; the rest of the
     * outcome arrives through [preparationState].
     */
    fun sendMedia(contact: ContactId, source: MediaSource, caption: String?, viewOnce: Boolean): MediaSendResult

    /** The preparation's state; null for an unknown id or after its final state was read once. */
    fun preparationState(preparation: PreparationId): PreparationView?

    /** §6.5: retry a FAILED object before its deadline (at most three times); see [SendResult]. */
    fun retryMedia(message: MessageId): SendResult

    /**
     * §6.5's `mediaState`: the object's kind, class, state and held/F progress; [MediaStateView.NOT_KEPT]
     * for a kind-5 message received in a request (D28); null for a message that is not media (or
     * is gone). A local read, no traffic.
     */
    fun mediaState(message: MessageId): MediaStateView?

    /**
     * §6.5/§7.4's `setConversationOnScreen`: the UI's statement of which conversation is visible
     * (null: none). With the foreground signal (the app lifecycle's ON_START/ON_STOP) it is the
     * gate every preview decode passes (§9.3's zero-click rules).
     */
    fun setConversationOnScreen(contact: ContactId?)

    /**
     * §6.5's `mediaPreview`: decoded pixels from the RAM cache or the sandbox; null unless §7.4
     * allows — the conversation named on screen, the process in the foreground, a contact the
     * zero-click rules allow, and an object `MEDIA-VERIFY` passed. A sandbox failure counts
     * towards the object's two-strikes rule (CS-M8) and answers null.
     */
    fun mediaPreview(message: MessageId): MediaPreview?

    /**
     * §6.5/§10.2's `openMedia`: a [MediaHandle] over a `verified` object — or the sender's own
     * `out` object in `uploading`, `uploaded` or `failed` (§7.4) —, null otherwise (no object,
     * a request's `NOT_KEPT`, a view-once object: those open through S8's `openViewOnce`, or
     * the object is not readable). The UI builds its player with [org.ghost.media.play.GhostPlayer]
     * over [MediaHandle.playable]; closing the handle zeroises the native reader (§13.2 M8),
     * and a lock closes every open handle (§13.7). A byte found corrupted after `verified`
     * makes the object `corrupt` and the player end with a typed error, never a crash (§7.3).
     */
    fun openMedia(message: MessageId): MediaHandle?

    /**
     * §6.5/§11.2's `openViewOnce`: the single display of a verified view-once object. The key is
     * erased in the opening transaction and the WAL checkpointed before the handle returns (a
     * crash after the commit loses the object — at most one display per device, CS-M5); closing
     * the handle — the UI, a lock, a wipe — is `VIEW-ONCE-CLOSE`, and a process that died mid-view
     * closes it at its next start. Null unless the object is verified, view-once and never opened.
     */
    fun openViewOnce(message: MessageId): MediaHandle?

    // -------------------------------------------------------- trust and restore

    /**
     * §8.4: the 60 digits and the 65-byte scannable form over both `ghost1` keys and both Olm
     * identity keys, or null when the contact has no pinned Olm identity yet (a card added but
     * never established) or the DM context is closed.
     *
     * Computing, displaying, scanning and comparing cause **no network I/O** (T31).
     */
    fun safetyNumber(contact: ContactId): SafetyNumberView?

    /**
     * §8.4: the number the contact **would** have after the pending key change is accepted, so the
     * user can verify before deciding rather than after. Null unless the contact is `CHANGED`.
     */
    fun pendingSafetyNumber(contact: ContactId): SafetyNumberView?

    /** §8.4: the user scanned this contact's code and it matched, so the contact is `VERIFIED`. */
    fun markVerified(contact: ContactId, scanned: ByteArray): VerifyResult

    /** §8.4: the user compared the 60 digits by voice or in person and says they matched. */
    fun markVerifiedManually(contact: ContactId): VerifyResult

    /**
     * §8.3 "explicit confirmation" (FR-4.6): the user accepts the new Olm identity **without**
     * comparing it. The contact becomes `UNVERIFIED` — nothing was asserted about the new key — its
     * sessions are deleted, and the messages held since the change are replayed in order.
     */
    fun acknowledgeKeyChange(contact: ContactId): Boolean

    /** §8.3: the same decision after scanning the contact's new code; the contact is `VERIFIED`. */
    fun verifyKeyChange(contact: ContactId, scanned: ByteArray): VerifyResult

    /**
     * §8.7: the user resets a conversation that stopped working. Both session rows go (R-SS0) and
     * the next message goes through the one-shot bundle fetch; the contact sees an ordinary
     * renewal, with no key-change warning.
     */
    fun resetSession(contact: ContactId): SendResult

    /**
     * §8.6: after a restore, the user re-adds cards and asks for the contacts to be reconnected.
     *
     * Each one gets a `session_reset` control due at its own `U[0, 48 h]` offset, drawn now and
     * persisted — a burst of k deposits into k inboxes in one session would show a degree of k.
     * Returns how many were accepted and scheduled.
     */
    fun reconnect(contacts: List<ContactId>): Int

    /**
     * §8.5: mints this identity's revocation certificate v2. **Local**: nothing is sent, and
     * nothing is published in a namespace contacts poll (T31).
     *
     * It returns the 102 bytes because schema v5 has no column for a self-issued certificate; hand
     * them back to [notifyContactsOfRevocation] to propagate. They are public and signed, and every
     * contact that receives one keeps a copy.
     */
    fun issueRevocation(reason: RevocationReason): ByteArray?

    /**
     * §8.5: one CONTROL message per contact carrying the certificate, each due at its own
     * `U[0, 24 h]` offset. Returns how many were scheduled.
     */
    fun notifyContactsOfRevocation(certificate: ByteArray): Int

    // ------------------------------------------------------------------- status

    /** §13.2 `status`: counts only, never an identity, a time or a rejection history (T33). */
    fun status(): MessagingStatus
}

/** §8.4: what a contact's safety number looks like to the UI. */
class SafetyNumberView(
    /** The 60 decimal digits, in the order §8.4 fixes (the smaller 30-digit string first). */
    val digits: String,
    scannable: ByteArray,
) {
    private val raw: ByteArray = scannable.copyOf()

    /** The 65-byte versioned form a QR code carries. */
    val scannable: ByteArray get() = raw.copyOf()

    /** Never shows the digits: they are a fingerprint of two identities (T3). */
    override fun toString(): String = "SafetyNumberView(redacted)"
}

/** What a verification decided (§8.4, §13.2). */
enum class VerifyResult {
    /** The code matched and the contact is verified (and, for a key change, re-pinned). */
    VERIFIED,

    /** The scanned code is of another format version. */
    VERSION_MISMATCH,

    /** The scanned code belongs to another pair, or to another key. */
    MISMATCH,

    /** No such contact, or it is not in the state this call needs. */
    UNKNOWN,

    /** The DM context is closed or the native library is missing (§13.2). */
    CRYPTO_UNAVAILABLE,
    ;

    internal companion object {
        fun of(outcome: KeyDecision.Outcome): VerifyResult = when (outcome) {
            KeyDecision.Outcome.DONE -> VERIFIED
            KeyDecision.Outcome.VERSION_MISMATCH -> VERSION_MISMATCH
            KeyDecision.Outcome.MISMATCH -> MISMATCH
            KeyDecision.Outcome.NOT_CHANGED -> UNKNOWN
            KeyDecision.Outcome.UNAVAILABLE -> CRYPTO_UNAVAILABLE
        }
    }
}

/** §8.5: why an identity was revoked (the Phase 3 code set, kept by certificate v2). */
enum class RevocationReason {
    DEVICE_LOST,
    DEVICE_COMPROMISED,
    KEY_ROTATION,
    ;

    internal fun toBridge(): DmRevocations.Reason = when (this) {
        DEVICE_LOST -> DmRevocations.Reason.DEVICE_LOST
        DEVICE_COMPROMISED -> DmRevocations.Reason.DEVICE_COMPROMISED
        KEY_ROTATION -> DmRevocations.Reason.KEY_ROTATION
    }
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
    /** The alias of Phase 13 §3.6, decrypted into memory only (like the message text). */
    val name: String? = null,
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
    /** Phase 13 §3.6: the message's own timer (null when off). */
    val timer: Timer? = null,
    /** Phase 13 §3.6: when this message expires (live timer messages only). */
    val expireAtMinute: Long? = null,
    /** Phase 13 §3.6: our reaction's grapheme, decrypted into memory only. */
    val myReaction: String? = null,
    /** Phase 13 §3.6: the peer's reaction's grapheme, decrypted into memory only. */
    val peerReaction: String? = null,
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

    /** No such contact, no message to retry, or no live message of the conversation to react to. */
    UNKNOWN,

    /** A retry past the original deadline (§7.5). */
    DEADLINE_PASSED,

    /** Phase 11 §6.5: the concurrent-preparation bound (`MediaSendLimits.MAX_CONCURRENT_PREPARATIONS`). */
    LIMIT_REACHED,

    /** Phase 11 §6.4/§6.5: a media retry of an object whose ciphertext is gone (the feed's hash rule). */
    NOT_RETRYABLE,
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
            SendStep.Outcome.UNKNOWN_TARGET -> UNKNOWN
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
    /**
     * PQ-C sending events by name since this process started (§9.4; slice S13 review): root offers
     * that went out classical and why, and `pq_key` announcements deferred or dropped. Counts only,
     * like [drops]; a conversation that never heals is visible here and nowhere else.
     */
    val pq: Map<String, Int> = emptyMap(),
) {
    override fun toString(): String =
        "MessagingStatus(drops=${drops.values.sum()}, poisoned=$poisoned, establishing=$establishing)"

    internal companion object {
        fun reasonName(reason: DmCounters.Reason): String = reason.name.lowercase()

        fun pqEventName(event: DmCounters.PqEvent): String = event.name.lowercase()
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

/** What changed, content-free (Phase 13 §3.6); the UI conflates and re-queries. */
enum class ChangeKind { CONTACTS, MESSAGES, REQUESTS, TRUST, OUTCOMES, STATUS }

/** The listener of [Messaging.setListener]; called on the actor thread after commits. */
fun interface MessagingListener {
    fun onChanged(kinds: Set<ChangeKind>)
}

/** A conversation-list row of Phase 13 §3.6: id, live unread count, newest live minute - no text. */
class ConversationSummary(
    val contactId: ByteArray,
    val unread: Int,
    val newestAuthorMinute: Long,
) {
    override fun toString(): String = "ConversationSummary(unread=$unread)"
}
