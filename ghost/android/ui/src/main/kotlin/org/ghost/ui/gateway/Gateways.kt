package org.ghost.ui.gateway

import org.ghost.ui.protect.SensitiveText

/**
 * Phase 13 design §3.2: the gateway interfaces — the closed surface through which the UI reaches
 * the engines. Every method maps to exactly one facade method or a local composition; UI models
 * hold only these types, UI enums, local ids and [SensitiveText] — no engine type crosses into
 * `:ui`. Adapters live in :app (`org.ghost.app.ui`) and run their blocking calls on the
 * `ghost-ui-io` executor (§3.2, CS-U6).
 *
 * A method that causes relay-visible traffic carries [UserAction] and may be called only from a
 * screen model's `on…` intent handler (PV-14).
 */

/** The result of the local invite inspection (§3.6, `Entitlement.inspectInvite` mapped). */
data class InvitePreview(
    val version: Int,
    val expiryDay: Int?,
    val refusedReason: String?,
)

/** The activation state of this installation's identity (§3.6). */
enum class ActivationState { NONE, ACTIVE, RESTORED }

/** The restore outcome (§5.7 step 3, `Entitlement.restore` mapped). */
enum class RestoreResult { RESTORED, REFUSED_MNEMONIC, ALREADY_ACTIVE, UNAVAILABLE }

/** The activation outcome (the engine's ActivationResult in UI naming, §3.6). */
enum class ActivateResult { ACTIVATED, ALREADY_ACTIVE, REFUSED, UNAVAILABLE }

/** Identity and onboarding: the database key, the invite, restore, the words, backup. */
interface IdentityGateway {
    /** Creates the database key envelope on first use (§3.6 `GhostApp.createDatabaseKey`). */
    suspend fun createDatabaseKey()

    /** Local inspection of an invite text — no state, no traffic (§3.6). */
    suspend fun inspectInvite(text: String): InvitePreview

    /** The activation state, for the onboarding flow's order (D36). */
    suspend fun activationState(): ActivationState

    /** Activates an inspected invite (traffic: ACTIVATE). */
    @UserAction
    suspend fun activateInvite(text: String): ActivateResult

    /** Genesis activation (Q21): refuses unless the build's genesis policy is on; §3.6. */
    @UserAction
    suspend fun activateGenesis(acknowledged: Boolean): ActivateResult

    /** Restores the identity from the 24 words (§5.7; local, `Entitlement.restore`). */
    @UserAction
    suspend fun restore(words: List<String>): RestoreResult

    /** The 24 word indices of the root, for display — never a joined string (§3.3, F-U4). */
    suspend fun mnemonicIndices(): IntArray

    /** The BIP-39 English word list, read from :identity — :ui holds no copy (CR-15). */
    suspend fun wordList(): List<String>

    /** The next backup challenge: [count] positions, the missed ones carried (§3.6). */
    suspend fun backupChallenge(count: Int, carried: List<Int>): List<Int>

    /** Verifies backup answers at [positions] (the full-check path passes all 24). */
    suspend fun verifyBackup(indices: IntArray, positions: List<Int>, answers: List<String>): Boolean

    /** New passphrase indices drawn with SecureRandom in the adapter (Q35). */
    suspend fun newPassphraseIndices(count: Int): IntArray
}

/** The app lock (§5.1, §5.2): one strength in Phase 13. */
interface LockGateway {
    /** True once a PIN exists; a new process starts locked when it does (§5.1). */
    suspend fun isConfigured(): Boolean

    /** Sets a new PIN (typed twice by the user; salt and tag stored, §5.2). */
    @UserAction
    suspend fun setPin(digits: CharArray)

    /** Submits the PIN: the failure is committed before the check (§5.2). */
    @UserAction
    suspend fun submitPin(digits: CharArray): PinSubmitResult

    /** Enables or disables the biometric convenience (§5.1). */
    @UserAction
    suspend fun setBiometricEnabled(enabled: Boolean)

    /** Whether the biometric convenience is on. */
    suspend fun biometricEnabled(): Boolean

    /** The lock timeout choice in seconds: 0, 60, 300 or 1 800 (Q5). */
    suspend fun timeoutSeconds(): Long

    @UserAction
    suspend fun setTimeoutSeconds(seconds: Long)
}

/** The result of a PIN submission (§5.2's state machine mapped to a value). */
sealed interface PinSubmitResult {
    /** Unlocked; the failure counter is reset. */
    data object Unlocked : PinSubmitResult

    /** Wrong PIN; [failures] is the committed count, [waitSeconds] the back-off (0 before 5). */
    data class Locked(val failures: Int, val waitSeconds: Long) : PinSubmitResult
}

/** Access and payment (J2, §3.6 `openPurchases`/`invites`). */
interface AccessGateway {
    /** Purchase id/state plus sync freshness and last successful issuer response; never amount/address. */
    suspend fun purchases(): List<PurchaseView>

    /** The invite index list (index, expiry day, state). */
    suspend fun invites(): List<InviteView>

    /** The payment instructions of a READY/UNDERPAID purchase (local; §3.5, D35). */
    @UserAction
    suspend fun paymentInstructions(purchaseId: String): PaymentView?

    /** The disclosures which still require an explicit acknowledgement before instructions exist. */
    suspend fun requiredDisclosures(purchaseId: String): Set<PaymentDisclosure>

    /** Records the user's acknowledgement of every required disclosure. */
    @UserAction
    suspend fun acknowledgeDisclosures(purchaseId: String, disclosures: Set<PaymentDisclosure>)

    /** "Check now": one InvoiceStatus user call; it never signs (STANDARD mode only). */
    @UserAction
    suspend fun checkNow(purchaseId: String)

    @UserAction
    suspend fun paymentScreenShown(purchaseId: String)

    @UserAction
    suspend fun paymentScreenHidden(purchaseId: String)

    /** Starts a purchase flow (traffic). */
    @UserAction
    suspend fun startPurchase(packId: String)

    /** "Get invoice now": the purchase's RequestInvoice as a user call (STANDARD mode only). */
    @UserAction
    suspend fun requestInvoiceNow(purchaseId: String)

    /** Revokes an invite (traffic). */
    @UserAction
    suspend fun revokeInvite(index: Int)

    /** Creates a signed invite locally; redemption happens in a later quiet run. */
    @UserAction
    suspend fun createInvite(expiryDay: Int): SensitiveText?

    /** Queues a payout to a fresh wallet subaddress; the claim is validated locally. */
    @UserAction
    suspend fun claimPayout(address: String): Boolean

    /** Cancels only a purchase whose instructions were never shown. */
    @UserAction
    suspend fun cancelPurchase(purchaseId: String): Boolean
}

/** DC-6…DC-10: the five explicit acknowledgements required before payment instructions. */
enum class PaymentDisclosure { KYC_EXCHANGE, NO_REFUND, EXACT_AMOUNT, NO_LOCK_TIME, WINDOWS }

/** Purchase state + freshness; lastSyncedMinute is epoch seconds, rounded down to a minute. */
data class PurchaseView(
    val id: String,
    val payWith: String,
    val state: PurchaseState,
    val sync: PurchaseSyncState = PurchaseSyncState.LOCAL_ONLY,
    val lastSyncedMinute: Long? = null,
)

/** §3.6's state set plus the honest local state after instructions were shown. */
enum class PurchaseState {
    PREPARED, INVOICE_PENDING, READY, PAYMENT_UNVERIFIED, UNDERPAID, CONFIRMING, FINALIZED,
    EXPIRED_UNPAID, EXPIRED_SEEN, LOST, CANCELLED,
}

enum class PurchaseSyncState { LIVE, STALE, ISSUER_UNAVAILABLE, LOCAL_ONLY }

/** The invite read model. */
data class InviteView(val index: Int, val expiryDay: Int?, val state: String)

/** The payment instructions read model (the subaddress and amount are SensitiveText). */
data class PaymentView(
    val subaddress: SensitiveText,
    val amount: SensitiveText,
    val deadlineDay: Int,
    val qrUri: SensitiveText? = null,
)

/** Direct messages (J3; §3.6's additions land with S4 — the facade shapes only). */
interface DmGateway {
    suspend fun conversationSummaries(): List<ConversationSummary>
    suspend fun conversation(contactId: String): ConversationView?
    suspend fun requests(): List<RequestView>

    /** Local aliases for the list and title; no message content crosses this read. */
    suspend fun contactNames(): Map<String, String>

    /** The owner's ghost://contact/ link for the in-person QR screen. */
    suspend fun myCard(): SensitiveText?

    @UserAction
    suspend fun send(contactId: String, body: SensitiveText, replyTo: String?)

    /** The batch the §3.5 "displayed" rule counted: exactly the ids half-visible for 500 ms. */
    @UserAction
    suspend fun markDisplayed(contactId: String, messageIds: List<String>)

    @UserAction
    suspend fun setConversationOnScreen(contactId: String?)

    @UserAction
    suspend fun setTimer(contactId: String, minutes: Int?)

    @UserAction
    suspend fun retry(messageId: String)

    @UserAction
    suspend fun addContact(cardText: String, source: String, name: String?)

    @UserAction
    suspend fun rename(contactId: String, name: String?): Boolean
}

/** The conversation-list row: contact id, live unread count, newest minute — no text (T33). */
data class ConversationSummary(val contactId: String, val unread: Int, val newestMinute: Long)

/** The conversation read model. */
data class ConversationView(
    val contactId: String,
    val items: List<MessageView>,
    val timerMinutes: Int?,
    val draftKeptInMemory: Boolean,
)

/** The message read model. */
data class MessageView(
    val id: String,
    val mine: Boolean,
    val minute: Long,
    val body: SensitiveText,
    val state: MessageState,
    val timerMinutes: Int?,
    val expireAtMinute: Long?,
    val myReaction: String?,
    val peerReaction: String?,
    /** 0 for text/control rows; otherwise the media kind used by the viewer. */
    val mediaKind: Int = 0,
)

/** The message states the UI distinguishes (§6.9 catalogue). */
enum class MessageState { SENDING, SENT, DELIVERED, READ, FAILED, HELD }

/** The contact-request read model. */
data class RequestView(val contactId: String, val receivedMinute: Long)

/** Contact trust, requests and safety-number decisions; all operations stay on the UI IO adapter. */
interface ContactGateway {
    suspend fun trustState(contactId: String): String?
    suspend fun safetyNumber(contactId: String, pending: Boolean): SafetyNumberData?

    @UserAction
    suspend fun acceptRequest(contactId: String): Boolean

    @UserAction
    suspend fun rejectRequest(contactId: String): Boolean

    @UserAction
    suspend fun blockRequest(contactId: String): Boolean

    @UserAction
    suspend fun verify(contactId: String, pending: Boolean, scannedPayload: String): Boolean

    @UserAction
    suspend fun verifyManually(contactId: String): Boolean

    @UserAction
    suspend fun acknowledgeKeyChange(contactId: String): Boolean

    @UserAction
    suspend fun block(contactId: String): Boolean

    @UserAction
    suspend fun unblock(contactId: String): Boolean

    @UserAction
    suspend fun deleteContact(contactId: String): Boolean

    @UserAction
    suspend fun resetSession(contactId: String): Boolean
}

/** The 60 digits and the versioned QR payload; neither is logged or persisted by the UI. */
data class SafetyNumberData(val digits: String, val qrPayload: SensitiveText)

/** Channels (J4; Phase 10's facade, S5). */
interface ChannelGateway {
    suspend fun channels(): List<ChannelView>
    suspend fun posts(channelId: String): List<ChannelPostView>
    suspend fun members(channelId: String): List<ChannelMemberView>
    suspend fun fingerprint(channelId: String): ChannelFingerprintView?

    @UserAction
    suspend fun removeMember(channelId: String, memberId: String): Boolean

    @UserAction
    suspend fun reveal(channelId: String, memberId: String): Boolean

    @UserAction
    suspend fun create(name: String, passwordIndices: IntArray?): String

    @UserAction
    suspend fun createInvite(channelId: String, passwordIndices: IntArray?): SensitiveText

    suspend fun inspectInvite(link: String): ChannelInvitePreview?

    @UserAction
    suspend fun acceptInvite(link: String, passwordIndices: IntArray?): String

    @UserAction
    suspend fun post(channelId: String, body: SensitiveText)

    @UserAction
    suspend fun leave(channelId: String)

    @UserAction
    suspend fun rejoin(channelId: String)
}

/** The channel read model. */
data class ChannelView(val id: String, val name: String, val unread: Int, val passwordProtected: Boolean)

/** One protected channel post; no plaintext appears in logs or route state. */
data class ChannelPostView(
    val id: String,
    val body: SensitiveText,
    val mine: Boolean,
    val minute: Long,
    val state: String,
    val kind: Int,
) {
    /** Phase 10's `ChannelContent.kind`: 1 is a text post; the other kinds are controls/media. */
    val isText: Boolean get() = kind == 1
}

/** One pseudonymous roster member. */
data class ChannelMemberView(val id: String, val committer: Boolean, val mine: Boolean = false)

/** The epoch and the hexadecimal form of the exact 8-byte authenticator prefix. */
data class ChannelFingerprintView(val epoch: Long, val code: String)

/** The local channel-invite inspection (§3.6 Phase 10 coordination). */
data class ChannelInvitePreview(
    val channelName: String,
    val passwordRequired: Boolean,
    val expiryDay: Int?,
    val alreadyMember: Boolean,
)

/** Media (J5; Phase 11's facade, S6). */
interface MediaGateway {
    @UserAction
    suspend fun sendMedia(conversationId: String, pickedUri: String)

    @UserAction
    suspend fun retryMedia(itemId: String)

    @UserAction
    suspend fun setDownloadsPaused(paused: Boolean)
}

/** Updates (J6; null in a build without :update — Q39, F14 §8.2 (c)). */
interface UpdateGateway {
    suspend fun status(): UpdateStatusView

    @UserAction
    suspend fun requestCheck()

    @UserAction
    suspend fun requestDownload()

    @UserAction
    suspend fun install()
}

/** The update read model (S7 fills the fields F14 §9.5 fixes). */
data class UpdateStatusView(val state: String, val version: String?)

/** Sync, entitlement and Keystore status (the top-bar chip and banners, §6.1). */
interface StatusGateway {
    /** The connection state for the status chip; hidden when READY. */
    suspend fun connection(): ConnectionState

    /** The banner of highest priority, or null (§6.1's order). */
    suspend fun banner(): Banner?
}

/** The connection states (§6.9 catalogue, constants with copy). */
enum class ConnectionState { READY, CONNECTING, UNAVAILABLE, NO_REPLICAS, STALE }

/** The banner kinds by priority (§6.1). */
enum class BannerKind { SECURITY, KEY_CHANGE, ACCESS, CONNECTIVITY, INFORMATION }

/** A banner: its kind and the constant copy id (never computed content). */
data class Banner(val kind: BannerKind, val copyId: String, val bound: String?)

/** Settings (the privacy mode, the notification and lock choices, Q5/Q7/Q38). */
interface SettingsGateway {
    suspend fun privacyMode(): PrivacyMode

    @UserAction
    suspend fun setPrivacyMode(mode: PrivacyMode)

    suspend fun notificationsEnabled(): Boolean

    @UserAction
    suspend fun setNotificationsEnabled(enabled: Boolean)

    suspend fun hideFromAllServices(): Boolean

    @UserAction
    suspend fun setHideFromAllServices(enabled: Boolean)
}

/** The privacy modes (§7.1; STANDARD default, Q38). */
enum class PrivacyMode { STANDARD, HIGH }

/** Local wipe (§5.5; the revocation screen is a separate P1 design, Q27). */
interface WipeGateway {
    /** Runs W2–W7 after the PIN and HoldToConfirm (§5.5); never returns on success. */
    @UserAction
    suspend fun wipe()
}
