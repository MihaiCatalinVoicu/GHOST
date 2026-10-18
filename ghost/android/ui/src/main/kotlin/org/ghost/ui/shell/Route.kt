package org.ghost.ui.shell

/**
 * Phase 13 design §3.4: the typed back stack. A sealed interface of plain objects and data
 * classes holding local ids only — never content, never engine types. The stack lives in the
 * [UnlockedSession] (a `SnapshotStateList` here), is never persisted (a new process starts at
 * the lock or home screen), and survives a lock in memory with only the one-shot routes popped
 * (§3.3).
 */
sealed interface Route {
    /** Onboarding steps (J1, §6.2). */
    data object OnboardingWelcome : Route
    data object OnboardingPrepare : Route
    data object OnboardingLock : Route
    data object OnboardingPrivacy : Route
    data object OnboardingInvite : Route
    data object OnboardingBackup : Route
    data object OnboardingWords : Route
    data object OnboardingNotifications : Route
    data object OnboardingDisclosures : Route

    /** Restore (§5.7). */
    data object RestoreIntro : Route
    data object RestoreWords : Route
    data object RestoreNext : Route

    /** Home and its three destinations (§6.1). */
    enum class HomeTab { CONVERSATIONS, CHANNELS, SETTINGS }
    data class Home(val tab: HomeTab) : Route

    /** Direct messages (J3). */
    data class Conversation(val contactId: String) : Route
    data object ContactAdd : Route
    data object MyCard : Route
    data object Requests : Route
    data class SafetyNumber(val contactId: String) : Route
    data class KeyChange(val contactId: String) : Route
    data class ContactInfo(val contactId: String) : Route

    /** Channels (J4). */
    data object ChannelList : Route
    data class Channel(val channelId: String) : Route
    data object ChannelCreate : Route
    data class ChannelInvite(val channelId: String) : Route
    data class ChannelAccept(val link: String) : Route
    data class Members(val channelId: String) : Route
    data class Reveal(val channelId: String, val memberId: String) : Route

    /** Access and payment (J2). */
    data object Access : Route
    data class Purchase(val purchaseId: String) : Route
    data class PaymentInstructions(val purchaseId: String) : Route
    data object Invites : Route
    data object Payout : Route

    /** Settings and reference (§6.8). */
    enum class SettingsSection { ACCESS, PRIVACY, SECURITY, ABOUT, HELP, WIPE }
    data class Settings(val section: SettingsSection) : Route
    data object WhoSeesWhat : Route
    data object Accessibility : Route
    data object Backup : Route
    data object Wipe : Route

    /** Update (J6). */
    data object Update : Route
    data object About : Route
    data object Licences : Route
    data object Crash : Route

    /** Media (J5). */
    data class MediaViewer(val itemId: String) : Route
    data class ViewOnce(val itemId: String) : Route
}

/**
 * The one-shot routes: popped at lock so they never reappear after an unlock (§3.3). The wipe
 * confirmation lives inside the Wipe screen's flow, not as a route.
 */
val LOCK_ONE_SHOT: Set<kotlin.reflect.KClass<out Route>> = setOf(
    Route.ViewOnce::class,
    Route.MediaViewer::class,
    Route.PaymentInstructions::class,
    Route.Backup::class,
    Route.OnboardingWords::class,
    Route.Reveal::class,
)
