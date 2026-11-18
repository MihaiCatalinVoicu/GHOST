package org.ghost.ui.protect

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import java.security.SecureRandom

/**
 * Phase 13 design §4.4: the only writer of the system clipboard (G-U2 confines every
 * `ClipData`/`setPrimaryClip`/`ClipboardManager` reference to this file and `GhostRoot.kt`).
 *
 * What may be copied is exactly the [CopyKind] list — an invite link, the own contact link, a
 * channel invite link, a payment subaddress, a payment amount. Message text, aliases, the 24
 * words, passphrases, safety digits and the PIN never reach the clipboard: nothing in the app
 * calls this class for them, and G-U2's path rule keeps the backup/restore/passphrase/
 * safety-number packages from importing it.
 *
 * Each write labels the clip with 16 hex characters of 8 random bytes (the ownership token),
 * marks it sensitive (`IS_SENSITIVE`, the string key works below API 33), and persists the label
 * in `ui_settings.clip_label` through [LabelStore] so a later process can recognise (and clear)
 * its own clip after a restart (Q10 (a)). The 30 000 ms clear runs on the main looper while the
 * app is alive; a timer that fires more than 5 minutes late (the cached-app freezer suspended the
 * process) does not clear unconditionally, and the persisted label is checked at every activity
 * resume instead (Q10 (a)).
 */
class SensitiveClipboard(
    private val context: Context,
    private val labelStore: LabelStore,
    private val random: SecureRandom = SecureRandom(),
) {
    /** Persists the ownership label between processes; implemented by :app over `ui_settings`. */
    interface LabelStore {
        fun readLabel(): String?
        fun writeLabel(label: String)
        fun clearLabel()
    }

    /** The closed list of what may be copied (§4.4). */
    enum class CopyKind { INVITE_LINK, OWN_CONTACT_LINK, CHANNEL_INVITE_LINK, PAYMENT_SUBADDRESS, PAYMENT_AMOUNT }

    private val manager: ClipboardManager
        get() = context.getSystemService(ClipboardManager::class.java)

    private val handler by lazy { Handler(Looper.getMainLooper()) }
    private var pendingClear: Runnable? = null

    /** The 30 s in-app clear window, kept as a named constant for the gate and the tests. */
    val clearDelayMs: Long = CLEAR_DELAY_MS

    /** Copies [text] of [kind], labelling the clip with the persisted ownership token. */
    fun copySensitive(kind: CopyKind, text: String) {
        val label = newLabel()
        val clip = ClipData.newPlainText(label, text)
        // The sensitive extra: API 33+ names it in ClipDescription; the string key is what the
        // platform reads on every level (developer.android.com, copy and paste).
        val extras = PersistableBundle()
        extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        clip.description.extras = extras
        manager.setPrimaryClip(clip)
        labelStore.writeLabel(label)
        scheduleClear()
    }

    /**
     * Clears GHOST's clip if it is still ours: with focus, only when the description's label
     * matches what we wrote (no paste toast on API 31+, no clobbering another app's clip);
     * without focus, unconditionally within the window (X-U3). Late (frozen) timers must not
     * reach this path with `hasFocus == false` and a stale due time — see [clearIfLate].
     * An absent ownership label is never evidence that a foreign, unlabelled clip is ours.
     */
    fun clearIfOurs(hasFocus: Boolean) {
        val expected = labelStore.readLabel() ?: return
        if (hasFocus) {
            val ours = manager.primaryClipDescription?.label?.toString() == expected
            if (ours) {
                manager.clearPrimaryClip()
                labelStore.clearLabel()
            } else {
                // Another app replaced the clip: the stored label no longer names anything.
                labelStore.clearLabel()
            }
        } else {
            manager.clearPrimaryClip()
            labelStore.clearLabel()
        }
    }

    /**
     * The freezer rule (§4.4, Q10 (a)): a clear due more than [LATE_MS] after its time does not
     * clear unconditionally; the persisted label is left for the next focus gain / process start.
     */
    fun clearIfLate(scheduledAtMs: Long, nowMs: Long, hasFocus: Boolean): Boolean {
        if (nowMs - scheduledAtMs > LATE_MS) return false
        clearIfOurs(hasFocus)
        return true
    }

    /** Clears unconditionally — the lock and the wipe paths (§4.4, §5.1, W6). */
    fun clearAtLockOrWipe() {
        pendingClear?.let(handler::removeCallbacks)
        pendingClear = null
        manager.clearPrimaryClip()
        labelStore.clearLabel()
    }

    private fun newLabel(): String {
        val bytes = ByteArray(8)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun scheduleClear() {
        pendingClear?.let(handler::removeCallbacks)
        val scheduledAt = SystemClock.elapsedRealtime()
        lateinit var task: Runnable
        task = Runnable {
            if (pendingClear !== task) return@Runnable
            pendingClear = null
            // Ownership is checked even without focus: a newer foreign clip is never erased.
            clearIfLate(scheduledAt, SystemClock.elapsedRealtime(), hasFocus = true)
        }
        pendingClear = task
        handler.postDelayed(task, CLEAR_DELAY_MS)
    }

    companion object {
        const val CLEAR_DELAY_MS: Long = 30_000L
        const val LATE_MS: Long = 300_000L
    }
}

/** Elapsed-realtime clock source, injectable for the virtual-clock tests. */
fun interface ElapsedClock {
    fun nowMs(): Long
}

/** The default clock. */
val systemElapsedClock: ElapsedClock = ElapsedClock { SystemClock.elapsedRealtime() }
