package org.ghost.app.ui

import android.app.Activity
import android.content.Intent
import java.security.MessageDigest

/**
 * Phase 13 design §3.4: link intake — the one path a `ghost://` link takes into the app.
 *
 *  1. The link is read ONCE, in `onCreate`/`onNewIntent`, bounded to 1 024 characters, into a
 *     [PendingLink] held by the Application in memory.
 *  2. The activity removes it from its intent (`setIntent(Intent())`) and, when the link was
 *     the task's launching intent, relaunches itself explicitly with
 *     `FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TASK`, so the task's persisted base intent
 *     carries no link and a recreation after process death does not process it again (D7,
 *     `persistableMode="persistNever"` is the manifest half, G-U11).
 *  3. Link data on an intent marked `FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY` is ignored.
 *  4. A pending link is acted on only after unlock, through a confirmation screen showing its
 *     kind, version and check sum (§4.7); the intake never acts on it.
 *
 * Another app may fire any `ghost://` intent at GHOST and may claim the scheme itself
 * (L11-U13); this class parses shape only and trusts nothing.
 */
object LinkIntake {
    const val MAX_LINK_CHARS = 1024

    /** The kinds the filters admit (§3.4): exactly the manifest's hosts. */
    enum class LinkKind { INVITE, CONTACT, CHANNEL, OTHER }

    /** A parsed pending link: its kind, the bounded text and the 8-hex-digit check sum. */
    data class PendingLink(val kind: LinkKind, val text: String, val checkSum: String)

    /** Parses a `ghost://` URI string of at most [MAX_LINK_CHARS] characters; null if not ours. */
    fun parse(uri: String): PendingLink? {
        if (uri.length > MAX_LINK_CHARS) return null
        if (!uri.startsWith("ghost://")) return null
        val rest = uri.removePrefix("ghost://")
        val host = rest.takeWhile { it != '/' && it != '?' && it != '#' }
        val kind = when (host) {
            "invite" -> LinkKind.INVITE
            "contact" -> LinkKind.CONTACT
            "channel" -> LinkKind.CHANNEL
            else -> LinkKind.OTHER
        }
        return PendingLink(kind = kind, text = uri, checkSum = checkSum(uri))
    }

    /**
     * §4.7's check sum: `SHA-256(link)[0..4]` as 8 hex digits. It detects a damaged or mistyped
     * link, NOT a substituted one (a forger can match 32 bits with about 2³² work, CR-8) — the
     * confirmation screen's copy says exactly that.
     */
    fun checkSum(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(8)
        for (i in 0 until 4) sb.append(String.format("%02x", digest[i]))
        return sb.toString()
    }

    /**
     * Reads the link from [activity]'s intent once: returns the pending link, clears the
     * intent, and relaunches when the link was the task's base intent. Idempotent — a second
     * call with the cleared intent returns null.
     */
    fun take(activity: Activity): PendingLink? {
        val intent = activity.intent ?: return null
        if (intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY != 0) return null
        val uri = intent.dataString ?: return null
        val link = parse(uri) ?: return null
        val wasBase = intent.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0
        activity.setIntent(Intent())
        if (wasBase) {
            val fresh = Intent(activity, activity.javaClass)
            fresh.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            activity.startActivity(fresh)
        }
        return link
    }
}
