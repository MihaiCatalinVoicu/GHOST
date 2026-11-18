package org.ghost.app.ui

import android.content.Context
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.text.AnnotatedString
import org.ghost.ui.protect.SensitiveClipboard
import org.ghost.ui.shell.ClipboardOwner

/**
 * Phase 13 §3.3's [ClipboardOwner] (G-U2): the Compose clipboard locals backed by
 * [SensitiveClipboard] — every write is labelled, marked sensitive and cleared on the 30 s
 * timer; the ownership label persists through [SettingsStore]'s `ui_settings.clip_label` so a
 * later process recognises (and clears) its own clip after a restart (Q10 (a)). GHOST never
 * reads foreign clips back (the getters stay empty).
 *
 * The closed [SensitiveClipboard.CopyKind] list names the only five copyable values (§4.4).
 * Feature buttons pass their kind explicitly; the generic Compose entry maps to the invite kind
 * as the single permitted default.
 */
internal class AppClipboardOwner(
    context: Context,
    settings: SettingsStore,
) : ClipboardOwner {

    private val sensitive = SensitiveClipboard(
        context = context,
        labelStore = object : SensitiveClipboard.LabelStore {
            override fun readLabel(): String? = settings.clipLabel()?.toHex()

            override fun writeLabel(label: String) {
                settings.setClipLabel(label.fromHex())
            }

            override fun clearLabel() {
                settings.clearClipLabel()
            }
        },
    )

    override val clipboard: androidx.compose.ui.platform.Clipboard =
        object : androidx.compose.ui.platform.Clipboard {
            override suspend fun getClipEntry(): ClipEntry? = null

            override suspend fun setClipEntry(clipEntry: ClipEntry?) {
                val text = clipEntry?.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text ?: return
                sensitive.copySensitive(SensitiveClipboard.CopyKind.INVITE_LINK, text.toString())
            }
        }

    override val clipboardManager: androidx.compose.ui.platform.ClipboardManager =
        object : androidx.compose.ui.platform.ClipboardManager {
            override fun setText(annotatedString: AnnotatedString) {
                sensitive.copySensitive(SensitiveClipboard.CopyKind.INVITE_LINK, annotatedString.text)
            }

            override fun getText(): AnnotatedString? = null

            override fun hasText(): Boolean = false

            override val nativeClipboard: android.content.ClipboardManager
                get() = context.getSystemService(android.content.ClipboardManager::class.java)
        }

    /** A feature-specific copy door; the kind selects the fixed label and sensitive payload. */
    internal fun copy(kind: SensitiveClipboard.CopyKind, text: org.ghost.ui.protect.SensitiveText) =
        text.copySensitiveTo(sensitive, kind)

    /** At every activity resume, clear only the clip still carrying our persisted label. */
    internal fun clearAtFocus() = sensitive.clearIfOurs(hasFocus = true)

    /** W6 uses the same ownership token and clear path as the normal clipboard lifecycle. */
    internal fun clearAtLockOrWipe() = sensitive.clearAtLockOrWipe()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun String.fromHex(): ByteArray {
        require(length == 16) { "the ownership token is 8 bytes" }
        return ByteArray(8) { i -> substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }
}
