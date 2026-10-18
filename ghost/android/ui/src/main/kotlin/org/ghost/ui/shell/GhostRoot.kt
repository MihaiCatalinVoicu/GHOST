package org.ghost.ui.shell

import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalClipboardManager
import org.ghost.ui.protect.ImeIncognito

/**
 * Phase 13 design §3.1, §4.2, §4.5: the window root every GHOST window composes. One [GhostRoot]
 * per window covers, from a single site:
 *
 *  - the IME interceptor ([org.ghost.ui.protect.ImeIncognito], applied inside [GhostTheme]):
 *    wraps every platform text input request of the window — dialogs included, because
 *    composition locals reach dialog content — and ORs `IME_FLAG_NO_PERSONALIZED_LEARNING`
 *    into `imeOptions`, so no IME learns from anything typed in GHOST (§4.5). G-U4 checks the
 *    interceptor is present in this file's tree.
 *  - the clipboard override: `LocalClipboard` and the deprecated `LocalClipboardManager` are
 *    backed by :app's `SensitiveClipboard` (the only writer, §4.4), so a copy or cut from any
 *    text field of the window routes through the sensitive writer with its label and timer
 *    (X-U2). The implementation pair arrives through [ClipboardOwner]; without one the platform
 *    clipboard stays in place (the demo skeleton).
 *  - the theme and the neutral surface (curtain) shown while hidden or locked (§3.3: no
 *    decrypted state waits in a hidden process).
 */
@Composable
fun GhostRoot(
    clipboardOwner: ClipboardOwner?,
    content: @Composable () -> Unit,
) {
    if (clipboardOwner == null) {
        // The skeleton runs without the clipboard override; :app's wiring always passes one.
        ImeIncognito {
            GhostTheme(content = content)
        }
    } else {
        CompositionLocalProvider(
            LocalClipboard provides clipboardOwner.clipboard,
            LocalClipboardManager provides clipboardOwner.clipboardManager,
        ) {
            ImeIncognito {
                GhostTheme(content = content)
            }
        }
    }
}

/**
 * The :app-provided pair that backs the composition locals: the `Clipboard` API and the
 * deprecated `ClipboardManager` wrapper, both over the same `SensitiveClipboard` instance.
 * Declared here so `GhostRoot` names the clipboard locals in this file only (G-U2's rule covers
 * this file together with `SensitiveClipboard.kt`).
 */
interface ClipboardOwner {
    val clipboard: androidx.compose.ui.platform.Clipboard
    val clipboardManager: androidx.compose.ui.platform.ClipboardManager
}
