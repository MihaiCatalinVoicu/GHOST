package org.ghost.ui.platform

import android.content.Intent
import android.net.Uri
import android.provider.Settings

/**
 * Phase 13 design §3.1: the one file of `:ui` that may name `android.net.Uri` and build an
 * `Intent`. Every exit to another app or to system settings is funnelled here (G-U2: no
 * `ACTION_VIEW`, `ACTION_SENDTO`, `mailto:`, `Intent.parseUri` or data-URI `startActivity`
 * anywhere else). The message-composer rule is that GHOST opens no browser, mail client or
 * other app with a URI — this file's list is therefore closed and short:
 *
 *  - the photo/document picker (§6.6): `ACTION_OPEN_DOCUMENT`, content scheme only — the picked
 *    bytes never pass through another app's clipboard or share sheet;
 *  - the unknown-sources settings screen (§6.7, the update journey): the platform settings
 *    intent, no package targeting.
 *
 * Nothing else. No `ACTION_VIEW`, no `http(s)` data, no share.
 */
object SystemIntents {

    /** The picker intent for a photo or document; the UI reads the returned content itself. */
    fun openDocument(): Intent =
        Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }

    /** The platform screen where the user allows installs from unknown sources (§6.7). */
    fun unknownSourcesSettings(): Intent =
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:"))
}
