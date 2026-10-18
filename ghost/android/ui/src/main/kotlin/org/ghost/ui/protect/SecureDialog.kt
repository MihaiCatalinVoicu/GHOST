package org.ghost.ui.protect

import android.os.Build
import android.view.View
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

/**
 * Phase 13 design §4.1: the only dialog primitive. Compose `Dialog` copies `FLAG_SECURE` from the
 * host window at creation (`SecureFlagPolicy.Inherit` is the default); this wrapper adds the
 * second layer — the dialog's own decor view is marked `ACCESSIBILITY_DATA_SENSITIVE_YES` on
 * API 34+ (§4.3), so non-tool accessibility services see no node of any dialog either.
 *
 * Banned everywhere else (G-U1): `android.app.Dialog`, `AlertDialog`, `DialogFragment`,
 * `PopupWindow`, `Toast`, `Presentation`, `WindowManager.addView`, `Spinner`,
 * `AutoCompleteTextView`, `PopupMenu`. Sheets and dropdown menus use the Material 3 primitives,
 * which inherit the secure flag the same way.
 */
@Composable
fun SecureDialog(
    onDismiss: () -> Unit,
    properties: DialogProperties = DialogProperties(),
    content: @Composable () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss, properties = properties) {
        val dialogView: View = LocalView.current
        if (Build.VERSION.SDK_INT >= 34) {
            dialogView.rootView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
        content()
    }
}
