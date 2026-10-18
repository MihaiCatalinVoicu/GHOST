package org.ghost.ui.protect

import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.contextmenu.data.ProcessTextKey
import androidx.compose.foundation.text.contextmenu.modifier.filterTextContextMenuComponents
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle

/**
 * Phase 13 design §4.2 (G-U4): the only place a text field is built. Every editable field of
 * every screen uses this composable, so two protections hold app-wide from one site:
 *
 *  - the text context menu is filtered to cut, copy, paste and select-all
 *    (`filterTextContextMenuComponents`). Compose Foundation adds `ProcessTextKey` items for
 *    activities that handle `ACTION_PROCESS_TEXT` (Translate and any installed app), which would
 *    receive the selected text (CR-14 of the design review); the filter removes every component
 *    keyed by [ProcessTextKey]. PM-U34 and the JVM menu-item test keep this.
 *  - the field state is a plain [TextFieldState] held by the caller's `remember` — never
 *    `rememberTextFieldState` (it is saveable, banned by G-U6) and never in a `Bundle`.
 *
 * The IME carries `IME_FLAG_NO_PERSONALIZED_LEARNING` from the window-level interceptor in
 * `GhostRoot` (§4.5); this composable adds nothing per-field because the interceptor reaches
 * every platform text input of the window, dialogs included.
 */
@Composable
fun GhostTextField(
    state: TextFieldState,
    modifier: Modifier = Modifier,
    textStyle: TextStyle = TextStyle.Default,
) {
    BasicTextField(
        state = state,
        modifier = modifier.filterTextContextMenuComponents { component ->
            component.key !is ProcessTextKey
        },
        textStyle = textStyle,
    )
}
