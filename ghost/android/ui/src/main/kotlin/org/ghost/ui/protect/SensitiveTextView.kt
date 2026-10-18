package org.ghost.ui.protect

import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle

/**
 * Phase 13 design §4.2: the one place a [SensitiveText] is unwrapped (G-U3). Renders the value
 * with `isSensitiveData = true` so accessibility services that are not declared tools never see
 * the node (§4.3, Compose UI ≥ 1.9). There is deliberately no selection, no copy and no link
 * handling here: message, post, caption, alias, pseudonym, word, PIN-dot and payment text all
 * render through this composable, and the platform text menu of *editable* fields is filtered
 * separately in `GhostTextField`.
 */
@Composable
fun SensitiveTextView(
    text: SensitiveText,
    modifier: Modifier = Modifier,
    style: TextStyle = TextStyle.Default,
) {
    BasicText(
        text = text.value,
        modifier = modifier.semantics { isSensitiveData = true },
        style = style,
    )
}
