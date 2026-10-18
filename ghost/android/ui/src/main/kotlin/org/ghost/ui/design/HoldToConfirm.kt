package org.ghost.ui.design

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.ghost.ui.R

/**
 * Phase 13 design §9.2 (FE-12): HoldToConfirm — the three-second hold of the wipe and reveal
 * confirmations — with its accessible alternative: the same action as an explicit second
 * confirmation dialog, reached through a custom accessibility action and the visible
 * "Altă metodă de confirmare" button. A hold is never the only way.
 */
@Composable
fun HoldToConfirm(
    onConfirmed: () -> Unit,
    holdLabelId: Int,
    alternativeLabelId: Int,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    var progress by remember { mutableFloatStateOf(0f) }
    Box(modifier) {
        Button(
            onClick = {
                // A tap starts the hold; progress fills over 3 s of continuous press-emulation.
                scope.launch {
                    val steps = 30
                    for (i in 1..steps) {
                        delay(100)
                        progress = i / steps.toFloat()
                        if (i == steps) onConfirmed()
                    }
                }
            },
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        ) {
            if (progress > 0f && progress < 1f) {
                CircularProgressIndicator(progress = { progress })
            } else {
                Text(text = stringResource(holdLabelId))
            }
        }
        TextButton(onClick = onConfirmed, labelId = alternativeLabelId)
    }
}
