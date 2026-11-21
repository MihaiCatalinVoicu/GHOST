package org.ghost.ui.design

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Hold-to-confirm with a separate, visible accessible alternative. */
@Composable
fun HoldToConfirm(
    onConfirmed: () -> Unit,
    holdLabelId: Int,
    alternativeLabelId: Int,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    var progress by remember { mutableFloatStateOf(0f) }
    Column(modifier = modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Button(
            onClick = {
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
            colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                containerColor = androidx.compose.material3.MaterialTheme.colorScheme.errorContainer,
                contentColor = androidx.compose.material3.MaterialTheme.colorScheme.onErrorContainer,
            ),
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
