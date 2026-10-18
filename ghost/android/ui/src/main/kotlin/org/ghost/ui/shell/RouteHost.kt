package org.ghost.ui.shell

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.window.core.layout.WindowSizeClass
import androidx.window.core.layout.WindowWidthSizeClass
import org.ghost.ui.R

/**
 * Phase 13 design §3.4: the route host. Own navigation (D6, Q3): transitions by `AnimatedContent`,
 * back by the platform `BackHandler`, a two-pane layout from a window width class of EXPANDED
 * (~600 dp). The content lambda is the screen registry the features fill in; the shell never
 * persists anything.
 */
@Composable
fun RouteHost(
    backStack: BackStack,
    windowSizeClass: WindowSizeClass,
    modifier: Modifier = Modifier,
    screen: @Composable (Route) -> Unit,
) {
    val expanded = windowSizeClass.windowWidthSizeClass == WindowWidthSizeClass.EXPANDED
    BackHandler(enabled = backStack.size > 1) {
        backStack.pop()
    }
    Row(modifier = modifier.fillMaxSize()) {
        if (expanded) {
            // Two panes: the list/master column beside the detail. The master pane is a neutral
            // navigation surface; its content comes from the features in S4+.
            Surface(modifier = Modifier.width(320.dp), tonalElevation = 2.dp) {
                Text(
                    text = stringResource(R.string.shell_master_pane),
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        }
        Box(modifier = Modifier.weight(1f)) {
            AnimatedContent(targetState = backStack.current, label = "route") { route ->
                screen(route)
            }
        }
    }
}
