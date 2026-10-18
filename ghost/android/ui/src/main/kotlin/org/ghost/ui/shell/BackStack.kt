package org.ghost.ui.shell

import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.snapshots.SnapshotStateList

/**
 * Phase 13 design §3.4: the back stack — a `SnapshotStateList<Route>` owned by the session.
 * Nothing is written to a bundle; a lock pops the one-shot routes (§3.3); a configuration
 * change keeps the stack because it lives in the session holder, not in the activity.
 */
class BackStack(initial: Route) {
    private val stack: SnapshotStateList<Route> = mutableStateListOf(initial)

    val current: Route
        get() = stack.last()

    val size: Int
        get() = stack.size

    fun push(route: Route) {
        stack.add(route)
    }

    /** Replaces the current route (a same-screen step change). */
    fun replace(route: Route) {
        stack[stack.lastIndex] = route
    }

    /** Pops the top; false when only the root remains (the root is never popped). */
    fun pop(): Boolean {
        if (stack.size <= 1) return false
        stack.removeAt(stack.lastIndex)
        return true
    }

    /** §3.3's lock duty: pop every one-shot route so none reappears after the unlock. */
    fun popOneShots(oneShots: Set<kotlin.reflect.KClass<out Route>> = LOCK_ONE_SHOT) {
        while (stack.size > 1 && oneShots.contains(stack.last()::class)) {
            stack.removeAt(stack.lastIndex)
        }
    }

    fun snapshot(): List<Route> = stack.toList()
}
