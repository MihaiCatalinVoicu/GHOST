package org.ghost.messaging.evasion

import kotlin.coroutines.Continuation

// The standard library's own coroutine package. Expected: line 3.
internal object StdlibCoroutines {
    var pending: Continuation<Unit>? = null
}
