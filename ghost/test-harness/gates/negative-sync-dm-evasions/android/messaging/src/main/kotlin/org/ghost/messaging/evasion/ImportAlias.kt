package org.ghost.messaging.evasion

import java.lang.Exception as Oops

// An import alias of Exception (the import is line 3). Expected: line 3.
internal object ImportAlias {
    fun run(block: () -> Unit) { try { block() } catch (e: Oops) { } }
}
