package org.ghost.messaging

// G-DM1 negative fixture: after a wildcard import only the bare class name is left on the line
// that uses it. Expected: 2 violations (line 5: the package; line 8: the class).
import java.net.*

internal fun open(): Any =
    Socket()
