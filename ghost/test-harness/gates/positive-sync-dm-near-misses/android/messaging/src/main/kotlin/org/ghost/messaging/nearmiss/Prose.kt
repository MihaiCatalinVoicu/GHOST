package org.ghost.messaging.nearmiss

/** The rule in prose: catch (e: Throwable) in a KDoc is not a catch. */
internal typealias Handler = (Throwable) -> Unit

internal object Prose {
    const val MESSAGE = "catch (e: Exception) is what this module never writes"
    val errors: List<Error> = emptyList()
}
