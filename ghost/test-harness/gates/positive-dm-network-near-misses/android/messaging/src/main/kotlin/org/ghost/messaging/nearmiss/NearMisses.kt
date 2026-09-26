package org.ghost.messaging.nearmiss

/**
 * Every line is a near miss the gate accepts: a suspended session is not a coroutine, and the word
 * suspend in prose or in a string is not the modifier.
 */
internal object NearMisses {
    val suspended = true
    val isSuspendable = false
    val label = "suspend the timer"
    val list = java
        .util
        .ArrayList<String>()
    val netValue = 1
    val queue = kotlin.collections.ArrayDeque<Int>()
}
