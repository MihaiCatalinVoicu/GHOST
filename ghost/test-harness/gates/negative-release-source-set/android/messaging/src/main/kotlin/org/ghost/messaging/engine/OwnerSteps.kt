package org.ghost.messaging.engine

// Fixture: the one allowed restricted call, so dm-enqueue-callers's corpus is not vacuous.
fun publish() { sync.outbox.enqueue(tx, blob) }
