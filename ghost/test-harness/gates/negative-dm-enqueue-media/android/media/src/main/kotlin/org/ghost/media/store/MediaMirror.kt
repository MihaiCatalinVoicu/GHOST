package org.ghost.media.store

/**
 * G-DM2 negative fixture (Phase 11, slice S3): a call that causes relay-visible behaviour made from the media store
 * layer. The stores of org.ghost.media.store read and write rows and files and make no port call (design faza11-media.md
 * 16.1, G-M6); a store that enqueued an operation in a read path would make what a relay sees depend on what was stored.
 * Expected: 1 violation, line 11.
 */
internal class MediaMirror(private val sync: SyncPorts) {
    fun feed(tx: Any, operation: Any) {
        sync.outbox.enqueue(tx, operation)
    }
}
