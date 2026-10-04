package org.ghost.messaging.channel.store

/**
 * G-DM2 negative fixture (Phase 10, slice S3): a call that causes relay-visible behaviour made from
 * the **channel store layer**. The stores of `org.ghost.messaging.channel.store` read and write rows
 * and make no port call (design faza10-forum.md section 10.4); a store that funded a namespace in
 * a read path would make what a relay sees depend on what was stored. Expected: 1 violation, line 11.
 */
internal class MirrorStore(private val sync: SyncPorts) {
    fun settle(tx: Any, namespace: Any) {
        sync.funding.set(tx, namespace, true)
    }
}
