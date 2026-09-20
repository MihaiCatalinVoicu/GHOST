package org.ghost.messaging.store

/**
 * G-DM2 negative fixture: `Namespaces.remove` from the **store layer**. §21.12 point 3 makes the
 * removal SWEEP's, after `block` and `deleteContact` have recorded an orphan row; a DAO that
 * removed the namespace itself would drop a relay set inside a read path.
 */
internal class ContactDao(private val sync: SyncPorts) {
    fun deleteContact(tx: Any, namespace: Any) {
        sync.namespaces.remove(tx, namespace)
    }
}
