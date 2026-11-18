package org.ghost.app.ui

import android.content.Context
import java.security.KeyStore

/** The two platform operations shared by the interactive and crash-resumed wipe paths. */
internal object WipeAndroid {
    fun deleteAliases() {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        store.aliases().toList().filter { it.startsWith("ghost.v1.") }.forEach(store::deleteEntry)
    }

    fun clearClipboard(owner: AppClipboardOwner) {
        owner.clearAtLockOrWipe()
    }

    fun cancelNotifications(context: Context) {
        context.getSystemService(android.app.NotificationManager::class.java)?.cancelAll()
    }
}
