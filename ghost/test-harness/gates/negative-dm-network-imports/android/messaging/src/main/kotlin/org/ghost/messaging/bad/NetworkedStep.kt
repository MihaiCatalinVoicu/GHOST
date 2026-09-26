package org.ghost.messaging.bad

// G-DM1 negative fixture: a DM step that opens its own connection instead of using the sync API.
// Expected: 7 violations in this file (two on each of lines 5 and 9, one on each of lines 6-8).
import java.net.Socket
import org.ghost.network.TorRelayTransport
import kotlinx.coroutines.launch
import javax.net.ssl.SSLContext
import android.net.LocalSocket

internal class NetworkedStep {
    // Decoys on the next line that must not match (word boundaries): 0 violations.
    val decoy = "Sockets and URLs of org.ghost.networking over javanet are SocketTimeoutish"
}
