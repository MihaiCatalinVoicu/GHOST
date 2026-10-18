package org.ghost.app.ui

import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import org.ghost.ui.gateway.WipeGateway

/**
 * Phase 13 design §3.2, §5.5: the [WipeGateway] — runs the [WipeController] on the dedicated
 * `ghost-wipe` thread (W2's engine stops wait for the pass in flight: never the main thread),
 * then never returns on success (W7 ends the process).
 */
class WipeGatewayAdapter(
    private val controller: WipeController,
    wipeThread: java.util.concurrent.ExecutorService,
) : WipeGateway {
    private val dispatcher = wipeThread.asCoroutineDispatcher()

    override suspend fun wipe(): Unit = withContext(dispatcher) {
        controller.wipe()
    }
}
