package org.ghost.messaging.channel.engine

/** The allowed step, so the fixture is not vacuous: CH-CREATE registers its namespace and funds it. */
internal class ChannelCreateStep(private val sync: ChannelSyncPorts) {
    fun create(tx: Any, ns: Any) {
        sync.namespaces.register(tx, ns)
        sync.fund.set(tx, ns, true)
    }
}
