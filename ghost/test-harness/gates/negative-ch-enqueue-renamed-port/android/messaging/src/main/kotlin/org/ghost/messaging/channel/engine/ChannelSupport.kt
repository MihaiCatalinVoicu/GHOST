package org.ghost.messaging.channel.engine

/** G-M5 negative fixture (§19.38): the ports holder with its funding port renamed. A port is a port by its type. */
internal class ChannelSyncPorts(
    val namespaces: Namespaces,
    val capabilities: Capabilities,
    val registrations: Registrations,
    val outbox: Outbox,
    val inbox: Inbox,
    val fund: Funding,
)
