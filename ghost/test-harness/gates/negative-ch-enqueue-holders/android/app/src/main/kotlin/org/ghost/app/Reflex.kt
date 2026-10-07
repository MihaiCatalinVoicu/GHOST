package org.ghost.app

import org.ghost.messaging.channel.engine.ChannelEngine

/** G-M5 negative fixture (§19.38): `:app` holds the channel engine, which only `MessagingRuntime` assembles. */
internal class Reflex(private val engine: Any)
