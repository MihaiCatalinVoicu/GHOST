package org.ghost.messaging.port

/**
 * What the wiring supplies for the channel engine (Phase 10 design §10.1, §10.4; slice S4), beside the DM ports it
 * shares: the pseudonym seed of each channel ([ChannelSeeds], derived from the identity the wiring unwraps) and the
 * Keystore wrapper of the channel state key (`mls_state_key`, §10.4 "State key": one key for all channels, wrapped by a
 * non-exportable Keystore key with the database key's authentication policy, the F9 §2.5 pattern). `MessagingRuntime`
 * builds no channel engine without it; `:app`'s wiring of it is Phase 13's (the facade of §10.3).
 */
class ChannelPorts(
    val seeds: ChannelSeeds,
    val stateKeys: KeyWrapper,
) {
    override fun toString(): String = "ChannelPorts"
}
