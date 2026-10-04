package org.ghost.sync.api

interface Namespaces {
    /**
     * Registers the namespace, or re-registers a known one (the row is reused, so tombstones keep
     * deduplicating). A known namespace keeps its consumer: a different one throws. Then applies
     * [relays] as in [setRelays]. `listen = false` means write-only (no inbox rows are kept);
     * registering a known write-only namespace with `listen = true` turns listening on as
     * [setListening] does.
     *
     * [capabilitySource] says who obtains the write access of the namespace (Phase 9 design §13.3
     * item 3); re-registering a known namespace applies it like the other arguments. A DM namespace
     * cannot turn the send delay off (`sendDelay = SendDelay.OFF` with `consumer = Consumer.DM`
     * throws, and a v4 trigger refuses it as well), nor can a channel namespace (`Consumer.CHANNEL`,
     * Phase 10 design §7.5 item 3; a v6 trigger refuses it as well).
     */
    fun register(
        tx: SyncTransaction,
        namespace: NamespaceId,
        consumer: Consumer,
        relays: Set<RelayId>,
        listen: Boolean,
        sendDelay: SendDelay = SendDelay.DEFAULT,
        capabilitySource: CapabilitySource = CapabilitySource.REDEEM,
    )

    /** Replaces the relay set and repairs deliveries (design §3.9). */
    fun setRelays(tx: SyncTransaction, namespace: NamespaceId, relays: Set<RelayId>)

    /** Cursors are kept. */
    fun setListening(tx: SyncTransaction, namespace: NamespaceId, listen: Boolean)

    /**
     * Whether the namespace is registered and listening, in the caller's transaction. Null when it
     * is not registered at all. Reads only: it registers nothing and wakes nothing.
     *
     * Phase 9's establishment steps need it (design §21.7 points 2, 4 and 5). A bundle fetch has
     * two states with one stored decision minute — a 15-minute attempt **window** that is open,
     * and the wait before the next attempt, which is at least 6 hours — and `dm_contact` carries
     * one column for both (`fetch_listen_until_minute`, whose CHECK ties it to
     * `establishment = 'fetching'`). The listening flag is the bit that tells them apart, and it
     * is already persisted here: keeping a second copy in `:messaging` would lose it at every
     * restart and turn a mid-window restart into either a lost attempt or an endless deferral.
     *
     * This is the same reason `Capabilities.installed` exists for the owner's READ credential
     * (Phase 9 design §4.8, slice S6).
     */
    fun listening(tx: SyncTransaction, namespace: NamespaceId): Boolean?

    /**
     * Refuses [SendDelay.OFF] for a [Consumer.DM] namespace (Phase 9 design §13.3 item 8) and for a
     * [Consumer.CHANNEL] namespace (Phase 10 design §7.5 item 3): the ADR-15 delay is what keeps a
     * store from naming the moment the user pressed send.
     */
    fun setSendDelay(tx: SyncTransaction, namespace: NamespaceId, sendDelay: SendDelay)

    /**
     * False while the namespace has operations or fetched, unconsumed blobs. Otherwise stops
     * listening, drops its relay set, cursors, capabilities (registration capabilities too) and
     * not-yet-fetched rows, ends its funding ([Funding]), and keeps the consumed-blob tombstones until
     * their retention day; the namespace row itself is removed by garbage collection once nothing
     * refers to it (design §11.2 #19).
     */
    fun remove(tx: SyncTransaction, namespace: NamespaceId): Boolean
}
