package org.ghost.sync.store

import org.ghost.network.OnionAddress
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.Capabilities
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilityNeed
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.EnqueueResult
import org.ghost.sync.api.Inbox
import org.ghost.sync.api.InboundBlob
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.Namespaces
import org.ghost.sync.api.OperationId
import org.ghost.sync.api.OutboundBlob
import org.ghost.sync.api.OutboundOutcome
import org.ghost.sync.api.Outbox
import org.ghost.sync.api.OutboxProgress
import org.ghost.sync.api.PrivacyMode
import org.ghost.sync.api.RelayDirectory
import org.ghost.sync.api.RelayEntry
import org.ghost.sync.api.RelayId
import org.ghost.sync.api.SendDelay
import org.ghost.sync.api.SyncCounts
import org.ghost.sync.api.SyncDatabase
import org.ghost.sync.api.SyncListener
import org.ghost.sync.api.SyncTransaction
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SyncClock

/**
 * The stores over one [SyncDatabase] and the public API (design §9) built on them. Consumer calls
 * that take a [SyncTransaction] run inside the caller's transaction; the others open their own
 * short transaction and must not be called inside one. [privacyMode] reads the current global mode
 * (set through the controller); the HIGH-mode send delay is drawn from [random]'s `sendDelay`.
 */
class SyncStores(
    val database: SyncDatabase,
    private val clock: SyncClock,
    private val random: RandomSources,
    private val privacyMode: () -> PrivacyMode,
) {
    internal val capabilityStore = CapabilityStore()
    internal val cursorStore = CursorStore()
    internal val outboxStore = OutboxStore(capabilityStore)
    internal val inboxStore = InboxStore(outboxStore, cursorStore)
    internal val directoryStore = DirectoryStore(outboxStore, capabilityStore)
    internal val statusStore = StatusStore(capabilityStore)
    internal val gc = Gc(outboxStore, capabilityStore)

    private fun SyncTransaction.checked(): SyncTransaction {
        requireActive(database)
        return this
    }

    /** Durable counts for the status report. */
    fun counts(): SyncCounts = database.transaction { tx -> statusStore.counts(tx, clock.epochSeconds()) }

    val outbox: Outbox = object : Outbox {
        override fun enqueue(tx: SyncTransaction, blob: OutboundBlob): EnqueueResult =
            outboxStore.enqueue(tx.checked(), blob, clock.epochSeconds(), privacyMode()) { random.sendDelay() }

        override fun cancel(tx: SyncTransaction, operationId: OperationId): Boolean =
            outboxStore.cancel(tx.checked(), operationId, clock.epochSeconds())

        override fun progress(operationId: OperationId): OutboxProgress? =
            database.transaction { tx -> outboxStore.progress(tx, operationId) }

        override fun outcomes(consumer: Consumer, limit: Int): List<OutboundOutcome> =
            database.transaction { tx -> outboxStore.outcomes(tx, consumer.code, limit) }

        override fun release(tx: SyncTransaction, operationId: OperationId): Boolean =
            outboxStore.release(tx.checked(), operationId)

        override fun toString(): String = "Outbox"
    }

    val inbox: Inbox = object : Inbox {
        override fun claim(consumer: Consumer, limit: Int): List<InboundBlob> =
            database.transaction { tx -> inboxStore.claim(tx, consumer.code, limit, clock.epochSeconds()) }

        override fun markConsumed(tx: SyncTransaction, namespace: NamespaceId, hash: BlobHash): Boolean =
            inboxStore.markConsumed(tx.checked(), namespace, hash)

        override fun defer(tx: SyncTransaction, namespace: NamespaceId, hash: BlobHash, seconds: Int): Boolean =
            inboxStore.defer(tx.checked(), namespace, hash, seconds, clock.epochSeconds())

        override fun setListener(listener: SyncListener?) = database.setConsumerListener(listener)

        override fun toString(): String = "Inbox"
    }

    val namespaces: Namespaces = object : Namespaces {
        override fun register(
            tx: SyncTransaction,
            namespace: NamespaceId,
            consumer: Consumer,
            relays: Set<RelayId>,
            listen: Boolean,
            sendDelay: SendDelay,
        ) = directoryStore.register(tx.checked(), namespace, consumer, relays, listen, sendDelay, clock.epochSeconds())

        override fun setRelays(tx: SyncTransaction, namespace: NamespaceId, relays: Set<RelayId>) =
            directoryStore.setRelays(tx.checked(), namespace, relays, clock.epochSeconds())

        override fun setListening(tx: SyncTransaction, namespace: NamespaceId, listen: Boolean) =
            directoryStore.setListening(tx.checked(), namespace, listen, clock.epochSeconds())

        override fun setSendDelay(tx: SyncTransaction, namespace: NamespaceId, sendDelay: SendDelay) =
            directoryStore.setSendDelay(tx.checked(), namespace, sendDelay)

        override fun remove(tx: SyncTransaction, namespace: NamespaceId): Boolean =
            directoryStore.remove(tx.checked(), namespace)

        override fun toString(): String = "Namespaces"
    }

    val capabilities: Capabilities = object : Capabilities {
        override fun put(
            tx: SyncTransaction,
            relay: RelayId,
            namespace: NamespaceId,
            kind: CapabilityKind,
            token: ByteArray,
            expiresAtEpochSeconds: Long?,
        ) {
            val checked = tx.checked()
            val now = clock.epochSeconds()
            capabilityStore.put(checked, relay, namespace, kind, token, expiresAtEpochSeconds)
            if (kind == CapabilityKind.WRITE) outboxStore.rearm(checked, relay, namespace, now)
        }

        override fun needed(): List<CapabilityNeed> =
            database.transaction { tx -> capabilityStore.needed(tx, clock.epochSeconds()) }

        override fun toString(): String = "Capabilities"
    }

    val relayDirectory: RelayDirectory = object : RelayDirectory {
        override fun upsert(tx: SyncTransaction, entries: List<RelayEntry>): Map<OnionAddress, RelayId> =
            directoryStore.upsert(tx.checked(), entries)

        override fun retire(tx: SyncTransaction, relay: RelayId) {
            directoryStore.retire(tx.checked(), relay, clock.epochSeconds())
        }

        override fun active(): List<RelayEntry> =
            database.transaction { tx -> directoryStore.relays(tx, activeOnly = true).map { it.entry } }

        override fun toString(): String = "RelayDirectory"
    }

    override fun toString(): String = "SyncStores"
}
