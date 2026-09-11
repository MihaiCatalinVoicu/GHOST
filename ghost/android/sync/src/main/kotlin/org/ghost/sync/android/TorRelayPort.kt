package org.ghost.sync.android

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.RelayTransport
import org.ghost.sync.api.BlobHash
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.port.FetchedBlob
import org.ghost.sync.port.ListPage
import org.ghost.sync.port.RelayPort
import org.ghost.sync.port.StoreReceipt

/** Runs one relay call on the transport of the moment; `NetworkException("closed")` when there is none. */
internal interface TransportAccess {
    fun <T> use(block: (RelayTransport) -> T): T
}

/**
 * [RelayPort] over [RelayTransport] (design §1.1): the sync port's typed identifiers become the
 * transport's byte arrays and back. It adds no protocol logic (ADR-19): the Rust core has already
 * validated every answer (hash, bucket, expiry bound, cursor length, check subset). This adapter
 * re-checks only the shapes the port's types need, so a malformed answer surfaces as
 * `malformed_response` (RELAY_HOSTILE: a possible copy for a store, design §3.6) and never as a
 * Kotlin argument error from a type constructor, which the engine would take for a local bug and
 * fail the delivery.
 *
 * Failures pass through unchanged: `NetworkException(category)` from the transport, and
 * [IllegalArgumentException] from its argument checks. Nothing is caught here, and no message
 * carries an identifier (T3).
 */
internal class TorRelayPort(private val transport: TransportAccess) : RelayPort {

    override fun store(
        relay: OnionAddress,
        ns: NamespaceId,
        capability: ByteArray,
        ciphertext: ByteArray,
        ttlSeconds: Int,
        deadlineMillis: Int,
    ): StoreReceipt {
        val receipt = transport.use { it.store(relay, ns.toByteArray(), capability, ciphertext, ttlSeconds, deadlineMillis) }
        return StoreReceipt(hashOf(receipt.blobHash), receipt.expiryUnixSeconds)
    }

    override fun get(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hash: BlobHash, deadlineMillis: Int): FetchedBlob {
        val blob = transport.use { it.get(relay, ns.toByteArray(), capability, hash.toByteArray(), deadlineMillis) }
        return FetchedBlob(blob.ciphertext, blob.expiryUnixSeconds)
    }

    override fun list(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): ListPage {
        val page = transport.use { it.list(relay, ns.toByteArray(), capability, cursor, limit, deadlineMillis) }
        val next = page.nextCursor
        if (page.hashes.size > limit || (next.isNotEmpty() && next.size != CURSOR_SIZE)) throw NetworkException(MALFORMED)
        return ListPage(page.hashes.map(::hashOf), next)
    }

    override fun check(relay: OnionAddress, ns: NamespaceId, capability: ByteArray, hashes: List<BlobHash>, deadlineMillis: Int): Set<BlobHash> {
        val held = transport.use { it.check(relay, ns.toByteArray(), capability, hashes.map { h -> h.toByteArray() }, deadlineMillis) }
        val requested = hashes.toHashSet()
        val out = HashSet<BlobHash>()
        for (raw in held) {
            val hash = hashOf(raw)
            // A subset of the request, each hash once: one held hash never counts twice.
            if (hash !in requested || !out.add(hash)) throw NetworkException(MALFORMED)
        }
        return out
    }

    private fun hashOf(raw: ByteArray): BlobHash {
        if (raw.size != BlobHash.SIZE) throw NetworkException(MALFORMED)
        return BlobHash(raw)
    }

    override fun toString(): String = "TorRelayPort"

    private companion object {
        const val MALFORMED = "malformed_response"
        const val CURSOR_SIZE = 8
    }
}
