package org.ghost.sync.android

import org.ghost.network.NetworkException
import org.ghost.network.OnionAddress
import org.ghost.network.RelayTransport
import org.ghost.sync.api.BlobHash
import org.ghost.sync.engine.CallResult
import org.ghost.sync.engine.ErrorClass
import org.ghost.sync.engine.relayCall
import org.ghost.sync.store.TestBytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The relay adapter (design §1.1): port types map to the transport's byte arrays and back, answers
 * that do not fit the port's types become `malformed_response` (never a Kotlin argument error), and
 * transport failures pass through unchanged so the engine's error table applies (design §3.6).
 */
class TorRelayPortTest {

    private class Call(val op: String, val relay: OnionAddress, val namespace: ByteArray, val capability: ByteArray, val args: List<Any>)

    /** A [RelayTransport] that records its arguments and returns configured answers. */
    private class FakeTransport : RelayTransport {
        val calls = ArrayList<Call>()
        var failure: RuntimeException? = null
        var receipt = RelayTransport.StoreReceipt(ByteArray(32) { 7 }, 1_900_003_600L)
        var fetched = RelayTransport.FetchedBlob(ByteArray(4096) { 9 }, 1_900_086_400L)
        var page = RelayTransport.Page(emptyList(), ByteArray(0))
        var held: List<ByteArray> = emptyList()

        private fun record(op: String, relay: OnionAddress, namespace: ByteArray, capability: ByteArray, vararg args: Any) {
            calls += Call(op, relay, namespace.copyOf(), capability.copyOf(), args.toList())
            failure?.let { throw it }
        }

        override fun bootstrap() = Unit

        override fun store(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, ciphertext: ByteArray, ttlSeconds: Int, deadlineMillis: Int): RelayTransport.StoreReceipt {
            record("store", relay, namespace, capability, ciphertext.copyOf(), ttlSeconds, deadlineMillis)
            return receipt
        }

        override fun get(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, blobHash: ByteArray, deadlineMillis: Int): RelayTransport.FetchedBlob {
            record("get", relay, namespace, capability, blobHash.copyOf(), deadlineMillis)
            return fetched
        }

        override fun list(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, cursor: ByteArray, limit: Int, deadlineMillis: Int): RelayTransport.Page {
            record("list", relay, namespace, capability, cursor.copyOf(), limit, deadlineMillis)
            return page
        }

        override fun check(relay: OnionAddress, namespace: ByteArray, capability: ByteArray, hashes: List<ByteArray>, deadlineMillis: Int): List<ByteArray> {
            record("check", relay, namespace, capability, hashes.map { it.copyOf() }, deadlineMillis)
            return held
        }

        override fun rotateCircuits() = Unit

        override fun close() = Unit
    }

    private class Direct(private val transport: RelayTransport) : TransportAccess {
        override fun <T> use(block: (RelayTransport) -> T): T = block(transport)
    }

    private val relay = TestBytes.onion(1)
    private val ns = TestBytes.namespace(1)
    private val cap = TestBytes.of(82, 3)
    private val fake = FakeTransport()
    private val port = TorRelayPort(Direct(fake))

    private fun hash(seed: Int): BlobHash = BlobHash(TestBytes.of(32, seed))

    private fun malformed(block: () -> Unit) {
        val e = assertThrows(NetworkException::class.java) { block() }
        assertEquals("malformed_response", e.category)
    }

    @Test
    fun storeSendsTheFrozenArgumentsAndMapsTheReceipt() {
        val ciphertext = TestBytes.ciphertext(5)
        val receipt = port.store(relay, ns, cap, ciphertext, 604_800, 60_000)
        val call = fake.calls.single()
        assertEquals("store", call.op)
        assertSame(relay, call.relay)
        assertArrayEquals(ns.toByteArray(), call.namespace)
        assertArrayEquals(cap, call.capability)
        assertArrayEquals(ciphertext, call.args[0] as ByteArray)
        assertEquals(604_800, call.args[1])
        assertEquals(60_000, call.args[2])
        assertEquals(BlobHash(ByteArray(32) { 7 }), receipt.blobHash)
        assertEquals(1_900_003_600L, receipt.expiryUnixSeconds)
    }

    @Test
    fun getSendsTheHashAndMapsTheBlob() {
        val blob = port.get(relay, ns, cap, hash(4), 20_000)
        val call = fake.calls.single()
        assertEquals("get", call.op)
        assertArrayEquals(hash(4).toByteArray(), call.args[0] as ByteArray)
        assertEquals(20_000, call.args[1])
        assertArrayEquals(ByteArray(4096) { 9 }, blob.ciphertext)
        assertEquals(1_900_086_400L, blob.expiryUnixSeconds)
    }

    @Test
    fun listPassesTheOpaqueCursorAndMapsThePage() {
        val cursor = byteArrayOf(0, 0, 0, 1, 0, 0, 0, 2)
        val next = byteArrayOf(0, 0, 0, 1, 0, 0, 0, 9)
        fake.page = RelayTransport.Page(listOf(hash(1).toByteArray(), hash(2).toByteArray()), next)
        val page = port.list(relay, ns, cap, cursor, 128, 20_000)
        val call = fake.calls.single()
        assertArrayEquals(cursor, call.args[0] as ByteArray)
        assertEquals(128, call.args[1])
        assertEquals(20_000, call.args[2])
        assertEquals(listOf(hash(1), hash(2)), page.hashes)
        assertArrayEquals(next, page.nextCursor)

        fake.page = RelayTransport.Page(emptyList(), ByteArray(0))
        val caughtUp = port.list(relay, ns, cap, ByteArray(0), 128, 20_000)
        assertArrayEquals(ByteArray(0), fake.calls.last().args[0] as ByteArray)
        assertTrue(caughtUp.hashes.isEmpty())
        assertEquals(0, caughtUp.nextCursor.size)
    }

    @Test
    fun checkSendsDistinctHashesAndReturnsTheHeldSubset() {
        fake.held = listOf(hash(3).toByteArray(), hash(1).toByteArray())
        val held = port.check(relay, ns, cap, listOf(hash(1), hash(2), hash(3)), 60_000)
        @Suppress("UNCHECKED_CAST")
        val sent = fake.calls.single().args[0] as List<ByteArray>
        assertEquals(3, sent.size)
        assertArrayEquals(hash(2).toByteArray(), sent[1])
        assertEquals(setOf(hash(1), hash(3)), held)
    }

    @Test
    fun answersThatDoNotFitThePortTypesAreMalformedResponses() {
        fake.receipt = RelayTransport.StoreReceipt(ByteArray(31), 1L)
        malformed { port.store(relay, ns, cap, TestBytes.ciphertext(1), 86_400, 60_000) }

        fake.page = RelayTransport.Page(listOf(ByteArray(33)), ByteArray(0))
        malformed { port.list(relay, ns, cap, ByteArray(0), 4, 20_000) }
        fake.page = RelayTransport.Page(emptyList(), ByteArray(5))
        malformed { port.list(relay, ns, cap, ByteArray(0), 4, 20_000) }
        fake.page = RelayTransport.Page((1..5).map { hash(it).toByteArray() }, ByteArray(0))
        malformed { port.list(relay, ns, cap, ByteArray(0), 4, 20_000) }

        fake.held = listOf(hash(9).toByteArray())
        malformed { port.check(relay, ns, cap, listOf(hash(1), hash(2)), 60_000) }
        fake.held = listOf(hash(1).toByteArray(), hash(1).toByteArray())
        malformed { port.check(relay, ns, cap, listOf(hash(1), hash(2)), 60_000) }
        fake.held = listOf(ByteArray(16))
        malformed { port.check(relay, ns, cap, listOf(hash(1)), 60_000) }
    }

    @Test
    fun aMalformedStoreAnswerIsAPossibleCopyForTheEngineNotALocalBug() {
        fake.receipt = RelayTransport.StoreReceipt(ByteArray(40), 1L)
        val result = relayCall { port.store(relay, ns, cap, TestBytes.ciphertext(1), 86_400, 60_000) }
        assertTrue(result is CallResult.Failed)
        assertEquals(ErrorClass.RELAY_HOSTILE, (result as CallResult.Failed).errorClass)
    }

    @Test
    fun transportFailuresPassThroughUnchanged() {
        for (category in listOf("timeout", "unauthorized", "closed", "not_bootstrapped", "quota")) {
            fake.failure = NetworkException(category)
            val e = assertThrows(NetworkException::class.java) { port.list(relay, ns, cap, ByteArray(0), 4, 20_000) }
            assertEquals(category, e.category)
            assertEquals(category, e.message)
        }
        val argument = IllegalArgumentException("deadline must be 1..60000 ms")
        fake.failure = argument
        assertSame(argument, assertThrows(IllegalArgumentException::class.java) { port.get(relay, ns, cap, hash(1), 0) })
        val result = relayCall { port.get(relay, ns, cap, hash(1), 0) }
        assertEquals(ErrorClass.LOCAL_BUG, (result as CallResult.Failed).errorClass)
    }

    @Test
    fun toStringCarriesNothing() {
        assertEquals("TorRelayPort", port.toString())
        assertFalse(port.toString().contains(relay.toString()))
    }
}
