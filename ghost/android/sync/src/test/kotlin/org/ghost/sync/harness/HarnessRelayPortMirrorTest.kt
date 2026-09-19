package org.ghost.sync.harness

import org.ghost.network.NetworkException
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.store.RetentionPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * The three client rules [HarnessRelayPort] mirrors from the Rust client, executed rather than only
 * written (review of S2): the exact-bucket TTL of design §10.2 point 6, the bearer-credential branch
 * of the T21 guard (§4.3, §22.8.7) and the store receipt's upper bound (T30, L7-D27).
 *
 * No world reaches them -- `TtlBucket` holds only buckets, every scenario gives the engine
 * capabilities, and an honest relay's receipt stays far inside the bound -- so without this test
 * deleting any of the three would leave the suite green. The port is driven directly inside a
 * synthetic lane item ([HarnessDriver.asLaneItem]); no session, engine or invariant runs here.
 */
internal class HarnessRelayPortMirrorTest {

    private fun secret(label: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(label.toByteArray(Charsets.US_ASCII))

    /** The category a refused call carries, or a failure if the call did not refuse. */
    private fun refusal(what: String, call: () -> Unit): String = try {
        call()
        throw AssertionError("$what was not refused")
    } catch (e: NetworkException) {
        e.category
    }

    @Test
    fun theMirroredClientRulesRefuseWhatTheRustClientRefuses() {
        World("port-mirror", 1L, JournalMode.WAL).use { w ->
            val a = w.relay("A", 1)
            val b = w.relay("B", 2)
            a.model.slot = 1
            val client = w.client(ClientSpec("mira", armed = true))
            client.directory(a, b)
            val ns = client.namespace("inbox", listOf(a, b), listen = true)
            val other: NamespaceId = client.namespace("drops", listOf(a, b), listen = false)
            val write = client.capability(a, ns, CapabilityKind.WRITE)
            val op = client.enqueue("op", ns)
            val port = client.port

            val depositSecret = secret("deposit")
            val deposit = ModelRelay.credentialBytes(ModelRelay.KIND_DEPOSIT, 1, ns, depositSecret)
            val read = ModelRelay.credentialBytes(ModelRelay.KIND_READ, 1, ns, secret("read"))
            val foreign = ModelRelay.credentialBytes(ModelRelay.KIND_DEPOSIT, 1, other, depositSecret)
            val relayNow = w.relayNow(a)
            val registered = a.model.registerKey(
                ns.toByteArray(),
                ModelRelay.week(relayNow),
                ModelRelay.KIND_DEPOSIT,
                ModelRelay.verifierOf(ModelRelay.Credential(ModelRelay.KIND_DEPOSIT, 1, ns, depositSecret)),
                write,
                ByteArray(16) { 1 },
                relayNow,
            )
            assertTrue("the deposit verifier is registered", registered is ModelRelay.Reply.Ok)

            w.driver.asLaneItem(client) {
                // 1. The TTL of a store is exactly one bucket; anything else is refused before any I/O.
                for (bad in listOf(0, 1, 1_800, 3_601, 7_200, 86_401, 30 * 86_400 + 1)) {
                    assertEquals(
                        "ttl $bad",
                        "invalid_argument",
                        refusal("a store of $bad s") { port.store(a.address, ns, write, op.ciphertext, bad, 30_000) },
                    )
                }

                // 2. A bearer credential v3 must name this namespace and fit the operation (T21).
                assertEquals(
                    "a deposit credential on a get",
                    "invalid_argument",
                    refusal("get") { port.get(a.address, ns, deposit, op.hash, 30_000) },
                )
                assertEquals(
                    "a deposit credential on a list",
                    "invalid_argument",
                    refusal("list") { port.list(a.address, ns, deposit, ByteArray(0), 4, 30_000) },
                )
                assertEquals(
                    "a read credential on a store",
                    "invalid_argument",
                    refusal("store") { port.store(a.address, ns, read, op.ciphertext, 604_800, 30_000) },
                )
                assertEquals(
                    "a deposit credential of another namespace",
                    "invalid_argument",
                    refusal("store") { port.store(a.address, ns, foreign, op.ciphertext, 604_800, 30_000) },
                )
                // The branch admits as well as refuses: the fitting credential reaches the relay.
                val deposited = port.store(a.address, ns, deposit, op.ciphertext, 604_800, 30_000)
                assertEquals(op.hash, deposited.blobHash)

                // 3. The receipt's upper bound: an over-promise of exactly sigma is tolerated, more
                //    is malformed_response (T30; the tolerated residue is L7-D27).
                a.model.longExpirySeconds = RetentionPolicy.SKEW_SECONDS
                val tolerated = port.store(a.address, ns, write, op.ciphertext, 604_800, 30_000)
                assertEquals(
                    "exactly sigma above the honest expiry",
                    deposited.expiryUnixSeconds + RetentionPolicy.SKEW_SECONDS,
                    tolerated.expiryUnixSeconds,
                )
                a.model.longExpirySeconds = RetentionPolicy.SKEW_SECONDS + 3_600
                assertEquals(
                    "a relay promising more than sigma over the TTL",
                    "malformed_response",
                    refusal("store") { port.store(a.address, ns, write, op.ciphertext, 604_800, 30_000) },
                )
            }
        }
    }
}
