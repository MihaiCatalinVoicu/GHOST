package org.ghost.update.harness

import org.ghost.network.UpdateNative
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * The two remaining named hostile worlds of Phase 14 design §11.2 (with CS-D7, DS-5, RK4 and
 * §3.5), on the standard harness. Both are behavioural: the world's normal clock, the model
 * mirrors, the recording installer where an install is modelled.
 *
 * - **The recovery-epoch world** (§11.2, CS-D7, §3.5 "Root key", L10-D13): two of the root
 *   keys are stolen; the attacker's roots v(n+1)…v(n+5) are correctly chained and logged —
 *   valid by the chain rule, which is the attack: clients on the old chain adopt them. A
 *   recovery APK whose embedded chain is a NEW lineage is installed on half the clients; at
 *   its first start the stored root not being on the embedded chain starts a new trust epoch
 *   from the embedded root (§7.4 step 0, decision.rs `fresh_epoch`): epoch := SHA-256(E),
 *   stored chain := embedded, pair (E.version, 0), floor 0, conflict flags cleared, no stored
 *   manifest. The recovery half follows ONLY the new chain — an attacker bundle under v(n+3)
 *   never verifies, and a later attacker root v(n+6) chained from v(n+5) does not reach it —
 *   while the other half stays on the old chain and follows it to v(n+6). This is MC-D28's
 *   named kill: the revision-1 rule (anchor = the newer root by version) would keep the
 *   attacker's higher-numbered chain; the recovery lineage takes version 1 of its own, "not
 *   because order decides anything" (§3.5).
 * - **The root-swap world** (§11.2, MC-D23): two stolen root keys; the attacker's own log and
 *   witnesses; a new root correctly signed under the old chain rule but logged under the
 *   ATTACKER's policy is refused with ROOT_UNLOGGED — the chain rule's logging clause checks
 *   the proof under the PREVIOUS root's policy (decision.rs step 2) — and no state changes.
 */
class NamedHostileWorldsTest {

    private fun assumeHostLibrary() = assumeTrue(
        "the ghost-dm-host library is not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    private fun serving(world: World, bundle: ByteArray): ModelMirror {
        val m = world.mirror(MirrorMode.EQUIVOCATE)
        m.equivocateBundle = bundle
        return m
    }

    private fun serve(client: Client, bundle: ByteArray) {
        client.updateRun(serving(client.world, bundle), serving(client.world, bundle))
    }

    private fun acceptCode(client: Client, bundle: ByteArray): Int {
        val loaded = client.store.load()!!
        return client.world.config.native.accept(
            loaded.blob, bundle, client.world.clock.trusted,
            client.world.clock.day(), client.world.clock.nowSeconds(),
        ).first
    }

    @Test
    fun recoveryEpochWorld() {
        assumeHostLibrary()
        World("recovery-epoch", seed = 201).use { world ->
            val fixtures = world.fixtures
            val recoveryChain = fixtures.doc("chain-rc.ghrc")
            val recoveryRoot = recoveryRootSha(recoveryChain)
            val clients = (0 until 4).map {
                world.client(installed = 1, sdk = 29).also { it.firstStart() }
            }

            // Phase 1 — the attack: v(n+1)…v(n+5), valid by the chain rule. Every client on
            // the old chain adopts them (§3.5: against two stolen root keys no version number
            // can win — the attacker's chain IS the old chain now).
            for (c in clients) {
                serve(c, fixtures.doc("bundle-2.ghrb"))
                serve(c, fixtures.doc("bundle-5.ghrb"))
            }
            for (c in clients) {
                val held = c.store.load()!!
                assertEquals(5, held.facts.rootVersion)
                assertArrayEquals(fixtures.doc("manifest-5.ghrm"), held.facts.manifestFile)
            }

            // Phase 2 — the recovery APK on the first half (§3.5: installed outside the
            // updater; the world models the platform replace and the app's next start).
            for (c in clients.take(2)) {
                c.installRecoveryChain(recoveryChain, newInstalled = 3)
            }

            // §7.4 step 0's fresh epoch: epoch := SHA-256(E), the embedded chain, pair
            // (E.version, 0), floor 0, no manifest, flags cleared.
            for (c in clients.take(2)) {
                val recovered = c.store.load()!!
                assertArrayEquals("the epoch is the new lineage's id", recoveryRoot, recovered.facts.epoch)
                assertArrayEquals(recoveryChain, recovered.facts.chain)
                assertEquals(1, recovered.facts.rootVersion)
                assertEquals(0L, recovered.facts.manifestSeq)
                assertEquals(1, recovered.facts.manifestRoot)
                assertNull(recovered.facts.manifestFile)
                assertEquals(0, recovered.facts.floorVersionCode)
                assertFalse(recovered.facts.conflict)
                assertFalse(recovered.facts.rootConflict)
            }
            // The other half stays on the old chain (L10-D13).
            for (c in clients.drop(2)) {
                assertEquals(5, c.store.load()!!.facts.rootVersion)
            }

            // The recovery half follows ONLY the new chain: an attacker bundle under v(n+3)
            // never verifies (§3.5: bundles on the old chain then never verify)…
            for (c in clients.take(2)) {
                val before = c.store.load()!!
                serve(c, fixtures.doc("bundle-3att.ghrb"))
                val after = c.store.load()!!
                assertEquals("the attacker bundle moved the recovery half", 1, after.facts.rootVersion)
                assertNull(after.facts.manifestFile)
                assertEquals(before.facts.epoch.toHex(), after.facts.epoch.toHex())
            }
            // …while the old half still reads the old chain's bundles.
            for (c in clients.drop(2)) {
                assertEquals(5, c.store.load()!!.facts.rootVersion)
            }

            // The recovery half accepts its own lineage's bundle and is offered the release.
            for (c in clients.take(2)) {
                serve(c, fixtures.doc("bundle-rc.ghrb"))
                assertArrayEquals(fixtures.doc("manifest-rc.ghrm"), c.store.load()!!.facts.manifestFile)
            }

            // A subsequent attacker root v(n+6), chained from v(n+5): the old half adopts it…
            for (c in clients.drop(2)) {
                serve(c, fixtures.doc("bundle-6.ghrb"))
                assertEquals(6, c.store.load()!!.facts.rootVersion)
            }
            // …and it does not reach the recovery half.
            for (c in clients.take(2)) {
                val before = c.store.load()!!
                serve(c, fixtures.doc("bundle-6.ghrb"))
                val after = c.store.load()!!
                assertEquals("the attacker reached the recovery half", 1, after.facts.rootVersion)
                assertArrayEquals(fixtures.doc("manifest-rc.ghrm"), after.facts.manifestFile)
                assertEquals(before.facts.epoch.toHex(), after.facts.epoch.toHex())
            }
        }
        report("recovery-epoch world: new epoch from the embedded chain; the recovery half follows only it; v(n+6) reaches only the old half")
    }

    /** The epoch id of a fresh epoch: SHA-256 of the embedded chain's last root (decision.rs).
     *  GHRC: "GHRC"‖u8‖u8‖first_version u32‖count u16‖count × lp32 roots. */
    private fun recoveryRootSha(chain: ByteArray): ByteArray {
        var pos = 12
        val count = ((chain[10].toInt() and 0xff) shl 8) or (chain[11].toInt() and 0xff)
        var last: ByteArray = ByteArray(0)
        repeat(count) {
            val n = ((chain[pos].toInt() and 0xff) shl 24) or ((chain[pos + 1].toInt() and 0xff) shl 16) or
                ((chain[pos + 2].toInt() and 0xff) shl 8) or (chain[pos + 3].toInt() and 0xff)
            pos += 4
            last = chain.copyOfRange(pos, pos + n)
            pos += n
        }
        return MessageDigest.getInstance("SHA-256").digest(last)
    }

    @Test
    fun rootSwapWorld() {
        assumeHostLibrary()
        World("root-swap", seed = 202).use { world ->
            val fixtures = world.fixtures
            val client = world.client(installed = 1, sdk = 29)
            client.firstStart()

            // The attacker's root: the block meets the old threshold (the stolen key), but
            // the proof is logged under the attacker's own log and witnesses. The chain rule's
            // logging clause checks the proof under the PREVIOUS root's policy → ROOT_UNLOGGED.
            // The bundle carries the honest manifest so the manifest arm accepts and the walk's
            // report surfaces (decision.rs: step 2's report stands when the manifest accepts).
            val swap = fixtures.doc("bundle-swap.ghrb")
            assertEquals(
                "the attacker-policy proof is refused at the logging clause (MC-D23)",
                UpdateNative.ROOT_UNLOGGED, acceptCode(client, swap),
            )

            // And no state changes: the stored root stays, nothing is adopted, the directory
            // saw no attacker relay.
            val held = client.store.load()!!
            assertEquals(1, held.facts.rootVersion)
            assertNull(held.facts.manifestFile)
            assertEquals(0, world.directory.staleSuppressions)
            assertTrue(world.directory.relabelAttempts.isEmpty())

            // The engine run tells the same story end to end.
            serve(client, swap)
            assertEquals(1, client.store.load()!!.facts.rootVersion)
            assertNull(client.store.load()!!.facts.manifestFile)
        }
        report("root-swap world: ROOT_UNLOGGED, no state change")
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    /** Appends the measured world line to the report fragment (the established style). */
    private fun report(line: String) {
        val dir = java.io.File("build/update-mutants").apply { mkdirs() }
        val file = java.io.File(dir, "report.txt")
        val lines = if (file.isFile) file.readLines() else emptyList()
        if (line !in lines) file.appendText(line + "\n")
    }
}
