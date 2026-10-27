package org.ghost.update.harness

import org.ghost.network.UpdateNative
import org.ghost.update.UpdateStatus
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The stolen-release-key world (Phase 14 design §11.2, DS-5): a manifest signed by the stolen
 * release key — validly signed, so the engine accepts it — lists only attacker mirrors and
 * pushes the floor to its bound; then RK4's root is published on the anchor mirrors only, and
 * every client must adopt it at its next run: the stored manifest's authority drops, floor and
 * conflict reset to the new root's scope. The security property the world pins (T50): neither
 * a mirror nor a stolen release key can hold a client below what a root-listed mirror serves —
 * the anchor channel stays live exactly because the draw always keeps an anchor mirror.
 */
class StolenReleaseKeyWorldTest {

    private fun assumeHostLibrary() = assumeTrue(
        "ghost-client-net host library not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    private fun serving(world: World, bundle: ByteArray): ModelMirror {
        val m = world.mirror(MirrorMode.EQUIVOCATE)
        m.equivocateBundle = bundle
        return m
    }

    @Test
    fun everyClientAdoptsTheRevocationRootAndDropsTheStolenManifestsAuthority() {
        assumeHostLibrary()
        World("stolen-release-key", seed = 51).use { world ->
            val stolen = world.fixtures.doc("bundle-stolen.ghrb")
            val rk4 = world.fixtures.doc("bundle-2.ghrb")
            val clients = (0 until 3).map { world.client(installed = 1, sdk = 29).also { it.firstStart() } }

            for (client in clients) {
                // Phase 1 — the stolen-key manifest: validly signed, so it is accepted; the
                // floor rides to its bound and the offer's below-floor escape still names v2.
                assertEquals(UpdateNative.OK, nativeAccept(client, stolen))
                client.updateRun(serving(world, stolen), serving(world, stolen))
                val held = client.store.load()!!
                assertArrayEquals(world.fixtures.doc("manifest-stolen.ghrm"), held.facts.manifestFile)
                assertEquals(2, held.facts.floorVersionCode)
                assertEquals(1, held.facts.floorRoot)
                assertTrue(client.updates.status is UpdateStatus.Ready)

                // Phase 2 — RK4's root, on the anchor mirrors only: adopted at the next run;
                // the floor and conflict scopes reset to the new root.
                client.updateRun(serving(world, rk4), serving(world, rk4))
                val recovered = client.store.load()!!
                assertEquals(2, recovered.facts.rootVersion)
                assertEquals(1L, recovered.facts.manifestSeq)
                assertArrayEquals(world.fixtures.doc("chain2.ghrc"), recovered.facts.chain)
                assertArrayEquals(world.fixtures.doc("manifest-2.ghrm"), recovered.facts.manifestFile)
                assertEquals(0, recovered.facts.floorVersionCode)
                assertEquals(2, recovered.facts.floorRoot)
                assertFalse(recovered.facts.conflict)
                assertFalse(recovered.facts.rootConflict)
                assertEquals("verified", client.store.staged(world.fixtures.apkSha256)!!.state)

                // The install path holds the verified bytes.
                client.updates.install().commit()
                client.installer.assertAllEqual(world.fixtures.apk)

                // Phase 3 — the stolen manifest is dead authority under the new root.
                assertEquals(UpdateNative.ROOT_MISMATCH, nativeAccept(client, stolen))
            }
        }
    }

    /** The oracle acceptance (decides, does not persist). */
    private fun nativeAccept(client: Client, bundle: ByteArray): Int {
        val loaded = client.store.load() ?: throw AssertionError("no stored state")
        return client.world.config.native.accept(
            loaded.blob, bundle, client.world.clock.trusted,
            client.world.clock.day(), client.world.clock.nowSeconds(),
        ).first
    }
}
