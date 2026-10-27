package org.ghost.update.harness

import org.ghost.update.UpdateStatus
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The benign update world (Phase 14 design §11.2's foundation test): a signed fixture bundle
 * served by two model mirrors → one update run of the real engine → the offer → the download →
 * the native verification → the staged row — and the facade's install commits into the
 * recording installer, which must hold exactly the verified APK's bytes. Skipped, not failed,
 * without the host library — the repo's standing native-test rule.
 */
class BenignUpdateWorldTest {

    private fun assumeHostLibrary() = assumeTrue(
        "ghost-client-net host library not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    @Test
    fun twoHonestMirrorsUpdateTwoClientsAndTheInstallerHoldsTheVerifiedBytes() {
        assumeHostLibrary()
        World("benign", seed = 14).use { world ->
            val mirrorA = world.mirror()
            val mirrorB = world.mirror()
            val first = world.client(installed = 1, sdk = 29)
            val second = world.client(installed = 1, sdk = 29)

            for (client in listOf(first, second)) {
                client.firstStart()

                // The update run: both mirrors serve the signed bundle; the engine accepts it,
                // the recomputed offer names version 2, the chunks stream, the native check
                // verifies, the row and the staged file land.
                client.updateRun(mirrorA, mirrorB)

                val loaded = client.store.load()
                    ?: throw AssertionError("the run left no stored facts")
                assertArrayEquals(
                    "ACCEPT stored the fixture manifest's hash",
                    world.fixtures.manifestSha256,
                    loaded.facts.manifestSha256,
                )
                assertArrayEquals(
                    "the stored manifest is the fixture manifest, byte for byte",
                    fixtureManifest(world),
                    loaded.facts.manifestFile,
                )
                assertEquals(0, loaded.failedRuns)

                val staged = client.store.staged(world.fixtures.apkSha256)
                    ?: throw AssertionError("the run staged no APK")
                assertEquals("verified", staged.state)
                assertEquals(world.fixtures.apk.size.toLong(), staged.received)

                // The facade's view: the update is ready, at the fixture release.
                val status = client.updates.status
                assertTrue("status is Ready, got $status", status is UpdateStatus.Ready)
                assertEquals(2, (status as UpdateStatus.Ready).versionCode)
                assertEquals(world.fixtures.issuedDay, client.updates.manifestIssuedDay)

                // The install: the facade streams the staged file into the recording installer.
                client.updates.install().commit()
            }

            // The recording installer is the T48 oracle: exactly the verified bytes, per client.
            first.installer.assertLastEquals(world.fixtures.apk)
            second.installer.assertLastEquals(world.fixtures.apk)

            // The mirror view: every client asked both mirrors for the bundle and the chunk
            // (T51's observatory: what the mirrors saw is recorded). The fixture APK is one
            // 4 MiB chunk; the engine alternates mirrors per chunk index, so chunk 0 goes to
            // slot 0 alone — mirror B saw the bundle but no chunk.
            assertEquals(2, mirrorA.bundleRequests)
            assertEquals(2, mirrorB.bundleRequests)
            assertEquals(2, mirrorA.chunkRequests)
            assertEquals(0, mirrorB.chunkRequests)
        }
    }

    private fun fixtureManifest(world: World): ByteArray =
        java.io.DataInputStream(
            requireNotNull(javaClass.getResourceAsStream("/update-world/manifest-1.ghrm")) {
                "manifest-1.ghrm missing from the test resources"
            },
        ).use { it.readBytes() }
}
