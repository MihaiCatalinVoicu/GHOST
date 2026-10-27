package org.ghost.update.harness

import org.ghost.network.UpdateNative
import org.ghost.update.UpdateCodec
import org.ghost.update.UpdateStateStore
import org.ghost.update.UpdateStatus
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * The revocation world (Phase 14 design §11.2's named worlds; DS-5's "until RK4" column here
 * realised by a NORMAL RK2 rotation, §3.5's release-key bullet): a release key is dropped by a
 * regular root rotation — the new root keeps the root keyset, the release set loses the key.
 * The world asserts DS-5's guarantees for exactly this move:
 *
 * (a) §3.5: "refuse manifests signed only by the removed key whatever their sequence" — a
 * manifest naming the NEW root at a pair HIGHER than the stored one (so no pair rule can
 * swallow it) and signed only by the removed key is refused with exactly `BAD_SIGNATURE`.
 * (b) §7.4 step 7's note: a newer root reached in step 2 is persisted even when a later step
 * refuses the manifest — "from that moment the stored manifest, which names the older root, is
 * not current: no offer, no directory change and no manifest mirror come from it, and only
 * the new root's anchor mirrors are asked, until a manifest under R is accepted." The world
 * seeds that persisted-adoption state through its own store (the engine stores only fully
 * accepted outcomes; the design's state is what step 2's transaction persists — the MC-D32
 * world's precedent).
 * (c) §3.5: a fresh manifest under the new root resumes normality — the offer returns, the
 * directory applies, and the new manifest's mirror list re-enters the run.
 */
class RevocationWorldTest {

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

    /** The run's draw with r1 = 1: the second mirror is the extra when extras exist. */
    private fun extraDraw(): ByteArray {
        val d = ByteArray(32)
        d[15] = 1
        return d
    }

    @Test
    fun revocationWorld() {
        assumeHostLibrary()
        World("revocation", seed = 301).use { world ->
            val fixtures = world.fixtures
            val client = world.client(installed = 1, sdk = 29)
            client.firstStart()
            // The world models the anchors and the new manifest's extra: anchorA/anchorB are
            // the anchors, extra the new manifest's listed mirror; the slot mapping is the
            // §7.8 replica — extras join the draw only while the stored manifest is fresh
            // and current (draw.rs), which is precisely authority (b) removes and (c) restores.
            val anchors = fixtures.anchors.map { it.first }
            val extra = world.mirror()
            val anchorA = world.mirror()
            val anchorB = world.mirror()
            fun pickNow(draw: ByteArray): Pair<ModelMirror, ModelMirror> {
                val loaded = client.store.load()!!
                val facts = loaded.facts
                val current = facts.manifestFile != null && facts.manifestRoot == facts.rootVersion
                val pool = mutableListOf<Pair<String, ModelMirror>>(
                    anchors[0] to anchorA, anchors[1] to anchorB,
                )
                if (current) pool += "extra" to extra
                val r0 = be64(draw, 0)
                val r1 = be64(draw, 8)
                val first = pool[(r0 % pool.size).toInt()]
                val candidates = pool.filter { it.first != first.first }
                val second = candidates[(r1 % candidates.size).toInt()]
                return first.second to second.second
            }
            fun run(draw: ByteArray = extraDraw()) {
                client.updateRun(anchorA, anchorB, draw = draw, pick = pickNow(draw))
            }

            // Phase 1 — normality under the old root: the stored manifest (signed by the
            // still-trusted release-1) offers the release and applies its directory.
            serve(client, fixtures.bundle)
            val held = client.store.load()!!
            assertArrayEquals(fixtures.doc("manifest-1.ghrm"), held.facts.manifestFile)
            assertTrue(client.updates.status is UpdateStatus.Ready)
            assertEquals(3, world.directory.upsertCalls)

            // Phase 2 — RK2's key drop: the new root (release set without release-1) is
            // reached, the stored manifest names the old root. The design's persisted
            // adoption (step 2 verified on its own; the engine persists only full
            // acceptances, so the world seeds the design's state through its own store).
            val loaded = client.store.load()!!
            val manifest1 = fixtures.doc("manifest-1.ghrm")
            val seeded = UpdateCodec.Facts(
                network = loaded.facts.network,
                epoch = loaded.facts.epoch,
                epochVersionCode = loaded.facts.epochVersionCode,
                chain = fixtures.doc("chain2.ghrc"),
                rootVersion = 2,
                manifestRoot = 1,
                manifestSeq = 1,
                manifestSha256 = MessageDigest.getInstance("SHA-256").digest(manifest1),
                manifestFile = manifest1,
                proofFile = loaded.facts.proofFile,
                floorVersionCode = loaded.facts.floorVersionCode,
                floorRoot = loaded.facts.floorRoot,
                conflict = false,
                rootConflict = false,
            )
            client.store.accept(seeded)
            assertEquals(2, client.store.load()!!.facts.rootVersion)

            // (b) The stored manifest is not current: no offer (§7.4 step 7's note)…
            val afterRk2 = client.store.load()!!
            val offer = world.config.native.offer(
                afterRk2.blob, 1, 29, afterRk2.rolloutKey, true, world.clock.day(),
            )
            assertTrue(offer is UpdateNative.Offer.None)
            assertEquals(UpdateNative.NO_MANIFEST, (offer as UpdateNative.Offer.None).code)
            // (The facade still shows Ready — the phase-1 download is staged, and §9.5's
            // status order puts Ready before the manifest checks; the "no offer" claim is
            // the offer oracle's, and no NEW offer or download comes from the old manifest.)
            // …no directory change and no manifest mirror from it: a run asks only the new
            // root's anchors (the armed extra serves nothing) and the directory is untouched.
            val upsertsBefore = world.directory.upsertCalls
            run()
            assertEquals(0, extra.bundleRequests)
            assertTrue(anchorA.bundleRequests >= 1)
            assertTrue(anchorB.bundleRequests >= 1)
            assertEquals(upsertsBefore, world.directory.upsertCalls)
            assertEquals(0, world.directory.staleSuppressions)

            // (a) A manifest signed only by the removed key, at a pair ABOVE the stored one:
            // whatever its sequence, the refusal is BAD_SIGNATURE — not a pair rule.
            assertEquals(
                "the removed key is refused whatever the sequence (DS-5, §3.5)",
                UpdateNative.BAD_SIGNATURE,
                acceptCode(client, fixtures.doc("bundle-removedkey.ghrb")),
            )
            // The refusal changed nothing.
            assertEquals(2, client.store.load()!!.facts.rootVersion)
            assertArrayEquals(manifest1, client.store.load()!!.facts.manifestFile)

            // (c) A manifest under the new root: normality resumes — the offer, the staged
            // download, and the manifest's extra mirror re-enter the run.
            serve(client, fixtures.doc("bundle-2x.ghrb"))
            val recovered = client.store.load()!!
            assertEquals(2, recovered.facts.rootVersion)
            assertArrayEquals(fixtures.doc("manifest-2x.ghrm"), recovered.facts.manifestFile)
            assertEquals("verified", client.store.staged(world.fixtures.apkSha256)!!.state)
            assertTrue(client.updates.status is UpdateStatus.Ready)
            assertTrue(world.directory.upsertCalls > upsertsBefore)
            val extrasBefore = extra.bundleRequests
            run()
            assertTrue(
                "the new manifest's mirror list re-entered the run (§3.5)",
                extra.bundleRequests > extrasBefore,
            )
            client.updates.install().commit()
            client.installer.assertAllEqual(world.fixtures.apk)
        }
        report("revocation world: removed-key manifest BAD_SIGNATURE at any sequence; the old root's manifest holds no authority; a manifest under the new root resumes normality")
    }

    private fun be64(b: ByteArray, at: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[at + i].toLong() and 0xff)
        return v
    }

    private fun report(line: String) {
        val dir = java.io.File("build/update-mutants").apply { mkdirs() }
        val file = java.io.File(dir, "report.txt")
        val lines = if (file.isFile) file.readLines() else emptyList()
        if (line !in lines) file.appendText(line + "\n")
    }
}
