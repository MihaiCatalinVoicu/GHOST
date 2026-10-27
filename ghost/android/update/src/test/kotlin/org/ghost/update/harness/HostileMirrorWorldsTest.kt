package org.ghost.update.harness

import org.ghost.network.NetworkException
import org.ghost.network.UpdateNative
import org.ghost.update.UpdateStatus
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The hostile-mirror worlds (Phase 14 design §11.2): the real engine — and, for the exact
 * refusal codes the engine's orchestration deliberately does not surface, the real native
 * decision called directly over the same stored state — against every hostile mode. The exact
 * codes are §9.2's vocabulary: the design's "each must give its exact Code".
 *
 * Where a refusal leaves stored facts untouched, the world asserts the stored state; where a
 * document is accepted as a fact but applied to nothing (an expired manifest), the world
 * asserts both halves.
 */
class HostileMirrorWorldsTest {

    private fun assumeHostLibrary() = assumeTrue(
        "ghost-client-net host library not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    /** The native acceptance over the client's current stored state: the exact-code oracle.
     *  (Storage happens only through the engine; this call decides, it does not persist.) */
    private fun accept(client: Client, bundle: ByteArray): Int {
        val loaded = client.store.load() ?: throw AssertionError("no stored state")
        return client.world.config.native.accept(
            loaded.blob, bundle, client.world.clock.trusted,
            client.world.clock.day(), client.world.clock.nowSeconds(),
        ).first
    }

    /** The native streaming APK check over [bytes] as the offered release: the exact code. */
    private fun checkApk(client: Client, bytes: ByteArray): Int {
        val loaded = client.store.load() ?: throw AssertionError("no stored state")
        val cdOffset = (bytes[bytes.size - 6].toInt() and 0xff) or
            ((bytes[bytes.size - 5].toInt() and 0xff) shl 8) or
            ((bytes[bytes.size - 4].toInt() and 0xff) shl 16) or
            ((bytes[bytes.size - 3].toInt() and 0xff) shl 24)
        val handle = client.world.config.native.apkBegin(
            loaded.blob, 0, client.sdk, bytes.size.toLong(), bytes.copyOfRange(bytes.size - 22, bytes.size),
        )
        var code = client.world.config.native.apkFooter(handle, bytes.copyOfRange(cdOffset - 24, cdOffset))
        if (code == UpdateNative.OK) {
            code = client.world.config.native.apkUpdate(handle, 0, bytes.copyOfRange(0, bytes.size - 22))
        }
        if (code == UpdateNative.OK) {
            code = client.world.config.native.apkFinish(handle)
        } else {
            client.world.config.native.apkAbort(handle)
        }
        return code
    }

    private fun freshClient(world: World, installed: Int = 1): Client {
        val client = world.client(installed = installed, sdk = 29)
        client.firstStart()
        return client
    }

    /** Mirrors that serve an arbitrary bundle (the mode is only a byte vehicle here). */
    private fun serving(world: World, bundle: ByteArray): ModelMirror {
        val m = world.mirror(MirrorMode.EQUIVOCATE)
        m.equivocateBundle = bundle
        return m
    }

    // ------------------------------------------------------------------
    // Freshness, pairs, networks, proofs, floors.
    // ------------------------------------------------------------------

    @Test
    fun staleManifestIsAcceptedAsFactButOffersNothingAndAppliesNothing() {
        assumeHostLibrary()
        World("stale", seed = 21).use { world ->
            val client = freshClient(world)
            assertEquals("the oracle: an expired manifest is still a fact", UpdateNative.OK,
                accept(client, world.fixtures.staleBundle))
            client.updateRun(world.mirror(MirrorMode.STALE), world.mirror(MirrorMode.STALE))
            val loaded = client.store.load()!!
            assertArrayEquals(world.fixtures.doc("manifest-stale.ghrm"), loaded.facts.manifestFile)
            assertTrue(client.updates.status is UpdateStatus.Stale)
            // §7.8: an expired manifest contributes no directory rows.
            assertEquals(1, world.directory.staleSuppressions)
            assertTrue(world.directory.entries.values.all { it.source == "config" })
        }
    }

    @Test
    fun aLowerPairAfterAHigherOneIsRefusedRollback() {
        assumeHostLibrary()
        World("rollback", seed = 23).use { world ->
            val client = freshClient(world)
            client.updateRun(world.mirror(), world.mirror())
            // First push the pair to seq 2 with the expired replay (accepted as a fact).
            client.updateRun(
                world.mirror(MirrorMode.EXPIRED_REPLAY), world.mirror(MirrorMode.EXPIRED_REPLAY),
            )
            assertEquals(2L, client.store.load()!!.facts.manifestSeq)
            // Then serve the old generation again: pair (1,1) < (1,2).
            assertEquals(UpdateNative.ROLLBACK, accept(client, world.fixtures.bundle))
            assertEquals(2L, client.store.load()!!.facts.manifestSeq)
        }
    }

    @Test
    fun manifestOfAnotherNetworkIsRefusedWrongNetwork() {
        assumeHostLibrary()
        World("wrongnet", seed = 24).use { world ->
            val client = freshClient(world)
            assertEquals(UpdateNative.WRONG_NETWORK, accept(client, world.fixtures.doc("bundle-mainnet.ghrb")))
            client.updateRun(world.mirror(MirrorMode.MIXED_ROOT), world.mirror(MirrorMode.MIXED_ROOT))
            assertNull(client.store.load()!!.facts.manifestFile)
        }
    }

    @Test
    fun manifestOfAnotherRootIsRefusedRootMismatch() {
        assumeHostLibrary()
        World("mixedroot", seed = 25).use { world ->
            val client = freshClient(world)
            assertEquals(UpdateNative.ROOT_MISMATCH, accept(client, world.fixtures.doc("bundle-wrongroot.ghrb")))
            client.updateRun(world.mirror(MirrorMode.MIXED_ROOT), world.mirror(MirrorMode.MIXED_ROOT))
            assertNull(client.store.load()!!.facts.manifestFile)
        }
    }

    @Test
    fun wrongProofIsRefusedLogProofInvalid() {
        assumeHostLibrary()
        World("wrongproof", seed = 26).use { world ->
            val client = freshClient(world)
            assertEquals(UpdateNative.LOG_PROOF_INVALID, accept(client, world.fixtures.doc("bundle-wrongproof.ghrb")))
            client.updateRun(world.mirror(MirrorMode.WRONG_PROOF), world.mirror(MirrorMode.WRONG_PROOF))
            assertNull(client.store.load()!!.facts.manifestFile)
        }
    }

    @Test
    fun withheldProofRefusesTheBundleMalformed() {
        assumeHostLibrary()
        World("withhold", seed = 27).use { world ->
            val client = freshClient(world)
            assertEquals(UpdateNative.MALFORMED, accept(client, world.fixtures.doc("bundle-nowproof.ghrb")))
            client.updateRun(world.mirror(MirrorMode.WITHHOLD_PROOF), world.mirror(MirrorMode.WITHHOLD_PROOF))
            assertNull(client.store.load()!!.facts.manifestFile)
        }
    }

    @Test
    fun fastForwardStoresTheMaximumPairAndTheRootEscapeStillAdopts() {
        assumeHostLibrary()
        World("ff", seed = 28).use { world ->
            val client = freshClient(world)
            client.updateRun(serving(world, world.fixtures.doc("bundle-ff.ghrb")),
                serving(world, world.fixtures.doc("bundle-ff.ghrb")))
            assertEquals(Long.MAX_VALUE, client.store.load()!!.facts.manifestSeq)
            // The root escape: a newer root's pair (2,1) orders above (1, MAX) — adopted.
            client.updateRun(serving(world, world.fixtures.doc("bundle-2.ghrb")),
                serving(world, world.fixtures.doc("bundle-2.ghrb")))
            assertEquals(2, client.store.load()!!.facts.rootVersion)
            assertEquals(1L, client.store.load()!!.facts.manifestSeq)
        }
    }

    @Test
    fun expiredReplayAdvancesThePairButAppliesNoDirectoryChange() {
        assumeHostLibrary()
        World("replay", seed = 29).use { world ->
            val client = freshClient(world)
            client.updateRun(world.mirror(), world.mirror())
            val bootstrap = world.directory.entries.keys.toSet()
            assertEquals("the fresh manifest applied the committed relays", 3,
                world.directory.entries.count { it.value.source == "manifest" })
            // The replay: pair (1,2), expired, carrying an attacker relay.
            assertEquals(UpdateNative.OK, accept(client, world.fixtures.doc("bundle-replay.ghrb")))
            client.updateRun(world.mirror(MirrorMode.EXPIRED_REPLAY), world.mirror(MirrorMode.EXPIRED_REPLAY))
            val loaded = client.store.load()!!
            assertEquals(2L, loaded.facts.manifestSeq)
            assertArrayEquals(world.fixtures.doc("manifest-replay.ghrm"), loaded.facts.manifestFile)
            // MC-D30: no directory adoption from the expired manifest. (The run's offer came
            // from the pre-accept facts, so the APK legitimately staged: Ready, not Stale.)
            assertTrue(client.updates.status is UpdateStatus.Ready)
            assertEquals(1, world.directory.staleSuppressions)
            assertEquals("the attacker relay never entered the directory", bootstrap,
                world.directory.entries.keys.toSet())
        }
    }

    @Test
    fun floorAtTheBoundOffersTheFloorReleaseIgnoringTheBucketAndNothingToThoseAtIt() {
        assumeHostLibrary()
        World("floor", seed = 30).use { world ->
            // The release sits at rollout_permille 0: no normal offer, but a client below the
            // floor is offered it, bucket ignored (§7.4 step 8's below-floor escape).
            val below = freshClient(world, installed = 1)
            assertEquals(UpdateNative.OK, accept(below, world.fixtures.doc("bundle-floor.ghrb")))
            below.updateRun(world.mirror(MirrorMode.FLOOR_MAX), world.mirror(MirrorMode.FLOOR_MAX))
            assertEquals(2, below.store.load()!!.facts.floorVersionCode)
            val status = below.updates.status
            assertTrue(status is UpdateStatus.Ready)
            assertEquals(2, (status as UpdateStatus.Ready).versionCode)

            // At the floor, the permille-0 release offers nothing.
            val at = freshClient(world, installed = 2)
            at.updateRun(world.mirror(MirrorMode.FLOOR_MAX), world.mirror(MirrorMode.FLOOR_MAX))
            assertNull(at.store.staged())
            assertEquals(UpdateStatus.UpToDate, at.updates.status)
        }
    }

    @Test
    fun relabelingAKnownOnionIsRefusedByTheDirectoryGuard() {
        assumeHostLibrary()
        World("relabel", seed = 31).use { world ->
            val client = freshClient(world)
            // The manifest itself is validly signed and accepted…
            assertEquals(UpdateNative.OK, accept(client, world.fixtures.doc("bundle-relabel.ghrb")))
            client.updateRun(world.mirror(MirrorMode.RELABEL), world.mirror(MirrorMode.RELABEL))
            assertArrayEquals(world.fixtures.doc("manifest-relabel.ghrm"), client.store.load()!!.facts.manifestFile)
            // …but its relay upserts flip the committed onions' operator ids: the write-once
            // guard refuses every one (MC-D31); the bootstrap entries stand, operators intact.
            assertEquals(3, world.directory.relabelAttempts.size)
            assertEquals(3, world.directory.entries.size)
            for ((onion, entry) in world.directory.entries) {
                assertTrue(onion in world.directory.entries.keys)
                assertEquals("config", entry.source)
            }
        }
    }

    // ------------------------------------------------------------------
    // Bundle garbage.
    // ------------------------------------------------------------------

    @Test
    fun garbageBundleIsRefusedMalformedAndStoresNothing() {
        assumeHostLibrary()
        World("garbage", seed = 32).use { world ->
            val client = freshClient(world)
            val garbage = world.mirror(MirrorMode.GARBAGE)
            assertEquals(UpdateNative.MALFORMED, accept(client, garbage.serveBundle(world.fixtures)))
            client.updateRun(world.mirror(MirrorMode.GARBAGE), world.mirror(MirrorMode.GARBAGE))
            assertNull(client.store.load()!!.facts.manifestFile)
            assertEquals(0, client.store.load()!!.failedRuns) // the mirror answered, with garbage
        }
    }

    @Test
    fun truncatedBundleIsRefusedMalformedAndStoresNothing() {
        assumeHostLibrary()
        World("truncate", seed = 33).use { world ->
            val client = freshClient(world)
            val truncate = world.mirror(MirrorMode.TRUNCATE)
            assertEquals(UpdateNative.MALFORMED, accept(client, truncate.serveBundle(world.fixtures)))
            client.updateRun(world.mirror(MirrorMode.TRUNCATE), world.mirror(MirrorMode.TRUNCATE))
            assertNull(client.store.load()!!.facts.manifestFile)
        }
    }

    @Test
    fun anOversizedAnswerIsRefusedMalformedOnThisSeam() {
        assumeHostLibrary()
        World("endless", seed = 34).use { world ->
            val client = freshClient(world)
            // On the wire the 1 MiB bound answers first (the native fetch's bound check, a
            // client-core/net scope test); over the byte seam the parse refusal is observable.
            assertEquals(UpdateNative.MALFORMED, accept(client, world.mirror(MirrorMode.ENDLESS).serveBundle(world.fixtures)))
        }
    }

    // ------------------------------------------------------------------
    // Equivocation.
    // ------------------------------------------------------------------

    @Test
    fun equivocatingMirrorsLeaveTheFirstManifestStored() {
        assumeHostLibrary()
        World("equivocate", seed = 35).use { world ->
            val client = freshClient(world)
            val a = serving(world, world.fixtures.doc("bundle-eq-a.ghrb"))
            val b = serving(world, world.fixtures.doc("bundle-eq-b.ghrb"))
            client.updateRun(a, b)
            // Fetch order is slot order: eq-a accepted; eq-b is the same pair with other bytes.
            val loaded = client.store.load()!!
            assertArrayEquals(world.fixtures.doc("manifest-eq-a.ghrm"), loaded.facts.manifestFile)
            assertEquals(UpdateNative.CONFLICT, accept(client, world.fixtures.doc("bundle-eq-b.ghrb")))
            // T49: an equal pair with other bytes changes nothing.
            assertArrayEquals(world.fixtures.doc("manifest-eq-a.ghrm"), client.store.load()!!.facts.manifestFile)
        }
    }

    // ------------------------------------------------------------------
    // APK tampering: the native streaming check's exact codes.
    // ------------------------------------------------------------------

    @Test
    fun swappedApkBytesAreCaughtByTheFullFileHash() {
        assumeHostLibrary()
        World("swap", seed = 36).use { world ->
            val client = freshClient(world)
            client.updateRun(world.mirror(), world.mirror())
            val swap = world.fixtures.doc("app-v2-swap.apk")
            assertEquals("the swap fixture must reach the hash check, not the length check",
                world.fixtures.apk.size, swap.size)
            assertEquals(UpdateNative.APK_HASH, checkApk(client, swap))
            // The engine run against the swapping mirror leaves no staged bytes.
            val engineClient = freshClient(world)
            engineClient.updateRun(world.mirror(MirrorMode.APK_SWAP), world.mirror(MirrorMode.APK_SWAP))
            assertNull(engineClient.store.staged())
            assertTrue(engineClient.files.list()?.none { it.endsWith(".apk") || it.endsWith(".part") } ?: true)
        }
    }

    @Test
    fun bytesSplicedInsideTheSigningBlockAreCaught() {
        assumeHostLibrary()
        World("extra", seed = 37).use { world ->
            val client = freshClient(world)
            client.updateRun(world.mirror(), world.mirror())
            val extra = world.fixtures.doc("app-v2-extra.apk")
            assertEquals(world.fixtures.apk.size, extra.size)
            val code = checkApk(client, extra)
            // The splice keeps the ZIP layout and the block's size fields: the block parses
            // and its v2 signature no longer verifies (the crafted suite pins the family).
            assertTrue("a signing-block splice must fail the native check, got code $code", code != UpdateNative.OK)
        }
    }

    // ------------------------------------------------------------------
    // Mid-range drops and slow answers: the resumable download.
    // ------------------------------------------------------------------

    @Test
    fun aDroppedMidRangeAbortsTheRunAndTheNextRunResumes() {
        assumeHostLibrary()
        World("drop", seed = 38).use { world ->
            val big = world.fixtures.doc("app-v2-big.apk")
            val bundleBig = world.fixtures.doc("bundle-big.ghrb")
            val client = freshClient(world)
            assertEquals(UpdateNative.OK, accept(client, bundleBig))
            val dropper = world.mirror(MirrorMode.DROP_MID_RANGE)
            dropper.droppedChunks = setOf(1)
            dropper.apkOverride = big
            dropper.bundleOverride = bundleBig
            val honest = world.mirror()
            honest.apkOverride = big
            honest.bundleOverride = bundleBig
            try {
                // Chunk 0 rides slot 0 (the honest mirror); chunk 1 rides slot 1 (the dropper).
                client.updateRun(honest, dropper)
                throw AssertionError("the dropped chunk must fail the run")
            } catch (e: NetworkException) {
                assertEquals("transport", e.category)
            }
            val row = client.store.staged()!!
            assertEquals("partial", row.state)
            assertEquals(ModelMirror.CHUNK, row.received)
            val part = java.io.File(client.files, row.sha256.toHex() + ".part")
            assertArrayEquals(big.copyOfRange(0, ModelMirror.CHUNK.toInt()),
                part.readBytes().copyOfRange(0, ModelMirror.CHUNK.toInt()))
            // The next run resumes at the missing range and verifies.
            val resumer = world.mirror()
            resumer.apkOverride = big
            resumer.bundleOverride = bundleBig
            client.updateRun(resumer, resumer)
            assertEquals("verified", client.store.staged()!!.state)
        }
    }

    @Test
    fun aSlowAnswerEndsTheRunAtItsFixedEndAndTheNextRunFinishes() {
        assumeHostLibrary()
        World("slow", seed = 39).use { world ->
            val big = world.fixtures.doc("app-v2-big.apk")
            val bundleBig = world.fixtures.doc("bundle-big.ghrb")
            val client = freshClient(world)
            assertEquals(UpdateNative.OK, accept(client, bundleBig))
            val slow = world.mirror(MirrorMode.SLOW)
            slow.apkOverride = big
            slow.bundleOverride = bundleBig
            val honest = world.mirror()
            honest.apkOverride = big
            honest.bundleOverride = bundleBig
            client.updateRun(slow, honest)
            // The run stalled out at its fixed end: exactly one chunk landed, nothing verified.
            assertEquals(ModelMirror.CHUNK, client.store.staged()!!.received)
            assertEquals("partial", client.store.staged()!!.state)
            val resumer = world.mirror()
            resumer.apkOverride = big
            resumer.bundleOverride = bundleBig
            client.updateRun(resumer, resumer)
            assertEquals("verified", client.store.staged()!!.state)
        }
    }

    private fun ByteArray.toHex(): String {
        val alphabet = "0123456789abcdef"
        return joinToString("") { b -> "${alphabet[(b.toInt() shr 4) and 15]}${alphabet[b.toInt() and 15]}" }
    }
}
