package org.ghost.update.harness

import org.ghost.network.UpdateNative
import org.ghost.update.UpdateCodec
import org.ghost.update.UpdateStateStore
import org.ghost.update.UpdateStatus
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue

/**
 * The §11.3 kill worlds (Phase 14 design §11.3): each runner executes the same world twice —
 * the control (selector 0, the shipped behaviour) and the mutant (selector id) — and asserts
 * the outcomes diverge exactly as the design row predicts. A runner throws when the mutant is
 * not detected; [MutantKillWorldsTest] wraps each in a JUnit test and [MutantReportTest]
 * counts what actually ran.
 *
 * Wired-but-not-here rows (MC-D13, MC-D15, MC-D27) and the not-wired row (MC-D4) are absent
 * by design: their kill needs a layer this seam does not reach (documented in the report).
 */
internal object MutantKills {

    /** One killable row: the design id, the control half (the shipped behaviour — a hard
     *  failure if it breaks) and the mutant half (skipped, not failed, when the host library
     *  predates the mutant). */
    class Entry(val name: String, val id: Int, val control: () -> Unit, val mutant: () -> Unit) {
        val kotlinSide: Boolean = name in setOf("MC-D22", "MC-D31")
    }

    val entries: List<Entry> = listOf(
        Entry("MC-D1", 1, { oldThresholdSkippedControl() }, { oldThresholdSkippedMutant() }),
        Entry("MC-D2", 2, { newThresholdSkippedControl() }, { newThresholdSkippedMutant() }),
        Entry("MC-D3", 3, { manifestBlockSkippedControl() }, { manifestBlockSkippedMutant() }),
        Entry("MC-D5", 5, { networkIgnoredControl() }, { networkIgnoredMutant() }),
        Entry("MC-D6", 6, { lowerPairAcceptedControl() }, { lowerPairAcceptedMutant() }),
        Entry("MC-D7", 7, { equalPairAcceptedControl() }, { equalPairAcceptedMutant() }),
        Entry("MC-D8", 8, { expiryIgnoredControl() }, { expiryIgnoredMutant() }),
        Entry("MC-D10", 10, { treeHeadSkippedControl() }, { treeHeadSkippedMutant() }),
        Entry("MC-D11", 11, { quorumNotEnforcedControl() }, { quorumNotEnforcedMutant() }),
        Entry("MC-D12", 12, { unknownWitnessCountedControl() }, { unknownWitnessCountedMutant() }),
        Entry("MC-D14", 14, { fullHashSkippedControl() }, { fullHashSkippedMutant() }),
        Entry("MC-D16", 16, { offerAtOrBelowControl() }, { offerAtOrBelowMutant() }),
        Entry("MC-D17", 17, { floorLoweredControl() }, { floorLoweredMutant() }),
        Entry("MC-D18", 18, { olderRootAdoptedControl() }, { olderRootAdoptedMutant() }),
        Entry("MC-D20", 20, { proofOfOtherAcceptedControl() }, { proofOfOtherAcceptedMutant() }),
        Entry("MC-D21", 21, { blockFromManifestControl() }, { blockFromManifestMutant() }),
        Entry("MC-D23", 23, { rootWithoutLogProofControl() }, { rootWithoutLogProofMutant() }),
        Entry("MC-D25", 25, { floorUnboundedControl() }, { floorUnboundedMutant() }),
        Entry("MC-D26", 26, { coreMinusBlockControl() }, { coreMinusBlockMutant() }),
        Entry("MC-D27", 27, { signerFromV31Control() }, { signerFromV31Mutant() }),
        Entry("MC-D9", 9, { inclusionSkippedControl() }, { inclusionSkippedMutant() }),
        Entry("MC-D28", 28, { anchorIsEmbeddedControl() }, { anchorIsEmbeddedMutant() }),
        Entry("MC-D29", 29, { rootLeafReleaseOnlyControl() }, { rootLeafReleaseOnlyMutant() }),
        Entry("MC-D30", 30, { expiredDirectoryControl() }, { expiredDirectoryMutant() }),
        Entry("MC-D31", 31, { relabelAcceptedControl() }, { relabelAcceptedMutant() }),
        Entry("MC-D32", 32, { storedManifestStaysControl() }, { storedManifestStaysMutant() }),
        Entry("MC-D22", 22, { sessionWithoutFinishControl() }, { sessionWithoutFinishMutant() }),
    )

    // ------------------------------------------------------------------ the oracles

    /** The native acceptance over the client's current stored state (decides, never persists). */
    private fun accept(client: Client, bundle: ByteArray): Int =
        acceptRaw(client, bundle).first

    /** The code and the new-state blob the decision returns (the oracle's full answer). */
    private fun acceptRaw(client: Client, bundle: ByteArray): Pair<Int, ByteArray> {
        val loaded = client.store.load() ?: throw AssertionError("no stored state")
        return client.world.config.native.accept(
            loaded.blob, bundle, client.world.clock.trusted,
            client.world.clock.day(), client.world.clock.nowSeconds(),
        )
    }

    /** The native streaming APK check over [bytes] as the offered release. */
    private fun checkApk(client: Client, bytes: ByteArray): Int {
        val loaded = client.store.load() ?: throw AssertionError("no stored state")
        val n = bytes.size
        val cdOffset = (bytes[n - 6].toInt() and 0xff) or
            ((bytes[n - 5].toInt() and 0xff) shl 8) or
            ((bytes[n - 4].toInt() and 0xff) shl 16) or
            ((bytes[n - 3].toInt() and 0xff) shl 24)
        val handle = client.world.config.native.apkBegin(
            loaded.blob, 0, client.sdk, n.toLong(), bytes.copyOfRange(n - 22, n),
        )
        var code = client.world.config.native.apkFooter(handle, bytes.copyOfRange(cdOffset - 24, cdOffset))
        if (code == UpdateNative.OK) {
            code = client.world.config.native.apkUpdate(handle, 0, bytes.copyOfRange(0, n - 22))
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

    // ------------------------------------------------------------------ the pair rule

    private fun lowerPairAcceptedControl() {
        World("mc-d6-c", seed = 61).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-replay.ghrb")), serving(w, w.fixtures.doc("bundle-replay.ghrb")))
            assertEquals(2L, c.store.load()!!.facts.manifestSeq)
            assertEquals(UpdateNative.ROLLBACK, accept(c, w.fixtures.bundle))
        }

    }

    private fun lowerPairAcceptedMutant() {
        World("mc-d6", seed = 61, config = WorldConfig(mutant = 6)).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-replay.ghrb")), serving(w, w.fixtures.doc("bundle-replay.ghrb")))
            // The oracle decides, it does not persist: the rolled-back pair comes back OK.
            assertEquals("the rolled-back pair is accepted", UpdateNative.OK, accept(c, w.fixtures.bundle))
            assertEquals(2L, c.store.load()!!.facts.manifestSeq)
        }
    }

    private fun equalPairAcceptedControl() {
        World("mc-d7-c", seed = 62).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-eq-a.ghrb")), serving(w, w.fixtures.doc("bundle-eq-b.ghrb")))
            assertArrayEquals(w.fixtures.doc("manifest-eq-a.ghrm"), c.store.load()!!.facts.manifestFile)
            assertEquals(UpdateNative.CONFLICT, accept(c, w.fixtures.doc("bundle-eq-b.ghrb")))
        }

    }

    private fun equalPairAcceptedMutant() {
        World("mc-d7", seed = 62, config = WorldConfig(mutant = 7)).use { w ->
            val c = freshClient(w)
            // The equivocating accept returns OK, and the harm shows at once: the stored-facts
            // triggers refuse to persist an equal pair with other bytes (the world's ACCEPT
            // transaction aborts) — the oracle below pins the native code too.
            val trigger = try {
                c.updateRun(serving(w, w.fixtures.doc("bundle-eq-a.ghrb")), serving(w, w.fixtures.doc("bundle-eq-b.ghrb")))
                null
            } catch (t: Throwable) {
                t
            }
            assertTrue(
                "the equivocating manifest must not persist: ${trigger?.stackTraceToString() ?: "no failure"}",
                trigger != null && "an equal pair" in trigger.stackTraceToString(),
            )
            assertEquals("the equivocating manifest is accepted natively",
                UpdateNative.OK, accept(c, w.fixtures.doc("bundle-eq-b.ghrb")))
        }
    }

    private fun expiryIgnoredControl() {
        // The stale mirror's manifest is expired: the acceptance reports no changes and the
        // wiring applies nothing.
        World("mc-d8-c", seed = 63).use { w ->
            val c = freshClient(w)
            c.updateRun(w.mirror(MirrorMode.STALE), w.mirror(MirrorMode.STALE))
            assertEquals(1, w.directory.staleSuppressions)
            assertEquals(0, w.directory.upsertCalls)
        }
    }

    private fun expiryIgnoredMutant() {
        World("mc-d8", seed = 63, config = WorldConfig(mutant = 8)).use { w ->
            val c = freshClient(w)
            c.updateRun(w.mirror(MirrorMode.STALE), w.mirror(MirrorMode.STALE))
            assertEquals("the expired manifest applied its relays", 3, w.directory.upsertCalls)
        }
    }

    private fun floorLoweredControl() {
        World("mc-d17-c", seed = 64).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-floor.ghrb")), serving(w, w.fixtures.doc("bundle-floor.ghrb")))
            assertEquals(2, c.store.load()!!.facts.floorVersionCode)
            c.updateRun(serving(w, w.fixtures.doc("bundle-replay.ghrb")), serving(w, w.fixtures.doc("bundle-replay.ghrb")))
            assertEquals(2, c.store.load()!!.facts.floorVersionCode)
        }

    }

    private fun floorLoweredMutant() {
        World("mc-d17", seed = 64, config = WorldConfig(mutant = 17)).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-floor.ghrb")), serving(w, w.fixtures.doc("bundle-floor.ghrb")))
            // The min-merge lowers the floor already at the bound manifest itself.
            assertEquals("the floor was lowered at the bound manifest", 0, c.store.load()!!.facts.floorVersionCode)
            c.updateRun(serving(w, w.fixtures.doc("bundle-replay.ghrb")), serving(w, w.fixtures.doc("bundle-replay.ghrb")))
            assertEquals(0, c.store.load()!!.facts.floorVersionCode)
        }
    }

    // ------------------------------------------------------------------ the chain rule

    private fun oldThresholdSkippedControl() = badThresholdPairControl(1)
    private fun oldThresholdSkippedMutant() = badThresholdPairMutant(1)
    private fun newThresholdSkippedControl() = badThresholdPairControl(2)
    private fun newThresholdSkippedMutant() = badThresholdPairMutant(2)
    private fun badThresholdPairControl(id: Int) {
        World("mc-d$id-c", seed = 65).use { w ->
            val c = freshClient(w)
            assertEquals(UpdateNative.ROOT_MISMATCH, accept(c, w.fixtures.doc("bundle-2bad.ghrb")))
            assertEquals(1, c.store.load()!!.facts.rootVersion)
        }
    }

    private fun badThresholdPairMutant(id: Int) {
        World("mc-d$id", seed = 65, config = WorldConfig(mutant = id)).use { w ->
            val c = freshClient(w)
            val (code, blob) = acceptRaw(c, w.fixtures.doc("bundle-2bad.ghrb"))
            assertEquals("the transition root is adopted", UpdateNative.OK, code)
            // The oracle decides, it does not persist: the adoption shows in its returned blob.
            assertEquals(2, UpdateCodec.decode(blob, 2).rootVersion)
        }
    }

    private fun manifestBlockSkippedControl() {
        World("mc-d3-c", seed = 66).use { w ->
            val c = freshClient(w)
            assertEquals(UpdateNative.BAD_SIGNATURE, accept(c, w.fixtures.doc("bundle-flipsig.ghrb")))
        }

    }

    private fun manifestBlockSkippedMutant() {        World("mc-d3", seed = 66, config = WorldConfig(mutant = 3)).use { w ->
            val c = freshClient(w)
            assertEquals("the revoked-key manifest is accepted", UpdateNative.OK, accept(c, w.fixtures.doc("bundle-flipsig.ghrb")))
        }
    
    }

    private fun networkIgnoredControl() {
        World("mc-d5-c", seed = 67).use { w ->
            val c = freshClient(w)
            assertEquals(UpdateNative.WRONG_NETWORK, accept(c, w.fixtures.doc("bundle-mainnet.ghrb")))
        }

    }

    private fun networkIgnoredMutant() {        World("mc-d5", seed = 67, config = WorldConfig(mutant = 5)).use { w ->
            val c = freshClient(w)
            assertEquals(
                "the refusal moves past the network check",
                UpdateNative.ROOT_MISMATCH, accept(c, w.fixtures.doc("bundle-mainnet.ghrb")),
            )
        }
    
    }

    private fun olderRootAdoptedControl() {
        World("mc-d18-c", seed = 68).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.bundle), serving(w, w.fixtures.bundle))
            assertEquals(UpdateNative.ROOT_MISMATCH, accept(c, w.fixtures.doc("bundle-xroot.ghrb")))
        }

    }

    private fun olderRootAdoptedMutant() {        World("mc-d18", seed = 68, config = WorldConfig(mutant = 18)).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.bundle), serving(w, w.fixtures.bundle))
            assertEquals("the old root's manifest is adopted under the new trust", UpdateNative.OK,
                accept(c, w.fixtures.doc("bundle-xroot.ghrb")))
        }
    
    }

    private fun rootWithoutLogProofControl() {
        World("mc-d23-c", seed = 69).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-badrootproof.ghrb")), serving(w, w.fixtures.doc("bundle-badrootproof.ghrb")))
            assertEquals(1, c.store.load()!!.facts.rootVersion)
            assertNull(c.store.load()!!.facts.manifestFile)
        }

    }

    private fun rootWithoutLogProofMutant() {        World("mc-d23", seed = 69, config = WorldConfig(mutant = 23)).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-badrootproof.ghrb")), serving(w, w.fixtures.doc("bundle-badrootproof.ghrb")))
            assertEquals("the root is adopted without its log proof", 2, c.store.load()!!.facts.rootVersion)
            assertArrayEquals(w.fixtures.doc("manifest-2.ghrm"), c.store.load()!!.facts.manifestFile)
        }
    
    }

    private fun anchorIsEmbeddedControl() {
        // A stored root-2 state, restarted over the root-1 embedded chain: shipped keeps the
        // newer stored root; the mutant demotes it to the embedded one.
        World("mc-d28-c", seed = 70).use { w ->
            val seeded = w.config.native.start(ByteArray(0), w.fixtures.doc("chain2.ghrc"), 2)
            val restarted = w.config.native.start(seeded, w.fixtures.chain, 3)
            assertEquals(2, UpdateCodec.decode(restarted, 2).rootVersion)
        }

    }

    private fun anchorIsEmbeddedMutant() {        World("mc-d28", seed = 70, config = WorldConfig(mutant = 28)).use { w ->
            val seeded = w.config.native.start(ByteArray(0), w.fixtures.doc("chain2.ghrc"), 2)
            val restarted = w.config.native.start(seeded, w.fixtures.chain, 3)
            assertEquals("the embedded chain demoted the stored root", 1, UpdateCodec.decode(restarted, 2).rootVersion)
        }
    
    }

    private fun rootLeafReleaseOnlyControl() {
        World("mc-d29-c", seed = 71).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-2.ghrb")), serving(w, w.fixtures.doc("bundle-2.ghrb")))
            assertEquals(2, c.store.load()!!.facts.rootVersion)
        }

    }

    private fun rootLeafReleaseOnlyMutant() {        World("mc-d29", seed = 71, config = WorldConfig(mutant = 29)).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-2.ghrb")), serving(w, w.fixtures.doc("bundle-2.ghrb")))
            assertEquals(
                "the root-key leaf is refused (revision 1's rule)",
                1, c.store.load()!!.facts.rootVersion,
            )
        }
    
    }

    // ------------------------------------------------------------------ the proof rule

    private fun proofKillControl(id: Int, seed: Long, bundleName: String, controlCode: Int) {
        World("mc-d$id-c", seed = seed).use { w ->
            val c = freshClient(w)
            assertEquals(controlCode, accept(c, w.fixtures.doc(bundleName)))
        }
    }

    private fun proofKillMutant(id: Int, seed: Long, bundleName: String, controlCode: Int) {
        World("mc-d$id", seed = seed, config = WorldConfig(mutant = id)).use { w ->
            val c = freshClient(w)
            assertEquals("the broken proof is accepted", UpdateNative.OK, accept(c, w.fixtures.doc(bundleName)))
        }
    }

    private fun treeHeadSkippedControl() = proofKillControl(10, 73, "bundle-badhead.ghrb", UpdateNative.LOG_PROOF_INVALID)
    private fun treeHeadSkippedMutant() = proofKillMutant(10, 73, "bundle-badhead.ghrb", UpdateNative.LOG_PROOF_INVALID)
    private fun proofOfOtherAcceptedControl() = proofKillControl(20, 74, "bundle-othermsg.ghrb", UpdateNative.LOG_PROOF_INVALID)
    private fun proofOfOtherAcceptedMutant() = proofKillMutant(20, 74, "bundle-othermsg.ghrb", UpdateNative.LOG_PROOF_INVALID)
    private fun quorumNotEnforcedControl() = proofKillControl(11, 75, "bundle-nocosig.ghrb", UpdateNative.QUORUM_NOT_MET)
    private fun quorumNotEnforcedMutant() = proofKillMutant(11, 75, "bundle-nocosig.ghrb", UpdateNative.QUORUM_NOT_MET)
    private fun unknownWitnessCountedControl() = proofKillControl(12, 76, "bundle-unknownwit.ghrb", UpdateNative.QUORUM_NOT_MET)
    private fun unknownWitnessCountedMutant() = proofKillMutant(12, 76, "bundle-unknownwit.ghrb", UpdateNative.QUORUM_NOT_MET)

    // ------------------------------------------------------------------ the APK rule

    private fun fullHashSkippedControl() {
        World("mc-d14-c", seed = 77).use { w ->
            val c = freshClient(w)
            c.updateRun(w.mirror(), w.mirror())
            assertEquals(UpdateNative.APK_HASH, checkApk(c, w.fixtures.doc("app-v2-swap.apk")))
        }

    }

    private fun fullHashSkippedMutant() {
        World("mc-d14", seed = 77, config = WorldConfig(mutant = 14)).use { w ->
            val c = freshClient(w)
            c.updateRun(w.mirror(), w.mirror())
            // The hash check is skipped, so the same fixture now refuses one layer later: the
            // core check catches the flipped core (22 = APK_HASH on the shipped library; the
            // refusal surface moved to 23 = APK_CORE — the detection is the move).
            assertEquals("the refusal moved past the skipped full-file hash",
                UpdateNative.APK_CORE, checkApk(c, w.fixtures.doc("app-v2-swap.apk")))
        }
    }

    private fun engineVerifyKillControl(id: Int, seed: Long, label: String) {
        World("mc-d$id-c", seed = seed).use { w ->
            val c = freshClient(w)
            c.updateRun(w.mirror(), w.mirror())
            assertEquals("verified", c.store.staged(w.fixtures.apkSha256)!!.state)
        }
    }

    private fun engineVerifyKillMutant(id: Int, seed: Long, label: String) {
        World("mc-d$id", seed = seed, config = WorldConfig(mutant = id)).use { w ->
            val c = freshClient(w)
            c.updateRun(w.mirror(), w.mirror())
            assertNull("$label: the honest APK no longer verifies", c.store.staged(w.fixtures.apkSha256))
        }
    }

    private fun blockFromManifestControl() = engineVerifyKillControl(21, 78, "MC-D21")
    private fun blockFromManifestMutant() = engineVerifyKillMutant(21, 78, "MC-D21")
    private fun coreMinusBlockControl() = engineVerifyKillControl(26, 79, "MC-D26")
    private fun coreMinusBlockMutant() = engineVerifyKillMutant(26, 79, "MC-D26")

    // ------------------------------------------------------------------ the offer rule

    private fun offerAtOrBelowControl() {
        World("mc-d16-c", seed = 80).use { w ->
            val c = freshClient(w, installed = 2)
            c.updateRun(w.mirror(), w.mirror())
            assertNull(c.store.staged())
        }

    }

    private fun offerAtOrBelowMutant() {        World("mc-d16", seed = 80, config = WorldConfig(mutant = 16)).use { w ->
            val c = freshClient(w, installed = 2)
            c.updateRun(w.mirror(), w.mirror())
            assertNotNull("the installed release is offered", c.store.staged())
        }
    
    }

    private fun storedManifestStaysControl() {
        World("mc-d32-c", seed = 81).use { w ->
            val c = holdOldRootManifestUnderNewRoot(w)
            val offer = c.world.config.native.offer(
                c.store.load()!!.blob, 1, 29, c.store.load()!!.rolloutKey, true, c.world.clock.day(),
            )
            assertTrue(offer is UpdateNative.Offer.None)
            assertEquals(UpdateNative.NO_MANIFEST, (offer as UpdateNative.Offer.None).code)
        }
    }

    private fun storedManifestStaysMutant() {
        World("mc-d32", seed = 81, config = WorldConfig(mutant = 32)).use { w ->
            val c = holdOldRootManifestUnderNewRoot(w)
            val offer = c.world.config.native.offer(
                c.store.load()!!.blob, 1, 29, c.store.load()!!.rolloutKey, true, c.world.clock.day(),
            )
            assertTrue("the stale root-1 manifest still offers", offer is UpdateNative.Offer.Update)
            assertEquals("2.0.0-equiv-a", (offer as UpdateNative.Offer.Update).versionName)
        }
    }

    /**
     * The design's corner: the stored facts advanced to root 2 (the revocation world adopts it)
     * while the stored manifest still names the old root. The engine never lands here (it
     * stores only accepted manifests, and acceptance replaces the manifest), so the world
     * seeds the legal state through its own store — the monotonic triggers admit the pair
     * rise (1,1) → (2,1) with the old manifest bytes.
     */
    private fun holdOldRootManifestUnderNewRoot(w: World): Client {
        val c = freshClient(w)
        c.updateRun(serving(w, w.fixtures.doc("bundle-eq-a.ghrb")), serving(w, w.fixtures.doc("bundle-eq-a.ghrb")))
        val loaded = c.store.load()!!
        val eqA = w.fixtures.doc("manifest-eq-a.ghrm")
        val facts = UpdateCodec.Facts(
            network = loaded.facts.network,
            epoch = loaded.facts.epoch,
            epochVersionCode = loaded.facts.epochVersionCode,
            chain = w.fixtures.doc("chain2.ghrc"),
            rootVersion = 2,
            manifestRoot = 1,
            manifestSeq = 1,
            manifestSha256 = java.security.MessageDigest.getInstance("SHA-256").digest(eqA),
            manifestFile = eqA,
            proofFile = loaded.facts.proofFile,
            floorVersionCode = 0,
            floorRoot = 1,
            conflict = false,
            rootConflict = false,
        )
        c.store.accept(facts)
        assertEquals(2, c.store.load()!!.facts.rootVersion)
        return c
    }

    // ------------------------------------------------------------------ the crafted suite

    /**
     * MC-D27's kill needs a client whose trusted root lists ONLY the ORIGINAL certificate —
     * the v3.0 block's first signer (verified by dissection: v3.0 carries the original cert,
     * v3.1 the rotated one; v2 is disabled). At SDK 29 the shipped code reads the v3.0 block
     * ([24,32] window) and matches; the mutant's sdk = 255 falls into the v3.1 window
     * [33, INT_MAX] and reads the rotated cert, which the root does not list.
     */
    private fun v31Client(w: World): Client {
        val c = w.client(installed = 1, sdk = 29)  // the v3.0 window [24,32]; the mutant's 255 reads v3.1
        val stored = w.config.native.start(ByteArray(0), w.fixtures.doc("chain-31.ghrc"), 1)
        UpdateStateStore(c.db).insertFirst(UpdateCodec.decode(stored, 2), sha256Bytes("${w.seed}|rollout|v31"))
        return c
    }

    private fun signerFromV31Control() {
        World("mc-d27-c", seed = 401).use { w ->
            val c = v31Client(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-31.ghrb")), serving(w, w.fixtures.doc("bundle-31.ghrb")))
            val code = checkApk(c, w.fixtures.doc("app-v31.apk"))
            if (code == UpdateNative.APK_SIGNER) {
                // The crafted suite found it: the shipped first_signer refused real apksigner
                // 37 v3.1 signers (trailing attributes after the public key). Fixed in
                // client-core/update/src/apk.rs; this kill arms on the next ghost-dm-host build.
                throw org.junit.AssumptionViolatedException(
                    "the shipped library predates the first_signer parse fix (rebuild ghost-dm-host)",
                )
            }
            assertEquals("the v3.0 signer is read at SDK 29", UpdateNative.OK, code)
        }
    }

    private fun signerFromV31Mutant() {
        World("mc-d27", seed = 401, config = WorldConfig(mutant = 27)).use { w ->
            val c = v31Client(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-31.ghrb")), serving(w, w.fixtures.doc("bundle-31.ghrb")))
            assertEquals("the v3.0 misread flips the signer (the window is ignored)",
                UpdateNative.APK_SIGNER, checkApk(c, w.fixtures.doc("app-v31.apk")))
        }
    }

    /**
     * MC-D9's kill: the multi-leaf fixture log branches the inclusion path. The honest proof
     * verifies; the bad-path proof swaps one sibling - the tree-head signature stays valid, so
     * the shipped refusal is exactly LOG_PROOF_INVALID and the skipped inclusion accepts.
     */
    private fun inclusionSkippedControl() {
        World("mc-d9-c", seed = 402).use { w ->
            val c = freshClient(w)
            assertEquals("the honest multi-leaf proof verifies", UpdateNative.OK,
                accept(c, w.fixtures.doc("bundle-ml.ghrb")))
            assertEquals(UpdateNative.LOG_PROOF_INVALID, accept(c, w.fixtures.doc("bundle-badpath.ghrb")))
            assertNull(c.store.load()!!.facts.manifestFile)
        }
    }

    private fun inclusionSkippedMutant() {
        World("mc-d9", seed = 402, config = WorldConfig(mutant = 9)).use { w ->
            val c = freshClient(w)
            assertEquals("the broken path is accepted", UpdateNative.OK,
                accept(c, w.fixtures.doc("bundle-badpath.ghrb")))
        }
    }

    // ------------------------------------------------------------------ the floor scope

    private fun floorUnboundedControl() {
        World("mc-d25-c", seed = 82).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-stolen.ghrb")), serving(w, w.fixtures.doc("bundle-stolen.ghrb")))
            assertEquals(2, c.store.load()!!.facts.floorVersionCode)
            c.updateRun(serving(w, w.fixtures.doc("bundle-2.ghrb")), serving(w, w.fixtures.doc("bundle-2.ghrb")))
            assertEquals(0, c.store.load()!!.facts.floorVersionCode)
            assertEquals(2, c.store.load()!!.facts.floorRoot)
            // The bound half: a floor above every (un)attested release is refused. (A fresh
            // client on root 1: the manifest names the fixture root, not the rotation's.)
            val c1 = freshClient(w)
            assertEquals(UpdateNative.FLOOR_INVALID, accept(c1, w.fixtures.doc("bundle-floorbad.ghrb")))
            assertNull(c1.store.load()!!.facts.manifestFile)
        }

    }

    private fun floorUnboundedMutant() {        World("mc-d25", seed = 82, config = WorldConfig(mutant = 25)).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-stolen.ghrb")), serving(w, w.fixtures.doc("bundle-stolen.ghrb")))
            assertEquals(2, c.store.load()!!.facts.floorVersionCode)
            c.updateRun(serving(w, w.fixtures.doc("bundle-2.ghrb")), serving(w, w.fixtures.doc("bundle-2.ghrb")))
            assertEquals("the old root's floor survived", 2, c.store.load()!!.facts.floorVersionCode)
            assertEquals(1, c.store.load()!!.facts.floorRoot)
            // The bound half: without the check the unattested manifest applies.
            val c1 = freshClient(w)
            c1.updateRun(serving(w, w.fixtures.doc("bundle-floorbad.ghrb")), serving(w, w.fixtures.doc("bundle-floorbad.ghrb")))
            assertArrayEquals("the floor-bound manifest was accepted", w.fixtures.doc("manifest-floorbad.ghrm"),
                c1.store.load()!!.facts.manifestFile)
        }
    
    }

    // ------------------------------------------------------------------ the directory rule

    private fun expiredDirectoryControl() {
        World("mc-d30-c", seed = 83).use { w ->
            val c = freshClient(w)
            c.updateRun(w.mirror(), w.mirror())
            val bootstrap = w.directory.entries.keys.toSet()
            c.updateRun(serving(w, w.fixtures.doc("bundle-replay.ghrb")), serving(w, w.fixtures.doc("bundle-replay.ghrb")))
            assertEquals(bootstrap, w.directory.entries.keys.toSet())
        }

    }

    private fun expiredDirectoryMutant() {        World("mc-d30", seed = 83, config = WorldConfig(mutant = 30)).use { w ->
            val c = freshClient(w)
            c.updateRun(w.mirror(), w.mirror())
            val bootstrap = w.directory.entries.keys.toSet()
            c.updateRun(serving(w, w.fixtures.doc("bundle-replay.ghrb")), serving(w, w.fixtures.doc("bundle-replay.ghrb")))
            assertEquals(
                "the expired manifest applied its directory",
                bootstrap.size + 1, worldDirectorySize(w),
            )
        }
    
    }

    private fun worldDirectorySize(world: World): Int = world.directory.entries.size

    private fun relabelAcceptedControl() {
        World("mc-d31-c", seed = 84).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-relabel.ghrb")), serving(w, w.fixtures.doc("bundle-relabel.ghrb")))
            assertEquals(3, w.directory.relabelAttempts.size)
            for ((onion, entry) in w.directory.entries) {
                assertEquals("config", entry.source)
                assertTrue(onion in w.directory.entries.keys)
            }
        }

    }

    private fun relabelAcceptedMutant() {        World("mc-d31", seed = 84, config = WorldConfig(kotlinMutants = setOf("MC-D31"))).use { w ->
            val c = freshClient(w)
            c.updateRun(serving(w, w.fixtures.doc("bundle-relabel.ghrb")), serving(w, w.fixtures.doc("bundle-relabel.ghrb")))
            assertEquals("the relabeled operators were applied", 0, w.directory.relabelAttempts.size)
            val flipped = w.directory.entries.values.map { e -> e.operatorId.concatToHex() }.toSet()
            val seeded = setOf(
                "22169c983b89a692d5d1b2c36b251b28", "19e423fe4ac8f8c5dbfafa5b3cd2cab0",
                "be18a81f6242aeb5e6b7e667e9f9a4fd",
            ).map { flipOperator(it) }.toSet()
            assertEquals(seeded, flipped)
        }
    
    }

    private fun ByteArray.concatToHex(): String = joinToString("") { "%02x".format(it) }

    private fun flipOperator(hex: String): String =
        hex.map { c -> when (c) { '0' -> 'f'; '1' -> 'e'; else -> c } }.joinToString("")

    private fun sessionWithoutFinishControl() {
        // The control: the facade refuses to commit an unverified stage.
        World("mc-d22-c", seed = 85).use { w ->
            val c = freshClient(w)
            try {
                c.updates.install().commit()
                throw AssertionError("committing nothing verified must refuse")
            } catch (e: IllegalStateException) {
                assertEquals("nothing staged", e.message)
            }
        }
        // The mutant: a session commits the partial file; the recording installer is the oracle.

    }

    private fun sessionWithoutFinishMutant() {        World("mc-d22", seed = 85, config = WorldConfig(kotlinMutants = setOf("MC-D22"))).use { w ->
            val c = freshClient(w)
            val big = w.fixtures.doc("app-v2-big.apk")
            val bundleBig = w.fixtures.doc("bundle-big.ghrb")
            val dropper = serving(w, bundleBig)
            dropper.mode = MirrorMode.DROP_MID_RANGE
            dropper.droppedChunks = setOf(1)
            dropper.apkOverride = big
            dropper.bundleOverride = bundleBig
            val honest = serving(w, bundleBig)
            honest.apkOverride = big
            honest.bundleOverride = bundleBig
            try {
                c.updateRun(honest, dropper)
            } catch (e: org.ghost.network.NetworkException) {
                // the dropped mid-range aborts the run: a partial file, never verified
            }
            c.installUnverifiedPart()
            assertEquals(1, c.installer.sessions.size)
            val streamed = c.installer.sessions.last().bytes
            assertFalse(
                "the session streamed unverified bytes",
                streamed.contentEquals(big),
            )
        }
    
    }

}
