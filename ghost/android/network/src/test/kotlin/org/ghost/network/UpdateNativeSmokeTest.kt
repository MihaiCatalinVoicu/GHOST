package org.ghost.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The first real JVM call of the shipped native update surface (Phase 14 design §9.3, slice S6):
 * the host build of `ghost-client-net` (`-Dghost.net.native`, the Phase 12 slice-S2 discipline)
 * answers `UpdateNative` — the embedded chain parses, step 0 starts the epoch, the run's mirror
 * set builds and names the stagenet paths natively (Kotlin names no path constant, PM-D9/PM-D10),
 * the chunk step is the native 4 MiB of §7.2, and D19's bootstrap relay list decodes strictly.
 * Skipped, not failed, without the host library — the repo's standing native-test rule.
 */
class UpdateNativeSmokeTest {

    private fun assumeHostLibrary() = assumeTrue(
        "ghost-client-net host library not loaded (-Dghost.net.native)",
        System.getProperty("ghost.net.native") != null,
    )

    @Test
    fun embeddedChainIsAParseableStagenetGhrc() {
        assumeHostLibrary()
        val chain = UpdateNative.embeddedChain()
        // GHRC v1 (§4.4): "GHRC" ‖ version ‖ network ‖ first_version u32 ‖ count u16 ‖ roots.
        assertTrue("the embedded chain is a non-empty GHRC", chain.size > 6)
        assertArrayEquals(
            "GHRC".toByteArray(Charsets.US_ASCII),
            chain.copyOfRange(0, 4),
        )
        assertEquals(1, chain[4].toInt() and 0xff)
        assertEquals(2, chain[5].toInt() and 0xff) // stagenet
        val count = (chain[10].toInt() and 0xff) shl 8 or (chain[11].toInt() and 0xff)
        assertTrue("at least one root in the chain", count >= 1)
    }

    @Test
    fun theUpdateSurfaceAnswersStartMirrorSetPathsAndRelays() {
        assumeHostLibrary()
        val chain = UpdateNative.embeddedChain()

        // §7.4 step 0, the minimal real sequence: the first start of a fresh install.
        val stored = UpdateNative.start(ByteArray(0), chain, installed = 1)
        assertTrue("nativeStart returns the stored blob", stored.isNotEmpty())

        // §7.8: the run's mirror set, from the stored state, the day and the run's draw.
        val draw = ByteArray(32) { it.toByte() }
        val set = UpdateNative.mirrorSet(
            stored = stored,
            embeddedChain = chain,
            noChannel = false,
            dayTrusted = true,
            day = 20_000,
            draw = draw,
            hasOffer = false,
            offerSha256 = ByteArray(0),
            offerLength = 0L,
        )
        try {
            // The network segment is the native "stagenet" (§7.2's <net>): the path is built
            // entirely on the native side; Kotlin can name neither a segment nor a file.
            assertEquals(
                "/ghost/v1/stagenet/current.ghrb",
                UpdateNative.mirrorPath(set, TorMirrorTransport.KIND_BUNDLE, 0),
            )
            assertEquals(4L * 1024 * 1024, UpdateNative.apkChunkStep())

            // Without an offer, an APK chunk path is refused before anything is named
            // (the native side holds no apk_sha256 to build the path from).
            assertThrows(NetworkException::class.java) {
                UpdateNative.mirrorPath(set, TorMirrorTransport.KIND_APK_CHUNK, 0)
            }
        } finally {
            UpdateNative.mirrorSetClose(set)
        }

        // D19's bootstrap: the committed, gate-checked relay directory, decoded strictly.
        val relays = UpdateNative.bootstrapRelays()
        assertTrue("the bootstrap relay directory is not empty", relays.isNotEmpty())
        relays.forEach {
            assertEquals(56, it.host.length)
            assertTrue(it.port > 0)
            assertEquals(16, it.operatorId.size)
        }
    }
}
