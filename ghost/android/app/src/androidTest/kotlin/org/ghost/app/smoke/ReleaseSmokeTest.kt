package org.ghost.app.smoke

import org.ghost.crypto.bridge.DmNative
import org.ghost.crypto.bridge.DmSessions
import org.ghost.device.DeviceRunner
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * **The release smoke test** (Phase 9 design §15.9 item 3, §21.13 point 5; slice S12).
 *
 * > On the release variant: load `libghost_client_net.so`, open a DM context and run one in-process
 * > Olm session between two in-memory state sets through `DmNative`; no transport. The loopback-relay
 * > session runs in the debug `androidTest` variant only. The release APK gains no
 * > transport-injection seam and no equivalence-test entry point (G-DM5 extended).
 *
 * `dm-emulator.yml` builds this test against the **R8-shrunk release** (`-Pghost.smoke.release=true`
 * sets `testBuildType = "release"`, signed with the build machine's throwaway debug key in that job
 * only), so what runs is the shipped library inside the shipped, shrunk APK: `DmNative` resolved by
 * its kept name, the facade's members that survived R8, and the shipped `libghost_client_net.so` —
 * nothing of the test library `ghost_dm_host`, and no transport at all. The two "devices" are two DM
 * contexts in this process.
 *
 * **Every member it calls must survive R8 in the release**, because nothing keeps a member for a
 * test: `DmNative.isAvailable`, the `DmSessions` functions and the result getters used below all have
 * production callers and are listed in the release `mapping.txt` (checked against the S12 build;
 * `usage.txt` is where a removed one would appear). **The same holds for the Kotlin standard
 * library** (first emulator run, design §22.32): AGP maps this APK's calls into it onto the
 * release's shrunk, renamed copy, so a stdlib function the release never calls is not there. The
 * first run died in `AppDeviceRunner.<init>` on `listOf(element)`; this file and `DeviceRunner`
 * call only JDK, Android, JUnit and kept `org.ghost` members, and inline stdlib functions.
 */
class ReleaseSmokeTest {

    private fun bytes(value: Int, size: Int) = ByteArray(size) { value.toByte() }

    private fun context(branch: Int): Long = requireNotNull(
        DmSessions.openContext(bytes(branch, 32), bytes(branch + 1, 32), bytes(branch + 2, 32))?.handle,
    ) { "ctxOpen" }

    @Test
    fun theShippedLibraryRunsOneOlmSessionThroughDmNative() {
        // Only members the release keeps (S12 review): `DmNative.loadFailure()` has no production
        // caller, R8 removes it from the shrunk release (usage.txt lists it), and calling it here —
        // in a message string that is built on every run — would end the test with
        // `NoSuchMethodError` before it asserted anything. `isAvailable()` has callers and is kept.
        assertTrue("libghost_client_net.so loads from the release APK", DmNative.isAvailable())
        val alice = context(0x11)
        val bob = context(0x21)
        try {
            val bobCard = requireNotNull(DmSessions.ownCard(bob, 0)) { "ownCard" }
            val aliceCard = requireNotNull(DmSessions.ownCard(alice, 0)) { "ownCard" }
            val generation = requireNotNull(DmSessions.bundleCreate(bob, 0, 2_870L, 0, 0x51_4f_00_01)) { "bundleCreate" }
            val contact = bytes(0x31, 16)
            // S2 (Phase 11) made function 3 validate the canonical L0 envelope (M labels, R-C4):
            // a raw body is refused NON_CANONICAL (surfacing as Encrypted.StateCorrupt) — the S12
            // era smoke predates that. Encode through the production content facade, exactly like
            // DmSessionsNativeTest's textL0 (DmContent has production callers, so R8 keeps it).
            val l0 = DmContent.encode(
                handle = alice,
                kind = DmContent.Kind.TEXT,
                messageId = bytes(0x41, 16),
                authorMinute = 0x10_00_00L + 0x41,
                minuteIndex = 0,
                timerCode = 0,
                timerVersion = 0,
                quoteRef = null,
                body = "smoke".toByteArray(),
            )
            assertTrue("l0Encode: $l0", l0 is DmContent.Encoded.Ok)
            l0 as DmContent.Encoded.Ok
            val outbound = DmSessions.outbound(alice, contact, bobCard.olmIdentity, generation.fallbackPublic, 100)
            assertTrue("outbound: $outbound", outbound is DmSessions.Outbound.Ok)
            outbound as DmSessions.Outbound.Ok
            val first = DmSessions.encrypt(alice, contact, DmSessions.StoredSlot(outbound.sessionId, outbound.stateEnv), l0.l0, 100)
            assertTrue("encrypt: $first", first is DmSessions.Encrypted.Ok)
            first as DmSessions.Encrypted.Ok
            val inbound = DmSessions.inbound(
                handle = bob,
                contactId = contact,
                genId = 0x51_4f_00_01,
                genSecretsEnv = generation.secretsEnv,
                genFallbackPublic = generation.fallbackPublic,
                expectedPeerIdentity = aliceCard.olmIdentity,
                l1 = first.l1,
                today = 100,
            )
            assertTrue("inbound: $inbound", inbound is DmSessions.Inbound.Ok)
            inbound as DmSessions.Inbound.Ok
            assertArrayEquals("the L0 record returns whole", l0.l0, inbound.plaintext)
            DeviceRunner.report("dm-smoke: release library, one in-process Olm session, no transport")
        } finally {
            DmSessions.closeContext(alice)
            DmSessions.closeContext(bob)
        }
    }
}

/**
 * The `:app` device suite: the release smoke test (§15.9 item 3). `Collections.singletonList`, not
 * `listOf`: the shrunk release has no `listOf(element)` for this test APK to call (DeviceRunner's
 * class note, design §22.32).
 */
class AppDeviceRunner : DeviceRunner(java.util.Collections.singletonList(ReleaseSmokeTest::class.java))
