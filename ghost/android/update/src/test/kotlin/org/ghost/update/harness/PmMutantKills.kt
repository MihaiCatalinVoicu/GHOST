package org.ghost.update.harness

import org.ghost.network.UpdateNative
import org.ghost.update.UpdateCodec
import org.ghost.update.UpdateStateStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import java.math.BigInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The killable PM-D rows (Phase 14 design §11.3) — the ones that do not need the job scheduler
 * or the wire. Each is an oracle assertion about the shipped binary: the named mutation's
 * prediction diverges from what the real surface does.
 *
 * - PM-D7 (one rollout bucket across releases): the fixture manifest holds two releases under
 *   one reused salt; the per-release buckets differ, so a single shared bucket is not what the
 *   core computes.
 * - PM-D9 (the native fetch taking a path or range from Kotlin): the closed JNI surface is
 *   asserted — Kotlin can name neither a path nor a range; the native side builds both.
 * - PM-D13 (the bucket hashing the salt without the APK's SHA-256): the fixture's permille sits
 *   between the with-APK bucket and the without-APK prediction; the native offer must follow
 *   the with-APK rule.
 *
 * PM-D1/2/6/8/10/11/12 are scheduler-held (the job model lands later); PM-D3/4/5 are seam-held
 * (headers and the roots path never cross the byte seam).
 */
internal object PmMutantKills {

    class Entry(val name: String, val run: () -> Unit)

    val entries: List<Entry> = listOf(
        Entry("PM-D7") { oneBucketAcrossReleases() },
        Entry("PM-D9") { nativeFetchBuildsPathAndRange() },
        Entry("PM-D13") { bucketWithoutApkHash() },
    )

    /** §7.4 step 8's bucket: ⌊1000 · BE64(HMAC-SHA256(key, domain ‖ apk ‖ salt)[0..8]) / 2^64⌋. */
    private fun bucket(key: ByteArray, withApk: ByteArray?, salt: ByteArray): Int {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        mac.update("ghost/v1/rollout".toByteArray())
        if (withApk != null) mac.update(withApk)
        mac.update(salt)
        val be64 = BigInteger(1, mac.doFinal().copyOfRange(0, 8))
        return be64.multiply(BigInteger.valueOf(1000)).shiftRight(64).toInt()
    }

    private fun oneBucketAcrossReleases() {
        World("pm-d7", seed = 90).use { w ->
            val f = w.fixtures
            val b2 = bucket(f.rolloutKey, f.apkSha256, f.bucketSalt)
            val b3 = bucket(f.rolloutKey, f.apkSwapSha256, f.bucketSalt)
            assertEquals("the JVM replay must reproduce the fixture's buckets", f.rolloutBuckets, b2 to b3)
            assertTrue("one bucket across releases is not what the core computes (PM-D7)", b2 != b3)
        }
    }

    private fun bucketWithoutApkHash() {
        World("pm-d13", seed = 91).use { w ->
            val f = w.fixtures
            // The fixture's permille is one above the with-APK bucket of version 2; the
            // without-APK prediction does not pass it. Seed the client with the fixture's
            // rollout key, accept the bucket manifest, and ask the native offer.
            val client = w.client(installed = 1, sdk = 29)
            val stored = w.config.native.start(ByteArray(0), f.chain, 1)
            val facts = UpdateCodec.decode(stored, f.network)
            UpdateStateStore(client.db).insertFirst(facts, f.rolloutKey)
            client.updateRun(serving(w, f.doc("bundle-bucket.ghrb")), serving(w, f.doc("bundle-bucket.ghrb")))
            val loaded = client.store.load()!!
            val offer = w.config.native.offer(
                loaded.blob, 1, 29, loaded.rolloutKey, true, w.clock.day(),
            )
            assertTrue(
                "the with-APK bucket must pass (PM-D13's mutant predicts no offer), got $offer",
                offer is UpdateNative.Offer.Update && offer.versionCode == 2,
            )
            assertTrue(
                "the without-APK prediction must disagree",
                bucket(f.rolloutKey, null, f.bucketSalt) >= f.rolloutPermille2,
            )
        }
    }

    private fun nativeFetchBuildsPathAndRange() {
        World("pm-d9", seed = 92).use { w ->
            val client = w.client(installed = 1, sdk = 29)
            client.firstStart()
            val loaded = client.store.load()!!
            val set = w.config.native.mirrorSet(
                loaded.blob, w.fixtures.chain, false, true, w.clock.day(), ByteArray(32), false, ByteArray(0), 0,
            )
            try {
                // The bundle path is the native <net>/current.ghrb; the chunk step is the
                // native 4 MiB: Kotlin supplied neither. The public fetch entries take no
                // path or range parameter at all — PM-D9's mutation has no surface to live on.
                assertEquals(
                    "/ghost/v1/stagenet/current.ghrb",
                    UpdateNative.mirrorPath(set, 0, 0),
                )
                assertEquals(4L * 1024 * 1024, UpdateNative.apkChunkStep())
                // The public fetch entries carry no path (a String or byte array) and no
                // range start beyond the chunk index the native side itself steps by 4 MiB —
                // the native side builds both (PM-D9). The exact numeric widths are the
                // closed surface's own business; the kill is the absence of a path carrier.
                for (name in listOf("fetchBundle", "fetchApkChunk")) {
                    val fetch = org.ghost.network.TorMirrorTransport::class.java.methods.first {
                        it.name == name
                    }
                    assertTrue(
                        "no path parameter reaches the native fetch (PM-D9, $name): " +
                            fetch.parameterTypes.joinToString { it.simpleName },
                        fetch.parameterTypes.none {
                            it == String::class.java || it == ByteArray::class.java
                        },
                    )
                }
            } finally {
                w.config.native.mirrorSetClose(set)
            }
        }
    }

    private fun serving(world: World, bundle: ByteArray): ModelMirror {
        val m = world.mirror(MirrorMode.EQUIVOCATE)
        m.equivocateBundle = bundle
        return m
    }
}
