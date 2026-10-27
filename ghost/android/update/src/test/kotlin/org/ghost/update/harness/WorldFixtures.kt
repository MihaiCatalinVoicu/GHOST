package org.ghost.update.harness

import org.ghost.network.NetworkException
import java.util.Properties

/** One hex-decoded SHA-256 from the fixture meta. */
internal fun sha256Hex(hex: String): ByteArray {
    require(hex.length == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' }) { "not lowercase sha256 hex: $hex" }
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

/** Deterministic 32 bytes from [label] (world draws: the run's draw, rollout keys). */
internal fun sha256Bytes(label: String): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest(label.toByteArray())

/** Hex-decoded bytes of any even-length lowercase hex string (operator ids, hashes). */
internal fun hexBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0 && hex.all { it in '0'..'9' || it in 'a'..'f' }) { "not lowercase hex: $hex" }
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

/** Deterministic 64-bit draw from [label]. */
internal fun sha256Long(label: String): Long {
    val d = sha256Bytes(label)
    var v = 0L
    for (i in 0 until 8) v = (v shl 8) or (d[i].toLong() and 0xff)
    return v
}

/**
 * The committed fixture world the model mirrors serve (Phase 14 design §11.2; built once by
 * `test-harness/update/gen-fixtures.sh`, regenerated from throwaway keys — never real ceremony
 * material). The host `ghost_client_net` embeds the real stagenet chain, so the world's clients
 * start their epoch from THIS chain through `UpdateNative.start` (§7.4 step 0 with a fixture
 * embedded chain): the stored facts' trusted root is then the fixture root the manifest is
 * signed under, and every later native call is over the shipped library, unmodified.
 *
 * Beside the benign documents, one bundle per hostile mode of §11.2 (each a real ops product or
 * a documented byte-level surgery on the committed formats), plus the rotation chain (root v2)
 * and the stolen-release-key manifest.
 */
internal class WorldFixtures private constructor(
    /** chain.ghrc: the fixture GHRC (one root, network 2). */
    val chain: ByteArray,
    val network: Int,
    /** bundle.ghrb: the fresh current bundle (chain + manifest + proof). */
    val bundle: ByteArray,
    /** stale-bundle.ghrb: the same release under an expired manifest. */
    val staleBundle: ByteArray,
    /** The fresh manifest's SHA-256 (what ACCEPT must store). */
    val manifestSha256: ByteArray,
    /** The offered APK's SHA-256 (the staged row's key and the mirror's APK path name). */
    val apkSha256: ByteArray,
    /** app-v2.apk: the real apksigner-signed fixture APK (version_code 2). */
    val apk: ByteArray,
    /** The fixed window the world's clock lives in (epoch days; from meta.properties). */
    val issuedDay: Int,
    val notAfterDay: Int,
    /** The trusted root's anchor mirrors (canonical `<56>.onion:<port>` + operator hex), the
     *  draw's input (§7.8) — the slot-to-mirror mapping of the draw-mutant worlds. */
    val anchors: List<Pair<String, String>>,
    /** The rollout oracle (PM-D7/PM-D13): the fixed test key, the per-release buckets and the
     *  without-APK-hash bucket, and version 2's permille (one above its bucket). */
    val rolloutKey: ByteArray,
    val rolloutBuckets: Pair<Int, Int>,
    val rolloutSharedBucket: Int,
    val rolloutPermille2: Int,
    /** The reused rollout salt (PM-D7/PM-D13) and the second release's APK hash. */
    val bucketSalt: ByteArray,
    val apkSwapSha256: ByteArray,
    /** Every other committed document, by resource name (loaded lazily by the modes). */
    private val resources: Map<String, ByteArray>,
) {
    /** A committed document (bundle, manifest, APK variant) by its resource file name. */
    fun doc(name: String): ByteArray =
        resources[name] ?: throw IllegalArgumentException("unknown fixture document $name")

    companion object {
        private val RESOURCE_NAMES = listOf(
            "bundle-eq-a.ghrb", "bundle-eq-b.ghrb",
            "bundle-wrongproof.ghrb", "bundle-nowproof.ghrb",
            "bundle-mainnet.ghrb", "bundle-wrongroot.ghrb",
            "bundle-ff.ghrb", "bundle-replay.ghrb", "bundle-floor.ghrb", "bundle-relabel.ghrb",
            "bundle-big.ghrb", "bundle-2.ghrb", "bundle-stolen.ghrb",
            "bundle-2bad.ghrb", "bundle-flipsig.ghrb",
            "bundle-badindex.ghrb", "bundle-badhead.ghrb", "bundle-othermsg.ghrb",
            "bundle-nocosig.ghrb", "bundle-unknownwit.ghrb",
            "bundle-badrootproof.ghrb", "bundle-xroot.ghrb", "bundle-bucket.ghrb",
            "manifest-eq-a.ghrm", "manifest-eq-b.ghrm", "manifest-replay.ghrm",
            "manifest-relabel.ghrm", "manifest-stale.ghrm", "manifest-1.ghrm", "manifest-2.ghrm",
            "manifest-stolen.ghrm", "manifest-xroot.ghrm", "chain2.ghrc",
            "app-v2-swap.apk", "app-v2-extra.apk", "app-v2-big.apk",
        )

        fun load(): WorldFixtures {
            val meta = Properties()
            java.io.InputStreamReader(
                requireNotNull(WorldFixtures::class.java.getResourceAsStream("/update-world/meta.properties")) {
                    "update-world fixtures missing from the test resources"
                },
                Charsets.US_ASCII,
            ).use { meta.load(it) }
            val chain = resource("chain.ghrc")
            // The same rule as UpdateEngine.networkOf (§4.4's GHRC header): magic ‖ version ‖
            // network, the network byte at offset 5.
            if (chain.size < 6 || chain[0] != 'G'.code.toByte() || chain[1] != 'H'.code.toByte() ||
                chain[2] != 'R'.code.toByte() || chain[3] != 'C'.code.toByte() || chain[4] != 1.toByte()
            ) {
                throw NetworkException("malformed_response")
            }
            return WorldFixtures(
                chain = chain,
                network = chain[5].toInt() and 0xff,
                bundle = resource("bundle.ghrb"),
                staleBundle = resource("stale-bundle.ghrb"),
                manifestSha256 = sha256Hex(meta.getProperty("manifest_sha256")),
                apkSha256 = sha256Hex(meta.getProperty("apk_sha256")),
                apk = resource("app-v2.apk"),
                issuedDay = meta.getProperty("issued_day").toInt(),
                notAfterDay = meta.getProperty("not_after_day").toInt(),
                anchors = listOf(
                    meta.getProperty("anchor.onion.0") to meta.getProperty("anchor.operator.0"),
                    meta.getProperty("anchor.onion.1") to meta.getProperty("anchor.operator.1"),
                ),
                rolloutKey = hexBytes(meta.getProperty("rollout.test_key")),
                rolloutBuckets = meta.getProperty("rollout.bucket2").toInt() to
                    meta.getProperty("rollout.bucket3").toInt(),
                rolloutSharedBucket = meta.getProperty("rollout.bucket.shared").toInt(),
                rolloutPermille2 = meta.getProperty("rollout.permille2").toInt(),
                bucketSalt = hexBytes(meta.getProperty("bucket.salt")),
                apkSwapSha256 = hexBytes(meta.getProperty("apk.swap_sha256")),
                resources = RESOURCE_NAMES.associateWith { resource(it) },
            )
        }

        internal fun resource(path: String): ByteArray =
            requireNotNull(WorldFixtures::class.java.getResourceAsStream("/update-world/$path")) { "missing fixture $path" }
                .use { it.readBytes() }
    }
}
