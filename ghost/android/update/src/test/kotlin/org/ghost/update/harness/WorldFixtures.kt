package org.ghost.update.harness

import org.ghost.network.NetworkException
import java.security.MessageDigest

/** One hex-decoded SHA-256 from the fixture meta. */
internal fun sha256Hex(hex: String): ByteArray {
    require(hex.length == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' }) { "not lowercase sha256 hex: $hex" }
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

/** Deterministic 32 bytes from [label] (world draws: the run's draw, rollout keys). */
internal fun sha256Bytes(label: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(label.toByteArray())

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
 */
internal class WorldFixtures(
    /** chain.ghrc: the fixture GHRC (one root, network 2). */
    val chain: ByteArray,
    val network: Int,
    /** bundle.ghrb: the fresh current bundle (chain + manifest + proof). */
    val bundle: ByteArray,
    /** stale-bundle.ghrb: the same release under an expired manifest (the STALE mirror). */
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
) {
    companion object {
        fun load(): WorldFixtures {
            val meta = java.util.Properties()
            java.io.InputStreamReader(
                requireNotNull(WorldFixtures::class.java.getResourceAsStream("/update-world/meta.properties")) {
                    "update-world fixtures missing from the test resources"
                },
                Charsets.US_ASCII,
            ).use { meta.load(it) }
            val chain = resource("/update-world/chain.ghrc")
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
                bundle = resource("/update-world/bundle.ghrb"),
                staleBundle = resource("/update-world/stale-bundle.ghrb"),
                manifestSha256 = sha256Hex(meta.getProperty("manifest_sha256")),
                apkSha256 = sha256Hex(meta.getProperty("apk_sha256")),
                apk = resource("/update-world/app-v2.apk"),
                issuedDay = meta.getProperty("issued_day").toInt(),
                notAfterDay = meta.getProperty("not_after_day").toInt(),
            )
        }

        private fun resource(path: String): ByteArray =
            requireNotNull(WorldFixtures::class.java.getResourceAsStream(path)) { "missing fixture $path" }
                .use { it.readBytes() }
    }
}
