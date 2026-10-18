package org.ghost.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest

/**
 * PT-U9 (Phase 12 design `faza12-transports.md` §5.4.4, §12.2): the extraction over
 * JVM-mocked asset streams — idempotence (the versioned stamp makes a repeat install a no-op),
 * the hash-mismatch refusal (temp deleted, fail closed), the versioned stamp re-done on update
 * (a changed asset hash forces re-extraction, atomically), the chmod-700 call, the unsupported
 * ABI, and the sums parsing. The real APK asset streams and filesDir exec are the emulator
 * probe's half (PT-1, V-T6 re-run).
 */
class PtInstallerTest {

    private val abi = "x86_64"
    private val other = "arm64-v8a"

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** A mocks-assets installer over a temp dir; [sums] maps abi -> expected hash. */
    private class Fixture(
        val root: File,
        val sums: Map<String, String>,
        val assets: Map<String, ByteArray>,
    ) {
        val chmods = ArrayList<File>()
        val installer = PtInstaller(
            ptRoot = root,
            abi = "x86_64",
            openAsset = { path -> assets[path]?.let { ByteArrayInputStream(it) } },
            chmod700 = { chmods += it },
        )

        companion object {
            fun create(sums: Map<String, String>, assets: Map<String, ByteArray>): Fixture {
                val root = File.createTempFile("pt-installer", "").apply { delete(); mkdirs() }
                return Fixture(root, sums, assets)
            }
        }
    }

    private fun sumsAsset(vararg entries: Pair<String, String>): ByteArray =
        (
            "# comment line\n\n" +
                entries.joinToString("") { (hash, name) -> "$hash  $name\n" } +
                "garbage line that is not a sum\n"
            ).toByteArray()

    @Test
    fun installExtractsVerifiesChmodsAndStamps() {
        val binary = ByteArray(1024) { it.toByte() }
        val hash = sha256(binary)
        val f = Fixture.create(
            mapOf(abi to hash),
            mapOf(
                PtInstaller.SUMS_ASSET to sumsAsset(hash to "$abi/lyrebird"),
                "pt/$abi/lyrebird" to binary,
            ),
        )
        val dir = f.installer.install()
        assertEquals(File(f.root, abi), dir)
        val installed = File(dir, PtInstaller.BINARY_NAME)
        assertTrue(installed.isFile)
        assertEquals(binary.toList(), installed.readBytes().toList())
        assertEquals(hash, File(dir, PtInstaller.STAMP_NAME).readText().trim())
        // The chmod happens on the verified temp file before the atomic rename (§5.4.4).
        assertEquals(1, f.chmods.size)
        assertEquals("${PtInstaller.BINARY_NAME}.tmp", f.chmods[0].name)
        assertTrue(f.installer.installed())
        // Atomic shape: no temp file left behind.
        assertEquals(listOf(PtInstaller.STAMP_NAME, PtInstaller.BINARY_NAME), dir.list()!!.sorted())
    }

    @Test
    fun repeatedInstallIsANoOp() {
        val binary = ByteArray(512) { 7 }
        val hash = sha256(binary)
        val f = Fixture.create(
            mapOf(abi to hash),
            mapOf(
                PtInstaller.SUMS_ASSET to sumsAsset(hash to "$abi/lyrebird"),
                "pt/$abi/lyrebird" to binary,
            ),
        )
        f.installer.install()
        val stamped = File(f.root, abi).resolve(PtInstaller.STAMP_NAME).readText()
        f.installer.install()
        assertEquals(1, f.chmods.size)
        assertEquals(stamped, File(f.root, abi).resolve(PtInstaller.STAMP_NAME).readText())
    }

    @Test
    fun hashMismatchFailsClosedAndDeletesTheTemp() {
        val f = Fixture.create(
            mapOf(abi to sha256(ByteArray(16) { 1 })),
            mapOf(
                PtInstaller.SUMS_ASSET to sumsAsset(sha256(ByteArray(16) { 1 }) to "$abi/lyrebird"),
                "pt/$abi/lyrebird" to ByteArray(16) { 2 },
            ),
        )
        val e = assertThrows(NetworkException::class.java) { f.installer.install() }
        assertEquals(PtErrorCategories.PT_HASH_MISMATCH, e.category)
        val dir = File(f.root, abi)
        assertFalse(File(dir, PtInstaller.BINARY_NAME).exists())
        assertFalse(File(dir, "${PtInstaller.BINARY_NAME}.tmp").exists())
        assertFalse(f.installer.installed())
    }

    @Test
    fun aChangedAssetForcesReextraction() {
        val v1 = ByteArray(128) { 1 }
        val v2 = ByteArray(128) { 2 }
        val assets = HashMap<String, ByteArray>()
        assets[PtInstaller.SUMS_ASSET] = sumsAsset(sha256(v1) to "$abi/lyrebird")
        assets["pt/$abi/lyrebird"] = v1
        val f = Fixture.create(mapOf(abi to sha256(v1)), assets)
        f.installer.install()
        assertEquals(v1.toList(), File(f.root, abi).resolve(PtInstaller.BINARY_NAME).readBytes().toList())

        // The app update: new asset bytes, new sums. The stale stamp forces re-extraction.
        assets[PtInstaller.SUMS_ASSET] = sumsAsset(sha256(v2) to "$abi/lyrebird")
        assets["pt/$abi/lyrebird"] = v2
        f.installer.install()
        assertEquals(v2.toList(), File(f.root, abi).resolve(PtInstaller.BINARY_NAME).readBytes().toList())
        assertEquals(sha256(v2), File(f.root, abi).resolve(PtInstaller.STAMP_NAME).readText().trim())
        assertEquals(2, f.chmods.size)
        assertFalse(File(f.root, abi).resolve("${PtInstaller.BINARY_NAME}.tmp").exists())
    }

    @Test
    fun unsupportedAbiWhenTheSumsHaveNoBinaryForIt() {
        val otherHash = sha256(ByteArray(8) { 3 })
        val f = Fixture.create(
            mapOf(other to otherHash),
            mapOf(
                PtInstaller.SUMS_ASSET to sumsAsset(otherHash to "$other/lyrebird"),
                "pt/$other/lyrebird" to ByteArray(8) { 3 },
            ),
        )
        val e = assertThrows(NetworkException::class.java) { f.installer.install() }
        assertEquals(PtErrorCategories.PT_UNSUPPORTED_ABI, e.category)
        assertFalse(f.installer.installed())
    }

    @Test
    fun missingAssetIsUnsupportedAbi() {
        val f = Fixture.create(
            mapOf(abi to sha256(ByteArray(4))),
            mapOf(PtInstaller.SUMS_ASSET to sumsAsset(sha256(ByteArray(4)) to "$abi/lyrebird")),
        )
        val e = assertThrows(NetworkException::class.java) { f.installer.install() }
        assertEquals(PtErrorCategories.PT_UNSUPPORTED_ABI, e.category)
    }

    @Test
    fun sumsParsingIgnoresCommentsAndGarbage() {
        val hashA = "a".repeat(64)
        val hashB = "0123456789abcdef".repeat(4)
        val sums = (
            "# a comment\n\n$hashA  arm64-v8a/lyrebird\nnot a sum\n$hashB  x86_64/lyrebird extra\n" +
                "$hashB x86_64/lyrebird\n" + hashB.uppercase() + "  arm64-v8a\n"
            ).toByteArray()
        // Well-formed `<hash>  <abi>/lyrebird` lines only: comments, the three-field line, the
        // bare `arm64-v8a` key (no `/lyrebird` suffix) are ignored. Case normalizes to lowercase.
        assertEquals(
            mapOf("arm64-v8a" to hashA, "x86_64" to hashB),
            PtInstaller(File("."), abi, { null }).parseSums(ByteArrayInputStream(sums)),
        )
    }
}
