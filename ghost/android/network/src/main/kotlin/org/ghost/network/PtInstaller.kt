package org.ghost.network

import android.content.Context
import android.os.Build
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

/**
 * PT-1/PT-2 (design `faza12-transports.md` §5.4.3–§5.4.5 (rev 3), §8.2; ADR-61 point 5):
 * extracts the ABI-matched lyrebird binary from the APK assets into the app-private
 * `filesDir/pt/<abi>/`, verifies its SHA-256 against the sums compiled into the APK, sets
 * the mode to 700 and hands arti's ptmgr the directory. Android executes only app-private
 * files (W^X; the APK mount and the native-library directory are noexec), which is why the
 * binary ships as an asset and lands here — the same shape Orbot and Tor Browser for
 * Android use (X-T1, §5.4). The exec itself is **linker-invocation** (rev 3, §5.4.5, OA-4
 * resolved): a direct `execve` of a filesDir binary is SELinux-denied on targetSdk ≥ 29
 * (`execute_no_trans` on `app_data_file`), while mmap-exec is granted — so the PT child is
 * the ABI's system dynamic linker (`/system/bin/linker64` for the shipped 64-bit ABIs)
 * exec'ed with the binary's absolute path as its first argument. That resolution lives in
 * `ghost-client-net`'s config build (ptmgr's `path` + `arguments`, no arti patch); this
 * class owns only the extraction, verification, chmod and stamp.
 *
 * The shape, per §5.4.4:
 *  - **Idempotent, versioned by the asset's hash**: the recorded stamp holds the *hash*, not a
 *    flag, so an app update whose asset changed forces re-extraction (the stamp mismatch), while
 *    a repeated install with the same asset is a no-op.
 *  - **Atomic**: the asset streams into `lyrebird.tmp`, is hash-verified and chmod'ed there, and
 *    only then renamed over `lyrebird`; a failed run (bad hash, missing asset, interrupted copy)
 *    deletes the temp file and fails closed — a PT line then meets no binary and `create` refuses
 *    it with `bridge_config` (`PtBinaryMissing`), never a half-trusted exec.
 *  - **Fail-closed categories only**: `pt_hash_mismatch` and `pt_unsupported_abi` (§8.3). No
 *    bridge line and no asset content ever reaches a log (T58).
 *
 * The class is pure JVM logic around injected streams so PT-U9 (extraction idempotence, the
 * hash-mismatch refusal, the update re-extract) runs on the host build without a device; the
 * emulator probe (V-T6 re-run, PT-1 in-app) drives [forApp] on a real filesDir.
 */
class PtInstaller internal constructor(
    private val ptRoot: File,
    private val abi: String,
    private val openAsset: (String) -> InputStream?,
    private val chmod700: (File) -> Unit = { it.setExecutable(true, /* ownerOnly = */ true) },
) {

    companion object {
        /** The sums file generated into the APK assets from `ghost/third_party/lyrebird/SHA256SUMS`. */
        const val SUMS_ASSET: String = "pt/SHA256SUMS"

        /** The extracted binary's name inside [ptDir]. */
        const val BINARY_NAME: String = "lyrebird"

        /** The stamp next to the binary, holding the asset's expected SHA-256 (the version). */
        const val STAMP_NAME: String = ".lyrebird.sha256"

        /** The ABIs the app ships (the jniLibs abiFilters; §4.2, Q9). */
        val SHIPPED_ABIS: Set<String> = setOf("arm64-v8a", "x86_64")

        /**
         * A hard cap on the streamed asset, an order of magnitude above the pinned budget
         * (§9.1: ≤ 7 668 008 B extracted per ABI): an asset that large is not the pinned binary,
         * and refusing it keeps a corrupt package from filling the data partition. Over the cap
         * is refused exactly like a hash mismatch, fail-closed.
         */
        private const val MAX_ASSET_BYTES: Long = 32L * 1024 * 1024

        /**
         * The device entry point: the app's own filesDir, the device's ABI (the first of
         * `Build.SUPPORTED_ABIS` the app ships — the same selection the runtime made when it
         * loaded `libghost_client_net.so` from the APK), and the APK asset opener. An ABI with
         * no shipped binary is `pt_unsupported_abi` (the app cannot install at all on such a
         * device, but the category is pinned and tested anyway, §8.3).
         */
        fun forApp(context: Context): PtInstaller {
            val app = context.applicationContext
            val abi = Build.SUPPORTED_ABIS.firstOrNull { it in SHIPPED_ABIS }
                ?: throw NetworkException(PtErrorCategories.PT_UNSUPPORTED_ABI)
            return PtInstaller(
                ptRoot = File(app.filesDir, "pt"),
                abi = abi,
                openAsset = { path ->
                    try {
                        app.assets.open(path)
                    } catch (e: IOException) {
                        null
                    }
                },
            )
        }
    }

    /** `filesDir/pt/<abi>` — the directory handed to arti as `TransportConfig.pt_dir`. */
    fun ptDir(): File = File(ptRoot, abi)

    /**
     * True iff the verified binary is installed for this ABI: the binary and the stamp exist and
     * the stamp equals the sums' expected hash (PT-2). False when PT is unavailable — PT bridge
     * lines are then config errors at `create`, not bootstrap-time surprises.
     */
    fun installed(): Boolean {
        val dir = ptDir()
        val binary = File(dir, BINARY_NAME)
        val stamp = File(dir, STAMP_NAME)
        if (!binary.isFile || !stamp.isFile) return false
        val expected = try {
            expectedHash()
        } catch (e: NetworkException) {
            return false
        }
        return stamp.readText().trim().equals(expected, ignoreCase = true)
    }

    /**
     * Extracts, verifies and chmods the binary (§5.4.4); idempotent — a second call with the same
     * asset is a no-op, an updated asset re-extracts (the versioned stamp). Returns [ptDir].
     *
     * @throws NetworkException `pt_unsupported_abi` (no sums entry or no asset for this ABI) or
     * `pt_hash_mismatch` (the asset's bytes differ from the compiled-in sums, or exceed the hard
     * cap). The temp file is deleted before either is thrown.
     */
    fun install(): File {
        val expected = expectedHash()
        val dir = ptDir()
        dir.mkdirs()
        val binary = File(dir, BINARY_NAME)
        val stamp = File(dir, STAMP_NAME)
        if (binary.isFile && stamp.isFile && stamp.readText().trim().equals(expected, ignoreCase = true)) {
            return dir
        }
        val tmp = File(dir, "$BINARY_NAME.tmp")
        try {
            val stream = openAsset(assetPath())
                ?: throw NetworkException(PtErrorCategories.PT_UNSUPPORTED_ABI)
            stream.use { input ->
                tmp.outputStream().use { out -> copyCapped(input, out) }
            }
            val actual = sha256(tmp)
            if (!actual.equals(expected, ignoreCase = true)) {
                throw NetworkException(PtErrorCategories.PT_HASH_MISMATCH)
            }
            chmod700(tmp)
            moveAtomically(tmp, binary)
            stamp.writeText("$actual\n")
        } catch (e: NetworkException) {
            tmp.delete()
            throw e
        } catch (e: IOException) {
            tmp.delete()
            throw NetworkException(PtErrorCategories.PT_UNSUPPORTED_ABI)
        }
        return dir
    }

    private fun assetPath(): String = "pt/$abi/$BINARY_NAME"

    /** The expected SHA-256 of this ABI's binary from the compiled-in sums, lowercase hex. */
    internal fun expectedHash(): String {
        val stream = openAsset(SUMS_ASSET)
            ?: throw NetworkException(PtErrorCategories.PT_UNSUPPORTED_ABI)
        val sums = stream.use { parseSums(it) }
        return sums[abi] ?: throw NetworkException(PtErrorCategories.PT_UNSUPPORTED_ABI)
    }

    /**
     * Parses the sums asset: `<64 lowercase-hex sha256>  <abi>/lyrebird` lines (the generated
     * APK asset's shape, two spaces as `sha256sum` writes), `#` comments and blank lines
     * ignored; a line whose key is not `<something>/lyrebird` is not a binary sum and is
     * ignored, so the file stays a strict subset of the in-repo `SHA256SUMS` (G-T4's twin
     * checks they agree).
     */
    internal fun parseSums(stream: InputStream): Map<String, String> {
        val text = stream.readBytes().toString(Charsets.UTF_8)
        val out = HashMap<String, String>()
        for (line in text.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            val parts = trimmed.split(Regex("\\s+"))
            if (parts.size != 2 || !parts[0].matches(Regex("[0-9a-fA-F]{64}"))) continue
            val key = parts[1].removeSuffix("/$BINARY_NAME")
            if (key.isNotEmpty() && key != parts[1]) out[key] = parts[0].lowercase()
        }
        return out
    }

    /** Copies at most [MAX_ASSET_BYTES]; an input beyond the cap is a hash mismatch, fail-closed. */
    private fun copyCapped(input: InputStream, out: java.io.OutputStream) {
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) return
            total += read
            if (total > MAX_ASSET_BYTES) {
                throw NetworkException(PtErrorCategories.PT_HASH_MISMATCH)
            }
            out.write(buffer, 0, read)
        }
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /** Renames over the target, atomically when the filesystem allows it (§5.4.4). */
    private fun moveAtomically(tmp: File, target: File) {
        try {
            java.nio.file.Files.move(
                tmp.toPath(),
                target.toPath(),
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (e: java.nio.file.AtomicMoveNotSupportedException) {
            java.nio.file.Files.move(
                tmp.toPath(),
                target.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
        }
    }
}
