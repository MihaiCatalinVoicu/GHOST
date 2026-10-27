package org.ghost.update

import org.ghost.network.UpdateNative
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.UpdateSession

/**
 * The [Updates] facade Phase 13 builds on (Phase 14 design §9.5): every status is derived from
 * the stored facts at read; nothing is persisted beyond `upd_state` and `upd_staged`. The
 * user-initiated calls run the same engine on a user [UpdateSession] (§7.3: the user's moment,
 * the foreground, the `Update` scope); the wiring injects `userCall`, the runtime's
 * user-update-call runner.
 *
 * The channel flags order the derivation: `ROOT_CONFLICT` and `CONFLICT` are alarms that outrank
 * an offer; an expired manifest is `Stale(day)` with no offer; `NO_CHANNEL` is the 12 unanswered
 * runs of §7.5. `install()` is Phase 13's surface (§7.7's platform session) and lands with the
 * UI wiring slice — the handle type is fixed here so the facade is complete.
 */
class UpdatesImpl(
    private val db: (org.ghost.sync.android.DatabaseOpener.Purpose) -> SqlExecutor,
    private val native: UpdateNativeBridge,
    private val engine: UpdateEngine,
    private val installedVersionCode: () -> Int,
    private val sdk: Int,
    /** The clock: day and now; the trusted flag is the provider's (§7.4's trust is the sync
     *  clock's, which the wiring reads). */
    private val clockTrusted: () -> Boolean,
    private val dayNow: () -> Pair<Int, Long>,
    /** The runtime's user-update-call runner: READY on the `Update` scope, the user's thread. */
    private val userCall: ((UpdateSession) -> Unit) -> Unit,
    /** `noBackupFilesDir/update`, the same directory [UpdateEngine] stages into (§7.7, X-D10). */
    private val files: java.io.File,
    /** §7.7's platform session opener (the PackageInstaller one in the app wiring). */
    private val installer: Updates.Installer,
) : Updates {

    private val store get() = UpdateStateStore(db(org.ghost.sync.android.DatabaseOpener.Purpose.FOREGROUND))

    override val status: UpdateStatus
        get() {
            val loaded = store.load() ?: return UpdateStatus.NoManifest
            if (loaded.facts.rootConflict) return UpdateStatus.RootConflict
            if (loaded.facts.conflict) return UpdateStatus.Conflict
            val trusted = clockTrusted()
            val (day, _) = dayNow()
            val staged = store.staged()
            if (staged != null && (staged.state == "verified" || staged.state == "committed")) {
                return UpdateStatus.Ready(nameOf(loaded.blob, staged.versionCode), staged.versionCode)
            }
            if (staged != null && staged.state == "partial") {
                return UpdateStatus.Downloading(staged.received, staged.apkLength)
            }
            val manifest = loaded.facts.manifestFile
            val issued = issuedDay(manifest)
            val expiry = if (manifest != null && manifest.size >= 58) be32(manifest, 54) else null
            if (issued != null && expiry != null && day > expiry) return UpdateStatus.Stale(issued)
            if (loaded.failedRuns >= NO_CHANNEL_RUNS) return UpdateStatus.NoChannel
            if (!trusted) return UpdateStatus.Failed(UpdateNative.CLOCK_UNTRUSTED)
            return when (val offer = native.offer(loaded.blob, installedVersionCode(), sdk, loaded.rolloutKey, trusted, day)) {
                is UpdateNative.Offer.Update -> UpdateStatus.Available(offer.versionName, offer.versionCode)
                is UpdateNative.Offer.None -> when (offer.code) {
                    UpdateNative.STALE -> UpdateStatus.Stale(issuedDay(loaded.blob) ?: 0)
                    UpdateNative.SDK_UNSUPPORTED -> UpdateStatus.SdkUnsupported
                    UpdateNative.UNSUPPORTED -> UpdateStatus.Unsupported(loaded.facts.floorVersionCode)
                    UpdateNative.NO_MANIFEST -> UpdateStatus.NoManifest
                    else -> UpdateStatus.UpToDate
                }
            }
        }

    override val manifestIssuedDay: Int? get() = store.load()?.let { issuedDay(it.facts.manifestFile) }

    override fun requestCheck(): Updates.CheckOutcome {
        userCall { session -> engine.onUpdateRun(session) }
        // The run's result is visible through [status]; a check is never an error by itself.
        return Updates.CheckOutcome.Ok
    }

    override fun requestDownload(): Updates.DownloadOutcome {
        var started = false
        userCall { session ->
            engine.onUpdateRun(session)
        }
        // The engine downloads when the accepted facts offer something; whether it did is a state,
        // not this call's answer — the user sees Downloading/Ready through [status].
        return if (status is UpdateStatus.Downloading || status is UpdateStatus.Ready) {
            Updates.DownloadOutcome.Started
        } else {
            Updates.DownloadOutcome.NothingToDownload
        }
    }

    override fun install(): Updates.InstallHandle = object : Updates.InstallHandle {
        // §7.7: the platform session. commit() runs on the user's action (the gateway's
        // @UserAction), after the engine's native check staged the APK as `verified`.
        private var used = false

        override fun commit() {
            check(!used) { "an install handle commits once" }
            used = true
            store.load() ?: throw IllegalStateException("no update state to install from")
            val row = store.staged() ?: throw IllegalStateException("nothing staged")
            check(row.state == "verified" || row.state == "committed") {
                "the staged APK is not verified"
            }
            val apk = java.io.File(files, row.sha256.toHex() + ".apk")
            if (!apk.isFile || apk.length() != row.apkLength) {
                throw IllegalStateException("the staged APK file is gone or truncated")
            }
            installer.install(apk)
        }

        override fun abandon() = Unit
    }

    // ------------------------------------------------------------------ the derivations

    /** The manifest's `issued_day` and `not_after_day` live at fixed offsets of the GHRM body
     * (§4.5: magic 4 ‖ version 1 ‖ network 1 ‖ seq 8 ‖ root_version 4 ‖ root_sha 32 ‖ issued 4 ‖
     * not_after 4). The codec hands the facade the manifest document; these reads check the magic
     * and length before touching a field. */
    private fun issuedDay(manifest: ByteArray?): Int? =
        if (manifest != null && manifest.size >= 54 && manifest[0] == 'G'.code.toByte() &&
            manifest[1] == 'H'.code.toByte() && manifest[2] == 'R'.code.toByte() && manifest[3] == 'M'.code.toByte()
        ) {
            be32(manifest, 50)
        } else {
            null
        }

    private fun be32(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xff) shl 24) or ((b[at + 1].toInt() and 0xff) shl 16) or
            ((b[at + 2].toInt() and 0xff) shl 8) or (b[at + 3].toInt() and 0xff)

    /** The release's `version_name` for [versionCode] (§4.5): `nrel` at offset 62, then
     * `nrel × release`, each `u32 version_code ‖ u16 name_len ‖ name ‖` a fixed tail of
     * 165 bytes, `nart`, `nart × 41`, an attestation block (`u8 n ‖ n × 64`). Every read is
     * bounds-checked; the walk replaces revision 1's fixed-offset read, which was only right
     * for a one-release manifest. */
    private fun nameOf(blob: ByteArray, versionCode: Int): String {
        val manifest = store.load()?.facts?.manifestFile ?: return "update"
        if (manifest.size < 63 || manifest[0] != 'G'.code.toByte()) return "update"
        val nrel = manifest[62].toInt() and 0xff
        if (nrel < 1 || nrel > 4) return "update"
        var at = 63
        for (entry in 0 until nrel) {
            if (at + 6 > manifest.size) return "update"
            val code = be32(manifest, at)
            val len = ((manifest[at + 4].toInt() and 0xff) shl 8) or (manifest[at + 5].toInt() and 0xff)
            if (len < 1 || at + 6 + len > manifest.size) return "update"
            if (code == versionCode) {
                return manifest.copyOfRange(at + 6, at + 6 + len).toString(Charsets.US_ASCII)
            }
            at += 6 + len
            if (at + 166 > manifest.size) return "update"
            val nart = manifest[at + 165].toInt() and 0xff
            at += 166 + nart * 41
            if (at + 1 > manifest.size) return "update"
            val nsig = manifest[at].toInt() and 0xff
            at += 1 + nsig * 64
        }
        return "update"
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private companion object {
        const val NO_CHANNEL_RUNS = 12
    }
}
