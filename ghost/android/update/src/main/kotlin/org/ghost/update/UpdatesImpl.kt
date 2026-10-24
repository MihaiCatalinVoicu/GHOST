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
    private val db: () -> SqlExecutor,
    private val native: UpdateNativeBridge,
    private val engine: UpdateEngine,
    private val installedVersionCode: () -> Int,
    private val sdk: Int,
    private val time: () -> Triple<Boolean, Int, Long>,
    /** The runtime's user-update-call runner: READY on the `Update` scope, the user's thread. */
    private val userCall: ((UpdateSession) -> Unit) -> Unit,
) : Updates {

    private val store get() = UpdateStateStore(db())

    override val status: UpdateStatus
        get() {
            val loaded = store.load() ?: return UpdateStatus.NoManifest
            if (loaded.facts.rootConflict) return UpdateStatus.RootConflict
            if (loaded.facts.conflict) return UpdateStatus.Conflict
            val (trusted, day, _) = time()
            val staged = stagedRow(loaded)
            if (staged != null && (staged.state == "verified" || staged.state == "committed")) {
                return UpdateStatus.Ready(nameOf(loaded.blob), staged.versionCode)
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
        // §7.7's PackageInstaller session (stream with the native check, commit after apkFinish =
        // OK) lands with the Phase 13 wiring slice; the handle shape is fixed here.
        override fun commit() = throw UnsupportedOperationException("install lands with the UI wiring slice")
        override fun abandon() = Unit
    }

    // ------------------------------------------------------------------ the derivations

    private fun stagedRow(loaded: UpdateStateStore.Loaded): UpdateStateStore.Staged? {
        // The staged row names its APK by hash; the offer's hash is not parsed here, so the row
        // is whatever the engine staged (at most one exists, §9.6).
        var row: UpdateStateStore.Staged? = null
        db().query("SELECT apk_sha256, version_code, apk_length, received, state FROM upd_staged") { r ->
            row = UpdateStateStore.Staged(r.long(1).toInt(), r.long(2), r.long(3), r.string(4))
        }
        return row
    }

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

    /** The release's `version_name` (§4.5: version_code u32 at 58, then a u16-length ASCII name). */
    private fun nameOf(blob: ByteArray): String {
        val manifest = store.load()?.facts?.manifestFile ?: return "update"
        if (manifest.size < 64 || manifest[0] != 'G'.code.toByte()) return "update"
        val len = ((manifest[62].toInt() and 0xff) shl 8) or (manifest[63].toInt() and 0xff)
        if (len < 1 || 64 + len > manifest.size) return "update"
        return manifest.copyOfRange(64, 64 + len).toString(Charsets.US_ASCII)
    }

    private companion object {
        const val NO_CHANNEL_RUNS = 12
    }
}
