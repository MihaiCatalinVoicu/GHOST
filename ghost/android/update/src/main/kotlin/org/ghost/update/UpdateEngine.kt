package org.ghost.update

import org.ghost.network.NetworkException
import org.ghost.network.UpdateNative
import org.ghost.storage.SqlExecutor
import org.ghost.sync.api.MirrorAccess
import org.ghost.sync.api.UpdateParticipant
import org.ghost.sync.api.UpdateSession
import java.io.File
import java.security.SecureRandom

/**
 * The update engine (Phase 14 design §7.3, §9.4, §9.5): the one [UpdateParticipant]. One update
 * run, in order:
 *
 *  1. START (step 0) at the first start of a fresh install;
 *  2. the run's mirror set, built from the stored state, the embedded chain and the run's draw
 *     (§7.8; on `NO_CHANNEL` the embedded anchors join the draw);
 *  3. the bundle from the run's two mirrors, accepted in fetch order (§7.4: equal pairs with
 *     different hashes set `CONFLICT`, lower pairs refuse with `ROLLBACK` and change nothing —
 *     sequential acceptance is observably the pair order for both);
 *  4. the offer recomputed against the accepted facts; if one exists and nothing is staged, the
 *     APK's chunks in index order until the run's fixed end (resumable; `received` never exceeds
 *     what is on disk);
 *  5. STAGE-VERIFY of a completed `.part`: the native check streams the file in order, then the
 *     rename and the row to `verified`;
 *  6. RUN-END: `failed_runs` counts only unanswered runs.
 *
 * The engine never parses a ZIP, a manifest or a proof: the native side decides everything, the
 * engine moves bytes and rows. The `directory` hook is how the wiring applies the §7.8 relay
 * changes in the same ACCEPT transaction through `:sync`'s store; it receives the transaction's
 * SqlExecutor and the ACCEPTed manifest's bytes (null when the accept carries no manifest).
 */
class UpdateEngine(
    /** The database, by purpose: a user call opens with the foreground purpose, a job with the
     *  background one (the opener's mayOpen rule, exactly as the sync runtime's engineFor). */
    private val db: (org.ghost.sync.android.DatabaseOpener.Purpose) -> SqlExecutor,
    /** `noBackupFilesDir/update`: the module's only file directory (§7.7, X-D10). */
    private val files: File,
    private val native: UpdateNativeBridge = RealUpdateNativeBridge,
    private val installedVersionCode: () -> Int,
    private val sdk: Int,
    /** The clock: day (epoch days) and now (unix seconds). The *trusted* flag is the session's
     * own (§7.4: from `:sync`'s clock trust), not a wall-clock guess. */
    private val dayNow: () -> Pair<Int, Long>,
    private val directory: (SqlExecutor, ByteArray?) -> Unit = { _, _ -> },
) : UpdateParticipant {

    private val random = SecureRandom()

    override fun onUpdateRun(session: UpdateSession) {
        var answered = false
        val store = UpdateStateStore(
            db(if (session.userInitiated) org.ghost.sync.android.DatabaseOpener.Purpose.FOREGROUND else org.ghost.sync.android.DatabaseOpener.Purpose.BACKGROUND),
        )
        try {
            val trusted = session.clockTrusted()
            val (day, now) = dayNow()
            var loaded = store.load() ?: start(store)
            val offer = native.offer(loaded.blob, installedVersionCode(), sdk, loaded.rolloutKey, trusted, day)
            val mirrorSet = native.mirrorSet(
                stored = loaded.blob,
                embeddedChain = native.embeddedChain(),
                noChannel = loaded.failedRuns >= NO_CHANNEL_RUNS,
                dayTrusted = trusted,
                day = day,
                draw = session.updateDraw(),
                hasOffer = offer is UpdateNative.Offer.Update,
                offerSha256 = if (offer is UpdateNative.Offer.Update) offer.apkSha256 else ByteArray(0),
                offerLength = if (offer is UpdateNative.Offer.Update) offer.apkLength else 0L,
            )
            try {
                val first = session.mirror.fetchBundle(mirrorSet, 0, FETCH_DEADLINE_MILLIS)
                answered = true
                val second = try {
                    session.mirror.fetchBundle(mirrorSet, 1, FETCH_DEADLINE_MILLIS).also { answered = true }
                } catch (e: NetworkException) {
                    null
                }
                for (bundle in listOfNotNull(first, second)) {
                    val (code, newBlob) = native.accept(loaded.blob, bundle, trusted, day, now)
                    if (code == UpdateNative.OK && newBlob.isNotEmpty()) {
                        store.accept(UpdateCodec.decode(newBlob, loaded.network), directory)
                        loaded = store.load()!!
                    }
                }
                // The offer is derived from the accepted facts: recompute it now (§9.5: acceptance
                // itself triggers no fetch; the offer below is this run's, after acceptance).
                val fresh = native.offer(loaded.blob, installedVersionCode(), sdk, loaded.rolloutKey, trusted, day)
                if (fresh is UpdateNative.Offer.Update) download(session, loaded, fresh, mirrorSet, store)
            } finally {
                native.mirrorSetClose(mirrorSet)
            }
        } finally {
            store.runEnd(answered)
        }
    }

    /** START (§7.4 step 0): the embedded chain becomes the first epoch; the row is inserted. */
    private fun start(store: UpdateStateStore): UpdateStateStore.Loaded {
        val embedded = native.embeddedChain()
        val blob = native.start(ByteArray(0), embedded, installedVersionCode())
        val facts = UpdateCodec.decode(blob, networkOf(embedded))
        store.insertFirst(facts, rolloutKey = ByteArray(32).also(random::nextBytes))
        return store.load()!!
    }

    /** The network byte of the embedded chain (a GHRC document: `GHRC` ‖ version ‖ network —
     *  network at offset 5, per §4.4's grammar; offset 6 is the first byte of first_version, which
     *  made every first start insert network = 0 and fail the schema's CHECK — caught by the
     *  emulator drill's direct-engine probe). */
    internal fun networkOf(embedded: ByteArray): Int {
        if (embedded.size < 6 || embedded[0] != 'G'.code.toByte() || embedded[1] != 'H'.code.toByte() ||
            embedded[2] != 'R'.code.toByte() || embedded[3] != 'C'.code.toByte() || embedded[4] != 1.toByte()
        ) {
            throw NetworkException("malformed_response")
        }
        return embedded[5].toInt() and 0xff
    }


    /**
     * The download of one offered release (§7.3, §7.7): chunks in index order into `<sha>.part`,
     * resuming from the staged row; a completed file passes the native check and is renamed
     * `<sha>.apk` with the row to `verified`. A refused or superseded download clears row and file.
     */
    private fun download(
        session: UpdateSession,
        loaded: UpdateStateStore.Loaded,
        offer: UpdateNative.Offer.Update,
        mirrorSet: Long,
        store: UpdateStateStore,
    ) {
        val part = File(files, offer.apkSha256.toHex() + ".part")
        val done = File(files, offer.apkSha256.toHex() + ".apk")
        files.mkdirs()
        var staged = store.staged(offer.apkSha256)
        if (staged == null) {
            store.stageBegin(offer.apkSha256, offer.versionCode, offer.apkLength)
            staged = store.staged(offer.apkSha256)!!
        }
        if (staged.state == "verified") return
        if (done.exists()) {
            // A `.apk` with a `partial` row is re-checked (§9.6.1 STAGE-VERIFY's crash rule).
            if (verify(store, loaded, offer, done)) return
            store.stageClear(offer.apkSha256)
            done.delete()
            store.stageBegin(offer.apkSha256, offer.versionCode, offer.apkLength)
        }
        val chunks = (offer.apkLength + CHUNK - 1) / CHUNK
        val out = java.io.RandomAccessFile(part, "rw")
        out.use {
            it.setLength(offer.apkLength)
            var index = staged.received / CHUNK
            while (index < chunks) {
                if (session.closed) return
                val chunk = session.mirror.fetchApkChunk(mirrorSet, (index % 2).toInt(), index, FETCH_DEADLINE_MILLIS)
                it.seek(index * CHUNK)
                it.write(chunk)
                it.fd.sync()
                store.stageAdvance(offer.apkSha256, minOf((index + 1) * CHUNK, offer.apkLength))
                index++
            }
        }
        if (!verify(store, loaded, offer, part)) {
            store.stageClear(offer.apkSha256)
            part.delete()
        }
    }

    /** STAGE-VERIFY (§9.6.1): the native check streams the file in order; on OK, rename + row. */
    private fun verify(store: UpdateStateStore, loaded: UpdateStateStore.Loaded, offer: UpdateNative.Offer.Update, file: File): Boolean {
        val bytes = file.readBytes()
        if (bytes.size.toLong() != offer.apkLength) return false
        if (bytes.size < 22 + 24) return false
        // The native ApkCheck's streaming contract: begin(tail) → footer(the 24 bytes before the
        // central directory) → the body in order → finish. The footer comes FIRST (its check
        // arms before any body byte); streaming the body first made the native refuse the first
        // chunk with OUT_OF_ORDER (caught by the emulator drill).
        val cdOffset = readCdOffset(bytes)
        if (cdOffset < 24) return false
        val handle = native.apkBegin(loaded.blob, offer.releaseIndex, sdk, offer.apkLength, bytes.copyOfRange(bytes.size - 22, bytes.size))
        try {
            if (native.apkFooter(handle, bytes.copyOfRange(cdOffset - 24, cdOffset)) != UpdateNative.OK) {
                native.apkAbort(handle)
                return false
            }
            var offset = 0L
            while (offset < bytes.size - 22) {
                val end = minOf(offset + STREAM_CHUNK, (bytes.size - 22).toLong()).toInt()
                if (native.apkUpdate(handle, offset, bytes.copyOfRange(offset.toInt(), end)) != UpdateNative.OK) {
                    native.apkAbort(handle)
                    return false
                }
                offset = end.toLong()
            }
            if (native.apkFinish(handle) != UpdateNative.OK) return false
        } catch (e: Throwable) {
            native.apkAbort(handle)
            throw e
        }
        val target = File(files, offer.apkSha256.toHex() + ".apk")
        if (!file.renameTo(target)) {
            store.stageClear(offer.apkSha256)
            return refuse("rename")
        }
        // The rename is the file half; the row follows in the same step.
        store.stageVerified(offer.apkSha256)
        return true
    }

    private fun readCdOffset(bytes: ByteArray): Int {
        // The footer range the native side names: 24 bytes before cd_offset. cd_offset is the
        // EOCD's own field; the engine reads only what the layout of §9.2(a) fixes — the EOCD
        // is the file's last 22 bytes.
        // The EOCD's fields are little-endian (ZIP's convention; the one-shot `check_apk` reads
        // them the same way).
        val n = bytes.size
        return (bytes[n - 6].toInt() and 0xff) or
            ((bytes[n - 5].toInt() and 0xff) shl 8) or
            ((bytes[n - 4].toInt() and 0xff) shl 16) or
            ((bytes[n - 3].toInt() and 0xff) shl 24)
    }

    private fun ByteArray.toHex(): String {
        val alphabet = "0123456789abcdef"
        return joinToString("") { b -> "${alphabet[(b.toInt() shr 4) and 15]}${alphabet[b.toInt() and 15]}" }
    }

    private companion object {
        const val CHUNK = 4L * 1024 * 1024
        const val FETCH_DEADLINE_MILLIS = 60_000
        const val STREAM_CHUNK = 256 * 1024
        const val NO_CHANNEL_RUNS = 12
    }
}
