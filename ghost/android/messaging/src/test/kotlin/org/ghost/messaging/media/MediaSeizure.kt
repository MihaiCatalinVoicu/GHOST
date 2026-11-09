package org.ghost.messaging.media

import org.ghost.messaging.port.MediaReaders

/**
 * The seizure check (Phase 11 design §15.6's T34-style paragraph; the F9 Seizure discipline):
 * past the horizon, dump every client's database and try every *stored* `key_env` against every
 * archived relay blob of expired, viewed and request objects — 0 open — while a live control
 * opens, so the oracle is not vacuous (JC-5's floor lesson).
 *
 * "Archived" is the model relay's stored set (recipes re-derived to bytes for the attempt); the
 * reader judge is the world's shared [FakeReaders], so an attempt is exactly the production
 * shape: open the manifest under the offered key envelope (role `IN`, the recipient's shape),
 * then validate every chunk against the archived fragments of the same object.
 */
internal class MediaSeizure(private val world: MediaPrivacyWorld) {

    class Result(
        val storedKeys: Int,
        val archivedBlobs: Int,
        val opened: Int,
        val controlOpened: Int,
        /** Diagnostica gate-scale (2026-11-09): cine ținea cheia fiecărei deschideri și atributele obiectului. */
        val openedDetails: List<String> = emptyList(),
        val retainedExpiredDetails: List<String> = emptyList(),
    ) {
        override fun toString(): String =
            "storedKeys=$storedKeys archivedBlobs=$archivedBlobs opened=$opened controlOpened=$controlOpened" +
                (if (openedDetails.isNotEmpty()) " opened: ${openedDetails.joinToString(" | ")}" else "") +
                (if (retainedExpiredDetails.isNotEmpty()) " retainedExpired: ${retainedExpiredDetails.joinToString(" | ")}" else "")
    }

    /** One line of truth attributes for a retained key, for the diagnostic. */
    private fun describe(device: Int, keyEnv: ByteArray, keyObjects: Map<String, TruthObject>): String {
        val o = keyObjects[hexOf(keyEnv)]
            ?: return "device=$device key=NOT-IN-TRUTH"
        val side = when (device) {
            o.sender -> "sender"
            o.recipient -> "recipient"
            else -> "third-party"
        }
        return "device=$device($side) sender=${o.sender} recipient=${o.recipient} viewOnce=${o.viewOnce} " +
            "inRequest=${o.inRequest} exemption=${o.exemption} viewed=${o.viewed} " +
            "timer=${o.timerSeconds} commitMinute=${o.commitMinute}"
    }

    /**
     * The system's key-retention bound, not the nominal timer deadline: a message's `delete_at`
     * is `ceilHour(deadline) + 24h` (the world's receiveDescriptor, §10.3's slack), and the sweep
     * erases the object's key only then. An object whose nominal deadline passed but whose
     * retention bound has not is legitimately still keyed on the client — counting it as
     * "expired" made the seizure flag opens that the retention contract allows (found at the
     * gate scale 2026-11-09: three week-timer objects expiring inside the slack window before
     * the horizon, `opened=6` across the relay's two manifest slots). The later bound also cannot
     * hide a real leak: a key erased at the earlier recipient deadline simply is not there to
     * open anything.
     */
    private fun retentionSeconds(o: TruthObject): Long {
        val deadline = MediaWorld.NOW + o.commitMinute * 60 + o.timerSeconds
        return org.ghost.messaging.engine.DmTime.ceilHour(deadline) + 24 * 3_600L
    }

    private fun expired(o: TruthObject, endSeconds: Long): Boolean =
        o.timerSeconds > 0 && endSeconds >= retentionSeconds(o)

    fun run(): Result {
        val endSeconds = world.endSeconds()
        val truth = world.truth
        val stored = world.relay.allStored()

        // Every stored key_env of every client, past the sweeps, mapped to its object.
        val keyObjects = HashMap<String, TruthObject>()
        for (o in truth.objects) keyObjects[hexOf(o.keyEnv)] = o
        val storedKeys = world.storedKeyEnvs()

        // The archived set: blobs of objects whose message has expired (production's invariant is
        // archived ⇒ expired — a relay blob's TTL is the message's bucket — so viewed objects and
        // requests enter the set through expiry: view-once by the key erasure at open, requests by
        // the sender's message expiring unopened, D28). A still-live object (off timer, unviewed)
        // legitimately holds its key — its blobs are not archived before its expiry.
        val archived = stored.filter { s ->
            val o = truth.objectByHash(hexOf(s.hash))
            o != null && expired(o, endSeconds)
        }
        val live = stored.filter { s ->
            val o = truth.objectByHash(hexOf(s.hash))
            o != null && !expired(o, endSeconds)
        }

        var opened = 0
        val openedDetails = ArrayList<String>()
        val retainedExpiredDetails = ArrayList<String>()
        for ((device, keyEnv) in storedKeys) {
            for (manifest in archived.filter { it.recipe is MediaRecipe.Manifest }) {
                if (attempt(world.readers, manifest, keyEnv, archived)) {
                    opened++
                    if (openedDetails.size < 12) {
                        openedDetails += "device=$device manifestObject=${hexOf(manifest.recipe.objectId)} " +
                            describe(device, keyEnv, keyObjects)
                    }
                }
            }
        }
        // Retained keys of expired objects that did NOT open (fragments missing from the archived
        // pool, or the manifest itself archived while a chunk is not): same retention class as an
        // open, visible even where the attempt cannot complete.
        for ((device, keyEnv) in storedKeys) {
            val o = keyObjects[hexOf(keyEnv)] ?: continue
            if (!expired(o, endSeconds)) continue
            if (openedDetails.any { it.startsWith("device=$device ") && it.contains(hexOf(keyEnv).take(16)) }) continue
            if (retainedExpiredDetails.size < 12) retainedExpiredDetails += describe(device, keyEnv, keyObjects)
        }
        // The control: a live object's stored key opens its own (live) blobs.
        var control = 0
        var controlEligible = 0
        var controlManifests = 0
        var notInTruth = 0
        var skippedExpired = 0
        var skippedViewed = 0
        for ((_, keyEnv) in storedKeys) {
            val o = keyObjects[hexOf(keyEnv)] ?: run { notInTruth++; continue }
            if (expired(o, endSeconds)) { skippedExpired++; continue }
            if (o.viewed || o.inRequest) { skippedViewed++; continue }
            controlEligible++
            val mine = live.filter { it.recipe.objectId.contentEquals(o.objectId) }
            for (manifest in mine.filter { it.recipe is MediaRecipe.Manifest }) {
                controlManifests++
                if (attempt(world.readers, manifest, keyEnv, mine)) control++
            }
        }
        if (control == 0) {
            val liveUnviewed = truth.objects.filter { !expired(it, endSeconds) && !it.viewed && !it.inRequest }
            val storedHexes = storedKeys.map { hexOf(it.second) }.toSet()
            println(
                "SEIZURE-DEBUG storedKeys=${storedKeys.size} notInTruth=$notInTruth " +
                    "skippedExpired=$skippedExpired skippedViewed=$skippedViewed eligible=$controlEligible " +
                    "manifests=$controlManifests liveBlobs=${live.size} archivedN=${archived.size} " +
                    "liveUnviewed=${liveUnviewed.size} " +
                    "anchorLike=" + liveUnviewed.take(3).map {
                        "timer=${it.timerSeconds} viewed=${it.viewed} keyStored=${hexOf(it.keyEnv) in storedHexes} " +
                            "exemption=${it.exemption} sender=${it.sender} recipient=${it.recipient}"
                    },
            )
        }
        return Result(
            storedKeys = storedKeys.size,
            archivedBlobs = archived.size,
            opened = opened,
            controlOpened = control,
            openedDetails = openedDetails,
            retainedExpiredDetails = retainedExpiredDetails,
        )
    }

    /**
     * Try one key envelope against one manifest blob: open under the key, validate every chunk
     * against the fragments of the same object in [pool]. True = opened.
     */
    private fun attempt(
        readers: FakeReaders,
        manifestBlob: MediaModelRelay.Stored,
        keyEnv: ByteArray,
        pool: List<MediaModelRelay.Stored>,
    ): Boolean {
        val parsed = FakeReaders.parseManifest(manifestBlob.recipe.bytes()) ?: return false
        val bytes = manifestBlob.recipe.bytes()
        val spec = MediaReaders.OpenSpec(
            keyEnv = keyEnv,
            role = org.ghost.crypto.bridge.MediaCrypto.Role.IN,
            destId = ByteArray(32),
            objectId = parsed.objectId,
            manifestHash = digest(bytes),
            manifestBlob = bytes,
            kind = if (parsed.kindCode == 1) org.ghost.crypto.bridge.MediaCrypto.Kind.IMAGE
                   else org.ghost.crypto.bridge.MediaCrypto.Kind.VIDEO,
            viewOnce = parsed.viewOnce,
            classCode = parsed.classCode,
            readable = true,
        )
        return when (val o = readers.open(spec)) {
            is MediaReaders.Opened.Ok -> {
                val fragments = pool.filter {
                    it.recipe.objectId.contentEquals(parsed.objectId) && it.recipe is MediaRecipe.Fragment
                }
                var ok = true
                val chunkCount = (parsed.hashes.size + 3) / 4
                for (chunk in 0 until chunkCount) {
                    val chunkBytes = ByteArray(4 * org.ghost.media.store.MediaLimits.FRAGMENT_BYTES)
                    for (k in 0 until 4) {
                        val hash = parsed.hashes.getOrNull(chunk * 4 + k) ?: break
                        val frag = fragments.firstOrNull { it.hash.contentEquals(hash) }
                        if (frag == null) { ok = false; break }
                        frag.recipe.bytes().copyInto(
                            chunkBytes, k * org.ghost.media.store.MediaLimits.FRAGMENT_BYTES,
                        )
                    }
                    if (!ok) break
                    if (readers.chunk(o.reader, chunk, chunkBytes, validate = true) !is MediaReaders.Chunked.Ok) {
                        ok = false
                        break
                    }
                }
                if (ok) readers.finish(o.reader) is MediaReaders.Validated.Ok else false
            }
            else -> false
        }
    }
}
