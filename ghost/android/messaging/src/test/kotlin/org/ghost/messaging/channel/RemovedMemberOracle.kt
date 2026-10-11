package org.ghost.messaging.channel

import org.ghost.crypto.bridge.ChannelCrypto
import org.ghost.crypto.bridge.ChannelRecognition
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.api.ChannelId

/**
 * **The removed-member seizure oracle, T38's channel case** (Phase 10 design §12.8, P-C4(a)/(b),
 * the exit gate's "membru scos nu decriptează epoch-uri noi" row, FR-3.8, TM S4, LIMITE:39): the
 * subject's whole dump — **every stored 32-byte value** (tried as a recognition key, the DM
 * seizure's method), **every stored 60-byte value** (the key envelopes: the generation secrets
 * `G_g`/`JK_g`, the box keys, the `mls_kv` rows, the KeyPackage keys), **every stored 68-byte
 * value** (the `ch_epoch` envelopes: `K_ep` with its epoch, `key(32) ‖ u64_be(epoch)`) — against
 * **every blob** the relays stored in the channel's namespaces, through the subject's own seized
 * native context.
 *
 * **Soundness of the sweep** (why recognition-matching is the pre-filter, not a shortcut): a blob
 * openable under a secret must first match that secret's hint — the hint is an HMAC of the
 * recognition key `R`, and `R` and the opening key derive from the same epoch/generation secret
 * (§5.6 CS-S5). So every (stored value, blob, mode) triple whose hint matches is tried for a real
 * open with every stored envelope under the classes the mode admits; a triple that matched nothing
 * cannot open under anything stored. Recognition matches over later blobs are themselves asserted
 * 0 — a stored value that *recognises* a later blob is already a leak (CS-S6).
 *
 * **The 68-byte envelopes are not recognition keys** (review finding F-1): a `ch_epoch` envelope
 * wraps `K_ep`, not `R_ep`, so no hint matches it and the recognition pre-filter can never admit
 * it — the old sweep, which only collected 32- and 60-byte values, never tried a leaked later
 * `K_ep` at all (a leak without its `ch_epoch` row is invisible to recognition, and with the row
 * the static residue check fired instead of an open). Every stored 68-byte value is therefore
 * tried **directly** as an epoch key (`KEY_CLASS_EPOCH`, mode 0x11) on every blob — T39's
 * `JoinerOracle` method, which opens with `e.kEnv` exactly so; its opens are classified like the
 * mode-0x11 branch's (the subject's own epochs' opens land in the earlier/removing-epoch counts,
 * the declared L8-C18 residue).
 *
 * **The assertions.** Opened must be 0 for every mode-0x11 blob of an epoch after the removing
 * commit and for every blob of a generation after the one the subject held (P-C4(a)/(b); the
 * restore variant of §19.16 — the replaced stack against every later generation, not only later
 * epochs). The join traffic (modes 0x12/0x13) of the subject's own draining generation, which a
 * removed member may open by design (L8-C5), is counted and reported, never asserted. What the
 * subject legitimately opens — its own epochs' posts, the removing epoch's posts composed before
 * their authors sighted the removing candidate (the removal hold, CO-13, keeps every later
 * composition out of that epoch) — is counted against the declared L8-C18 residue and reported,
 * not hidden. Static residue checks on the dump itself: no `ch_epoch` row past the removal, no
 * `ch_generation` row of a later generation, no held post of a later epoch.
 */
internal object RemovedMemberOracle {

    class Report(
        val subject: String,
        val kind: String,
        /** Distinct stored values of the dump. */
        val stored32: Int,
        val stored60: Int,
        /** The `ch_epoch` envelopes (`K_ep ‖ epoch`): tried directly as epoch keys (F-1's widening). */
        val stored68: Int,
        /** Distinct blobs of the channel's namespaces the relays stored. */
        val blobs: Int,
        /** (value, blob, mode) triples whose hint matched: what the opening sweep tried. */
        val matched: Int,
        val opens: Int,
        /** MUST be 0: mode-0x11 blobs of an epoch after the removal that opened. */
        val openedLaterEpoch: Int,
        /** MUST be 0: blobs of a generation after the subject's that opened. */
        val openedLaterGeneration: Int,
        /** The removing epoch's blobs that opened: the L8-C18 residue, reported. */
        val openedRemovingEpoch: Int,
        /** Blobs of epochs at or before the removal that opened: the subject's own history. */
        val openedEarlierEpoch: Int,
        /** Join traffic the subject's held generations opened (its own generation's, L8-C5: allowed). */
        val joinTrafficOpened: Int,
        /** Recognition matches over later-epoch or later-generation blobs: MUST be 0. */
        val recognisedLater: Int,
        /** Diagnostic: each later-generation open, classified. */
        val openViolations: List<String>,
        /** Static residue of the dump: rows past the subject's removal. */
        val laterEpochRows: Long,
        val laterGenerationRows: Long,
        val heldPostsLater: Long,
    ) {
        val violations: List<String>
            get() = listOfNotNull(
                "$subject: $openedLaterEpoch blobs of an epoch after the $kind opened"
                    .takeIf { openedLaterEpoch > 0 },
                "$subject: $openedLaterGeneration blobs of a generation it never held opened"
                    .takeIf { openedLaterGeneration > 0 },
                "$subject: a stored value recognised $recognisedLater later blobs"
                    .takeIf { recognisedLater > 0 },
                "$subject: the dump holds $laterEpochRows epoch rows past the removal"
                    .takeIf { laterEpochRows > 0 },
                "$subject: the dump holds $laterGenerationRows generation rows it never held"
                    .takeIf { laterGenerationRows > 0 },
                "$subject: the dump holds $heldPostsLater posts of later epochs"
                    .takeIf { heldPostsLater > 0 },
            )

        val floors: List<String>
            get() = listOfNotNull(
                "$subject: only $blobs blobs to try (the channel's relay set)".takeIf { blobs < 100 },
                "$subject: no stored 32-byte value in the dump".takeIf { stored32 == 0 },
                "$subject: no stored envelope in the dump".takeIf { stored60 == 0 && stored68 == 0 },
                "$subject: nothing matched, so nothing was tried (a broken attempt would print 0)"
                    .takeIf { matched == 0 },
            )

        val passed: Boolean get() = violations.isEmpty() && floors.isEmpty()

        fun line(): String =
            "channel T38 $kind: ${if (passed) "PASS" else "FAIL"} $subject: $blobs blobs, " +
                "$stored32 stored values (32 B) recognised, ${stored60 + stored68} envelopes tried " +
                "($stored60 of 60 B, $stored68 of 68 B), " +
                "$matched matches, $opens opened: later epochs $openedLaterEpoch, " +
                "later generations $openedLaterGeneration, the removing epoch $openedRemovingEpoch " +
                "(L8-C18, reported), earlier $openedEarlierEpoch, join traffic $joinTrafficOpened (L8-C5, allowed); " +
                "dump residue: $laterEpochRows epoch rows, $laterGenerationRows generation rows, $heldPostsLater posts" +
                (if (violations.isEmpty()) "" else "; " + violations.joinToString("; ")) +
                (if (floors.isEmpty()) "" else "; floors: " + floors.joinToString("; "))
    }

    /**
     * Runs the oracle for [subject] (a client opened over the subject's **seized dump**, its native
     * context the adversary's tool) against [blobs] — every distinct blob the world's relays stored
     * in the channel's namespaces. [removedAtEpoch] is the removing commit's epoch and
     * [heldGeneration] the last generation the subject held; [generationOf] maps a namespace to its
     * generation from the live world's view (the subject's dump names only the generations it held).
     */
    fun run(
        subject: ChannelClient,
        subjectName: String,
        kind: String,
        id: ChannelId,
        blobs: List<ModelChannelRelay.Stored>,
        removedAtEpoch: Long,
        heldGeneration: Long,
        generationOf: (ByteArray) -> Long?,
        /** The blob's epoch from the live world's view (built once by the caller with the anchor's keys), null when unknown. */
        blobEpoch: (ByteArray) -> Long?,
    ): Report {
        val c = id.toByteArray()
        val crypto = (subject.contexts.open(c) ?: error("the seized dump's channel does not open")).crypto

        // The dump's every stored value of the three key shapes (the DM seizure's SQL; the
        // 68-byte `ch_epoch` envelopes are F-1's widening — see the object's doc).
        val (v32, v60, v68) = storedValues(subject)
        val distinct = blobs.distinctBy { ModelChannelRelay.hex(it.namespace) + ModelChannelRelay.hex(it.hash) }

        // Static residue: rows of the dump past the subject's removal.
        var laterEpochRows = 0L
        var laterGenerationRows = 0L
        var heldPostsLater = 0L
        subject.sql.query("SELECT count(*) FROM ch_epoch WHERE channel_id = ? AND epoch > ?", listOf(c, removedAtEpoch)) {
            laterEpochRows = it.long(0)
        }
        subject.sql.query("SELECT count(*) FROM ch_generation WHERE channel_id = ? AND generation > ?", listOf(c, heldGeneration)) {
            laterGenerationRows = it.long(0)
        }
        subject.sql.query("SELECT count(*) FROM ch_post WHERE channel_id = ? AND epoch > ?", listOf(c, removedAtEpoch)) {
            heldPostsLater = it.long(0)
        }

        // Recognition: every stored 32-byte value against every blob's hint, all three modes.
        var matched = 0
        var recognisedLater = 0
        val violations = ArrayList<String>()
        var opens = 0
        var openedLaterEpoch = 0
        var openedLaterGeneration = 0
        var openedRemovingEpoch = 0
        var openedEarlierEpoch = 0
        var joinTrafficOpened = 0
        for (blob in distinct) {
            val nsGen = generationOf(blob.namespace)
            val laterGeneration = nsGen != null && nsGen > heldGeneration
            val knownEpoch = blobEpoch(blob.hash)
            val laterEpoch = knownEpoch != null && knownEpoch > removedAtEpoch
            val modes = ArrayList<Pair<Int, Int>>() // (mode, class) pairs that matched, to try for opens
            for (key in v32) {
                for (mode in listOf(ChannelCrypto.MODE_EPOCH, ChannelCrypto.MODE_JOIN, ChannelCrypto.MODE_WELCOME)) {
                    if (!ChannelRecognition.matches(blob.ciphertext, key, mode)) continue
                    matched++
                    // A recognition match over a blob the world knows to be later is a leak at
                    // once (CS-S6) — even before any open is tried. Blobs of unknown epoch that
                    // match only report: their epoch is read off any successful open below, and a
                    // value that knows a later epoch's R key implies that epoch's ch_epoch row in
                    // the dump, which the static residue check asserts absent.
                    if (laterGeneration || laterEpoch) recognisedLater++
                    modes += mode to when (mode) {
                        ChannelCrypto.MODE_EPOCH -> ChannelCrypto.KEY_CLASS_EPOCH
                        else -> ChannelCrypto.KEY_CLASS_JOIN
                    }
                }
            }
            for ((mode, klass) in modes.distinct()) {
                for (env in v60) {
                    for (cls in if (klass == ChannelCrypto.KEY_CLASS_JOIN) listOf(klass, ChannelCrypto.KEY_CLASS_INVITE_JOIN) else listOf(klass)) {
                        val o = crypto.open(c, env, cls, blob.namespace, mode, blob.ciphertext)
                        if (o is MlsOutcome.Ok) {
                            opens++
                            val openedGen = nsGen
                            when {
                                mode == ChannelCrypto.MODE_EPOCH -> {
                                    val headerEpoch = o.value.headerEpoch ?: o.value.order.epoch
                                    when {
                                        openedGen != null && openedGen > heldGeneration -> {
                                            openedLaterGeneration++
                                            violations += "OPENED-LATER-GEN mode=0x11 nsGen=$openedGen hdrEpoch=$headerEpoch purpose=${blob.purpose} from=${blob.from} size=${blob.ciphertext.size}"
                                        }
                                        headerEpoch > removedAtEpoch -> openedLaterEpoch++
                                        headerEpoch == removedAtEpoch -> openedRemovingEpoch++
                                        else -> openedEarlierEpoch++
                                    }
                                }
                                openedGen != null && openedGen > heldGeneration -> {
                                    openedLaterGeneration++
                                    violations += "OPENED-LATER-GEN mode=0x${"%02x".format(mode)} cls=$cls nsGen=$openedGen purpose=${blob.purpose} from=${blob.from} size=${blob.ciphertext.size}"
                                }
                                else -> joinTrafficOpened++
                            }
                        }
                    }
                }
            }
            // The 68-byte `ch_epoch` envelopes (`K_ep ‖ u64_be(epoch)`): not recognition keys, so
            // the pre-filter can never admit them — every one is tried directly as an epoch key on
            // every blob, T39's JoinerOracle method. This is the branch that catches a leaked later
            // `K_ep` with no `ch_epoch` row in the dump (review finding F-1).
            for (env in v68) {
                val o = crypto.open(c, env, ChannelCrypto.KEY_CLASS_EPOCH, blob.namespace, ChannelCrypto.MODE_EPOCH, blob.ciphertext)
                if (o is MlsOutcome.Ok) {
                    opens++
                    val headerEpoch = o.value.headerEpoch ?: o.value.order.epoch
                    when {
                        nsGen != null && nsGen > heldGeneration -> {
                            openedLaterGeneration++
                            violations += "OPENED-LATER-GEN mode=0x11 env nsGen=$nsGen hdrEpoch=$headerEpoch purpose=${blob.purpose} from=${blob.from} size=${blob.ciphertext.size}"
                        }
                        headerEpoch > removedAtEpoch -> openedLaterEpoch++
                        headerEpoch == removedAtEpoch -> openedRemovingEpoch++
                        else -> openedEarlierEpoch++
                    }
                }
            }
        }
        return Report(
            subject = subjectName,
            kind = kind,
            stored32 = v32.size,
            stored60 = v60.size,
            stored68 = v68.size,
            blobs = distinct.size,
            matched = matched,
            opens = opens,
            openedLaterEpoch = openedLaterEpoch,
            openedLaterGeneration = openedLaterGeneration,
            openedRemovingEpoch = openedRemovingEpoch,
            openedEarlierEpoch = openedEarlierEpoch,
            joinTrafficOpened = joinTrafficOpened,
            openViolations = violations,
            recognisedLater = recognisedLater,
            laterEpochRows = laterEpochRows,
            laterGenerationRows = laterGenerationRows,
            heldPostsLater = heldPostsLater,
        )
    }

    /** Every distinct BLOB value of 32, 60 and 68 bytes of every table of the seized dump
     *  (the 68-byte ones are the `ch_epoch` envelopes — F-1's widening). */
    private fun storedValues(client: ChannelClient): Triple<List<ByteArray>, List<ByteArray>, List<ByteArray>> {
        val tables = ArrayList<String>()
        client.sql.query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'") {
            tables += it.string(0)
        }
        val v32 = LinkedHashSet<Key>()
        val v60 = LinkedHashSet<Key>()
        val v68 = LinkedHashSet<Key>()
        for (table in tables) {
            val columns = ArrayList<String>()
            client.sql.query("SELECT name FROM pragma_table_info(?)", listOf(table)) { columns += it.string(0) }
            for (column in columns) {
                client.sql.query(
                    "SELECT \"$column\" FROM \"$table\" WHERE typeof(\"$column\") = 'blob' AND length(\"$column\") IN (32, 60, 68)",
                ) { r ->
                    val bytes = r.blob(0)
                    when (bytes.size) {
                        32 -> v32 += Key(bytes)
                        60 -> v60 += Key(bytes)
                        else -> v68 += Key(bytes)
                    }
                }
            }
        }
        return Triple(v32.map { it.bytes }, v60.map { it.bytes }, v68.map { it.bytes })
    }

    private class Key(val bytes: ByteArray) {
        override fun equals(other: Any?): Boolean = (other as? Key)?.bytes?.contentEquals(bytes) == true
        override fun hashCode(): Int = bytes.contentHashCode()
    }
}
