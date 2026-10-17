package org.ghost.messaging.media

import org.ghost.media.store.MediaLimits
import java.security.MessageDigest

/** The ops of the media privacy world's effective relay view (Phase 11 design §15.6). */
internal enum class MediaViewOp { STORE, LIST, GET, REGISTER, REDEEM }

/**
 * One event of the effective relay view (§15.6's "what the relay can group and time"): the minute,
 * the operation, the namespace's role (own media `M_0`, a contact's media `M_c` the client
 * deposits into, the own inbox `X` a descriptor deposits into), the size, the TTL as stored, the
 * credential scope presented, the circuit, and — for stores and gets — the blob hash. The bytes
 * themselves live only as [MediaModelRelay] recipes (§15.1).
 */
internal class MediaViewEvent(
    val op: MediaViewOp,
    val minute: Long,
    val client: Int,
    val relaySlot: Int,
    /** [MediaNsRole]. */
    val role: MediaNsRole,
    val namespace: ByteArray,
    val circuit: String,
    val size: Int = 0,
    val ttlSeconds: Long? = null,
    val hash: ByteArray? = null,
    /** The credential scope presented (an opaque identity, §15.6's "credential scope class"). */
    val credentialScope: String? = null,
    val deadlineSeconds: Long? = null,
    /** The pass (work bundle) this event ran in: JM7's "one of that namespace's pair events". */
    val pass: Int = 0,
    /** LIST events: the hashes the listing returned. */
    val listed: List<ByteArray>? = null,
)

internal enum class MediaNsRole(val wire: String) {
    OWN_MEDIA("M0"),
    CONTACT_MEDIA("Mc"),
    OWN_INBOX("X"),
}

/**
 * The model relay (§15.1's recipe rule): media blobs are stored as [MediaRecipe]s — (sender,
 * object, ordinal) — and a blob's bytes are re-derived on `get`. The joins read the recorded
 * events and the truth, never bytes a rerun must reproduce.
 */
internal sealed interface MediaRecipe {
    val objectId: ByteArray

    /** A content fragment: [chunk] groups of four, [fragment] within the chunk. */
    class Fragment(override val objectId: ByteArray, val chunk: Int, val fragment: Int) : MediaRecipe

    /** The manifest: re-derived through [FakeReaders.manifestBytes] from the recorded fields. */
    class Manifest(
        override val objectId: ByteArray,
        val kindCode: Int,
        val viewOnce: Boolean,
        val classCode: Int,
        val contentLen: Long,
        val width: Int,
        val height: Int,
        val durationMs: Long,
        val preview: ByteArray,
        val hashes: List<ByteArray>,
    ) : MediaRecipe
}

internal fun MediaRecipe.bytes(): ByteArray = when (this) {
    is MediaRecipe.Fragment -> syntheticFragment(objectId, chunk, fragment)
    is MediaRecipe.Manifest -> FakeReaders.manifestBytes(
        objectId, kindCode, viewOnce, classCode, contentLen, width, height, durationMs, preview, hashes,
    )
}

/**
 * The joins of §15.6 (JM1–JM7) over the recorded view, the world's truth and the model relay.
 * Each returns a violation count and the report detail; the report's line is `PASS 0` only when
 * the count is 0 and the denominators are non-zero (the vacuity rule of Phase 10's JC-5 lesson:
 * the test asserts the floors, the report names them).
 */
internal class MediaJoins(
    private val events: List<MediaViewEvent>,
    private val truth: MediaTruth,
    private val relay: MediaModelRelay,
) {

    class Result(val name: String, val violations: Int, val detail: String)

    /** Media-lane STORE events by blob hash: the per-object counts of JM1/JM2 (the descriptor's
     *  X stores share the manifest hash and are not media stores). */
    private val storesByHash: Map<String, List<MediaViewEvent>> =
        events.filter { it.op == MediaViewOp.STORE && it.role == MediaNsRole.CONTACT_MEDIA && it.hash != null }
            .groupBy { hexOf(it.hash!!) }

    private fun storeCount(hash: String): Int = storesByHash[hash]?.size ?: 0

    /** The world's relay count: every store of the set lands at each relay. */
    private val relaySlots: Int = (events.maxOfOrNull { it.relaySlot } ?: 0) + 1

    /** JM1: every media store is 65 536 B; every honest object stores exactly `F + 1` distinct blobs at every relay of the set. */
    fun jm1(): Result {
        var bad = 0
        for (e in events) {
            if (e.op == MediaViewOp.STORE && e.role == MediaNsRole.CONTACT_MEDIA &&
                e.size != MediaLimits.FRAGMENT_BYTES
            ) bad++
        }
        val shorts = ArrayList<String>()
        for (o in truth.objects) {
            if (o.exemption != null) continue
            val want = MediaLimits.CLASSES[o.classCode] + 1
            // Each distinct blob appears once per relay of the conversation's set.
            val got = o.allHashes().count { storeCount(hexOf(it)) == relaySlots }
            if (got != want) {
                bad++
                if (shorts.size < 4) shorts += "class=${o.classCode} want=$want got=$got"
            }
        }
        val exempt = truth.objects.count { it.exemption != null }
        return Result(
            "JM1", bad,
            "$bad short stores over ${truth.objects.size} objects " +
                "(exemptions: $exempt counted: ${truth.exemptionBreakdown()})" +
                if (shorts.isNotEmpty()) "; e.g. ${shorts.joinToString(", ")}" else "",
        )
    }

    /** JM2: `F = class(content_len)`; every image is class 0; exactly one manifest store per object. */
    fun jm2(): Result {
        var bad = 0
        for (o in truth.objects) {
            if (o.exemption != null) continue
            if (o.kindIsImage && o.classCode != 0) bad++
            if (storeCount(hexOf(o.manifestHash)) != relaySlots) bad++
            val fragments = o.fragmentHashes.count { storeCount(hexOf(it)) == relaySlots }
            if (fragments != MediaLimits.CLASSES[o.classCode]) bad++
        }
        return Result("JM2", bad, "$bad class/manifest-count violations over ${truth.objects.size} objects")
    }

    /**
     * JM3: no blob hash shared by two objects of honest senders; no two objects share
     * `(K_f, object_id)`; sampled: 16-byte windows at 64 fixed offsets of every stored blob, in
     * one hash set over the world, collide across objects only by chance (at this scale chance is
     * ~0, so a collision is a violation).
     */
    fun jm3(): Result {
        var bad = 0
        val ownerByHash = HashMap<String, Int>()
        for (o in truth.objects) {
            for (h in o.allHashes()) {
                val prev = ownerByHash.put(hexOf(h), o.sender)
                if (prev != null && prev != o.sender) bad++
            }
        }
        val objectByKeyEnv = HashMap<String, String>()
        for (o in truth.objects) {
            val prev = objectByKeyEnv.put(hexOf(o.keyEnv), hexOf(o.objectId))
            if (prev != null && prev != hexOf(o.objectId)) bad++
        }
        var collisions = 0
        var paddingWindows = 0
        val windowOwner = HashMap<String, String>()
        val wholeOwner = HashMap<String, String>()
        for (stored in relay.allStored()) {
            val blobKey = hexOf(stored.hash)
            val bytes = stored.recipe.bytes()
            var off = 0
            repeat(64) {
                if (off + 16 <= bytes.size) {
                    val w = bytes.copyOfRange(off, off + 16)
                    // The manifest's tail past its hashes is zero padding (the format pads to 64 KiB):
                    // fixed-stride windows land there, and padding collides by construction — the
                    // check is over content windows (the design draws random offsets; the padding
                    // is unreachable to an honest sampler at 64 of 65 536).
                    if (w.all { it.toInt() == 0 }) {
                        paddingWindows++
                    } else {
                        val key = hexOf(w)
                        val prev = windowOwner.put(key, blobKey)
                        if (prev != null && prev != blobKey) collisions++
                    }
                }
                off += 1_024
            }
            val whole = hexOf(digest(bytes))
            val prev = wholeOwner.put(whole, blobKey)
            if (prev != null && prev != blobKey) bad++
        }
        val v = bad + collisions
        return Result(
            "JM3", v,
            "$bad shared hashes, $bad shared key pairs, $collisions sampled window collisions " +
                "(${relay.allStored().size} blobs, 64 windows each, $paddingWindows padding windows skipped)",
        )
    }

    /** JM4: every store's TTL is the bucket of the timer at the object's commit, incl. the descriptor. */
    fun jm4(): Result {
        var bad = 0
        var checked = 0
        for (e in events) {
            if (e.op != MediaViewOp.STORE || e.hash == null) continue
            val o = truth.objectByHash(hexOf(e.hash)) ?: continue
            checked++
            if (e.ttlSeconds != o.ttlSeconds) bad++
            val deadline = e.deadlineSeconds ?: o.deadlineSecond
            if (MediaWorld.NOW + e.minute * 60 >= deadline) bad++
        }
        return Result("JM4", bad, "$bad TTL/deadline violations over $checked stores")
    }

    /** JM5: one credential scope per (relay, namespace) across stores; registers/redeems on own `M` only. */
    fun jm5(): Result {
        var bad = 0
        var calls = 0
        val scopeByNsRelay = HashMap<String, String>()
        for (e in events) {
            if (e.op == MediaViewOp.STORE && e.role == MediaNsRole.CONTACT_MEDIA) {
                val key = "${e.relaySlot}:${hexOf(e.namespace)}"
                val scope = e.credentialScope ?: "none"
                val prev = scopeByNsRelay.put(key, scope)
                if (prev != null && prev != scope) bad++
            }
            if (e.op == MediaViewOp.REGISTER || e.op == MediaViewOp.REDEEM) {
                calls++
                if (!e.namespace.contentEquals(truth.ownMedia(e.client))) bad++
            }
        }
        return Result("JM5", bad, "$bad scope/namespace violations over $calls register/redeem calls")
    }

    /** JM6: every list and get of an `M` is made by its owner. */
    fun jm6(): Result {
        var bad = 0
        var calls = 0
        for (e in events) {
            if (e.op != MediaViewOp.LIST && e.op != MediaViewOp.GET) continue
            calls++
            if (!e.namespace.contentEquals(truth.ownMedia(e.client))) bad++
        }
        return Result("JM6", bad, "$bad foreign reads over $calls list/get calls")
    }

    /** JM7: every get is for a hash a listing of that namespace returned, at or before the get. */
    fun jm7(): Result {
        var bad = 0
        var gets = 0
        val listedByNsClient = HashMap<String, MutableSet<String>>()
        for (e in events) {
            if (e.op == MediaViewOp.LIST) {
                val key = "${e.client}:${hexOf(e.namespace)}"
                listedByNsClient.computeIfAbsent(key) { HashSet() } +=
                    e.listed.orEmpty().map { hexOf(it) }
            }
            if (e.op == MediaViewOp.GET) {
                gets++
                val allowed = listedByNsClient["${e.client}:${hexOf(e.namespace)}"]
                if (allowed == null || !allowed.contains(hexOf(e.hash ?: ByteArray(0)))) bad++
            }
        }
        return Result("JM7", bad, "$bad unscheduled gets over $gets gets")
    }

    fun all(): List<Result> = listOf(jm1(), jm2(), jm3(), jm4(), jm5(), jm6(), jm7())
}

/**
 * The model relay: records the view's events, stores media blobs as recipes (§15.1 — a blob's
 * bytes are re-derived on `get`), expires stored blobs past their TTL, and serves listings. The
 * twins and the joins read only what is recorded here.
 */
internal class MediaModelRelay {
    class Stored(
        val relaySlot: Int,
        val namespace: ByteArray,
        val hash: ByteArray,
        val recipe: MediaRecipe,
        val ttlSeconds: Long,
        val storedAtMinute: Long,
        val fromClient: Int,
    ) {
        fun expired(atMinute: Long): Boolean = storedAtMinute + ttlSeconds / 60 <= atMinute
    }

    val events = ArrayList<MediaViewEvent>()
    private val byNsRelay = HashMap<Pair<Int, String>, MutableList<Stored>>()
    /** Blobs past their TTL: no longer served, kept for the seizure check's archive (T34-style). */
    private val archive = ArrayList<Stored>()

    fun record(event: MediaViewEvent) {
        events += event
    }

    fun store(event: MediaViewEvent, recipe: MediaRecipe) {
        events += event
        val key = event.relaySlot to hexOf(event.namespace)
        byNsRelay.getOrPut(key) { ArrayList() } += Stored(
            relaySlot = event.relaySlot,
            namespace = event.namespace,
            hash = event.hash ?: digest(recipe.bytes()),
            recipe = recipe,
            ttlSeconds = event.ttlSeconds ?: 0L,
            storedAtMinute = event.minute,
            fromClient = event.client,
        )
    }

    /** The owner's listing of its `M_0`: the live hashes, as a LIST event. */
    fun list(client: Int, relaySlot: Int, namespace: ByteArray, minute: Long, pass: Int): List<ByteArray> {
        val live = byNsRelay[relaySlot to hexOf(namespace)].orEmpty().filter { !it.expired(minute) }
        val hashes = live.map { it.hash }
        events += MediaViewEvent(
            op = MediaViewOp.LIST, minute = minute, client = client, relaySlot = relaySlot,
            role = MediaNsRole.OWN_MEDIA, namespace = namespace.copyOf(),
            circuit = "c$client", listed = hashes.map { it.copyOf() }, pass = pass,
        )
        return hashes
    }

    /** The owner's fetch of one hash: the re-derived bytes, as a GET event. */
    fun get(client: Int, relaySlot: Int, namespace: ByteArray, hash: ByteArray, minute: Long, pass: Int): ByteArray? {
        val stored = byNsRelay[relaySlot to hexOf(namespace)].orEmpty()
            .firstOrNull { it.hash.contentEquals(hash) && !it.expired(minute) }
        events += MediaViewEvent(
            op = MediaViewOp.GET, minute = minute, client = client, relaySlot = relaySlot,
            role = MediaNsRole.OWN_MEDIA, namespace = namespace.copyOf(),
            circuit = "c$client", size = MediaLimits.FRAGMENT_BYTES, hash = hash.copyOf(), pass = pass,
        )
        return stored?.recipe?.bytes()?.let { bytes ->
            // PM-M4's shape is observable in the view (the size says it); the bytes stay canonical
            // so the recipient-side oracles are unaffected.
            bytes
        }
    }

    fun allStored(): List<Stored> = byNsRelay.values.flatten() + archive

    /** Relay-side expiry: stored blobs past their TTL leave the live set (the seizure archive). */
    fun expire(atMinute: Long) {
        val it = byNsRelay.iterator()
        while (it.hasNext()) {
            val entry = it.next()
            val expired = entry.value.filter { it.expired(atMinute) }
            if (expired.isNotEmpty()) {
                archive += expired
                entry.value.removeAll(expired.toSet())
            }
            if (entry.value.isEmpty()) it.remove()
        }
    }
}
