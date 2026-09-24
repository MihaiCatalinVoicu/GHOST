package org.ghost.messaging.dmworld

import org.ghost.messaging.DmWorld

/**
 * One request of a relay view as the edge attackers of S-DM1 and S-DM2 read it (Phase 9 design
 * §15.6 "Statistics"), in one of two projections of the same [ViewEvent]: the **full** effective view
 * (§1.1) and its restriction to the **declared leakage LD** (§1.2 with §21.11 point 1).
 *
 * Nothing here is ground truth except [cluster] and [role], which are the **clustering oracle** both
 * attackers hold — which namespace is whose inbox and whose bundle namespace, the AD-1 worst case T2's
 * attackers hold too (`t2-join/src/stats.rs`: "clusters are clients"), and what L7-D6 and the session
 * co-occurrence of L7-D2 give a relay anyway. A request's **client** is never in it: that is what the
 * attackers are scored on recovering.
 */
internal class EdgeEvent(
    val op: ViewOp,
    val slot: Int,
    /** The exact arrival second (§21.11 point 1: exact arrival times are LD). */
    val second: Long,
    /**
     * The arrival order: the index of the event in the relays' record. Every request of one relay
     * session arrives in the same world second (the world's sessions are instantaneous), so the
     * order is the part of "exact arrival time" finer than the second, which a relay sees and which
     * the model records — the fetch before the reply stored after it.
     */
    val seq: Int,
    val namespace: String,
    /** The clustering oracle: the owner of a card namespace, or -1. */
    val cluster: Int,
    /** `X` (a card's inbox), `P` (a card's bundle namespace) or `?`. */
    val role: Char,
    /** Full view: the stored or served byte length; LD: its size bucket. */
    val size: Int,
    /** Full view: the TTL as stored; LD: its bucket (§10.1). 0 when the op has none. */
    val ttl: Long,
    /** An opaque class of the stored or served bytes (equal bytes, equal class), or -1. */
    val blob: Int,
    /** Full view only: the stored or served bytes. */
    val bytes: ByteArray?,
    /** Full view only: the credential presented. */
    val credential: ByteArray?,
    /** Full view only: the `keys.redb` verifier of a registration. */
    val verifier: ByteArray?,
    /** REGISTER: the period and key kind (LD: "the owner's `register` events", §1.2). */
    val period: Long,
    val keyKind: String?,
)

/**
 * The two projections of one world's relay record, event for event where LD keeps an event.
 *
 * **LD, exactly** (what §1.2 lets through, with §21.11 point 1's additions), per event of the record:
 *  - a STORE into a card's **inbox** by anyone but its owner (a deposit): op, relay, namespace, exact
 *    second and order, **size bucket**, **TTL bucket**, and the equality class of its bytes (a relay
 *    knows which of its stored items a later GET serves, and §21.11 declares the identical hash of
 *    an identical-bytes resend); the credential is the inbox's one static deposit scope per relay, a
 *    function of fields already here, so it adds nothing and is dropped;
 *  - a STORE into a card's **bundle** namespace by its owner (a publication), the same fields;
 *  - a LIST or GET of a client's **own** namespace, and a REGISTER of it (with its period and key
 *    kind; the verifier is dropped);
 *  - a LIST or GET of a card's bundle namespace by anyone else **inside an attempt window** of an
 *    establishment the world recorded — JD7's windows, at most three per establishment (§21.7) —
 *    and nothing outside one.
 * Every other event — a read of anything else, a store anywhere else, a registration of a namespace
 * not the registrar's, a bundle read beyond the bound — is **outside LD**: it is in the full view
 * and not in LD's. Fields LD drops: bytes, exact sizes and TTLs, credentials, verifiers.
 *
 * **Which bundle reads are LD is decided by ground truth** — the establishments the world recorded —
 * not by anything in the relay record. In an honest engine every bundle read is an establishment's,
 * so nothing turns on it; in one that also reads bundles outside every window, LD keeps the reads
 * that fall in a window (mostly contacts') and drops the rest, so the LD attacker holds a selection
 * no relay could make, and the one-sided comparison can understate what the full view adds (§22.30
 * item 4 (f)). Such an engine fails JD7 exactly.
 *
 * **Circuits are in neither view.** The model relay names a circuit by (client, namespace, relay
 * session) whatever the engine does (`ViewRelay.circuit`), so it carries nothing the engine chose,
 * and circuit isolation (T21) is not tested here.
 *
 * **The full view** is every event with every other field ([ViewEvent] minus the ground truth: the
 * client, the cause, the deadline and the diagnostic reader state are never copied).
 */
internal class EdgeViews(
    events: List<ViewEvent>,
    /** The clustering oracle: namespace hex → (owner, role). */
    val clusters: Map<String, Pair<Int, Char>>,
    establishments: List<PrivacyWorld.Establishment>,
    /**
     * Which events **outside LD** the full view keeps, by their index in the record (all of them but
     * in the controls' thinned views, which measure how few such events the comparison still sees).
     */
    keepOutside: (Int) -> Boolean = { true },
) {
    constructor(world: PrivacyWorld, keepOutside: (Int) -> Boolean = { true }) :
        this(world.relay.events, clustersOf(world), world.establishments, keepOutside)

    val full: List<EdgeEvent>
    val ld: List<EdgeEvent>

    /** Events of the full view outside LD's categories, by what they are. */
    val outsideLd: Map<String, Int>

    init {
        val cluster = clusters
        // JD7's attempt windows (Joins.Windows), fed each (reader, bundle owner) pair's reads in order.
        val wakes = HashMap<Int, java.util.TreeSet<Long>>()
        for (e in events) {
            val c = cluster[hex(e.namespace)]
            if (e.op == ViewOp.LIST && c != null && c.first == e.client) wakes.getOrPut(e.client) { java.util.TreeSet() } += e.second
        }
        val byPair = establishments.groupBy { it.reader to it.owner }.mapValues { (_, l) -> l.sortedBy { it.at } }
        val windows = HashMap<Pair<Int, Int>, Joins.Windows>()
        val blobClass = HashMap<GroundTruth.Key, Int>()
        val ldBlobClass = HashMap<String, Int>()
        val fullOut = ArrayList<EdgeEvent>(events.size)
        val ldOut = ArrayList<EdgeEvent>(events.size)
        val outside = java.util.TreeMap<String, Int>()
        for ((seq, e) in events.withIndex()) {
            val ns = hex(e.namespace)
            val c = cluster[ns]
            val owner = c?.first ?: -1
            val role = c?.second ?: '?'
            val own = owner == e.client
            val bytes = e.bytes
            val blob = bytes?.let { b -> blobClass.getOrPut(GroundTruth.Key(ViewRelay.sha256(b))) { blobClass.size } } ?: -1
            val category: String? = when (e.op) {
                ViewOp.STORE -> when {
                    role == 'X' && !own -> null
                    role == 'P' && own -> null
                    role == 'X' -> "a store into the storer's own inbox"
                    role == 'P' -> "a store into another card's bundle namespace"
                    else -> "a store into a namespace no card names"
                }
                ViewOp.LIST, ViewOp.GET -> when {
                    own -> null
                    role == 'P' -> {
                        val w = windows.getOrPut(e.client to owner) {
                            Joins.Windows(byPair[e.client to owner].orEmpty(), wakes[e.client] ?: java.util.TreeSet())
                        }
                        if (w.accept(e.second)) null else "a bundle read outside every attempt window"
                    }
                    role == 'X' -> "a read of another card's inbox"
                    else -> "a read of a namespace no card names"
                }
                ViewOp.REGISTER -> if (own) null else "a registration of a namespace not the registrar's"
            }
            if (category != null && !keepOutside(seq)) continue
            fullOut += EdgeEvent(
                op = e.op, slot = e.relaySlot, second = e.second, seq = seq, namespace = ns, cluster = owner, role = role,
                size = bytes?.size ?: 0, ttl = e.ttlSeconds ?: 0, blob = blob, bytes = bytes,
                credential = e.credential, verifier = e.verifier, period = e.period ?: -1, keyKind = e.keyKind,
            )
            if (category != null) {
                outside.merge(category, 1, Int::plus)
                continue
            }
            // LD's byte equality is **within a namespace** (§21.11: the identical hash of an
            // identical-bytes resend): a blob shared by two namespaces is not declared, and its LD
            // ids are kept apart by the namespace.
            ldOut += EdgeEvent(
                op = e.op, slot = e.relaySlot, second = e.second, seq = seq, namespace = ns, cluster = owner, role = role,
                size = bytes?.let { sizeBucket(it.size) } ?: 0,
                ttl = e.ttlSeconds?.let { ttlBucket(it) } ?: 0,
                blob = bytes?.let { b -> ldBlobClass.getOrPut(ns + "/" + hex(ViewRelay.sha256(b))) { ldBlobClass.size } } ?: -1,
                bytes = null, credential = null, verifier = null, period = e.period ?: -1, keyKind = e.keyKind,
            )
        }
        full = fullOut
        ld = ldOut
        outsideLd = outside
    }

    companion object {
        /** The clustering oracle of a world: every card namespace with its owner and role. */
        fun clustersOf(world: PrivacyWorld): Map<String, Pair<Int, Char>> {
            val cluster = HashMap<String, Pair<Int, Char>>()
            for (t in world.truth.clients.values) {
                t.inboxNamespace?.let { cluster[hex(it)] = t.index to 'X' }
                t.bundleNamespace?.let { cluster[hex(it)] = t.index to 'P' }
            }
            return cluster
        }

        fun hex(bytes: ByteArray): String = Joins.hex(bytes)

        /** R-B1's size classes; anything else rounds up (LD carries the class, never the length). */
        fun sizeBucket(length: Int): Int = listOf(4_096, 16_384, 65_536).firstOrNull { length <= it } ?: 65_536

        /** §10.1's TTL buckets (D15: 1 h, 1 d, 7 d, 30 d and 90 d, which JD5 accepts too). */
        val TTL_BUCKETS: List<Long> = listOf(DmWorld.HOUR, DmWorld.DAY, 7 * DmWorld.DAY, 30 * DmWorld.DAY, 90 * DmWorld.DAY)

        /** The smallest §10.1 bucket at least [ttl]; anything above the largest is the largest (LD carries the bucket). */
        fun ttlBucket(ttl: Long): Long = TTL_BUCKETS.firstOrNull { ttl <= it } ?: TTL_BUCKETS.last()
    }
}
