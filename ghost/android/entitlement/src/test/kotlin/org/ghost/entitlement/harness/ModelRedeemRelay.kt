package org.ghost.entitlement.harness

import org.ghost.entitlement.engine.Grid
import org.ghost.network.EntitlementCrypto
import org.ghost.network.OnionAddress
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.TreeMap

/**
 * The redemption side of one relay in the `:entitlement` harness (Phase 8 design §10.2–§10.5,
 * §19.10, §19.21 point 2): exactly the rules pinned by `protocol/test-vectors/redeem.txt`, which
 * [ModelRedeemRelayConformanceTest] replays against it (the real relay replays the same file,
 * `relay/crates/node/tests/redeem_vectors.rs`), so the model cannot drift from the relay.
 *
 * Rules, in the order of §10.2: redemption disabled → `UNIMPLEMENTED`; lengths → `INVALID_ARGUMENT`;
 * type 0x0002 and a key id naming an ACCESS key of week p, not revoked, with this relay's onion
 * (matched by service key) listed for its slot in week p → else `PERMISSION_DENIED`; the persisted
 * closed-period high-water and the window `[start(p) − 24 h, start(p + 1) + 1 h)` → else
 * `WRONG_PERIOD` (nothing recorded); periods refused after a store reset → `UNAVAILABLE`; the
 * challenge of (ACCESS, p, my slot) and the PSS signature → else `PERMISSION_DENIED`; the nullifier
 * and its binding tag recorded before minting (another tag → `REPLAYED`); the deterministic mint of
 * a write capability v2 (serial and MAC keyed by the relay key), so an identical retry, also after a
 * restart, gets identical bytes (MS-8). The sweep closes periods for good and never runs below its
 * high-water minute. The [Disk] is the relay's data directory: it survives restarts.
 */
internal class ModelRedeemRelay private constructor(
    private val schedule: TestSchedule?,
    val slot: Int,
    val onion: OnionAddress,
    private val key: () -> ByteArray,
    val disk: Disk,
) {
    /** The relay's persistent redemption state (`nullifiers.redb` and the redemption marker). */
    class Disk {
        var exists = false
        var marker = false
        var keyCheck: String? = null
        val rows = TreeMap<String, String>()
        var closedThrough: Long? = null
        var refuseThrough: Long? = null
        var sweepHighWater: Long? = null

        /** State changes (crash-point classification of the harness). */
        var mutations = 0L

        fun digest(): String = Bytes.hex(
            Bytes.sha256(Bytes.ascii("$exists|$marker|$keyCheck|$closedThrough|$refuseThrough|$sweepHighWater|${rows.entries.joinToString(",")}")),
        )

        override fun toString(): String = "Disk(rows=${rows.size})"
    }

    enum class Mode { CREATE, RESET, EXISTING }

    class Refused(message: String) : Exception(message)

    sealed class Result {
        class Ok(val capability: ByteArray) : Result()
        object Replayed : Result()
        object WrongPeriod : Result()

        /** A gRPC refusal: [status] is the capture's word (`rejected_token`, `rejected_size`, `unavailable`, `unimplemented`). */
        class Denied(val status: String) : Result() {
            /** The client category of the refusal (`for_relay`). */
            val category: String get() = when (status) {
                REJECTED_TOKEN -> "unauthorized"
                REJECTED_SIZE -> "rejected"
                else -> "relay_unavailable"
            }
        }
    }

    class Answer(val result: Result, val relayPeriod: Long, val relayMinute: Long)

    class Sweep(val closedThrough: Long?, val removed: Int)

    fun redeem(token: ByteArray, namespace: ByteArray, requestId: ByteArray, now: Long): Answer {
        fun answer(r: Result) = Answer(r, Grid.week(now), Math.floorDiv(now, 60L))
        val s = schedule ?: return answer(Result.Denied(UNIMPLEMENTED))
        if (token.size != TestSchedule.TOKEN_BYTES || namespace.size != 32 || requestId.size != 16) return answer(Result.Denied(REJECTED_SIZE))
        if (token[0] != 0.toByte() || token[1] != 2.toByte()) return answer(Result.Denied(REJECTED_TOKEN))
        val k = s.keyById(token.copyOfRange(66, 98))
        if (k == null || k.kind != EntitlementCrypto.KIND_ACCESS) return answer(Result.Denied(REJECTED_TOKEN))
        val p = k.epoch
        if (s.isRevoked(EntitlementCrypto.KIND_ACCESS, p) || !listed(s, slot, p, onion)) return answer(Result.Denied(REJECTED_TOKEN))
        if (disk.closedThrough.let { it != null && p <= it } || !accepts(p, now, s.constants.earlyWindowHours)) return answer(Result.WrongPeriod)
        if (disk.refuseThrough.let { it != null && p <= it }) return answer(Result.Denied(UNAVAILABLE))
        val v = s.verify(token, EntitlementCrypto.KIND_ACCESS, slot)
        if (v == null || v.epoch != p) return answer(Result.Denied(REJECTED_TOKEN))
        val relayKey = key()
        val tag = Bytes.hmac(relayKey, Bytes.ascii("ghost/v1/redeem-binding"), Bytes.u64(p), v.nullifier, byteArrayOf(2), namespace).copyOf(16)
        val row = Bytes.hex(Bytes.u64(p) + v.nullifier)
        when (val existing = disk.rows[row]) {
            null -> {
                disk.rows[row] = Bytes.hex(tag)
                disk.mutations++
            }
            Bytes.hex(tag) -> Unit
            else -> return answer(Result.Replayed)
        }
        return answer(Result.Ok(mint(relayKey, namespace, p, v.nullifier, s.constants.capabilityQuotaBytes)))
    }

    /** One sweep at [now]; null when the clock is below the persisted high-water minute (nothing ran). */
    fun sweep(now: Long): Sweep? {
        val minute = Math.floorDiv(now, 60L)
        val high = disk.sweepHighWater
        if (high != null && minute < high) return null
        disk.sweepHighWater = minute
        val closed = listOfNotNull(disk.closedThrough, closedThrough(now)).maxOrNull()
        disk.closedThrough = closed
        var removed = 0
        if (closed != null) {
            val doomed = disk.rows.keys.filter { ByteBuffer.wrap(Bytes.unhex(it), 0, 8).long <= closed }
            doomed.forEach { disk.rows.remove(it) }
            removed = doomed.size
        }
        disk.mutations++
        return Sweep(closed, removed)
    }

    fun count(): Int = disk.rows.size

    override fun toString(): String = "ModelRedeemRelay(slot $slot)"

    companion object {
        const val REJECTED_TOKEN = "rejected_token"
        const val REJECTED_SIZE = "rejected_size"
        const val UNAVAILABLE = "unavailable"
        const val UNIMPLEMENTED = "unimplemented"
        private const val LATE_WINDOW = 3_600L

        /**
         * Starts a relay (design §10.5, §19.10 point 2, §19.21 point 2): the slot is 0…31 and the
         * schedule lists this onion for it in the current week; the store opens as [mode] says (a
         * missing store of a directory that had one, or [Mode.EXISTING] without one, is refused; a
         * store under another relay key only through a reset, which refuses every period open now).
         * A relay without a [schedule] does not redeem.
         */
        fun open(schedule: TestSchedule?, slot: Int, onion: OnionAddress, key: () -> ByteArray, disk: Disk, mode: Mode, now: Long): ModelRedeemRelay {
            if (schedule != null) {
                if (slot !in 0..31) throw Refused("relay slot must be 0..31")
                if (!listed(schedule, slot, Grid.week(now), onion)) throw Refused("the schedule does not list this onion for its slot now")
                val check = Bytes.hex(Bytes.sha256(Bytes.ascii("relay-key-check"), key())).substring(0, 16)
                when (mode) {
                    Mode.EXISTING -> if (!disk.exists) throw Refused("nullifier store is missing")
                    Mode.CREATE -> if (disk.marker && !disk.exists) throw Refused("nullifier store is missing")
                    Mode.RESET -> Unit
                }
                if (!disk.exists) {
                    disk.exists = true
                    disk.keyCheck = check
                }
                if (disk.keyCheck != check) {
                    if (mode != Mode.RESET) throw Refused("the nullifier store was written under another relay key")
                    disk.keyCheck = check
                }
                if (mode == Mode.RESET) {
                    val refuse = Grid.week(now + schedule.constants.earlyWindowHours * 3_600L)
                    disk.refuseThrough = maxOf(disk.refuseThrough ?: refuse, refuse)
                }
                disk.marker = true
                disk.mutations++
            }
            return ModelRedeemRelay(schedule, slot, onion, key, disk)
        }

        /** The schedule lists the onion with [onion]'s service key for [slot] in [week]. */
        fun listed(schedule: TestSchedule, slot: Int, week: Long, onion: OnionAddress): Boolean =
            schedule.slotOnion(slot, week)?.host == onion.host

        /** `start(p) − early ≤ now < start(p + 1) + 1 h` (design §3.4). */
        fun accepts(p: Long, now: Long, earlyHours: Int): Boolean =
            now >= Grid.start(p) - earlyHours * 3_600L && now < Grid.start(p + 1) + LATE_WINDOW

        /** The last week whose window has closed at [now], or null before any has. */
        fun closedThrough(now: Long): Long? {
            val t = now - LATE_WINDOW
            if (t < Grid.start(1)) return null
            return Grid.week(t) - 1
        }

        /**
         * Capability v2 (design §10.3): `02 ‖ 02 (write) ‖ namespace ‖ quota(8) ‖ expiry(8) ‖
         * serial(16) ‖ mac(32)`, expiry = start(p + 1) + 3600, serial = HMAC(key, "ghost/v1/cap-serial"
         * ‖ p ‖ nullifier)[0..16], mac = HMAC(key, bytes 0..66).
         */
        fun mint(key: ByteArray, namespace: ByteArray, p: Long, nullifier: ByteArray, quota: Long): ByteArray {
            val serial = Bytes.hmac(key, Bytes.ascii("ghost/v1/cap-serial"), Bytes.u64(p), nullifier).copyOf(16)
            val body = byteArrayOf(2, 2) + namespace + Bytes.u64(quota) + Bytes.u64(Grid.start(p + 1) + LATE_WINDOW) + serial
            return body + Bytes.hmac(key, body)
        }

        fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    }
}
