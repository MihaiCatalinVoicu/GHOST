package org.ghost.messaging.port

/**
 * The ports of the DM engine (Phase 9 design §13.1, §13.7). Production wiring is `:app`'s
 * `MessagingWiring` (slice S12); the JVM tests of this module supply deterministic fakes, which is
 * what makes the owner steps of §7.2 reproducible in a seeded world.
 */

/**
 * The two clocks the DM engine reads. Neither is ever read inside `ghost-client-dm`, which has no
 * clock at all (G-R8): every time value crosses the JNI boundary as an argument.
 */
interface DmClock {
    /**
     * Wall clock, in unix seconds. Everything the DM tables store is floored or ceiled from this
     * onto the minute, hour or day grid of `DmTime` (T13).
     */
    fun nowEpochSeconds(): Long

    /**
     * Elapsed realtime, in milliseconds: the clock `ConsumerTail`'s deadline is on (§13.3 item 6).
     *
     * It is a **separate** clock because a wall clock can step and a deadline cannot: the tail
     * must return by the job's end whatever the user did with the system time. `:app` wires one
     * object to this and to `:sync`'s `SyncClock`, so both see one elapsed-realtime source.
     */
    fun monotonicMillis(): Long
}

/** The CSPRNG of the DM layer. Generation ids, operation ids and the two device keys come from it. */
interface DmRandom {
    fun bytes(count: Int): ByteArray

    /** A `u32`, for `gen_id` (§3.1 "Random, never derived"). */
    fun u32(): Long {
        val b = bytes(4)
        var v = 0L
        for (byte in b) v = (v shl 8) or (byte.toLong() and 0xff)
        return v
    }
}

/**
 * The Keystore wrapper of a 32-byte device key (§2.5, §13.8, C-23): `content_key` and
 * `session_state_key` are stored in `dm_self` wrapped by a non-exportable Keystore key with the
 * database key's authentication policy, and unwrapped only into the native DM context at unlock.
 *
 * The schema admits a wrapped key of 40..256 bytes, which is what an AES-GCM wrap of 32 bytes
 * with its IV and tag costs; the port therefore returns bytes, not a fixed length.
 *
 * The device implementations are `KeystoreContentKeyWrapper` and `KeystoreStateKeyWrapper` of
 * §13.1's `…messaging.android` package (slice S12); the JVM tests use an in-memory implementation,
 * which is the "JVM tests use an in-memory wrapper port" of §13.8.
 */
interface KeyWrapper {
    /** Wraps a freshly generated 32-byte device key for `dm_self`. */
    fun wrap(key: ByteArray): ByteArray

    /**
     * Unwraps a stored column back into the 32 bytes the DM context is opened with.
     *
     * Throws [IllegalArgumentException] — and nothing else — when the column does not open here:
     * a corrupted envelope, a Keystore key a device reset deleted, an authentication-bound key
     * outside its window. Callers read that as "the key is not available" (`CRYPTO_UNAVAILABLE`),
     * never as a crash.
     */
    fun unwrap(wrapped: ByteArray): ByteArray
}

/**
 * The ES slot table, as the owner steps need it (§5.2): for an ISO week, which relay of the local
 * directory serves each slot and who operates it.
 *
 * **Why a port and not a call into `:entitlement`.** The signed entitlement schedule is Phase 8
 * state and `:messaging` does not depend on `:entitlement` (§13.1's dependency column). `:app`
 * wires this to the schedule summary the entitlement engine already holds, exactly as it wires the
 * activation hook in the other direction (§13.4).
 */
fun interface EsSlots {
    /**
     * The slots valid in [week], each with the relay id of the active directory entry serving it
     * and that relay's operator id. A slot no active relay serves is left out; an empty list means
     * the owner cannot compute a set this week and the step makes no change.
     */
    fun slotsInWeek(week: Long): List<EsSlot>
}

/** One ES slot of a week: the slot number credentials are bound to, its relay and its operator. */
class EsSlot(val slot: Int, val relay: org.ghost.sync.api.RelayId, operatorId: ByteArray) {
    private val operator: ByteArray = operatorId.copyOf()

    init {
        require(slot in 0..255) { "slot is not a byte" }
        require(operatorId.isNotEmpty()) { "operator id is empty" }
    }

    val operatorId: ByteArray get() = operator.copyOf()

    /** Never shows the operator id or the relay (T3). */
    override fun toString(): String = "EsSlot(redacted)"
}

/**
 * The open DM context (§2.5): the native handle `ghost-client-dm` holds the MESSAGING branch, the
 * `ghost1` seed and the `session_state_key` behind.
 *
 * `null` means the context is closed — locked, wiped, or the library did not load — which every
 * caller turns into `CRYPTO_UNAVAILABLE` and never into a crash loop (§13.2).
 */
interface DmContext {
    fun handleOrNull(): Long?

    /**
     * The **wrapped** `session_state_key` this context was opened with (§2.5), for `dm_self` at
     * ACTIVATE.
     *
     * **Recorded deviation (S6).** §3.1 puts the creation of `session_state_key` at "ACTIVATE or
     * restore". The bytes are created where the context is opened, because that is the one place
     * that needs them in clear, and ACTIVATE persists them: the step decides *when* the key
     * becomes the identity's, and never holds it. A raw key passed through the step's frame would
     * be a copy on the JVM heap that §2.5 exists to avoid.
     *
     * Null when the context is closed, like [handleOrNull].
     */
    fun stateKeyWrapped(): ByteArray?
}
