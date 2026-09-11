package org.ghost.sync.engine

import org.ghost.sync.api.RelayId
import org.ghost.sync.port.PairKey
import org.ghost.sync.port.RandomSources
import org.ghost.sync.port.SchedulePurpose
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * [RandomSources] as HmacSHA256 over a 32-byte key (design §1.6, §11.3). Production uses the
 * no-argument constructor: the key comes from [SecureRandom], lives only in this object for the
 * life of the process, and is never exposed or persisted. Tests fix the key to compare runs (T19).
 *
 * Every value is `HMAC(key, domain ‖ fields)` mapped to [0, 1) from its first 53 bits. The
 * schedule and read-breaker values are pure functions of the key and their arguments; the
 * send-delay and selection streams are counters of their own, so draws on one stream never shift
 * another.
 */
class KeyedRandomSources(key: ByteArray = freshKey()) : RandomSources {
    private val keySpec: SecretKeySpec

    init {
        require(key.size == KEY_SIZE) { "schedule key has the wrong length" }
        keySpec = SecretKeySpec(key.copyOf(), ALGORITHM)
    }

    private val mac: ThreadLocal<Mac> = ThreadLocal.withInitial { Mac.getInstance(ALGORITHM).apply { init(keySpec) } }
    private val sendDelayCounter = AtomicLong()
    private val selectionCounter = AtomicLong()

    override fun schedule(pair: PairKey, purpose: SchedulePurpose, index: Long): Double =
        unit(DOMAIN_SCHEDULE, purposeCode(purpose), pair.relayId.value, pair.namespace.raw, index)

    override fun readBreaker(relay: RelayId, index: Long): Double = unit(DOMAIN_READ_BREAKER, 0, relay.value, EMPTY, index)

    override fun sendDelay(): Double = unit(DOMAIN_SEND_DELAY, 0, 0, EMPTY, sendDelayCounter.getAndIncrement())

    override fun selection(): Double = unit(DOMAIN_SELECTION, 0, 0, EMPTY, selectionCounter.getAndIncrement())

    private fun unit(domain: Byte, purpose: Byte, relay: Long, namespace: ByteArray, index: Long): Double {
        val input = ByteBuffer.allocate(1 + 1 + 8 + 1 + namespace.size + 8)
            .put(domain).put(purpose).putLong(relay).put(namespace.size.toByte()).put(namespace).putLong(index)
            .array()
        val out = checkNotNull(mac.get()) { "no mac" }.doFinal(input)
        val bits = ByteBuffer.wrap(out, 0, 8).long ushr 11
        return bits * TWO_POW_MINUS_53
    }

    /** Never shows the key (T3). */
    override fun toString(): String = "KeyedRandomSources(redacted)"

    companion object {
        const val KEY_SIZE: Int = 32
        private const val ALGORITHM = "HmacSHA256"
        private const val TWO_POW_MINUS_53: Double = 1.0 / (1L shl 53)
        private val EMPTY = ByteArray(0)
        private const val DOMAIN_SCHEDULE: Byte = 1
        private const val DOMAIN_READ_BREAKER: Byte = 2
        private const val DOMAIN_SEND_DELAY: Byte = 3
        private const val DOMAIN_SELECTION: Byte = 4

        private fun purposeCode(purpose: SchedulePurpose): Byte = when (purpose) {
            SchedulePurpose.FOREGROUND_START -> 1
            SchedulePurpose.FOREGROUND_STEP -> 2
            SchedulePurpose.BACKGROUND_OFFSET -> 3
            SchedulePurpose.ROUND_ROBIN -> 4
        }

        private fun freshKey(): ByteArray = ByteArray(KEY_SIZE).also { SecureRandom().nextBytes(it) }
    }
}
