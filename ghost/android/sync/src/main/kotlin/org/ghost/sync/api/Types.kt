package org.ghost.sync.api

/**
 * Fixed-size opaque identifiers of the sync layer (design §9). Bytes are copied in and out, equality
 * is by content, and `toString()` never shows the bytes (T3). Length errors carry a constant message.
 */
sealed class OpaqueId(bytes: ByteArray, size: Int, private val label: String) {
    internal val raw: ByteArray

    init {
        require(bytes.size == size) { "$label has the wrong length" }
        raw = bytes.copyOf()
    }

    fun toByteArray(): ByteArray = raw.copyOf()

    override fun equals(other: Any?): Boolean =
        other is OpaqueId && other.javaClass == javaClass && other.raw.contentEquals(raw)

    override fun hashCode(): Int = raw.contentHashCode()

    override fun toString(): String = "$label(redacted)"
}

/** Caller-chosen idempotency key of an outbound blob; 16 bytes. Never leaves the device (T1). */
class OperationId(bytes: ByteArray) : OpaqueId(bytes, SIZE, "OperationId") {
    companion object { const val SIZE: Int = 16 }
}

/** Relay namespace; 32 bytes. */
class NamespaceId(bytes: ByteArray) : OpaqueId(bytes, SIZE, "NamespaceId") {
    companion object { const val SIZE: Int = 32 }
}

/** SHA-256 of a ciphertext; 32 bytes. */
class BlobHash(bytes: ByteArray) : OpaqueId(bytes, SIZE, "BlobHash") {
    companion object { const val SIZE: Int = 32 }
}

/** Local row id of a relay in the directory. It is a local handle, never sent anywhere. */
@JvmInline
value class RelayId(val value: Long) {
    override fun toString(): String = "RelayId(redacted)"
}

/** Relay TTL buckets; the relay rounds the expiry up to the hour. */
enum class TtlBucket(val seconds: Int) {
    DAY_1(86_400), DAYS_7(604_800), DAYS_30(2_592_000), DAYS_90(7_776_000);

    val days: Long get() = seconds / 86_400L

    companion object {
        internal fun ofSeconds(seconds: Long): TtlBucket =
            entries.firstOrNull { it.seconds.toLong() == seconds } ?: throw IllegalStateException("unknown ttl bucket")
    }
}

/** Ciphertext bucket sizes (T9); the schema CHECK and the Rust core enforce the same set. */
object Buckets {
    val SIZES: Set<Int> = setOf(1024, 4096, 16384, 65536)
}

/** Which later phase consumes a namespace's blobs and outcomes. */
enum class Consumer(val code: String) {
    DM("dm"), PREKEYS("prekeys"), CHANNEL("channel"), MEDIA("media"), IDENTITY("identity");

    companion object {
        internal fun ofCode(code: String): Consumer =
            entries.firstOrNull { it.code == code } ?: throw IllegalStateException("unknown consumer")
    }
}

enum class CapabilityKind(internal val code: String) {
    READ("read"), WRITE("write");

    companion object {
        internal fun ofCode(code: String): CapabilityKind =
            entries.firstOrNull { it.code == code } ?: throw IllegalStateException("unknown capability kind")
    }
}

/** Global privacy mode (default STANDARD until the Phase 13 UI, design §11.1). */
enum class PrivacyMode { STANDARD, HIGH }

/**
 * Per-namespace override of the HIGH-mode send delay (design §11.2 #15): DEFAULT follows the global
 * mode (delay in HIGH, none in STANDARD), ON always delays, OFF never delays.
 */
enum class SendDelay(internal val code: String) {
    DEFAULT("default"), ON("on"), OFF("off");

    companion object {
        internal fun ofCode(code: String): SendDelay =
            entries.firstOrNull { it.code == code } ?: throw IllegalStateException("unknown send delay")
    }
}

/** Decided outcome of an outbound operation (design D5, OUT-4). */
enum class Outcome(internal val code: String) {
    /** At least the required number of distinct operators showed the hash after a receipt. */
    SENT("sent"),

    /** At least one verified copy, under quorum. Do not resend. */
    DEGRADED("degraded"),

    /** No store attempt could have left a copy anywhere; re-encrypting and resending is safe. */
    FAILED("failed"),

    /** A copy may exist or may have existed; resend only the identical bytes, after release. */
    INDETERMINATE("indeterminate");

    companion object {
        internal fun ofCode(code: String): Outcome? = entries.firstOrNull { it.code == code }
    }
}

/** Enqueue refused: the namespace's active relays belong to fewer than two distinct operators (ADR-11). */
class InsufficientReplicasException : IllegalStateException("fewer than two distinct relay operators")
