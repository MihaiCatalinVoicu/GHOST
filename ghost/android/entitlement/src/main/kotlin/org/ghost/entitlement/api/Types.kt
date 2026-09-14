package org.ghost.entitlement.api

/** Fixed-size local identifiers of the facade: copied in and out, equal by content, never printed (T3). */
sealed class LocalId(bytes: ByteArray, private val label: String) {
    internal val raw: ByteArray = bytes.copyOf()

    init {
        require(raw.size == SIZE) { "$label has the wrong length" }
    }

    fun toByteArray(): ByteArray = raw.copyOf()

    override fun equals(other: Any?): Boolean = other is LocalId && other.javaClass == javaClass && other.raw.contentEquals(raw)

    override fun hashCode(): Int = raw.contentHashCode()

    override fun toString(): String = "$label(redacted)"

    companion object {
        const val SIZE: Int = 16
    }
}

/** A purchase, trial or refresh flow (16 random bytes, local only, never sent). */
class PurchaseId(bytes: ByteArray) : LocalId(bytes, "PurchaseId")

/** A payout claim (its 16 random bytes are the claim's idempotency key at the issuer). */
class ClaimId(bytes: ByteArray) : LocalId(bytes, "ClaimId")

/** How a pack is paid (design §4.2, §4.6). */
enum class PayWith { XMR, CREDITS }

/** The invite activation of this device (design §8.3). */
enum class ActivationState { NONE, PENDING, ACTIVE, FAILED }

/**
 * What [Entitlement.activate] did: the trial started ([PENDING]), or why the invite was refused
 * before anything was sent (the invite parser's order, design §8.2).
 */
enum class ActivationResult {
    PENDING,
    ALREADY_ACTIVE,
    REFUSED_MALFORMED,
    REFUSED_VERSION,
    REFUSED_SIGNATURE,
    REFUSED_TOKEN,
    REFUSED_EXPIRED,
    REFUSED_REPLAYED,

    /** No accepted schedule or no database yet: nothing was recorded. */
    UNAVAILABLE,
}

/**
 * What [Entitlement.restore] did (design §8.4, §19.26): the identity was restored and its drop scan is
 * owed, installed by the next relay session with a trusted clock ([RESTORED]), or why nothing was
 * recorded.
 */
enum class RestoreResult {
    RESTORED,

    /** An identity exists, or an invite activation is pending ([Entitlement.activationState] is PENDING). */
    ALREADY_ACTIVE,

    /** Not a 24-word GHOST backup (a word outside the list, a wrong checksum or length). */
    REFUSED_MNEMONIC,

    /** No accepted schedule or no database yet. */
    UNAVAILABLE,
}
