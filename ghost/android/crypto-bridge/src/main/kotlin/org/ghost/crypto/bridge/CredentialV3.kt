package org.ghost.crypto.bridge

import java.security.MessageDigest

/**
 * The bearer credential v3 and its verifier (Phase 9 design §4.3, as corrected by §21.2 and
 * §22.8.7).
 *
 * ```
 * credential (67 bytes) = version(1) = 3 || kind(1) || slot(1) || namespace(32) || secret(32)
 * verifier   (32 bytes) = SHA-256(label(kind) || u8(slot) || namespace(32) || secret(32))
 * ```
 *
 * **Why the two are different shapes.** The credential is what a client *presents*; the verifier is
 * what the owner *registers* (`RegisterKey`, §4.4) and all the relay ever stores. A relay that is
 * seized holds hashes of secrets it does not have (§4.6 "Privacy at rest").
 *
 * **Why it carries no MAC.** Its authority is the registered verifier, nothing else. That makes it
 * **deterministic**: every presenter of the same secret at the same relay sends identical bytes, so
 * `capability_scope = SHA-256(credential)` is one value per (relay, namespace, kind) for every
 * depositor of an inbox or every fetcher of a bundle, in every week (P-2, §21.2). A credential that
 * varied per sender or per week would be a sender field in substance.
 *
 * **Why the slot and not the relay.** The verifier names the relay's ES **slot number**, so a relay
 * cannot replay a secret it saw at the relays of other slots (§4.3). The residue that an operator
 * which held slot s keeps its rights at the slot's successor relay is declared as L7-D26.
 *
 * **No week anywhere.** §21.2 moved the week out of the credential and into the registration
 * period: the credential is static per (card, relay slot, kind), which is what makes the scope one
 * value across weeks. A `week` parameter here would be mutant PM-27/PM-28 territory.
 *
 * Placement: `:crypto-bridge` per §13.1, which lists the "CredentialV3 builder and verifier" among
 * this module's contents. **Recorded deviation (S6):** the functions take raw bytes (a namespace as
 * 32 bytes, a slot as an int) rather than `:sync`'s `NamespaceId`/`RelayId`, because this module
 * has no production dependency at all and §22.9 item 3 fixed that as the rule — the same reason
 * `DmSessions` takes row values instead of a transaction. `:messaging` does the type mapping.
 */
object CredentialV3 {

    /** The on-the-wire length of a credential v3 (§4.3). */
    const val CREDENTIAL_BYTES: Int = 67

    /** The length of a verifier, which is a SHA-256 digest. */
    const val VERIFIER_BYTES: Int = 32

    /** The length of a namespace id and of a registered secret. */
    const val SECRET_BYTES: Int = 32

    /** The version byte every credential v3 starts with. */
    const val VERSION: Int = 3

    /**
     * What a credential authorizes. The codes are the wire bytes of §4.3; `0x02` is deliberately
     * absent — it is Write in capability headers and is never a key kind, which is the "unknown
     * kind 0x02" row of the T21 refused-token matrix (§4.3).
     */
    enum class Kind(
        /** The `kind` byte of the credential. */
        val code: Int,
        /** The verifier's domain-separation label (§4.3). */
        val label: String,
    ) {
        /** `list`, `get`, `check` on the owner's own inbox. The D11 key: seed-derived (§3.1). */
        READ(0x01, "ghost/v1/read-verifier"),

        /** `store` and `check` only. Card-derived, so every contact of a card presents one value. */
        DEPOSIT(0x03, "ghost/v1/deposit-verifier"),

        /** `list` and `get` on a bundle namespace, with week-coarse times (§22.8.7). */
        FETCH(0x04, "ghost/v1/fetch-verifier"),
    }

    /**
     * The 67 credential bytes. [slot] is the relay's ES slot number, which must fit one byte: a
     * wider value would be silently truncated into a credential no relay accepts.
     */
    fun credential(kind: Kind, slot: Int, namespace: ByteArray, secret: ByteArray): ByteArray {
        require(slot in 0..255) { "slot is not a byte" }
        require(namespace.size == SECRET_BYTES) { "namespace has the wrong length" }
        require(secret.size == SECRET_BYTES) { "secret has the wrong length" }
        val out = ByteArray(CREDENTIAL_BYTES)
        out[0] = VERSION.toByte()
        out[1] = kind.code.toByte()
        out[2] = slot.toByte()
        namespace.copyInto(out, 3)
        secret.copyInto(out, 35)
        return out
    }

    /**
     * `SHA-256(label(kind) || u8(slot) || namespace || secret)`: the 32 bytes the owner registers
     * with `RegisterKey` and that the relay checks a presented credential against.
     *
     * The label is hashed as its ASCII bytes with no separator and no length prefix, exactly as
     * §4.3 writes it; the three labels have no common prefix, so no two kinds can collide.
     */
    fun verifier(kind: Kind, slot: Int, namespace: ByteArray, secret: ByteArray): ByteArray {
        require(slot in 0..255) { "slot is not a byte" }
        require(namespace.size == SECRET_BYTES) { "namespace has the wrong length" }
        require(secret.size == SECRET_BYTES) { "secret has the wrong length" }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(kind.label.toByteArray(Charsets.US_ASCII))
        digest.update(slot.toByte())
        digest.update(namespace)
        digest.update(secret)
        return digest.digest()
    }

    /**
     * `SHA-256(credential)`: the `capability_scope` a relay captures for a presented credential
     * (§4.7). Computed here so a test can assert the P-2 property — that two different card holders
     * of the same card produce the **same** scope — without reimplementing the hash.
     */
    fun scope(credential: ByteArray): ByteArray {
        require(credential.size == CREDENTIAL_BYTES) { "credential has the wrong length" }
        return MessageDigest.getInstance("SHA-256").digest(credential)
    }
}
