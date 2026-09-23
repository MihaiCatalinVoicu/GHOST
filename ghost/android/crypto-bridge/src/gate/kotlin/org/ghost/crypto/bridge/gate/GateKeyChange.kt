package org.ghost.crypto.bridge.gate

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * **The debug key-change hook** (Phase 9 design §15.1 "Debug key-change hook", §15.10 step 5,
 * §21.13 point 7; slice S12). `gate` build type only: this source set is compiled into the `gate`
 * variant and into nothing else, and gate G-DM5 (`apk-no-debug-hooks.sh`) fails if this class, or a
 * reference to it, reaches a release source set or R8's release mapping.
 *
 * > a DM context whose Olm identity differs from the derived one but is bound by its real Ed25519
 * > key (the "stolen seed on a modified client" scenario).
 *
 * It is exactly that and nothing more: the MESSAGING branch the DM context is opened with is
 * replaced by `HMAC-SHA256(key = m, "ghost/v1/gate/key-change")`, while the `ghost1` identity seed is
 * left alone. Every value §3.1 derives from `m` changes with it — the Olm identity, `card_secret_0`,
 * `X_0`, `P_0`, the read secrets — and the Ed25519 key that signs binding v3 does not, so a contact
 * that pinned the old Olm identity sees a **validly bound** new one: §8.3's key change, not a
 * forgery. The derivation is fixed, so the "new" identity is the same one at every switch, and
 * switching back restores the derived one.
 *
 * It lives in `:crypto-bridge`'s `gate` source set because §21.13 point 7 puts it there (a G-R6
 * exception for that source set); it references no native method.
 */
object GateKeyChange {
    /** The HMAC input that names the alternate branch. */
    const val LABEL: String = "ghost/v1/gate/key-change"

    /** The alternate MESSAGING branch for [branch]; [branch] is left untouched. */
    fun alternateBranch(branch: ByteArray): ByteArray {
        require(branch.size == BRANCH_BYTES) { "a MESSAGING branch is 32 bytes" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(branch, "HmacSHA256"))
        return mac.doFinal(LABEL.toByteArray(Charsets.US_ASCII))
    }

    private const val BRANCH_BYTES = 32
}
