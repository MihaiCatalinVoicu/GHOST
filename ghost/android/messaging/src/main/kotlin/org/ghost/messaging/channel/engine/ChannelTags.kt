package org.ghost.messaging.channel.engine

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The keyed dedup tags of the channel tables (Phase 10 design §9): `ch_seen.tag = HMAC(local key, op_id)[0..16]`
 * (§6.3.4 layer 4, "the `dm_seen` pattern") and `ch_kp_seen.tag = HMAC(local key, kp_ref ‖ init_key)[0..16]`
 * (§6.2.4 (B)). The local key is the random seen key of `dm_self` (F9 §7.6), never derived and never sent; a tag stays in
 * the local database, so a seized device shows which ids it saw only to someone who also has the key.
 *
 * **The channel is part of the input**, and a one-byte domain separates the two tags: an op id reused in another channel,
 * or a KeyPackage reference equal to an op id, is another tag. No `ghost/v1/ch…` label is needed (G-M3 rule 4).
 *
 * **The author is part of the op tag** (§19.38): an op id is the author's to choose, so layer 4 remembers which author
 * used it. The same author's second copy — a re-encryption after FAILED keeps its op id — is the duplicate layer 4 drops;
 * another author's reuse of the id reaches the insert, which keeps the first holder and counts the clash (§19.35 F-10)
 * instead of calling it a duplicate. (§9 wrote the tag over the op id alone; the tag stays 16 bytes, local and unsent.)
 *
 * **What the KeyPackage tag covers (finding F-S4-4 of §19.37).** `joinVerify` (§10.2 fn 15) returns the KeyPackage's
 * reference and not its init key, so the tag is over `kp_ref` alone: a KeyPackage seen before is refused, a new
 * KeyPackage that reuses an init key is not. `kp_ref` is the hash of the whole KeyPackage, init key included.
 */
internal object ChannelTags {

    /** The tag length of both tables. */
    const val TAG_BYTES: Int = 16

    private const val DOMAIN_OP: Byte = 1
    private const val DOMAIN_KEY_PACKAGE: Byte = 2

    /** `ch_seen.tag` of [author]'s op id [opId] in [channelId]. */
    fun opTag(seenKey: ByteArray, channelId: ByteArray, author: ByteArray, opId: ByteArray): ByteArray =
        mac(seenKey, byteArrayOf(DOMAIN_OP) + channelId + author + opId)

    /** `ch_kp_seen.tag` of the KeyPackage [kpRef] in [channelId]. */
    fun keyPackageTag(seenKey: ByteArray, channelId: ByteArray, kpRef: ByteArray): ByteArray =
        mac(seenKey, byteArrayOf(DOMAIN_KEY_PACKAGE) + channelId + kpRef)

    private fun mac(seenKey: ByteArray, input: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(seenKey, "HmacSHA256"))
        return mac.doFinal(input).copyOf(TAG_BYTES)
    }
}
