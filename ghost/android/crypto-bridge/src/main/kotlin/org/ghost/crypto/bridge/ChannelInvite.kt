package org.ghost.crypto.bridge

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.text.Normalizer

/**
 * The channel invite's link codec (Phase 10 design §5.9, §19.28.3 corrected by §19.29.3): a
 * `ChannelInviteV2` is 335 bytes, and its link is `ghost://channel/` followed by the bytes in
 * lowercase unpadded base32 (RFC 4648 alphabet), 552 characters. This wraps the transport form
 * only: the invite's contents are opened, checked and parsed natively (`inviteParse`, fn 14), and
 * nothing here reads a field — except [needsPassword], the one header bit a link shows anyway,
 * because the client has to know whether to ask for a password before it runs Argon2id
 * (§19.29.3: "the cleartext `kdf_code` tells any link holder whether a password is needed").
 */
object ChannelInvite {

    /** The link prefix of §5.9. */
    const val LINK_PREFIX: String = "ghost://channel/"

    /** Every `ChannelInviteV2` is this long (§19.29.3, open and password, any name). */
    const val INVITE_BYTES: Int = 335

    /** A link's length: the prefix and 536 base32 characters (2 680 bits, no padding). */
    const val LINK_CHARS: Int = 552

    /** The `kdf_code` of the P0 password profile (Argon2id, 64 MiB, t = 1, p = 4; §19.28.5). */
    const val KDF_ARGON2ID_P0: Int = 1

    private const val ALPHABET: String = "abcdefghijklmnopqrstuvwxyz234567"

    /** The link of an invite's bytes. */
    fun toLink(invite: ByteArray): String {
        require(invite.size == INVITE_BYTES) { "an invite is $INVITE_BYTES bytes" }
        val out = StringBuilder(LINK_CHARS)
        out.append(LINK_PREFIX)
        var buffer = 0
        var bits = 0
        for (b in invite) {
            buffer = (buffer shl 8) or (b.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                out.append(ALPHABET[(buffer ushr (bits - 5)) and 0x1f])
                bits -= 5
            }
        }
        if (bits > 0) out.append(ALPHABET[(buffer shl (5 - bits)) and 0x1f])
        return out.toString()
    }

    /**
     * The invite bytes of a link, or `null` for anything that is not exactly a canonical link: the
     * prefix and 536 characters of the lowercase alphabet, which carry exactly the 335 bytes.
     */
    fun fromLink(link: String): ByteArray? {
        if (link.length != LINK_CHARS || !link.startsWith(LINK_PREFIX)) return null
        val out = ByteArray(INVITE_BYTES)
        var buffer = 0
        var bits = 0
        var n = 0
        for (i in LINK_PREFIX.length until link.length) {
            val v = ALPHABET.indexOf(link[i])
            if (v < 0) return null
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                if (n == INVITE_BYTES) return null
                out[n++] = (buffer ushr (bits - 8)).toByte()
                bits -= 8
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (n != INVITE_BYTES || buffer != 0) return null
        return out
    }

    /**
     * Whether the invite asks for a password: its header's `kdf_code` (byte 1) is not 0. A link
     * whose header the native parser would refuse answers `false` here and `NON_CANONICAL` there.
     */
    fun needsPassword(invite: ByteArray): Boolean = invite.size == INVITE_BYTES && invite[0].toInt() == 2 &&
        invite[1].toInt() != 0
}

/**
 * The channel password as it crosses the JNI boundary (§10.2 fn 14, §19.29.3): the NFKD UTF-8
 * bytes of what the user typed, built from a `CharArray` — never a `String`, which is immutable
 * and cannot be zeroed — and zeroed by the facade after the native call.
 */
object ChannelPassword {

    /**
     * The NFKD form of [password], UTF-8 encoded, in an array the caller zeroes after use.
     *
     * NFKD of ASCII is ASCII, so an ASCII password (the app-generated passphrase Q44 proposes) never
     * becomes a `String`. Any other password goes through `java.text.Normalizer`, which accepts a
     * `CharSequence` but returns a `String`: that one normalized copy is immutable and stays on the
     * heap until the collector reclaims it — the JDK offers no normalizer into a caller's buffer,
     * and the native side has no Unicode tables (a recorded residue, §19.32). An unpaired surrogate
     * is refused (`null`) rather than replaced, so two different typed passwords never encode alike.
     */
    fun nfkdUtf8(password: CharArray): ByteArray? {
        var i = 0
        while (i < password.size) {
            val c = password[i]
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= password.size || !Character.isLowSurrogate(password[i + 1])) return null
                i += 2
            } else if (Character.isLowSurrogate(c)) {
                return null
            } else {
                i += 1
            }
        }
        val ascii = password.all { it.code < 0x80 }
        val chars: CharBuffer = if (ascii) {
            CharBuffer.wrap(password)
        } else {
            CharBuffer.wrap(Normalizer.normalize(CharBuffer.wrap(password), Normalizer.Form.NFKD))
        }
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val encoded: ByteBuffer = encoder.encode(chars)
        val out = ByteArray(encoded.remaining())
        encoded.get(out)
        if (encoded.hasArray()) encoded.array().fill(0)
        return out
    }
}
