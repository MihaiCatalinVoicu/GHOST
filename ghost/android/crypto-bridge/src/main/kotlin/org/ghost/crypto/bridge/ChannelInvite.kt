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
 * bytes of what the user typed, built from a `CharArray` — never a `String` of our own, which is
 * immutable and cannot be zeroed — and zeroed by the facade after the native call
 * ([withNfkdUtf8]).
 */
object ChannelPassword {

    /** The most UTF-8 bytes one UTF-16 unit needs (a surrogate pair's two units make four). */
    private const val UTF8_MAX_BYTES_PER_CHAR: Int = 3

    /**
     * The NFKD form of [password], UTF-8 encoded, in an array the caller zeroes after use.
     *
     * NFKD of ASCII is ASCII, so an ASCII password (the app-generated passphrase Q44 proposes) is
     * encoded straight from the caller's array and leaves no copy behind. Any other password goes
     * through `java.text.Normalizer`, and **its copies are a recorded residue** (§19.36; measured
     * by the review of S2b with heap dumps, HotSpot 17): `normalize` turns its `CharSequence` into a
     * `String` of the typed password (JDK 17 calls `toString()` on it) and builds the NFKD form in a
     * builder and a result `String` — immutable copies that stay on the heap until the collector
     * reclaims them. The JDK has no normalizer into a caller's buffer, and the native side has no
     * Unicode tables. The encoding itself leaves nothing: it writes into a buffer sized for the
     * worst case and zeroed after ([encodeUtf8]; the JDK encoder's own buffer grew and dropped the
     * outgrown one unzeroed). An unpaired surrogate is refused (`null`) rather than replaced, so two
     * different typed passwords never encode alike.
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
        return encodeUtf8(chars, ByteBuffer.allocate(UTF8_MAX_BYTES_PER_CHAR * chars.remaining()))
    }

    /**
     * Runs [call] with the NFKD UTF-8 bytes of [password] and zeroes them afterwards, however
     * [call] ends — what the facade hands `inviteBuild` and `inviteParse`; `null`, with no call, for
     * a password [nfkdUtf8] refuses. [password] itself stays the caller's.
     */
    internal inline fun <T : Any> withNfkdUtf8(password: CharArray, call: (ByteArray) -> T): T? {
        val bytes = nfkdUtf8(password) ?: return null
        try {
            return call(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * [chars] as UTF-8, copied out at its exact length, through [scratch] — a heap buffer of at least
     * [UTF8_MAX_BYTES_PER_CHAR] bytes per char, so the encoder never grows it — which is zeroed
     * however the encoding ends. `null` for input UTF-8 cannot encode, or a [scratch] too small.
     */
    internal fun encodeUtf8(chars: CharBuffer, scratch: ByteBuffer): ByteArray? {
        try {
            val encoder = Charsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            if (!encoder.encode(chars, scratch, true).isUnderflow) return null
            if (!encoder.flush(scratch).isUnderflow) return null
            val out = ByteArray(scratch.position())
            scratch.flip()
            scratch.get(out)
            return out
        } finally {
            scratch.array().fill(0)
        }
    }
}
