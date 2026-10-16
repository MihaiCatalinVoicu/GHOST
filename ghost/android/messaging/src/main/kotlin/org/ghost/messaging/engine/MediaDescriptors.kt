package org.ghost.messaging.engine

import org.ghost.media.store.MediaDescriptor
import org.ghost.media.store.MediaKind

/**
 * The kind-5 L0's descriptor body (§4.1), parsed on the recipient: `d_version(1) || kind(1) ||
 * flags(1) || class(1) || object_id(16) || key_slot(32) || manifest_hash(32) || caption_len(2) ||
 * caption`. The sender's builder is [MediaSteps.descriptorBody]; this parser is its mirror and
 * the two are kept next to each other so a layout change cannot touch one and miss the other.
 *
 * The parse is fail-closed: anything outside the fixed shape is null, which `RECV` drops as bad
 * content before any row exists. The key slot must be zero — §4.2: only `encrypt` fills it, and
 * only `decrypt`/`sessionInbound` empty it, so a non-zero slot here means a peer (or a bug)
 * shipped the file key in the clear and the message is refused whole.
 */
internal object MediaDescriptors {

    /** A parsed descriptor: the store's fields and the caption the message row carries. */
    class Parsed(
        val store: MediaDescriptor,
        val caption: ByteArray,
    ) {
        override fun toString(): String = "Parsed(${store.kind}, class=${store.classCode})"
    }

    const val VERSION: Int = 1
    const val HEADER_BYTES: Int = 86
    const val CAPTION_MAX_BYTES: Int = 1_024

    private const val OFFSET_VERSION: Int = 0
    private const val OFFSET_KIND: Int = 1
    private const val OFFSET_FLAGS: Int = 2
    private const val OFFSET_CLASS: Int = 3
    private const val OFFSET_OBJECT_ID: Int = 4
    private const val OFFSET_KEY_SLOT: Int = 20
    private const val OFFSET_MANIFEST_HASH: Int = 52
    private const val OFFSET_CAPTION_LEN: Int = 84
    private const val OFFSET_CAPTION: Int = 86

    private const val OBJECT_ID_BYTES: Int = 16
    private const val KEY_SLOT_BYTES: Int = 32
    private const val MANIFEST_HASH_BYTES: Int = 32
    private const val FLAG_VIEW_ONCE: Int = 1

    /** The fail-closed parse; null for every shape outside §4.1. */
    fun parse(body: ByteArray): Parsed? {
        if (body.size < HEADER_BYTES) return null
        if (body[OFFSET_VERSION].toInt() != VERSION) return null
        val kind = when (body[OFFSET_KIND].toInt()) {
            MediaKind.IMAGE.code -> MediaKind.IMAGE
            MediaKind.VIDEO.code -> MediaKind.VIDEO
            else -> return null
        }
        val flags = body[OFFSET_FLAGS].toInt()
        if (flags and FLAG_VIEW_ONCE.inv() != 0) return null
        val classCode = body[OFFSET_CLASS].toInt()
        if (classCode !in 0..org.ghost.media.send.MediaSendLimits.MAX_CLASS) return null
        if (kind == MediaKind.IMAGE && classCode != 0) return null // every image is class 0 (§13.6)
        for (i in OFFSET_KEY_SLOT until OFFSET_KEY_SLOT + KEY_SLOT_BYTES) {
            if (body[i].toInt() != 0) return null // the slot crosses in clear only as zero (§4.2)
        }
        val captionLen = ((body[OFFSET_CAPTION_LEN].toInt() and 0xFF) shl 8) or
            (body[OFFSET_CAPTION_LEN + 1].toInt() and 0xFF)
        if (captionLen > CAPTION_MAX_BYTES) return null
        if (body.size != OFFSET_CAPTION + captionLen) return null
        val objectId = body.copyOfRange(OFFSET_OBJECT_ID, OFFSET_OBJECT_ID + OBJECT_ID_BYTES)
        val manifestHash = body.copyOfRange(OFFSET_MANIFEST_HASH, OFFSET_MANIFEST_HASH + MANIFEST_HASH_BYTES)
        val caption = body.copyOfRange(OFFSET_CAPTION, body.size)
        val store = try {
            MediaDescriptor(objectId, kind, flags and FLAG_VIEW_ONCE != 0, classCode, manifestHash)
        } catch (e: org.ghost.media.store.MediaStoreException) {
            return null // a CHECK the store owns refused the field: bad content, not a crash
        }
        return Parsed(store, caption)
    }
}
