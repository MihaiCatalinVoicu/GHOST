package org.ghost.media.store

/**
 * The media stores of `:media` (Phase 11 design §13.1, `org.ghost.media.store`: "`MediaObjects`, the tables, `CiphertextFiles`,
 * reconcile"), in one place for the transactions that slices S5 to S8 build.
 *
 * Nothing here is a second source of truth: each store is stateless and holds no connection, and every method takes the
 * `SqlExecutor` of a read or the `SyncTransaction` of a write from its caller (§13.5: each transaction is exactly one
 * `SyncDatabase.transaction`). The tables each store owns:
 *
 * | Store | Tables |
 * |---|---|
 * | [objects] | `media_object`, `media_upload` |
 * | [fragments] | `media_fragment`, `media_outbound_op` |
 * | [blobs] | `media_blob` |
 *
 * The files are [CiphertextFiles]'s, and [MediaReconcile] makes the two agree.
 */
class MediaStores {
    val fragments = MediaFragments()
    val blobs = MediaBlobs(fragments)
    val objects = MediaObjects(fragments)

    override fun toString(): String = "MediaStores"
}
