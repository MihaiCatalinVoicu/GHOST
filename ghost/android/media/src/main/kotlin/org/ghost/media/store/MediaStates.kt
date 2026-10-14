package org.ghost.media.store

/** Whether an object is ours (we uploaded it) or theirs (we download it): `media_object.role`. */
enum class MediaRole(val code: String) {
    OUT("out"),
    IN("in"),
    ;

    companion object {
        fun of(code: String): MediaRole = entries.firstOrNull { it.code == code } ?: throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_object.role")
    }
}

/** What the object is: `media_object.kind` (§3: an image is always class 0, a video any class). */
enum class MediaKind(val code: Int) {
    IMAGE(1),
    VIDEO(2),
    ;

    companion object {
        fun of(code: Int): MediaKind = entries.firstOrNull { it.code == code } ?: throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_object.kind")
    }
}

/**
 * The twelve states of an object (§7.6) and the transitions between them, the table the trigger `media_object_state` is
 * written from: [MediaStateMachinesTest] compares this class with the schema on every pair, so the two statements of one
 * machine cannot drift. `gone` is not a state: it exists only inside the transaction that deletes the row.
 *
 * | Role | States |
 * |---|---|
 * | out | `uploading` → `uploaded` / `failed`; `failed` → `uploading` (user retry before the deadline, at most 3) |
 * | in | `awaiting` → `fetching` / `corrupt` / `incomplete`; `fetching` → `complete` / `incomplete`; `complete` → `verified` / `corrupt`; `verified` → `corrupt` / `undecodable` / `viewing`; `viewing` → `viewed` |
 */
enum class ObjectState(val code: String, val role: MediaRole) {
    UPLOADING("uploading", MediaRole.OUT),
    UPLOADED("uploaded", MediaRole.OUT),
    FAILED("failed", MediaRole.OUT),
    AWAITING("awaiting", MediaRole.IN),
    FETCHING("fetching", MediaRole.IN),
    COMPLETE("complete", MediaRole.IN),
    VERIFIED("verified", MediaRole.IN),
    CORRUPT("corrupt", MediaRole.IN),
    INCOMPLETE("incomplete", MediaRole.IN),
    UNDECODABLE("undecodable", MediaRole.IN),
    VIEWING("viewing", MediaRole.IN),
    VIEWED("viewed", MediaRole.IN),
    ;

    /** Whether a row in this state may become [to] (the state itself is no change and is allowed). */
    fun allows(to: ObjectState): Boolean = this == to || to in next

    private val next: Set<ObjectState>
        get() = when (this) {
            UPLOADING -> setOf(UPLOADED, FAILED)
            FAILED -> setOf(UPLOADING)
            AWAITING -> setOf(FETCHING, CORRUPT, INCOMPLETE)
            FETCHING -> setOf(COMPLETE, INCOMPLETE)
            COMPLETE -> setOf(VERIFIED, CORRUPT)
            VERIFIED -> setOf(CORRUPT, UNDECODABLE, VIEWING)
            VIEWING -> setOf(VIEWED)
            UPLOADED, CORRUPT, INCOMPLETE, UNDECODABLE, VIEWED -> emptySet()
        }

    /** True for a state in which the row holds no key (the CHECK of §13.6: a key is held only by an object that can still be opened). */
    val keyless: Boolean get() = this == VIEWING || this == VIEWED || this == CORRUPT || this == INCOMPLETE

    companion object {
        fun of(code: String): ObjectState =
            entries.firstOrNull { it.code == code } ?: throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_object.state")
    }
}

/** Whether a fragment's blob is on this device (`bound`) or still awaited (`expected`): `media_fragment.state`. */
enum class FragmentState(val code: String) {
    EXPECTED("expected"),
    BOUND("bound"),
    ;

    companion object {
        fun of(code: String): FragmentState =
            entries.firstOrNull { it.code == code } ?: throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_fragment.state")
    }
}

/**
 * The upload state of a fragment of an outgoing object (§6.4): `unsent` → `open` → one of four final states, and `failed`
 * back to `unsent` only after a retry of the object.
 */
enum class UploadState(val code: String) {
    UNSENT("unsent"),
    OPEN("open"),
    SENT("sent"),
    DEGRADED("degraded"),
    INDETERMINATE("indeterminate"),
    FAILED("failed"),
    ;

    /** Whether the state is final for the descriptor's purposes: every ordinal `sent`, `degraded` or `indeterminate` makes the object ready (§6.4). */
    val acknowledged: Boolean get() = this == SENT || this == DEGRADED || this == INDETERMINATE

    /**
     * Whether a fragment in this state may become [to] (the state itself is no change and is allowed). `failed` → `unsent`
     * is allowed here as an edge of the machine; the schema adds the condition that the object's retry generation moved
     * past the generation of the fragment's last operation, which [MediaFragments.settle] and [MediaObjects.retryUpload]
     * keep by writing the generation first.
     */
    fun allows(to: UploadState): Boolean = this == to || when (this) {
        UNSENT -> to == OPEN
        OPEN -> to == SENT || to == DEGRADED || to == INDETERMINATE || to == FAILED
        FAILED -> to == UNSENT
        else -> false
    }

    companion object {
        fun of(code: String): UploadState =
            entries.firstOrNull { it.code == code } ?: throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_fragment.upload_state")
    }
}

/** Where a blob came from: `media_blob.origin` (§13.6). A sealed blob is ours; an ingested one was fetched from a relay and may be pooled. */
enum class BlobOrigin(val code: String) {
    SEALED("sealed"),
    INGESTED("ingested"),
    ;

    companion object {
        fun of(code: String): BlobOrigin =
            entries.firstOrNull { it.code == code } ?: throw MediaStoreException(MediaStoreError.BAD_VALUE, "media_blob.origin")
    }
}
