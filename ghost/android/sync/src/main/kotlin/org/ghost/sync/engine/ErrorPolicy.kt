package org.ghost.sync.engine

import org.ghost.network.NetworkException
import org.ghost.sync.api.StatusFlag

/**
 * Class of a failed relay call (design §3.6). Every `NetworkException` category listed in
 * `client-core/README.md` maps to exactly one class through [ErrorPolicy.CATEGORIES]; a Kotlin
 * `IllegalArgumentException` from a port is [LOCAL_BUG]; a category missing from the table is
 * [UNKNOWN] (defensive: treated as ambiguous).
 */
internal enum class ErrorClass {
    /** `closed`: the transport was closed under the call. */
    ABORT,

    /** `not_bootstrapped`: the holder bootstraps the transport again. */
    NEEDS_BOOTSTRAP,

    /** `tor_bootstrap`, `tor_bootstrap_timeout`: close and recreate the transport, with backoff. */
    NEW_TRANSPORT,

    /** `tor_setup`, `runtime`, `native_missing`: nothing works until something local changes. */
    LOCAL_FATAL,

    /** `bridge_config`: no retry until the bridge configuration changes. */
    CONFIG,

    /** `transport`: the relay was not reached; nothing was sent. */
    RELAY_TRANSIENT,

    /** `timeout`, `relay_unavailable`, `internal`: the request may have been applied. */
    RELAY_TRANSIENT_AMBIGUOUS,

    /** `malformed_response`: the relay broke the protocol (a store may have been applied). */
    RELAY_HOSTILE,

    /** `not_stored`: the relay kept the blob for less than asked (a short membership exists). */
    RELAY_ANOMALY,

    /** `unauthorized`: the capability was refused. */
    NEEDS_CAPABILITY,

    /** `quota`: the capability's quota is spent (nothing was persisted). */
    QUOTA,

    /** `not_found`: the blob is not in the capability's namespace on that relay. */
    MISSING,

    /** `rejected`: the relay refuses the request permanently. */
    PERMANENT,

    /** `invalid_argument`, `not_bucket_sized`, `not_onion`, Kotlin `IllegalArgumentException`. */
    LOCAL_BUG,

    /** A category not in the table. */
    UNKNOWN;

    /** The failure is about the transport, not a relay: the session stops its calls (design §3.6 first rows). */
    val transportLevel: Boolean
        get() = this == ABORT || this == NEEDS_BOOTSTRAP || this == NEW_TRANSPORT || this == LOCAL_FATAL || this == CONFIG
}

/** What a failed store attempt means for the delivery's possible copy (`copy_hour`, design §3.6). */
internal enum class CopyEffect {
    /** Nothing can have been persisted by this attempt. */
    NONE,

    /** The relay may hold a copy: `copy_hour` records the attempt's lease hour. */
    POSSIBLE,
}

/** Store column of the §3.6 table. */
internal enum class StoreAction {
    /** Stop the session's calls (transport); the result transaction follows [CopyEffect]. */
    STOP,

    /** Lease backoff; no possible copy. */
    NOT_APPLIED,

    /** Lease backoff; possible copy (the next attempt checks first). */
    AMBIGUOUS,

    /** Refuse the token of the failing generation; the delivery waits for a new one. */
    PARK_UNAUTHORIZED,

    /** `check([h])` with the same token: present → verified, otherwise exhausted and parked. */
    QUOTA_CHECK,

    /** The delivery fails (nothing was persisted). */
    FAIL,
}

/** List, get and check columns of the §3.6 table. */
internal enum class ReadAction {
    /** Stop the session's calls (transport). */
    STOP,

    /** Skip; the cursor or row is unchanged (a get keeps its lease backoff). */
    SKIP,

    /** The answer is not trusted: a list page is dropped, a get source becomes `bad`, a check has no answer. */
    HOSTILE,

    /** `get` only: the source answered `not_found`. */
    NOT_FOUND,

    /** Refuse the token of the failing generation; the pair waits for a new one. */
    SUSPEND,

    /** Pause the pair for 24 h. */
    PAUSE,
}

/** One row of the §3.6 table for one kind of call. */
internal class Disposition<A>(
    val action: A,
    /** Failures added to the lane's breaker for the relay (0: none). */
    val breakerWeight: Int,
    /** Status flag raised, if any. */
    val flag: StatusFlag?,
    /** Store only: what the failure means for the attempt's possible copy. */
    val copyEffect: CopyEffect,
) {
    override fun toString(): String = "Disposition($action, $breakerWeight, $flag, $copyEffect)"
}

/**
 * Mapping of every error category to its handling (design §3.6). The category table in
 * `client-core/README.md` is the source; `ErrorPolicyTest` parses it and fails on any category
 * without an explicit entry here.
 */
internal object ErrorPolicy {

    /** Every category of `client-core/README.md` (`categories.rs` ALL plus Kotlin `native_missing`). */
    val CATEGORIES: Map<String, ErrorClass> = linkedMapOf(
        "invalid_argument" to ErrorClass.LOCAL_BUG,
        "not_onion" to ErrorClass.LOCAL_BUG,
        "closed" to ErrorClass.ABORT,
        "runtime" to ErrorClass.LOCAL_FATAL,
        "bridge_config" to ErrorClass.CONFIG,
        "tor_setup" to ErrorClass.LOCAL_FATAL,
        "tor_bootstrap" to ErrorClass.NEW_TRANSPORT,
        "tor_bootstrap_timeout" to ErrorClass.NEW_TRANSPORT,
        "not_bootstrapped" to ErrorClass.NEEDS_BOOTSTRAP,
        "transport" to ErrorClass.RELAY_TRANSIENT,
        "timeout" to ErrorClass.RELAY_TRANSIENT_AMBIGUOUS,
        "unauthorized" to ErrorClass.NEEDS_CAPABILITY,
        "quota" to ErrorClass.QUOTA,
        "not_found" to ErrorClass.MISSING,
        "rejected" to ErrorClass.PERMANENT,
        "relay_unavailable" to ErrorClass.RELAY_TRANSIENT_AMBIGUOUS,
        "not_bucket_sized" to ErrorClass.LOCAL_BUG,
        "not_stored" to ErrorClass.RELAY_ANOMALY,
        "malformed_response" to ErrorClass.RELAY_HOSTILE,
        "internal" to ErrorClass.RELAY_TRANSIENT_AMBIGUOUS,
        "native_missing" to ErrorClass.LOCAL_FATAL,
    )

    /** `not_onion` also pauses the relay's work lane for 24 h (design §3.6). */
    const val NOT_ONION: String = "not_onion"

    /** `native_missing` disables sync for the process (design §3.6). */
    const val NATIVE_MISSING: String = "native_missing"

    fun classify(category: String): ErrorClass = CATEGORIES[category] ?: ErrorClass.UNKNOWN

    /** Store column: every class has an explicit row (the `when` is exhaustive). */
    fun store(errorClass: ErrorClass): Disposition<StoreAction> = when (errorClass) {
        ErrorClass.ABORT -> Disposition(StoreAction.STOP, 0, null, CopyEffect.POSSIBLE)
        ErrorClass.NEEDS_BOOTSTRAP, ErrorClass.NEW_TRANSPORT, ErrorClass.LOCAL_FATAL, ErrorClass.CONFIG ->
            Disposition(StoreAction.STOP, 0, null, CopyEffect.NONE)
        ErrorClass.RELAY_TRANSIENT -> Disposition(StoreAction.NOT_APPLIED, 1, null, CopyEffect.NONE)
        ErrorClass.RELAY_TRANSIENT_AMBIGUOUS -> Disposition(StoreAction.AMBIGUOUS, 1, null, CopyEffect.POSSIBLE)
        ErrorClass.RELAY_HOSTILE, ErrorClass.RELAY_ANOMALY -> Disposition(StoreAction.AMBIGUOUS, 2, null, CopyEffect.POSSIBLE)
        ErrorClass.NEEDS_CAPABILITY -> Disposition(StoreAction.PARK_UNAUTHORIZED, 0, null, CopyEffect.NONE)
        ErrorClass.QUOTA -> Disposition(StoreAction.QUOTA_CHECK, 0, null, CopyEffect.NONE)
        // not_found cannot answer a store: treated as RELAY_HOSTILE.
        ErrorClass.MISSING -> Disposition(StoreAction.AMBIGUOUS, 2, null, CopyEffect.POSSIBLE)
        ErrorClass.PERMANENT -> Disposition(StoreAction.FAIL, 0, StatusFlag.RELAY_REJECTS, CopyEffect.NONE)
        ErrorClass.LOCAL_BUG -> Disposition(StoreAction.FAIL, 0, StatusFlag.BUG, CopyEffect.NONE)
        ErrorClass.UNKNOWN -> Disposition(StoreAction.AMBIGUOUS, 1, StatusFlag.UNKNOWN_CATEGORY, CopyEffect.POSSIBLE)
    }

    /**
     * List, get and check column. `quota` and `not_stored` cannot answer these calls and are
     * treated as RELAY_HOSTILE; `not_found` is meaningful for `get` only and hostile otherwise.
     */
    fun read(errorClass: ErrorClass, isGet: Boolean): Disposition<ReadAction> = when (errorClass) {
        ErrorClass.ABORT, ErrorClass.NEEDS_BOOTSTRAP, ErrorClass.NEW_TRANSPORT, ErrorClass.LOCAL_FATAL, ErrorClass.CONFIG ->
            Disposition(ReadAction.STOP, 0, null, CopyEffect.NONE)
        ErrorClass.RELAY_TRANSIENT, ErrorClass.RELAY_TRANSIENT_AMBIGUOUS -> Disposition(ReadAction.SKIP, 1, null, CopyEffect.NONE)
        ErrorClass.RELAY_HOSTILE, ErrorClass.RELAY_ANOMALY, ErrorClass.QUOTA -> Disposition(ReadAction.HOSTILE, 2, null, CopyEffect.NONE)
        ErrorClass.MISSING ->
            if (isGet) Disposition(ReadAction.NOT_FOUND, 0, null, CopyEffect.NONE) else Disposition(ReadAction.HOSTILE, 2, null, CopyEffect.NONE)
        ErrorClass.NEEDS_CAPABILITY -> Disposition(ReadAction.SUSPEND, 0, null, CopyEffect.NONE)
        ErrorClass.PERMANENT -> Disposition(ReadAction.PAUSE, 0, StatusFlag.RELAY_REJECTS, CopyEffect.NONE)
        ErrorClass.LOCAL_BUG -> Disposition(ReadAction.PAUSE, 0, StatusFlag.BUG, CopyEffect.NONE)
        ErrorClass.UNKNOWN -> Disposition(ReadAction.SKIP, 1, StatusFlag.UNKNOWN_CATEGORY, CopyEffect.NONE)
    }
}

/** Outcome of one relay call: the value, or the failure's category (null for a Kotlin argument error) and class. */
internal sealed class CallResult<out T> {
    class Ok<T>(val value: T) : CallResult<T>()

    class Failed(val category: String?, val errorClass: ErrorClass) : CallResult<Nothing>() {
        override fun toString(): String = "Failed($errorClass)"
    }
}

/**
 * Runs one relay port call. Only the two failure types a port may throw are caught
 * (`NetworkException` and Kotlin `IllegalArgumentException`, design §1.6); anything else,
 * including every JVM `Error`, propagates (design §11.2 #11). [block] must contain the port call only.
 */
internal inline fun <T> relayCall(block: () -> T): CallResult<T> =
    try {
        CallResult.Ok(block())
    } catch (e: NetworkException) {
        CallResult.Failed(e.category, ErrorPolicy.classify(e.category))
    } catch (e: IllegalArgumentException) {
        CallResult.Failed(null, ErrorClass.LOCAL_BUG)
    }
