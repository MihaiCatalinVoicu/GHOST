package org.ghost.crypto.bridge

/**
 * What every typed DM facade of this module shares (Phase 9 design §2.6, §21.6 point 6).
 *
 * The facades — [DmSessions], [DmCards], [DmBundles], [DmSeal], [DmPairing], [DmContent] — are the
 * only callers of [DmNative], and each one turns a native reply into a **sealed outcome**: a code
 * the native function can return is an arm, and a code it cannot is [unexpected], which throws.
 * `DmResultCodesTest` reads `FUNCTION_CODES` out of the crate and compares it with the arms of
 * every facade file in this package, in both directions, so a code with no arm cannot reach a
 * caller as an exception and an arm cannot outlive the code it answered.
 *
 * **Value semantics (§7.9).** Every call takes stored envelopes and returns new ones; nothing is
 * cached across calls or transactions, and the caller writes what came back only inside the
 * transaction it called from and only on a success arm.
 */

/**
 * Calls the native side and decodes the reply.
 *
 * An `UnsatisfiedLinkError` from a library that disappeared between the availability check and
 * the call becomes `CRYPTO_UNAVAILABLE`, never an `Error` escaping into `:messaging` (§2.7).
 */
internal inline fun dmCall(body: () -> ByteArray?): DmResult = try {
    DmResult.decode(body())
} catch (e: UnsatisfiedLinkError) {
    DmResult.unavailable()
}

/**
 * A code the surface cannot produce for this function.
 *
 * `INTERNAL` is a caught Rust panic; everything else reaching here is a disagreement between the
 * facade and the native library, which `DmResultCodesTest` fails the build on. Both mean the
 * caller must roll back and treat the blob as poison (§7.4 R2, §7.8) — which is why a code a
 * **peer** can provoke must never arrive here (review round 2, S4B2-01/R2-01).
 */
internal fun unexpected(code: DmCode, function: String): Nothing =
    throw IllegalStateException("DM native $function returned ${code.name}")

/** The empty array every optional byte-array argument of the closed surface uses. */
internal val DM_NO_BYTES: ByteArray = ByteArray(0)

/** A 32-byte zero array for the identity arguments a mode does not use. */
internal val DM_NO_KEY: ByteArray = ByteArray(32)

/** A 16-byte zero array for the contact id a mode does not use. */
internal val DM_NO_CONTACT: ByteArray = ByteArray(16)
