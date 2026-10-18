package org.ghost.network

/**
 * The four Phase 12 PT error categories (design `faza12-transports.md` §8.3; ADR-61/62), the
 * Kotlin half of `client-core/net/src/categories.rs`'s list. `pt_hash_mismatch` and
 * `pt_unsupported_abi` are raised by [PtInstaller] (the PT-1 surface, extraction from the APK
 * assets); `bridge_line_invalid` and `bridge_line_unsupported_transport` are raised by
 * [BridgeLines] (the PT-3 surface, the storage write validated natively). None of them ever
 * carries a bridge line's text — the failing index is the exception's detail (§6.6, T58).
 * [PtErrorCategoriesTest] pins these names against the `client-core/README.md` category table,
 * the same documented-and-tested discipline as `ErrorPolicyTest` (§8.3).
 */
internal object PtErrorCategories {
    /** The extracted PT binary's SHA-256 does not match the sums compiled into the APK (§5.4.4). */
    const val PT_HASH_MISMATCH: String = "pt_hash_mismatch"

    /** The device's ABI has no PT binary in the APK assets (§5.4.3). */
    const val PT_UNSUPPORTED_ABI: String = "pt_unsupported_abi"

    /** A bridge line failed the structural validation at write time (§6.2). */
    const val BRIDGE_LINE_INVALID: String = "bridge_line_invalid"

    /** A bridge line names a transport GHOST does not implement, snowflake included (§3.3, §3.4). */
    const val BRIDGE_LINE_UNSUPPORTED_TRANSPORT: String = "bridge_line_unsupported_transport"
}
