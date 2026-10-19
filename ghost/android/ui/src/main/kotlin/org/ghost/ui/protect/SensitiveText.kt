package org.ghost.ui.protect

/**
 * Phase 13 design §3.3 (T24, T3): a sensitive string. A value class over `String` whose
 * `toString` is redacted, so no log, exception message, semantics dump or state print can carry
 * the value. The single unwrap site is `SensitiveTextView` (G-U3); UI models hold secrets only
 * as `SensitiveText`, never as plain `String` (the reflection test of §12.2 allowlists the few
 * non-secret names).
 */
@JvmInline
value class SensitiveText(val value: String) {
    override fun toString(): String = "SensitiveText(redacted)"

    /**
     * The single non-rendering consumption: pixel encoders (the QR of a card or an invite link)
     * build the matrix inside the call and hold no copy of the value. Everything textual renders
     * through SensitiveTextView (G-U3); this is the one other door, declared on the value class
     * itself so it stays countable (the gate scans `.value` reads; this file holds the class).
     */
    fun <T> encodePixels(block: (String) -> T): T = block(value)
}
