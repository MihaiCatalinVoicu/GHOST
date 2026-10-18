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
}
