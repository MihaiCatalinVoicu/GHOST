package org.ghost.update.harness

import org.ghost.update.RealUpdateNativeBridge
import org.ghost.update.UpdateNativeBridge

/**
 * The world's configuration (Phase 14 design §11.2, §11.3): what the world's clients run. The
 * [mutant] hook is the door §11.3's slices walk through — the Rust mutants of
 * `ghost-client-update` compile behind a feature only `ghost-dm-host` enables, exported through
 * one test-only JNI symbol the host library selects a mutant with; a world then names its
 * mutant here (null = the shipped core, the control). Kotlin-side mutants override [native]
 * directly, the F10/F11 pattern.
 */
internal data class WorldConfig(
    /** The native bridge the clients call; the production delegate is the shipped surface. */
    val native: UpdateNativeBridge = RealUpdateNativeBridge,

    /** §11.3's mutant selection: null runs the shipped core (the same-scale control). */
    val mutant: String? = null,
)
