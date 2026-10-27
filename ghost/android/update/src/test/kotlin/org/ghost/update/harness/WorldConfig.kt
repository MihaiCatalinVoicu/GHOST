package org.ghost.update.harness

/**
 * The world's configuration (Phase 14 design §11.2, §11.3): what the world's clients run.
 *
 * [mutant] is the §11.3 selection: the design-row id (MC-Dn → n) the world's native calls run
 * under, set through the host library's `UpdateMutants.select` at the world's first native
 * call and reset to 0 (the shipped behaviour, the same-scale control) when the world closes.
 * 0 (the default) runs the shipped core.
 *
 * [kotlinMutants] are the rows whose site lives on the Kotlin side (§11.3: "Kotlin mutants
 * live in test sources") — the world's own ports model them: MC-D31 (the directory guard's
 * write-once operator rule) and MC-D22 (an install session committed without the verified
 * row). The world's ports consult this set and skip the guard exactly as the row describes.
 */
internal data class WorldConfig(
    /** The native bridge the clients call; the production delegate is the shipped surface. */
    val native: org.ghost.update.UpdateNativeBridge = org.ghost.update.RealUpdateNativeBridge,

    /** §11.3's mutant selection: 0 runs the shipped core (the same-scale control). */
    val mutant: Int = 0,

    /** Kotlin-side mutant rows active in this world (MC-D31, MC-D22). */
    val kotlinMutants: Set<String> = emptySet(),
)
