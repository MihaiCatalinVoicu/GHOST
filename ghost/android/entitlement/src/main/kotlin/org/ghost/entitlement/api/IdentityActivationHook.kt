package org.ghost.entitlement.api

/**
 * The K20 hook of Phase 9 design §13.4 (RS K20): `:entitlement` tells whoever owns the messaging
 * layer that an identity now exists, **after** its own transactions have committed.
 *
 * `:app` wires it to `Messaging.onActivated()` / `onRestored()`, which run the `ACTIVATE`
 * transaction of §7.2 — `dm_self`, the two own namespaces and the first bundle generation. This
 * closes the Phase 8 §8.3 step 4 gap ("prekey and inbox namespaces registered at activation").
 *
 * **`:entitlement` does not depend on `:messaging`.** The hook is an interface here and an
 * implementation there, so the module graph of §13.1 keeps its direction.
 *
 * **It is a prompt, not the guarantee.** §21.12 point 2 is the guarantee: at every actor start and
 * database open, an activated identity with no `dm_self` row runs ACTIVATE. This hook only makes
 * it happen at once instead of at the next start, so an implementation that is slow, absent or
 * throwing must not be able to lose an activation — which is why every call site below runs it
 * outside its transaction and swallows nothing it could have handled.
 */
fun interface IdentityActivationHook {
    /**
     * An identity is now stored. [restored] distinguishes the two semantics of §13.4: a trial or
     * genesis activation from a restore, whose `accept_after_minute` refuses pre-restore content.
     *
     * Called on the thread that finished the activation, never inside an entitlement transaction.
     */
    fun onIdentityActivated(restored: Boolean)
}
