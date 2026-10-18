package org.ghost.ui.gateway

/**
 * Phase 13 design §3.2 (G-U5, PV-14): marks a gateway method whose call causes relay-visible
 * traffic (the §2.4 closed list). In `:ui` such a method may be called only from an `on…`
 * intent handler of a `*Model.kt` screen model — never from composition, a hint collector, a
 * poll or a lifecycle callback. G-U5's gateway half enforces the file shape; the recording
 * gateways (§12.2) enforce the behaviour.
 */
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.BINARY)
annotation class UserAction
