package org.ghost.messaging.engine

import org.ghost.crypto.bridge.RelaySets
import org.ghost.messaging.port.EsSlot
import org.ghost.messaging.port.EsSlots

/**
 * What the DM engine needs from `:sync` (Phase 9 design §13.3), gathered so the steps take one
 * argument and a test can supply one set of fakes.
 *
 * It is the same shape `OwnerSteps.SyncPorts` has for the owner side, with the inbox added: the
 * send and receive steps consume blobs, and the owner steps do not.
 */
internal class DmSyncPorts(
    val namespaces: org.ghost.sync.api.Namespaces,
    val capabilities: org.ghost.sync.api.Capabilities,
    val registrations: org.ghost.sync.api.Registrations,
    val outbox: org.ghost.sync.api.Outbox,
    val inbox: org.ghost.sync.api.Inbox,
)

/**
 * `set(ns, w)` over a week's ES slots (§5.2, as corrected by §21.1).
 *
 * The rule itself is `:crypto-bridge`'s [RelaySets]; this resolves the week's slot table through
 * the [EsSlots] port and maps the result back to the caller's `EsSlot` values, which carry the
 * `RelayId` the `:sync` calls take. `OwnerSteps` does the same for the owner's own namespaces;
 * the two share this class so a send and a bundle publication cannot disagree about a set.
 */
internal class RelaySetResolver(private val esSlots: EsSlots) {

    /** `set(ns, w)`, or null when the week's table yields no set at all (§5.2). */
    fun forNamespace(namespace: ByteArray, week: Long): List<EsSlot>? {
        val slots = esSlots.slotsInWeek(week)
        if (slots.isEmpty()) return null
        val chosen = RelaySets.forNamespace(
            namespace,
            slots.map { RelaySets.Slot(it.slot, it.relay.value, it.operatorId) },
        )
        if (chosen.isEmpty()) return null
        return chosen.map { picked -> slots.first { it.slot == picked.slot } }
    }
}
