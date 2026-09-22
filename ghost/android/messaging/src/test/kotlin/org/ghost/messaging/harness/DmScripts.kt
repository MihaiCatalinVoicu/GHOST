package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.SendResult

/**
 * The setup scripts every scenario shares: activation, the one-scan flow of §12.2, and the small
 * queries a check needs.
 *
 * They are written against [DmCrashWorld] rather than against a `DmDevice`, because a scenario's
 * steps run after reboots that replaced the device, and a helper holding a stale reference would
 * silently drive the dead one.
 */
internal object DmScripts {

    fun activate(world: DmCrashWorld) {
        for (node in world.nodes()) {
            node.device.engine.onActivated()
            requireNotNull(node.device.engine.myCard()) { "${node.name} has no card after ACTIVATE" }
        }
    }

    /**
     * The §12.2 flow from [a]'s scan to pair mode on both sides, driven to completion.
     *
     * Records both contact ids in [DmCrashWorld.contacts] under `"<a>-><b>"` and `"<b>-><a>"`, so a
     * step that runs after a reboot looks the id up rather than holding one.
     */
    fun establishBothWays(world: DmCrashWorld, a: String, b: String) {
        val nodeA = world[a]
        val nodeB = world[b]
        check(nodeA.device.engine.addContact(nodeB.device.card(), CardSource.QR_IN_PERSON) == AddContactResult.ADDED) {
            "$a could not add $b's card"
        }
        val contactB = nodeA.device.engine.contacts().single().id
        check(nodeA.device.engine.send(contactB, "hello", null) == SendResult.QUEUED)
        world.pump()
        nodeA.device.timeTriggeredPass()
        // `EST-READY` waits two minutes for a better bundle candidate (§21.7 point 4).
        world.advanceBy(3 * DmWorld.MINUTE)
        nodeA.device.timeTriggeredPass()
        world.pump()
        nodeB.device.hintPass()
        val contactA = nodeB.device.engine.contacts().single { it.trust.name == "REQUEST" }.id
        check(nodeB.device.engine.acceptRequest(contactA)) { "$b could not accept $a's request" }
        check(nodeB.device.engine.send(contactA, "hi back", null) == SendResult.QUEUED)
        world.pump()
        nodeA.device.hintPass()
        check(nodeA.device.engine.send(contactB, "pair now", null) == SendResult.QUEUED)
        world.pump()
        nodeB.device.hintPass()
        world.pump()
        nodeA.device.hintPass()
        world.contacts["$a->$b"] = contactB
        world.contacts["$b->$a"] = contactA
    }

    fun contact(world: DmCrashWorld, from: String, to: String): ContactId =
        requireNotNull(world.contacts["$from->$to"]) { "no contact $from->$to" }

    /** The inbound texts of one node's single conversation, oldest first. */
    fun inboundTexts(world: DmCrashWorld, node: String): List<String> {
        val device = world[node].device
        val contact = device.engine.contacts().firstOrNull()?.id ?: return emptyList()
        return device.engine.conversation(contact, 200, null).reversed()
            .filter { !it.outgoing }
            .mapNotNull { it.text }
    }

    /** The outbound states of one node's single conversation, oldest first. */
    fun outboundStates(world: DmCrashWorld, node: String): List<String> {
        val device = world[node].device
        val contact = device.engine.contacts().firstOrNull()?.id ?: return emptyList()
        return device.engine.conversation(contact, 200, null).reversed()
            .filter { it.outgoing }
            .map { it.state.name }
    }

    fun count(world: DmCrashWorld, node: String, query: String): Long {
        var out = 0L
        world[node].raw.query(query) { out = it.long(0) }
        return out
    }
}
