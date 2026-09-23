package org.ghost.messaging.harness

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AddContactResult
import org.ghost.messaging.api.CardSource
import org.ghost.messaging.api.ContactId
import org.ghost.messaging.api.MessageState
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
        // The ids before and after, because a seeded world is a **chain**: by the time carol adds
        // dave she already holds bob, so `contacts().single()` is only correct in a two-client
        // world and silently wrong in every other one.
        val beforeA = nodeA.device.engine.contacts().map { it.id.toByteArray().toList() }.toSet()
        check(
            nodeA.device.engine.addContact(nodeB.device.card(), CardSource.QR_IN_PERSON) ==
                AddContactResult.ADDED,
        ) { "$a could not add $b's card" }
        val contactB = nodeA.device.engine.contacts()
            .first { it.id.toByteArray().toList() !in beforeA }.id
        check(nodeA.device.engine.send(contactB, "hello", null) == SendResult.QUEUED)
        val beforeB = nodeB.device.engine.contacts().map { it.id.toByteArray().toList() }.toSet()
        world.pump()
        nodeA.device.timeTriggeredPass()
        // `EST-READY` waits two minutes for a better bundle candidate (§21.7 point 4).
        world.advanceBy(3 * DmWorld.MINUTE)
        nodeA.device.timeTriggeredPass()
        world.pump()
        nodeB.device.hintPass()
        val contactA = nodeB.device.engine.contacts()
            .first { it.id.toByteArray().toList() !in beforeB }.id
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

    /**
     * The inbound texts of [node]'s conversation with [contact], oldest first (S10c).
     *
     * [inboundTexts] reads whichever contact `contacts()` lists first, which is `contact_id` order
     * and therefore random: right for a device with one contact, and a coin flip for SCN-C's bob,
     * who holds alice's contact beside carol's request. The liveness oracle reads through this.
     */
    fun inboundTextsWith(world: DmCrashWorld, node: String, contact: ContactId): List<String> =
        world[node].device.engine.conversation(contact, 200, null).reversed()
            .filter { !it.outgoing }
            .mapNotNull { it.text }

    /**
     * The inbound texts of **every** conversation of one node, requests included.
     *
     * [inboundTexts] reads the first contact only, which is right for the two-client scenarios it
     * was written for and wrong for a device that holds a request beside its contact (SCN-I's lost
     * device, which carol wrote to): the no-loss oracle charged with the lost device's rendering
     * has to see all of it.
     */
    fun everyInboundText(node: DmNode): List<String> {
        val device = node.device
        return device.engine.contacts().flatMap { contact ->
            device.engine.conversation(contact.id, 200, null).reversed()
                .filter { !it.outgoing }
                .mapNotNull { it.text }
        }
    }

    /**
     * The texts of every outgoing message this node has marked **SENT**, over every conversation.
     *
     * `SENT` is the engine's own statement that the op was released with a `sent` outcome, so it is
     * the promise the no-loss oracle of [DmCrashRunner] holds it to. Every conversation, not the
     * first one, because a seeded world is a chain and a device in the middle of it sends both ways.
     */
    fun sentTexts(world: DmCrashWorld, node: String): List<String> {
        val device = world[node].device
        return device.engine.contacts().flatMap { contact ->
            device.engine.conversation(contact.id, 200, null)
                .filter { it.outgoing && it.state.name == "SENT" }
                .mapNotNull { it.text }
        }
    }

    /**
     * Every outgoing message this node gave up on: `FAILED` or `INDETERMINATE`, over every
     * conversation, by text — a timer change, which has none, as [DmScenario.TIMER_ROW].
     */
    fun abandonedOutgoing(node: DmNode): List<String> {
        val device = node.device
        return device.engine.contacts().flatMap { contact ->
            device.engine.conversation(contact.id, 200, null)
                .filter {
                    it.outgoing &&
                        (it.state == MessageState.FAILED || it.state == MessageState.INDETERMINATE)
                }
                .map { it.text ?: DmScenario.TIMER_ROW }
        }
    }

    /** The state of the outgoing message [text] on [node], or null when it has none. */
    fun outgoingState(world: DmCrashWorld, node: String, text: String): MessageState? {
        val device = world[node].device
        return device.engine.contacts().asSequence()
            .flatMap { device.engine.conversation(it.id, 200, null).asSequence() }
            .firstOrNull { it.outgoing && it.text == text }
            ?.state
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
