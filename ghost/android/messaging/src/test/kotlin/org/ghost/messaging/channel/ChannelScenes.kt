package org.ghost.messaging.channel

import org.ghost.messaging.DmWorld
import org.ghost.messaging.api.AcceptResult
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.PostResult
import org.ghost.messaging.channel.engine.ChannelCounters
import org.ghost.messaging.channel.store.ChannelState
import org.junit.Assert.assertEquals

/** The scenes the receive suites start from (slice S4): built through the engine, as SCN-CA builds them. */
internal object ChannelScenes {

    /**
     * A channel of [owner] that every one of [joiners] joined by an invite of the owner, all admitted by **one** pass of
     * the owner (one commit with every Add, epoch 1): every member active at epoch 1.
     */
    fun channelOf(w: ChannelWorld, owner: ChannelClient, vararg joiners: ChannelClient): ChannelId {
        val id = ChannelAdmissionTest.create(owner)
        for (j in joiners) {
            val link = ChannelAdmissionTest.invite(owner, id)
            assertEquals(AcceptResult.PENDING, j.engine.accept(link, null))
            w.recordKeyPackage(j, id)
        }
        w.quiesce()
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        for (j in joiners) assertEquals("${j.name} joined", ChannelState.ACTIVE, j.channel(id)!!.state)
        assertEquals(1L, owner.channel(id)!!.epoch)
        return id
    }

    /** One more member admitted into an existing channel by [owner]'s next pass (CO-8's spacing passed first). */
    fun admit(w: ChannelWorld, owner: ChannelClient, id: ChannelId, joiner: ChannelClient) {
        val link = ChannelAdmissionTest.invite(owner, id)
        w.quiesce()
        assertEquals(AcceptResult.PENDING, joiner.engine.accept(link, null))
        w.recordKeyPackage(joiner, id)
        w.quiesce()
        w.advance(6 * DmWorld.HOUR)
        w.admissionPass(owner)
        w.quiesce()
        w.pastSettleWindow()
        w.quiesce()
        assertEquals("${joiner.name} joined", ChannelState.ACTIVE, joiner.channel(id)!!.state)
    }

    /** Posts [text] as [author] and expects it queued. */
    fun post(author: ChannelClient, id: ChannelId, text: String) {
        assertEquals(PostResult.QUEUED, author.engine.post(id, text.toByteArray(), null))
    }

    /** The relay's stores of [author]'s posts (and reactions), in the order they were stored. */
    fun postsOf(w: ChannelWorld, author: ChannelClient): List<ModelChannelRelay.Stored> =
        w.relay.stored.filter { it.from == author.name && it.purpose == "post" && !it.injected }

    /** A client's counter. */
    operator fun ChannelClient.get(reason: ChannelCounters.Reason): Int = counters[reason]

    /** The op id of the post [text] at [client] (from its displayed rows). */
    fun opIdOf(client: ChannelClient, id: ChannelId, text: String): ByteArray = client.database.transaction { tx ->
        client.channelStores.posts.page(tx.sql, id.toByteArray(), client.clock.now, 500).first { row ->
            val body = client.content.open(row.bodyEnv, org.ghost.messaging.channel.engine.ChannelAd.postBody(row.opId))
            body != null && String(body, Charsets.UTF_8) == text
        }.opId
    }
}
