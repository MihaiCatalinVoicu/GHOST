package org.ghost.messaging.channel.engine

import org.ghost.crypto.bridge.ChannelPolicy
import org.ghost.crypto.bridge.MlsCode
import org.ghost.crypto.bridge.MlsOutcome
import org.ghost.messaging.api.ChannelId
import org.ghost.messaging.api.CreateResult
import org.ghost.messaging.channel.store.ChannelState
import org.ghost.messaging.channel.store.ChannelStore
import org.ghost.messaging.channel.store.GenerationState
import org.ghost.messaging.engine.DmTime
import org.ghost.storage.StorageFullException
import org.ghost.sync.api.CapabilityKind
import org.ghost.sync.api.CapabilitySource
import org.ghost.sync.api.Consumer
import org.ghost.sync.api.KeyKind
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.api.SendDelay

/**
 * **`CH-CREATE`** (Phase 10 design §6.1, §7.1, §7.5, §10.4), a user action, **one transaction**.
 *
 * The creator draws `channel_id` (32 bytes of the engine's CSPRNG; §5.1 says the creator's CSPRNG in Rust, but
 * `groupCreate` takes the id as an argument, §10.2 fn 3 as S2b built it — recorded in §19.37), opens the channel on the
 * native context with its pseudonym seed and calls `groupCreate` with the policy of §6.1: committers and funders `[P]`,
 * the timer the user chose (7 days by default), the class, `members_may_invite = 1`, `idle_evict_days = 63` and the
 * name. A **password channel** (§19.28) is created with flag bit 2 and `pw_version` 1 instead of bit 0 (Q46 (b)): the
 * owner's later set, change and removal are policy commits of S5; creating one directly is this slice's way to a
 * password channel for its JN cases (recorded in §19.37).
 *
 * Then, with generation 0's values and the credentials of every relay slot of `set(ns_0, w)` (fn 13), in one
 * transaction: `ch_channel` (active), `ch_generation(0, current)`, `ch_epoch(0, open)`, the OpenMLS rows, the creator's
 * box key, the namespace (`Namespaces.register(ns_0, CHANNEL, set(ns_0, w), listen = true, LOCAL)`), the READ and DEPOSIT
 * credentials of each slot (installed with no local expiry: the bearer credential lives as long as its relay registration,
 * which the funders renew — §19.37 on F-6), the funding flag (`Funding.set`, the creator is the default funder, Q7) and
 * the READ and DEPOSIT registrations of the week. **No traffic follows from the creation** but the funder's redemptions
 * and registrations (§6.1 point 3). The registrations of `{c, c + 1}` of a registration capability (the F9 §4.8 `REGROWS`
 * rule) are the funder renewal step's, slice S6: at creation no such capability exists yet.
 *
 * Gate G-M5 lists this file for `Namespaces.register`, `Capabilities.put`, `Funding.set` and `Registrations.keep`.
 */
internal class ChannelCreateStep(
    private val env: ChannelEnv,
    private val sync: ChannelSyncPorts,
) {
    private val stores = env.stores

    fun create(name: ByteArray, timerCode: Int, sizeClass: Int, passwordRequired: Boolean): CreateResult {
        if (name.size > MAX_NAME || timerCode !in 0..5 || sizeClass !in 0..1) return CreateResult(CreateResult.Status.INVALID, null)
        val now = env.now()
        val day = DmTime.day(now)
        val week = DmTime.week(now)
        val content = env.keys.content() ?: return unavailable()
        if (env.database.transaction { tx -> env.liveChannels(tx.sql) } >= ChannelEnv.MAX_CHANNELS) {
            return CreateResult(CreateResult.Status.LIMIT_REACHED, null)
        }
        val channelId = env.random.bytes(ChannelId.SIZE)
        val opened = env.contexts.open(channelId, create = true) ?: return unavailable()
        val p = opened.pseudonym
        val policy = ChannelPolicy(
            channelId = channelId,
            sizeClass = sizeClass,
            timerCode = timerCode,
            timerVersion = 0,
            historyPolicy = 0,
            flags = if (passwordRequired) ChannelEnv.FLAG_PASSWORD else ChannelEnv.FLAG_MEMBERS_MAY_INVITE,
            idleEvictDays = ChannelEnv.IDLE_EVICT_DAYS,
            pwVersion = if (passwordRequired) 1 else 0,
            name = name,
            committers = listOf(p),
            funders = listOf(p),
        )
        val created = when (val c = opened.crypto.groupCreate(channelId, policy, day.toInt())) {
            is MlsOutcome.Ok -> c.value
            is MlsOutcome.Refused -> return if (c.code == MlsCode.INVALID_POLICY || c.code == MlsCode.NON_CANONICAL) {
                CreateResult(CreateResult.Status.INVALID, null)
            } else {
                unavailable()
            }
        }
        val g = created.generation
        // S0-15's digest of the creator's committers, the anchor of every invite of this context (§19.37 F-S4-2): learnt
        // now for an open channel, where members invite too; a password channel's committer learns it at its first invite.
        val digest = if (passwordRequired) {
            null
        } else {
            ChannelDigest.learn(opened.crypto, channelId, MlsRows.applied(emptyList(), created.changes), g.gEnv, g.generation, day)
        }
        val set = env.relaySet(g.ns, week) ?: return CreateResult(CreateResult.Status.NO_REPLICAS, null)
        val slots = ByteArray(set.size) { set[it].slot.toByte() }
        val credentials = opened.crypto.generation(channelId, g.gEnv, g.generation.toInt(), g.openEpoch, slots)
            .valueOrNull()?.slots ?: return unavailable()
        val nameEnv = if (name.isEmpty()) null else env.seal(content, ChannelAd.name(channelId), name)
        return try {
            env.database.transaction { tx ->
                stores.channels.insert(
                    tx,
                    ChannelStore.NewChannel(
                        channelId = channelId,
                        state = ChannelState.ACTIVE,
                        generation = g.generation,
                        epoch = created.epoch.epoch,
                        joinedEpoch = created.epoch.epoch,
                        sizeClass = sizeClass,
                        timerCode = timerCode,
                        myPseudonym = p,
                        nameEnv = nameEnv,
                        pwRequired = passwordRequired,
                    ),
                )
                stores.generations.insert(
                    tx, channelId, g.generation, g.ns, GenerationState.CURRENT, g.gEnv, g.jkEnv, g.rJoin, g.openEpoch,
                )
                stores.epochs.insert(tx, channelId, created.epoch.epoch, created.epoch.kEnv, created.epoch.rEp)
                stores.mls.apply(tx, channelId, MlsRows.changes(created.changes))
                digest?.let { stores.channels.setCommittersDigest(tx, channelId, it) }
                stores.members.insertBoxKey(tx, channelId, created.boxPk, created.boxEnv)
                val ns = NamespaceId(g.ns)
                sync.namespaces.register(
                    tx = tx,
                    namespace = ns,
                    consumer = Consumer.CHANNEL,
                    relays = set.map { it.relay }.toSet(),
                    listen = true,
                    sendDelay = SendDelay.DEFAULT,
                    capabilitySource = CapabilitySource.LOCAL,
                )
                for (slot in set) {
                    val c = credentials.firstOrNull { it.slot == slot.slot }
                        ?: throw IllegalStateException("generation returned no credential for a slot it was asked for")
                    sync.capabilities.put(tx, slot.relay, ns, CapabilityKind.READ, c.readCredential, null)
                    sync.capabilities.put(tx, slot.relay, ns, CapabilityKind.WRITE, c.depositCredential, null)
                    sync.registrations.keep(tx, slot.relay, ns, week, KeyKind.READ, c.readVerifier)
                    sync.registrations.keep(tx, slot.relay, ns, week, KeyKind.DEPOSIT, c.depositVerifier)
                }
                sync.funding.set(tx, ns, true)
                CreateResult(CreateResult.Status.CREATED, ChannelId(channelId))
            }
        } catch (e: StorageFullException) {
            CreateResult(CreateResult.Status.STORAGE_FULL, null)
        }
    }

    private fun unavailable() = CreateResult(CreateResult.Status.CRYPTO_UNAVAILABLE, null)

    override fun toString(): String = "ChannelCreateStep"

    companion object {
        /** §5.3: a name of 0 … 48 bytes. */
        const val MAX_NAME: Int = 48
    }
}
