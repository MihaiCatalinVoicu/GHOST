package org.ghost.messaging.entworld

import org.ghost.entitlement.harness.Bytes
import org.ghost.entitlement.harness.TestSchedule
import org.ghost.sync.api.NamespaceId
import org.ghost.sync.harness.ModelRelay
import org.ghost.sync.harness.RelayNode

/**
 * What an [EntDmWorld] run left behind at its end, read from the **models** and the clients' own
 * tables, never from anything the harness installed: the evidence that a DM world ran on the
 * capability lifecycle and not on a fairy (design §22.22). It complements the checks the world makes
 * while it runs ([EntDmWorld.checkCommit], [EntDmWorld.checkScopes]); it is the raw material a SCN-E,
 * JD8 or OS check reads, not those checks.
 *
 * All reads go through the raw connection (`Client.jdbc`), so collecting evidence raises no event.
 */
internal object EntDmEvidence {

    /**
     * One `write`-kind row a client holds, and where it came from. Two things live there: a
     * relay-minted capability (v2, from a redemption) for an own namespace, and — for a contact's
     * inbox — the DEPOSIT bearer credential v3 the DM layer derives from the contact's card (§4.3),
     * which `Capabilities.put` stores under the write kind because it authorizes stores.
     */
    class WriteCapability(
        val relay: String,
        val namespaceHex: String,
        val state: String,
        /** The ISO week the capability belongs to (§4.4 point 3); −1 for a bearer credential. */
        val week: Long,
        /** The nullifier (hex) of the token a `ModelRedeemRelay` minted it for, or null: minted by nobody. */
        val nullifier: String?,
        /** The redeem relay's `nullifiers.redb` model holds that (week, nullifier): the token is spent there. */
        val spentAtRelay: Boolean,
        /** The bearer kind (`ModelRelay.KIND_DEPOSIT` …) when the row is a credential v3, else null. */
        val bearerKind: Int?,
    ) {
        val redeemed: Boolean get() = nullifier != null && spentAtRelay

        /** Either a redeemed capability or a credential the DM layer minted itself: nothing else may exist. */
        val accounted: Boolean get() = redeemed || bearerKind != null

        override fun toString(): String =
            "write@$relay/${namespaceHex.take(8)} " + (if (bearerKind != null) "bearer$bearerKind" else "w$week redeemed=$redeemed") + " $state"
    }

    /** One `relay_key_registration` row of a client, and what the relay model holds for it. */
    class Registration(
        val relay: String,
        val namespaceHex: String,
        val period: Long,
        val kind: String,
        val state: String,
        /** The relay's `bearer_keys` model holds (namespace, period, kind, verifier). */
        val recorded: Boolean,
        /**
         * The weeks of the capabilities whose serials the record accumulated, one entry per serial:
         * a week for a capability a `ModelRedeemRelay` minted, −1 for any other. A record is credited
         * by every capability that registered the same verifier (§4.4), so this is how a check tells
         * which redemption paid for it.
         */
        val serialWeeks: List<Long>,
        /** Bytes the relay's deposit ledger charged to this record (DEPOSIT only; §4.5). */
        val depositBytes: Long,
    ) {
        /** Every serial of the record is a redeemed capability's (and there is at least one). */
        val paidByRedemption: Boolean get() = serialWeeks.isNotEmpty() && serialWeeks.none { it < 0 }

        override fun toString(): String =
            "reg@$relay/${namespaceHex.take(8)} p$period $kind $state recorded=$recorded paidBy=w$serialWeeks deposits=$depositBytes"
    }

    private fun node(world: EntDmWorld, dmc: EntDmClient, relayId: Long): RelayNode? =
        dmc.c.relayIds.entries.firstOrNull { it.value.value == relayId }?.let { world.w.relays[it.key] }

    fun writeCapabilities(world: EntDmWorld, dmc: EntDmClient): List<WriteCapability> {
        val out = ArrayList<WriteCapability>()
        val now = world.w.clock.epochSeconds()
        dmc.c.jdbc.query("SELECT relay_id, namespace_id, token, state FROM relay_capability WHERE kind = 'write' ORDER BY relay_id, namespace_id") { r ->
            val token = r.blob(2)
            val header = ModelRelay.header(token)
            val week = header?.let { ModelRelay.capabilityWeek(token, it.expiry, now) } ?: -1
            val nullifier = world.ent.records.minted[Bytes.hex(token)]
            out += WriteCapability(
                relay = node(world, dmc, r.long(0))?.name ?: "?",
                namespaceHex = Bytes.hex(r.blob(1)),
                state = r.string(3),
                week = week,
                nullifier = nullifier,
                spentAtRelay = nullifier != null && world.ent.bound(nullifier, week),
                bearerKind = ModelRelay.credential(token)?.kind,
            )
        }
        return out
    }

    /** Every non-write capability row that is **not** a bearer credential v3 the DM layer minted from its own secrets. */
    fun foreignReadTokens(dmc: EntDmClient): Int {
        var n = 0
        dmc.c.jdbc.query("SELECT token FROM relay_capability WHERE kind = 'read'") { r ->
            if (ModelRelay.credential(r.blob(0)) == null) n++
        }
        return n
    }

    /** Serial (hex) → week of every capability a `ModelRedeemRelay` minted. */
    fun mintedSerialWeeks(world: EntDmWorld): Map<String, Long> = world.ent.records.minted.keys.associate { hex ->
        val token = Bytes.unhex(hex)
        val expiry = checkNotNull(ModelRelay.header(token)) { "a minted capability without a header" }.expiry
        Bytes.hex(ModelRelay.capabilitySerial(token)) to ModelRelay.capabilityWeek(token, expiry, expiry)
    }

    fun registrations(world: EntDmWorld, dmc: EntDmClient): List<Registration> {
        val minted = mintedSerialWeeks(world)
        val out = ArrayList<Registration>()
        dmc.c.jdbc.query(
            "SELECT relay_id, namespace_id, period_id, kind, verifier, state FROM relay_key_registration ORDER BY relay_id, namespace_id, period_id, kind",
        ) { r ->
            val relay = node(world, dmc, r.long(0))
            val ns = r.blob(1)
            val period = r.long(2)
            val kind = r.string(3)
            val verifier = r.blob(4)
            val code = when (kind) {
                "read" -> ModelRelay.KIND_READ
                "deposit" -> ModelRelay.KIND_DEPOSIT
                else -> ModelRelay.KIND_FETCH
            }
            val record = relay?.model?.record(NamespaceId(ns), period, code, verifier)
            out += Registration(
                relay = relay?.name ?: "?",
                namespaceHex = Bytes.hex(ns),
                period = period,
                kind = kind,
                state = r.string(5),
                recorded = record != null,
                serialWeeks = record?.serials?.map { minted[it] ?: -1L }.orEmpty(),
                depositBytes = relay?.model?.depositsUsed(NamespaceId(ns), period, verifier) ?: 0,
            )
        }
        return out
    }

    /** The relay set of [namespace] in [dmc]'s tables (`namespace_relay`), by relay name. */
    fun relaySet(world: EntDmWorld, dmc: EntDmClient, namespace: ByteArray): List<String> {
        val out = ArrayList<String>()
        dmc.c.jdbc.query("SELECT relay_id FROM namespace_relay WHERE namespace_id = ?1 ORDER BY relay_id", listOf(namespace)) { r ->
            node(world, dmc, r.long(0))?.let { out += it.name }
        }
        return out
    }

    /**
     * Redemptions by (relay, namespace, week of the token): the distinct tokens **sent** for each —
     * every `RedeemToken` request that left a client, whether or not it reached the relay
     * (`EntRecords.relayLog`, NI-1's record) — so T27's "exactly one ACCESS token per (relay, own
     * namespace, week)" is read on the stricter side.
     */
    fun tokensPerPair(world: EntDmWorld): Map<Triple<String, String, Long>, Set<String>> {
        val out = LinkedHashMap<Triple<String, String, Long>, MutableSet<String>>()
        for (line in world.ent.records.relayLog) {
            val f = line.split('|')
            if (f.size < 6 || f[1] != "redeem") continue
            val token = Bytes.unhex(f[4])
            if (token.size != TestSchedule.TOKEN_BYTES) continue
            val week = world.ent.schedule.verify(token, org.ghost.network.EntitlementCrypto.KIND_ACCESS)?.epoch ?: continue
            out.getOrPut(Triple(f[2], f[3], week)) { LinkedHashSet() } += Bytes.hex(TestSchedule.nullifier(token))
        }
        return out
    }
}
