package org.ghost.sync.api

/**
 * A namespace this client funds (Phase 10 design §7.4, §7.5 item 1): the owner of a channel and up to
 * two members its policy names redeem their own ACCESS tokens for the registration capabilities
 * ([CapabilityKind.REGISTER]) that keep the channel's shared bearer credentials registered at the
 * relays; every other member stores with the generation's DEPOSIT credential and reads with its READ
 * credential, both installed through [Capabilities.put] as for any [CapabilitySource.LOCAL] namespace,
 * and spends no token.
 *
 * The flag is a fact about this client, kept in the sync database beside the namespace it describes
 * (`sync_namespace_fund`, migration 6) and gone with it. A funded namespace differs from an unfunded
 * one in exactly three places, all inside `:sync` and `:entitlement`:
 *  - [Capabilities.needed] reports a [CapabilityKind.REGISTER] need for it, with source
 *    [CapabilitySource.REDEEM] whatever the namespace's own source is, when a registration is pending
 *    and no registration capability is held (the planner then redeems at once, as for WRITE MISSING),
 *    and renews a held one at the Phase 8 EXPIRING time;
 *  - the registration step serves its rows with the registration capability and never with the
 *    namespace's write capability (for an unfunded namespace it uses the write capability as before,
 *    and only if the namespace's source is [CapabilitySource.REDEEM]);
 *  - a [Capabilities.put] of kind [CapabilityKind.WRITE] re-arms the parked deliveries but not the
 *    registrations of a funded namespace, and a [CapabilityKind.REGISTER] one re-arms the
 *    registrations and not the deliveries.
 *
 * **Funding causes no traffic by itself.** It is a flag: nothing is redeemed, registered or stored
 * until a registration row is pending (`Registrations.keep`), which is the funder's renewal step's act
 * (design §7.5 item 7), never a received blob's. The channel engine therefore calls [set] from the
 * transactions that may cause relay-visible behaviour only (`CH-CREATE`, `CH-SWITCH` of a rotating
 * committer, the funder renewal step), and gate G-DM2 lists the call among the restricted ones.
 */
interface Funding {
    /**
     * Marks the namespace funded ([funded] true) or not, in the caller's transaction. Idempotent: it
     * returns normally when the flag already has the value. Marking an unregistered namespace funded
     * throws [IllegalStateException] ("namespace is not registered"); unmarking one is a no-op.
     *
     * Unmarking keeps the registration capabilities the namespace already holds: they are inert
     * (nothing reads them for an unfunded namespace, and [Capabilities.needed] stops reporting them)
     * and are collected at their expiry, so a funder that is named again within the week reuses them.
     */
    fun set(tx: SyncTransaction, namespace: NamespaceId, funded: Boolean)

    /** Whether the namespace is funded, in the caller's transaction. Reads only. False for an unknown namespace. */
    fun isFunded(tx: SyncTransaction, namespace: NamespaceId): Boolean
}
