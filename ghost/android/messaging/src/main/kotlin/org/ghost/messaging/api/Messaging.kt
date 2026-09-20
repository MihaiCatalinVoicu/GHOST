package org.ghost.messaging.api

import org.ghost.messaging.engine.OwnerSteps

/**
 * The UI-less DM facade of Phase 9 design §13.2, **as far as slice S6 builds it**.
 *
 * §13.2 gives the whole interface Phase 13 will call: `myCard`, `addContact`, `contacts`,
 * `conversation`, `send`, `react`, `setTimer`, `markDisplayed`, `retry`, the safety-number and
 * key-change calls, `resetSession`, `reconnect`, the request calls, `block`/`unblock`/
 * `deleteContact`, revocation, `status` and the two listener setters. S6 is the **owner side**:
 * the identity's own card and the activation hooks. Everything that needs a contact arrives with
 * S7, trust and restore with S8, the ephemeral calls with S9. Each signature lands **with** its
 * slice rather than ahead of it: a method that compiled and answered nothing would be refused by
 * the static gates, and a caller written against one would be written against a promise.
 *
 * The contract §13.2 states already holds for what is here: every method posts to the DM actor and
 * returns after its transaction commits, none performs network I/O, and `toString()` of every
 * value type is redacted (T3).
 *
 * **The DM actor is S7's.** §13.7 makes one thread the only DM writer, and §17.1 puts it in the
 * S7 row with the listener hand-off and the `ConsumerTail` body. S6's writers are serialized by
 * `SyncDatabase`'s own transaction lock, which is what §13.7 relies on underneath; the actor adds
 * ordering between transactions, which no owner step of this slice needs.
 */
interface Messaging {

    /**
     * The owner's contact card v2 and its `ghost://contact/` link (§3.3, §12.1). No network, no
     * transaction: the card is a pure function of the seed and the card index, so a restored
     * device shows the same card and every contact keeps working.
     *
     * Null means `CRYPTO_UNAVAILABLE`: the DM context is closed (locked, wiped) or
     * `libghost_client_net.so` could not be loaded (§13.2).
     */
    fun myCard(): CardExport?

    /**
     * The K20 activation hook (§13.4, RS K20): `:entitlement` calls it after the activation
     * finalization of a trial or a genesis identity, through `:app`. Runs **ACTIVATE** (§7.2).
     *
     * It is safe to call more than once and from any state: ACTIVATE is idempotent per identity,
     * and §21.12 point 2 has the actor run it again at every start and database open, which is
     * what covers a crash between the identity's creation and this commit.
     */
    fun onActivated(): ActivationOutcome

    /**
     * The restore half of the same hook (§13.4, §8.6). Runs ACTIVATE with the restore semantics:
     * `dm_self.accept_after_minute` is this minute, so content authored before the restore is
     * refused at `RECV` R9 — `dm_seen` and the pair keys did not survive, so it could not be
     * deduplicated (§7.6 "Restore").
     */
    fun onRestored(): ActivationOutcome

    /**
     * The four owner-side time-triggered steps of §7.2 — OWNER-WEEK, KEEPER and REGROWS — run in
     * the order §13.7 gives them, from a relay session start, a database open or the actor timer
     * (§21.9 rule 1). It is **never** called from an `INBOX` hint or a user send: that is the
     * whole of PM-30, and the engine has no other path to it.
     *
     * Returns counts only (T3).
     */
    fun runOwnerMaintenance(): MaintenanceReport
}

/** The owner's own card: 131 bytes and the 226-character link (§3.3). */
class CardExport(card: ByteArray, val link: String) {
    private val bytes: ByteArray = card.copyOf()

    val card: ByteArray get() = bytes.copyOf()

    /** Never shows the card: it is a bearer secret for "may message me" (§3.3). */
    override fun toString(): String = "CardExport(redacted)"
}

/** What [Messaging.onActivated] or [Messaging.onRestored] did. Enums only. */
enum class ActivationOutcome {
    /** `dm_self`, the own namespaces and the first bundle generation were created. */
    ACTIVATED,

    /** An identity was already activated here: ACTIVATE is idempotent per identity (§7.2). */
    ALREADY_ACTIVE,

    /** The DM context is closed or the native library is missing (§13.2). */
    CRYPTO_UNAVAILABLE,

    /**
     * This week's ES slot table yields no relay set, so no namespace could be registered (§5.2).
     * Nothing was written; §21.12 point 2's resumable activation runs it again.
     */
    NO_RELAYS,
    ;

    internal companion object {
        fun of(result: OwnerSteps.Result): ActivationOutcome = when (result) {
            OwnerSteps.Result.DONE -> ACTIVATED
            OwnerSteps.Result.UNCHANGED, OwnerSteps.Result.NOT_ACTIVATED -> ALREADY_ACTIVE
            OwnerSteps.Result.CRYPTO_UNAVAILABLE -> CRYPTO_UNAVAILABLE
            OwnerSteps.Result.NO_RELAYS -> NO_RELAYS
        }
    }
}

/** What one maintenance pass did. Counts and enums only, never a time (T3, §13.2 `status`). */
class MaintenanceReport(
    val ownerWeek: OwnerSteps.Result,
    val keeper: OwnerSteps.Result,
    val regrows: OwnerSteps.Result,
) {
    /** True when any of the three changed something. */
    val changed: Boolean
        get() = ownerWeek == OwnerSteps.Result.DONE ||
            keeper == OwnerSteps.Result.DONE ||
            regrows == OwnerSteps.Result.DONE

    override fun toString(): String = "MaintenanceReport($ownerWeek, $keeper, $regrows)"
}
