package org.ghost.messaging.harness

import org.ghost.crypto.bridge.DmEquivalence
import org.ghost.messaging.MovableClock
import org.ghost.messaging.engine.DmTime
import org.ghost.messaging.engine.DmTimers
import org.ghost.messaging.port.DmEnvelopes

/**
 * The correctness and ephemeral mutants of Phase 9 design §15.7, as far as slice S10 implements
 * them, with the discipline `Mutants.kt` and `t2_mutants.rs` already set in this repository: **a
 * mutant is registered only when a named test kills it.** A registered mutant with no test that
 * detects it is not evidence, it is a claim.
 *
 * §15.7's own set is 97 — 40 privacy (S11's), 33 correctness and 24 ephemeral (this slice's 57).
 * Fifteen are here: seven from S10, four from S10b — MC-18 and MC-26, which S10b's SCN-I makes
 * reachable, MC-28, which its SCN-H does, and MC-33, which its `SCN-G-week` does — two from
 * SCN-E (§22.25), MC-14 and MC-15, killed on the entitlement world by `entworld.ScnETest`, and two
 * from the suite cases of §22.27, MC-21 and MC-24, which RS2 and KC12 make reachable. The other
 * 42 are listed in §22.15, §22.19, §22.25 and §22.27 with the reason each is not, and the gate line
 * says **fifteen**, not fifty-seven, for the same reason `dm-report-check.sh` refuses a PASS on an empty sample: a
 * number a run did not measure is worse than no number. The line is built from the kills the run
 * **recorded** ([DmKills]), never from this registry, so an ignored or deleted kill test lowers
 * the count instead of leaving it standing. **S10b's four, SCN-E's two and §22.27's two are held
 * to a stricter kill than S10's seven**: detected fault-free by the check their entry names, *and*
 * at crash points — spread over the scenario for S10b's, over the window from the loss to the
 * fault-free failure for SCN-E's (§22.25 item 14), inside the transaction the mutant first changes
 * for §22.27's (as its review corrected the rule) — each beside the unmutated scenario crashed at
 * the same point ([Mutation.expectUnderCrash]).
 *
 * **What a mutant may be, here.** `:messaging` has no `Steps` seam the way `:sync` does, so a
 * mutation is one of three things: a **statement rewrite** on the device's executor (the same
 * mechanism as the Phase 7 harness's SQL-level mutants M2, M6, M8, M10 and M11), a **decorator**
 * on the `DmEnvelopes` port, or a **transaction split** ([FaultyDmSqlExecutor.defer]) that holds a
 * statement back into a second transaction. The third is new in this slice's review and is what
 * makes MC-1 reachable; §22.15 item 8 had recorded it as out of reach of the first two, and it is.
 * That is what decides which of §15.7's 57 are reachable here, and §22.15 says so per mutant
 * rather than in general. SCN-E adds a fourth, a **trigger substitution** in the entitlement
 * world's wiring ([Mutation.hintKeeper], MC-15), and it is the only one that changes *when* a
 * production step runs rather than what a statement or a port does. §22.27's MC-21 is a statement
 * rewrite that also reads the device's clock ([Mutation.rewriteOn]) — the first mechanism, given
 * the one input SWEEP's erasure bound needs that no statement argument carries.
 */
internal object DmMutants {

    /**
     * One substitution in the armed world. Exactly one of the mechanisms is set: a rewrite (plain
     * or bound to the device's clock), a decorator, a split or a trigger substitution.
     */
    class Mutation(
        val id: String,
        /** The property §15.7 says this mutant defeats, in its own words. */
        val defeats: String,
        /** Which scenario or suite case §15.7 says detects it, and which one here does. */
        val detectedBy: String,
        /**
         * A substring the killing failure's message **must** contain.
         *
         * Without it "detected" means only "the mutated run threw an `AssertionError`", and a
         * mutant that made the harness fall over would be indistinguishable from one the scenario
         * caught. It is also what keeps [detectedBy] honest: the first version of this registry
         * said MC-5 was killed by RP6's `seen > 1` check, and it is not — the `dm_message` replace
         * guard refuses the second row first, and the run fails there. Both strings now say the
         * same thing because the test compares one against the other.
         */
        val expect: String,
        /**
         * What the killing failure says when the mutant runs **under a crash** (S10b).
         *
         * A faulted run does not run the scenario's `finalChecks` — a crash may have lost the very
         * step they assert — so a mutant detected fault-free by a final check is, under a crash,
         * detected by something else or by nothing. For the mutants S10b registers the kill test
         * also runs the mutant at crash points spread over the scenario's own events, beside the
         * unmutated scenario at the same points, and this is the list of messages that count as a
         * kill there: §15.3's two oracles at quiescence, in the words `DmCrashRunner` writes them,
         * or a clause of the structural invariants. Empty for the S10 mutants, whose kills are
         * what they were.
         */
        val expectUnderCrash: List<String> = emptyList(),
        val rewrite: ((String, List<Any?>) -> Pair<String, List<Any?>>)? = null,
        /**
         * A **statement rewrite that reads the device's own clock** (§22.27, MC-21): the same
         * mechanism as [rewrite], bound to one node's clock when the node is built
         * (`DmCrashWorld.node`). A rewrite sees a statement and its arguments and nothing else, and
         * SWEEP's erasure bound is a comparison with `now_e`, which no argument of the statement
         * MC-21 changes carries; the clock is the device's wall clock, the half of `now_e` that is
         * not in the database (the other half, `dm_self.expiry_clock_minute`, is read in the
         * rewritten SQL itself). Only the crash world installs it.
         */
        val rewriteOn: ((MovableClock) -> ((String, List<Any?>) -> Pair<String, List<Any?>>))? = null,
        val decorate: ((DmEnvelopes) -> DmEnvelopes)? = null,
        /** The transaction-split seam of [FaultyDmSqlExecutor.defer]; only a crash run kills these. */
        val defer: ((String) -> Boolean)? = null,
        /**
         * The split for an `execUpdate`, with the count its caller is given
         * ([FaultyDmSqlExecutor.deferUpdate], §22.37): MC-7′'s second half.
         */
        val deferUpdate: ((String) -> Int?)? = null,
        /**
         * A **native** mutation (§22.37): the binding v3 field every DM context of the world leaves
         * out of its transcript (`DmEquivalence.bindingHooks`, a test-library entry point). The
         * crate's own code, switched per context, where the three JVM mechanisms cannot reach:
         * binding v3 is signed and verified inside it.
         */
        val bindingOmit: Int = DmEquivalence.BINDING_NONE,
        /**
         * A **policy substitution** (§22.38): RECV's freshness rule ([org.ghost.messaging.engine.ContentFreshness]),
         * handed to every device of the world. MC-9 only.
         */
        val freshness: org.ghost.messaging.engine.ContentFreshness? = null,
        /** True when the mutant is invisible without a crash, so its kill runs the enumeration. */
        val needsACrash: Boolean = false,
        /**
         * A **native hook** of the state wrap (§22.38): every context of the world stores its Olm
         * session states unwrapped (`DmEquivalence.stateWrapHook`). ME-24 only.
         */
        val stateUnwrapped: Boolean = false,
        /**
         * A **native hook** of the sidecar (§22.38): every context of the world keeps its sessions'
         * first-seen sidecars as insert-only logs (`DmEquivalence.sidecarLogHook`). MC-30's second
         * half only.
         */
        val sidecarLog: Boolean = false,
        /**
         * For a mutant that changes only the **bytes** a statement writes — its world issues the same
         * statements, so no trace ever departs (§22.37's window of a native mutant has no event to
         * find): the statements it acts at, by their label. Its window is the transaction of the
         * first one after the scenario's mark. ME-24, MC-30's sidecar half, and ME-20 — a rewrite
         * that acted in the setup, where nothing is an event, and changes no statement after it.
         */
        val actsAt: ((String) -> Boolean)? = null,
        /**
         * For a **rewrite of a read** whose changed result need not change anything the device then
         * does (§22.38's review of ME-17): the window is not the first rewritten span after the mark
         * but the transaction in which the traced mutated world first departs from the clean one —
         * where the device first decides otherwise — measured as a native mutant's is (§22.37). A
         * rewritten span says only that a statement's text changed; ME-17's first one after its mark
         * was alice's read-only conversation read, whose `now_e` is her wall clock either way.
         */
        val windowByDeparture: Boolean = false,
        /**
         * A **trigger substitution** in the entitlement world's wiring (SCN-E, §22.25): the contact
         * half of KEEPER — the production `ContactKeeper` — runs on every `CAPABILITIES` hint instead
         * of on time-triggered passes only. A fourth mechanism beside the rewrite, the decorator and
         * the split, and the only one here that moves *when* a production step runs: the wiring is
         * the one piece of the DM runtime a harness owns (`EntDmClient`, a copy of `MessagingWiring`'s
         * decisions, §22.22 item 6(g)). Only `ScnE` reads it.
         */
        val hintKeeper: Boolean = false,
    ) {
        override fun toString(): String = id
    }

    /**
     * **MC-1 — the ratchet state and the op committed in two transactions.** §15.7's first
     * correctness mutant, and the one CS-1 names: *"a ratchet step commits if and only if its
     * message row and outbox op commit"*.
     *
     * §7.9's rule is that the new session envelope goes back through `tx.sql` **in the transaction
     * that writes the message row and enqueues the op**. The mutation holds the one statement that
     * writes it — `UPDATE olm_session SET state_env = ?`, which `SessionStore.setStateEnv` is —
     * back until the enclosing transaction has committed, and commits it in a transaction of its
     * own. Nothing else changes: the same statement, the same bytes, one commit later.
     *
     * With no fault it is invisible, which is the whole point: the second transaction follows the
     * first by microseconds and every run is green. With a crash in the window between the two, the
     * op is out and the ratchet did not move, so the **next** send re-uses the message key the
     * recipient has already consumed and that message never opens — §15.7's own words for what
     * SCN-A sees, "a lost message, then an undecryptable next message". The no-loss oracle of
     * [DmCrashRunner] is what catches it: the sender's item reached `sent` and no device ever
     * rendered it.
     *
     * It is the only mutant here that **no fault-free run can detect**, and that is why it is
     * registered: without one, nothing proves the ~2 000 crash runs of a gate can fail at all.
     */
    val MC1 = Mutation(
        id = "MC-1",
        defeats = "CS-1: the ratchet step commits if and only if the message row and the op commit",
        detectedBy = "SCN-A under a crash in the split window (a lost message the sender calls sent)",
        expect = "marked it sent",
        needsACrash = true,
        defer = { sql -> sql.startsWith("UPDATE olm_session SET state_env") },
    )

    /**
     * **MC-5 — D3 off.** The `dm_seen` tag of §7.6 is never written, so the fourth dedup layer is
     * gone.
     *
     * §15.7: "detected by SCN-G FAILED retry after a lost receipt; RP2 with D1 expired". RP6 is the
     * first of those here: every other duplicate a sender can produce carries identical bytes and
     * dies at D1's tombstone, while a **user retry after a wrongly reported FAILED** re-encrypts, so
     * the bytes and the hash differ and the only thing left that names the message is the tag over
     * its `message_id`.
     *
     * **What actually kills it is not RP6's `seen > 1` check, and saying so was this registry's own
     * false claim.** With the tag gone the second copy is *new* to RECV, so RECV inserts the message
     * row again — and `dm_message`'s **replace guard** (§13.6, "dm_message rows are never replaced")
     * refuses it with `SQLITE_CONSTRAINT_TRIGGER`. The pass dies there, and
     * `DmCrashRunner.onlyExpectedExceptionsWereSwallowed` reports it, before anything is rendered
     * twice. So the schema is a **fifth** layer under D3 for this particular duplicate, and the
     * claim that D3 "is the only thing between the recipient and a message rendered twice" is false
     * as stated — what is true is that D3 is the only thing that makes the copy a *duplicate*
     * rather than an error. The [expect] string is what pins the difference, and §22.15 item 14
     * records it, including that the CS-2 half of the oracle is therefore still unexercised.
     *
     * **Since the phase review (ENG-3) the fifth layer drops instead of aborting.** A peer could
     * reach the same guard on purpose — re-using an id — and every such blob aborted three passes,
     * so RECV now writes the row with an insert that selects nothing when the id is taken and drops
     * the message as `id_taken`, a reason of its own. The replace guard's abort no longer kills this
     * mutant; RP6's check that no copy it retries ever reaches the message row does, which is D3's
     * own property at last: with the tag written, the copy is a `duplicate` at R10.
     */
    val MC5 = Mutation(
        id = "MC-5",
        defeats = "D3: the dm_seen tag makes a re-encrypted copy of a message a duplicate",
        detectedBy = "RP6's retry, which D3's absence lets reach the message row (counted id_taken)",
        expect = "the retried copy passed D3 and reached the message row",
        // The tag written is a random one, so the insert still **succeeds** and the real tag is
        // never recorded. Suppressing the statement outright would be the opposite mutant:
        // `markSeen` reports "new" by `execUpdate(...) == 1`, so a statement that changes no row
        // makes every message look like a duplicate and the recipient renders nothing at all.
        rewrite = { sql, args ->
            if (sql.startsWith("INSERT OR IGNORE INTO dm_seen")) {
                Pair(
                    "INSERT OR IGNORE INTO dm_seen(tag, until_day) VALUES (randomblob(16), ?)",
                    listOf(args[1]),
                )
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-7′ — D2b not enforced.** The `olm_prekey_used` reuse tuple of §7.6 and §5.6 is never
     * written, so a replayed first flight builds a second session.
     *
     * §5.6 is why the tuple exists at all: GHOST publishes no one-time keys, so vodozemac does not
     * consume anything when an inbound session is created, and nothing but this row stops the same
     * PreKey message from creating a new session every time it is served. §12.3's "a rejected
     * request leaves nothing behind" is what breaks first — the rejected requester's next envelope
     * makes a **second** request.
     */
    val MC7 = Mutation(
        id = "MC-7'",
        defeats = "D2b: a replayed first flight never builds a second session",
        detectedBy = "the rejected-request replay of §12.3 (a second request appears), RP4 (the session bob " +
            "reset comes back) and RP5, fault-free and under a crash in the transaction that writes the tuple; " +
            "its second half (the tuple written outside the RECV transaction) by RP5 under a crash in its " +
            "split window",
        expect = "a rejected request came back as a second one",
        // Under a crash inside the RECV transaction that writes the tuple (§22.37): the transaction
        // rolls back, the first flight is taken again after the reboot, and the rewrite writes a
        // tuple that matches nothing once more.
        expectUnderCrash = listOf("a rejected request came back as a second one"),
        // A random `session_id`, for the same reason MC-5 writes a random tag: the row still goes
        // in, so nothing downstream sees a failed write, and `firstFlightUsed` — which is what D2b
        // actually asks — never finds the tuple it is looking for.
        rewrite = { sql, args ->
            if (sql.startsWith("INSERT OR IGNORE INTO olm_prekey_used")) {
                Pair(
                    "INSERT OR IGNORE INTO olm_prekey_used(gen_id, session_id) " +
                        "VALUES (?, randomblob(32))",
                    listOf(args[0]),
                )
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-7′'s second half — the reuse tuple written outside the RECV transaction** (§15.7:
     * "D2b not enforced, or written outside the RECV transaction"; §22.27 item 8; built by §22.37).
     * The same §15.7 id as [MC7], which is its first half, and not a new one: it is not in [all],
     * and MC-7′ is recorded as detected only once both halves are killed (`DmMutantDetectionTest`).
     *
     * `SessionStore.markFirstFlightUsed`'s insert is held back until the RECV transaction that built
     * the inbound session has committed, and committed in a transaction of its own — the split of
     * [MC1], for an `execUpdate`, with the count 1 the unmutated insert returns there
     * ([FaultyDmSqlExecutor.deferUpdate]). With no fault it is invisible. A crash between the two
     * commits loses the tuple while the session, the request and the consumed blob stand, which is
     * exactly what §7.8's "a crash after `sessionInbound` rolls back the session row and the reuse
     * tuple together" forbids; RP5 then sees it: bob rejects the request, restarts, and the
     * requester's next envelope of the same session builds a second request.
     */
    val MC7_SPLIT = Mutation(
        id = "MC-7'",
        defeats = "D2b: the reuse tuple commits in the RECV transaction that builds the session",
        detectedBy = "RP5, a PreKey replay across a restart, under a crash in the split window",
        expect = "a rejected request came back as a second one",
        needsACrash = true,
        deferUpdate = { sql -> if (sql.startsWith("INSERT OR IGNORE INTO olm_prekey_used")) 1 else null },
    )

    /**
     * **MC-20 — binding without namespace, minute, ciphertext or base key** (§21.4 point 1, §3.4;
     * built by §22.37). Binding v3's transcript leaves one of the four out, on every device of the
     * world — signed without it and verified without it, so the world's own traffic still verifies
     * and only a binding moved to another value of that field tells. KC5b moves one per field: the
     * intro whose genuine binding names another value of the omitted field is accepted, and bob
     * gains a request from it. One §15.7 id, four omissions; the entry registered below carries the
     * namespace, and the kill runs all four ([MC20_OMISSIONS]).
     */
    val MC20 = mc20(DmEquivalence.BINDING_NAMESPACE, "namespace")

    /** MC-20's four omissions, in KC5b's order. */
    val MC20_OMISSIONS: List<Mutation> = listOf(
        MC20,
        mc20(DmEquivalence.BINDING_MINUTE, "minute"),
        mc20(DmEquivalence.BINDING_CIPHERTEXT, "ciphertext"),
        mc20(DmEquivalence.BINDING_BASE_KEY, "base key"),
    )

    private fun mc20(field: Int, label: String) = Mutation(
        id = "MC-20",
        defeats = "binding v3 covers the recipient namespace, the minute, the X-Wing ciphertext and the base key",
        detectedBy = "KC5b (a genuine binding replayed with another namespace, a stale minute, another " +
            "ciphertext or another base key: no state change), each omission by its own replay",
        expect = "KC5b: bob accepted an intro whose binding names another $label",
        // Under a crash inside the transaction the omission first changes — bob's first RECV of the
        // replay whose binding it lets verify (§22.37 item 6): it rolls back, the blob is taken again
        // after the reboot, and the omission lets it through again.
        expectUnderCrash = listOf("KC5b: bob accepted an intro whose binding names another $label"),
        bindingOmit = field,
    )

    /**
     * **ME-9 — expiry extendable** (R-T6, §10.3; built by §22.38). Migration 5 does not create
     * `dm_message_expiry`, the trigger by which an expiry time only moves earlier. The engine never
     * asks it to refuse anything — DISPLAY writes `expire_at_minute` under its own guard and only
     * for an unread row — so no traffic sees it gone; what sees it is §15.7's "trigger test", which
     * is the open path's own trigger set (`verifyIntegrity`), and it refuses the file. A statement
     * rewrite of the migration, which only a migration on the bus reaches (SCN-L-v3).
     */
    val ME9 = Mutation(
        id = "ME-9",
        defeats = "R-T6: an expiry time only moves earlier (the dm_message_expiry trigger)",
        detectedBy = "SCN-L-v3 (the open path refuses a file without dm_message_expiry)",
        expect = "bob's database was refused at open: schema integrity: missing triggers [dm_message_expiry]",
        expectUnderCrash = listOf("bob's database was refused at open: schema integrity: missing triggers [dm_message_expiry]"),
        rewrite = { sql, args ->
            if (sql.startsWith("CREATE TRIGGER dm_message_expiry")) Pair("SELECT 1", emptyList()) else Pair(sql, args)
        },
    )

    /**
     * **ME-24 — session state stored unwrapped** (§2.5, R-S6; built by §22.38). A native hook under
     * `test-vectors` (`ghost_client_dm::wrap::hooks`, per DM context, like MC-20's): the context
     * stores every Olm session state as it is and reads it back as stored, so the world's ratchet
     * still runs and what differs is only what `olm_session.state_env` holds — the pickle and its
     * sidecar, the session's keys, in the clear. §15.7 names T3's and T25's physical scans for
     * exported root-key canaries; what kills it here is their logical half, the standing clause
     * that every stored state opens under the device's state key
     * (`DmStructuralInvariants.sessionStatesAreWrapped`). The physical canary scan is not built.
     */
    val ME24 = Mutation(
        id = "ME-24",
        defeats = "§2.5: every Olm session state is stored wrapped under session_state_key with its own binding",
        detectedBy = "SCN-C (the standing clause: every stored session state opens under the device's state key)",
        expect = "a stored session state does not open under the device's state key",
        expectUnderCrash = listOf("a stored session state does not open under the device's state key"),
        stateUnwrapped = true,
        actsAt = { label -> label.startsWith("INSERT INTO olm_session(") || label.startsWith("UPDATE olm_session SET state_env") },
    )

    /**
     * **ME-11 — no checkpoint** (§10.7 "Checkpoint", §10.9 item 3; built by §22.38). SWEEP's
     * `PRAGMA wal_checkpoint(TRUNCATE)` answers as a truncation that succeeded (`busy = 0`) and
     * truncates nothing: the engine goes on as if the log were empty, and the freed frames stay in
     * the `-wal`. A statement rewrite, because the pragma is read through the device's executor
     * (`Checkpoint.truncate(sql)`, the real one, `DmWorld`'s `checkpoints`); R-K1 at every open runs
     * on the raw connection and is untouched, which is what makes a crash at the checkpoint a
     * point where the mutant acts **and** is healed — so its kill needs a second checkpoint after it.
     */
    val ME11 = Mutation(
        id = "ME-11",
        defeats = "§10.7: after a SWEEP that deleted rows, wal_checkpoint(TRUNCATE) empties the log",
        detectedBy = "EP-sweep-log (the log is 0 bytes right after every checkpoint the device reports done, " +
            "§10.9 item 3)",
        expect = "the log held",
        expectUnderCrash = listOf("the log held"),
        rewrite = { sql, args ->
            if (sql.startsWith("PRAGMA wal_checkpoint")) Pair("SELECT 0, 0, 0", emptyList()) else Pair(sql, args)
        },
    )

    /**
     * **ME-17 — a wall-clock back step delays deletion** (R-T7, §10.3, §10.9 item 4; built by
     * §22.38). The expiry clock `dm_self.expiry_clock_minute` reads as 0 in the one statement that
     * reads it (`OwnerStore.self`), so `now_e = max(wall, 0)` is the wall clock for every deadline:
     * a device whose clock stepped back keeps rows past the minute its sweeps had already reached.
     * The column itself is untouched — SWEEP raises it with `... WHERE expiry_clock_minute < ?`,
     * which a smaller `now_e` never matches, so no guard fires and the mutant is seen only by what it
     * delays.
     *
     * What EP-clock-back sees of it is **RECV's** held-cap check (§21.10 point 5): the clean RECV
     * refuses the row, whose cap lies at or below `now_e` (`expired_while_held`), and the mutated one
     * — comparing with the stepped-back wall clock — inserts it, past its deadline on the expiry
     * clock. SWEEP's own `now_e` decides nothing in the case: the row it would delete never exists in
     * the clean world (§22.38's review). The rewrite changes the text of every `dm_self` read of every
     * node, so its window is where the traced worlds part, bob's RECV ([windowByDeparture]), not its
     * first rewritten span — alice's conversation read, which decides nothing.
     */
    val ME17 = Mutation(
        id = "ME-17",
        defeats = "R-T7: every deadline is measured against now_e = max(wall, expiry_clock_minute)",
        detectedBy = "EP-clock-back (the RECV of a message whose unread cap lies between the stepped-back wall clock " +
            "and the expiry clock refuses it, §10.9 item 4, §21.10 point 5)",
        expect = "past their delete_at_minute on the expiry clock",
        expectUnderCrash = listOf("past their delete_at_minute on the expiry clock"),
        windowByDeparture = true,
        rewrite = { sql, args ->
            if (sql.startsWith("SELECT card_index, seen_key, content_key_wrapped") && sql.contains(" FROM dm_self")) {
                Pair(sql.replace("expiry_clock_minute, accept_after_minute", "0, accept_after_minute"), args)
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-9 — no freshness check** (R9 and binding B1, §7.6; built by §22.38). RECV's freshness
     * policy admits content of any age and of any week; `accept_after_minute` (§8.6, a restore rule
     * and not MC-9's) is kept. It is read for **every** content — `acceptAfter()` first,
     * unconditionally — where [org.ghost.messaging.engine.ContentFreshness.RULE] reads it only once
     * the age bound has passed: the same statements as the clean world for content inside the age
     * bound, one self-row read more for content outside it (§22.38's review corrected this comment,
     * which said "read exactly when the rule reads it"). The decision is Kotlin comparisons over the
     * decrypted author minute, which no statement carries and no port result is, so the mutant lives
     * on the policy parameter §22.38 added to `ReceiveStep`.
     *
     * **Its kill is its B1 half** (§22.38's review). RP7's back-dated L0 lies inside R9's age bound,
     * so RP7 refuses it by B1 alone: the age bound dropped alone ([MC9_WITHOUT_R9]) passes RP7, and B1
     * dropped alone ([MC9_WITHOUT_B1]) fails it for this entry's reason — both run beside the kill, and
     * the kill is recorded as B1's. R9's half is covered by `ContentFreshnessTest` (each edge of the
     * age bound, and the grid on which the rule decides and reads as the inline code did), not by
     * this mutant.
     */
    val MC9 = Mutation(
        id = "MC-9",
        defeats = "R9 and B1: content older than FRESH(bucket), from the future, or of another week than its key is refused",
        detectedBy = "RP7, its B1 half (an L0 of last week re-sealed under this week's key is rendered); its R9 half, " +
            "the age bound, by ContentFreshnessTest and not by a kill",
        expect = "RP7: bob rendered an L0 dated in another week",
        expectUnderCrash = listOf("RP7: bob rendered an L0 dated in another week"),
        freshness = org.ghost.messaging.engine.ContentFreshness { authorSeconds, _, _, _, acceptAfter ->
            val after = acceptAfter()
            after == null || authorSeconds >= after
        },
    )

    /**
     * [MC9]'s B1 half alone, a control of what its kill shows and **not** a registered mutant (not in
     * [all]): the production rule with the key week withheld, so R9's age bound and
     * `accept_after_minute` stand and the self row is read exactly when the rule reads it. RP7 must
     * fail under it for [MC9]'s reason.
     */
    val MC9_WITHOUT_B1 = Mutation(
        id = "MC-9",
        defeats = "B1: content of another week than the key that sealed it is refused",
        detectedBy = "RP7 (an L0 of last week re-sealed under this week's key is rendered)",
        expect = MC9.expect,
        freshness = org.ghost.messaging.engine.ContentFreshness { authorSeconds, arrivalSeconds, freshSeconds, _, acceptAfter ->
            org.ghost.messaging.engine.ContentFreshness.RULE.admits(authorSeconds, arrivalSeconds, freshSeconds, null, acceptAfter)
        },
    )

    /**
     * [MC9]'s R9 half alone, the other control and not a registered mutant: the production rule
     * without its age bound — `accept_after_minute` and B1 stand. RP7 must **pass** under it: its L0
     * is inside the age bound, so no RP7 run can tell this half, which is why the kill is B1's.
     */
    val MC9_WITHOUT_R9 = Mutation(
        id = "MC-9",
        defeats = "R9: content older than FRESH(bucket) or more than 2σ ahead of its arrival is refused",
        detectedBy = "no crash-world case (ContentFreshnessTest covers the age bound)",
        expect = MC9.expect,
        freshness = org.ghost.messaging.engine.ContentFreshness { authorSeconds, _, _, pairWeek, acceptAfter ->
            val after = acceptAfter()
            if (after != null && authorSeconds < after) {
                false
            } else {
                pairWeek == null || DmTime.week(authorSeconds) == pairWeek
            }
        },
    )

    /**
     * **MC-30 — skipped keys not pruned at `FRESH + 2σ`** (§7.7 point 4, V-15; built by §22.38), its
     * first half. A `DmEnvelopes` decorator: SWEEP's `sessionPrune` removes nothing — the call reports
     * no key removed and the stored state is left as it was — so a skipped key outlives its 51 days.
     * One §15.7 id, two halves: this one is the entry registered below, and the kill runs both
     * ([MC30_LOG]). RO-prune kills it by the age clause after SWEEP
     * (`DmStructuralInvariants.skippedKeysPruned`).
     */
    val MC30 = Mutation(
        id = "MC-30",
        defeats = "§7.7 point 4: skipped keys are pruned at FRESH + 2σ, and the first-seen sidecar is the projection " +
            "of the pickle rebuilt at every store",
        detectedBy = "RO-prune (the age clause after SWEEP; the sidecar projection clause)",
        expect = "past FRESH + 2σ (51 days, §7.7 point 4)",
        expectUnderCrash = listOf("past FRESH + 2σ (51 days, §7.7 point 4)"),
        decorate = { real -> NoPrune(real) },
    )

    /**
     * MC-30's second half: the first-seen sidecar kept as an insert-only **log** instead of the
     * projection rebuilt at every store — a native hook under `test-vectors` (`olm::state::hooks`, per
     * DM context), so a key the pickle no longer holds keeps its entry for good. RO-prune's prune is
     * where that first shows: the key goes from the pickle, its entry stays, and the standing
     * projection clause refuses the state. The world issues the clean world's statements, so its
     * window is named by the statement it acts at ([actsAt]): the first session state written after
     * the mark, the prune's.
     */
    val MC30_LOG = Mutation(
        id = "MC-30",
        defeats = MC30.defeats,
        detectedBy = "RO-prune (the sidecar projection clause, at the prune)",
        expect = "is not the projection of its pickle (§7.7 point 4)",
        expectUnderCrash = listOf("is not the projection of its pickle (§7.7 point 4)"),
        sidecarLog = true,
        actsAt = { label -> label.startsWith("INSERT INTO olm_session(") || label.startsWith("UPDATE olm_session SET state_env") },
    )

    /**
     * **ME-7 — the recipient's countdown at receive** (§10.3, ADR-27 point 9; built by §22.38). A
     * statement rewrite of RECV's incoming insert, bound to the device's clock (like MC-21's): the
     * row is written with `expire_at_minute = ceil_minute(receive + timer)` — the sender's formula,
     * at the recipient's arrival — and `delete_at_minute` with it, as its CHECK requires, so an
     * unread five-minute message goes five minutes after it arrived instead of at its unread cap.
     * Killed by EP-stale-display's check, ten minutes on, that the unread message is still there,
     * fault-free and at crash points of bob's first RECV after the mark.
     */
    val ME7 = Mutation(
        id = "ME-7",
        defeats = "§10.3, ADR-27 point 9: the recipient's countdown starts at the first display, not at receipt",
        detectedBy = "EP-stale-display (the unread message is still there past its own timer, before its unread cap)",
        expect = "the recipient's countdown started before its display",
        expectUnderCrash = listOf("the recipient's countdown started before its display"),
        rewriteOn = { clock ->
            { sql, args ->
                if (sql.startsWith(ME19_INSERT) && sql.contains(ME19_INCOMING) && args[9] != null) {
                    val expireAt = org.ghost.messaging.engine.DmTimers.senderExpireMinute(
                        clock.now,
                        (args[6] as Long).toInt(),
                    )
                    val mutated = sql.replace(ME7_NO_COUNTDOWN, "?, ?, ?, ?")
                    check(mutated != sql) { "ME-7's rewrite found no NULL countdown in RECV's insert" }
                    Pair(mutated, args.toMutableList().also { it.add(9, expireAt); it[11] = expireAt })
                } else {
                    Pair(sql, args)
                }
            }
        },
    )

    /** RECV's insert leaves the countdown NULL between the state and the cap: `?, NULL, ?, ?`. */
    private const val ME7_NO_COUNTDOWN: String = "?, NULL, ?, ?"

    /**
     * **ME-19 — the unread deadline from `author + bucket`** (C-11, §10.3; built by §22.38). A
     * statement rewrite of RECV's incoming insert: the cap it writes into `unread_deadline_minute`
     * (and into `delete_at_minute`, which its CHECK ties to it while the row is unread) is
     * `ceil_minute(author + bucket + 1 h)` — the production formula with the content's author time
     * where the recipient's own arrival belongs. `min(E, …)` is dropped with it: the rewrite sees
     * no relay expiry, and E — thirty days in the crash world — binds only past R9's six-day bound
     * on how far ahead an author may be. Killed by EP-sender-ahead's check that no cap lies past the
     * recipient's own `now_e` plus its bucket, an hour and a minute, fault-free and at crash points
     * of bob's RECV of the message dated five days ahead.
     */
    val ME19 = Mutation(
        id = "ME-19",
        defeats = "C-11, §10.3: an unread message's cap is min(E, consume + bucket + 1 h), from the recipient's own arrival",
        detectedBy = "EP-sender-ahead (a sender clock five days ahead: no cap past the recipient's own clock)",
        expect = "the cap came from the sender's clock (C-11, §10.3)",
        expectUnderCrash = listOf("the cap came from the sender's clock (C-11, §10.3)"),
        rewrite = { sql, args ->
            if (sql.startsWith(ME19_INSERT) && sql.contains(ME19_INCOMING) && args[9] != null) {
                val cap = org.ghost.messaging.engine.DmTimers.unreadDeadlineMinute(
                    consumeSeconds = args[3] as Long,
                    relayExpiryHour = Long.MAX_VALUE,
                    timerCode = (args[6] as Long).toInt(),
                )
                Pair(sql, args.toMutableList().also { it[9] = cap; it[10] = cap })
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * RECV's incoming insert (`MessageStore.insertIncomingIfAbsent`), told from SEND's outgoing one —
     * which starts the same and binds its arguments differently — by the `'in'` it selects: its
     * arguments 3, 6, 9 and 10 are the author minute, the timer, the cap and `delete_at_minute`.
     */
    private const val ME19_INSERT: String =
        "INSERT INTO dm_message(message_id, conversation_id, direction, kind, author_minute, "
    private const val ME19_INCOMING: String = "SELECT ?, ?, 'in', "

    /**
     * **ME-20 — the retained blob survives its message's deletion** (§7.5 "Retained blob", §21.10
     * point 2, T25; built by §22.38). A statement rewrite of migration 5 (and of migration 8, which rebuilds the table):
     * `dm_outbound_op.item_id`
     * loses its foreign key — the whole clause, since a key kept without its cascade makes SWEEP's
     * delete fail instead of leaving the op — so when SWEEP deletes a message whose op is still in
     * flight, the cascade takes the message and its item and leaves the op with its blob, and the
     * op's late outcome then finds no item and never clears it. Only a device that migrates on the
     * bus has its schema rewritten: EP-store-after-expiry's alice, in the setup
     * ([DmCrashWorld.node]). §15.7 names T25's physical scan of the blob bytes; what kills it here
     * is its logical half, the standing clause [DmStructuralInvariants.retainedBlobs]. The rewrite
     * acts in the setup, where nothing is an event, and changes no statement the world then issues,
     * so its window is named by the statement it acts at ([actsAt]): the SWEEP delete of the first
     * message after the mark, whose cascade is the one the schema no longer has.
     */
    val ME20 = Mutation(
        id = "ME-20",
        defeats = "§7.5, §21.10 point 2: a message's retained blob is deleted with the message, by the cascade message → item → op",
        detectedBy = "EP-store-after-expiry (the standing clause: no retained blob outlives its message)",
        expect = "a retained blob that outlives its message (T25",
        expectUnderCrash = listOf("a retained blob that outlives its message (T25"),
        rewrite = { sql, args ->
            if (sql.startsWith("CREATE TABLE dm_outbound_op")) {
                val mutated = sql.replace(ME20_KEY, "item_id BLOB,")
                check(mutated != sql) { "ME-20's rewrite found no foreign key on dm_outbound_op.item_id" }
                Pair(mutated, args)
            } else {
                Pair(sql, args)
            }
        },
        actsAt = { label -> label.startsWith("DELETE FROM dm_message WHERE message_id") },
    )

    /**
     * `dm_outbound_op.item_id`'s foreign key, as migration 5 writes it (the spacing is the schema's) **and as migration 8
     * writes it**: migration 8 (Phase 11, slice S3) rebuilds the table as `dm_outbound_op_v8`, whose key names its parent
     * `dm_outbound_item_v8` until the renames, and `startsWith("CREATE TABLE dm_outbound_op")` matches both statements, so
     * the rewritten world ends with the table the mutant means: the one migration 8 leaves, without the key.
     */
    private val ME20_KEY = Regex("""item_id\s+BLOB REFERENCES dm_outbound_item(?:_v8)?\(item_id\) ON DELETE CASCADE,""")

    /** MC-30's decorator: every `sessionPrune` reports that it removed nothing and leaves the state as it was. */
    private class NoPrune(private val real: org.ghost.messaging.port.DmEnvelopes) : org.ghost.messaging.port.DmEnvelopes by real {
        override fun prune(
            contactId: ByteArray,
            slot: org.ghost.crypto.bridge.DmSessions.StoredSlot,
            today: Int,
        ): org.ghost.crypto.bridge.DmSessions.Pruned =
            org.ghost.crypto.bridge.DmSessions.Pruned.Ok(slot.stateEnv, 0)
    }

    /**
     * **MC-10 — arrival-order display.** The conversation page is ordered by the row identity
     * instead of §7.7's `(sort_minute, minute_index)`.
     *
     * §15.7 detects it with RO1; SCN-B is the same property here. `dm_message` is `WITHOUT ROWID`,
     * so there is no insertion counter to order by and the mutation takes the primary key instead —
     * a 16-byte random id, which is an order unrelated to the author's. That is the same defect RO1
     * is about ("identical rendering on both clients"), reached by the one substitution the schema
     * allows.
     */
    val MC10 = Mutation(
        id = "MC-10",
        defeats = "CS-4: the rendering order is (sort_minute, minute_index) and nothing else",
        detectedBy = "SCN-B (six messages reordered across the relay set)",
        expect = "out of A's order (CS-4)",
        rewrite = { sql, args ->
            if (sql.contains("ORDER BY sort_minute DESC, minute_index DESC, message_id DESC")) {
                Pair(
                    sql.replace(
                        "ORDER BY sort_minute DESC, minute_index DESC, message_id DESC",
                        "ORDER BY message_id DESC",
                    ),
                    args,
                )
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-12 — offers ignored (no poison guard).** The write-ahead `offers` counter of the inbox
     * never advances, so a blob that kills the process is offered again for ever.
     *
     * §15.7 detects it with "SCN-J native crash loop", which is what `DmPoisonTest` runs: a
     * `SimulatedNativeCrash` from the `DmNative` port on every attempt to open one blob. With the
     * guard the blob is consumed as poison at the fourth offer — a declared loss, and the only
     * thing that keeps one malformed blob from stopping an inbox for ever. Without it the counter
     * stays at 1 and the fourth offer never comes.
     */
    val MC12 = Mutation(
        id = "MC-12",
        defeats = "the write-ahead poison guard: a blob that kills RECV is consumed at the fourth offer",
        detectedBy = "DmPoisonTest (SimulatedNativeCrash on every open of one blob)",
        expect = "the blob was not consumed as poison",
        rewrite = { sql, args ->
            if (sql.startsWith("UPDATE inbox_blob SET offers = offers + 1")) {
                Pair(sql.replace("offers = offers + 1", "offers = offers"), args)
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-16 — automatic resend beyond 2.** The op's `resend_count` is read back as 0, so the
     * bound of §7.5 and G-7 is never reached.
     *
     * The bound itself is a Kotlin constant and out of a statement rewrite's reach; what is in
     * reach is the column the bound is compared against, and reading it as 0 has exactly the effect
     * the mutant names. §15.7 detects it with SCN-G, and so does this: the item resends for ever
     * and never reaches INDETERMINATE, which is the outcome §7.5 owes the user after two.
     */
    val MC16 = Mutation(
        id = "MC-16",
        defeats = "G-7 and C-15: at most two identical-bytes resends, then the item is decided",
        detectedBy = "SCN-G (the ambiguous store never reaches INDETERMINATE)",
        expect = "never became INDETERMINATE",
        rewrite = { sql, args ->
            if (sql.contains("SELECT operation_id, purpose, item_id, bundle_week, blob, resend_count")) {
                Pair(sql.replace(", blob, resend_count,", ", blob, 0,"), args)
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **ME-16 — a read path ignores expiry.** The `delete_at_minute` guard of §10.6 is dropped from
     * the conversation page, so an expired message is still rendered.
     *
     * §15.7 detects it with "DAO lint", which is the static half (`DmExpiredRowLint` over
     * `DmDaoQueries`). This is the behavioural half: the message passes its deadline, SWEEP has not
     * run yet, and the read path shows it anyway. Both halves are wanted — the lint catches a query
     * nobody runs in a test, the world catches a guard that is present but wrong.
     */
    val ME16 = Mutation(
        id = "ME-16",
        defeats = "§10.6: no read path returns a row past its delete_at_minute",
        detectedBy = "EP-read-expiry (an expired row is still readable before SWEEP)",
        expect = "an expired row is still readable before SWEEP",
        rewrite = { sql, args ->
            // The `?` stays: dropping it would shift every later bind index and the statement
            // would fail as a harness bug instead of running as a mutant. Moving the comparison
            // a billion seconds into the past makes it true for every row, which is what "the
            // read path ignores expiry" means.
            if (sql.startsWith("SELECT message_id, conversation_id")) {
                Pair(sql.replace("delete_at_minute > ?", "delete_at_minute > ? - 1000000000"), args)
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-17 — the outbox rebuild loses a rowid or a trigger** (CS-9, §13.6 step 1; built by
     * §22.38). Migration 4 rebuilds `outbox_op` to admit a one-hour TTL; this half copies the rows
     * **without** their rowids (`INSERT INTO outbox_op_v4(…) SELECT …` with `rowid` left out of both
     * lists), so they are numbered afresh — in the same order, which is why only a table with gaps,
     * [DmV3Fixture]'s, shows it. A statement rewrite of the migration, which only a migration on the
     * bus reaches (SCN-L-v3, [DmNode.migrateOnTheBus]). One §15.7 id, two halves: this one is the
     * entry registered below, and the kill runs both ([MC17_TRIGGER]).
     */
    val MC17 = Mutation(
        id = "MC-17",
        defeats = "CS-9: the outbox rebuild keeps every row at its rowid and re-creates every trigger",
        detectedBy = "SCN-L-v3 (the v3 file's Phase 7 rows at their rowids after the migrations; the open path's " +
            "trigger set)",
        expect = "SCN-L-v3: bob's migrations did not keep the v3 file's Phase 7 rows (CS-9)",
        expectUnderCrash = listOf("SCN-L-v3: bob's migrations did not keep the v3 file's Phase 7 rows (CS-9)"),
        rewrite = { sql, args ->
            if (sql.startsWith("INSERT INTO outbox_op_v4(rowid, ")) {
                Pair(sql.replaceFirst("outbox_op_v4(rowid, ", "outbox_op_v4(").replaceFirst("SELECT rowid, ", "SELECT "), args)
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * MC-17's other half: the rebuild does not re-create one of the eight v2 triggers of the table
     * it replaced — `outbox_op_outcome`, "an outcome is decided once" (any other is the same
     * statement's shape) — so the open path's own trigger set (`verifyIntegrity`) refuses the file.
     */
    val MC17_TRIGGER = Mutation(
        id = "MC-17",
        defeats = "CS-9: the outbox rebuild keeps every row at its rowid and re-creates every trigger",
        detectedBy = "SCN-L-v3 (the open path refuses a file without outbox_op_outcome)",
        expect = "bob's database was refused at open: schema integrity: missing triggers [outbox_op_outcome]",
        expectUnderCrash = listOf("bob's database was refused at open: schema integrity: missing triggers [outbox_op_outcome]"),
        rewrite = { sql, args ->
            if (sql.startsWith("CREATE TRIGGER outbox_op_outcome")) Pair("SELECT 1", emptyList()) else Pair(sql, args)
        },
    )

    /**
     * **MC-18 — the out-key floor kept across a renewal** (§21.3 point 2; slice S10b).
     *
     * A RECV decryption of a PreKey message that creates a new session under R-SS1 is a *renewal
     * from c*, and the same transaction deletes every out key for c — so the next root c sends is
     * accepted whatever its generation. A restore restarts c's `root_gen` at 0; with the floor kept,
     * the restored device's first root is "not newer" than the lost device's, is dropped, and this
     * side goes on sealing under a root the restored device no longer has. §15.7 names SCN-I as the
     * detector and so does this: alice's first pair-mode answer never opens on the restored device.
     *
     * **One call site, not the statement.** `ContactStore.deleteOutPairKeys` is also what a new
     * root (`applyTlvs`), a revocation and a KEYDEC acceptance use, and a rewrite of the statement
     * alone would have been four mutants in one — the run would no longer say which of them it
     * detected. So the rewrite fires only when the **caller** is RECV's renewal branch
     * (`ReceiveStep.decryptAndApply`), read off the stack of the thread that is executing it: the
     * same statement, the same bytes everywhere else. The stack read is stateless, so one
     * `Mutation` shared by every node of every parallel run stays correct, which a flag set by the
     * preceding `olm_prekey_used` insert would not.
     */
    val MC18 = Mutation(
        id = "MC-18",
        defeats = "§21.3 point 2: a renewal from c deletes every out key for c, so c's next root is accepted",
        detectedBy = "SCN-I (alice's first pair-mode answer never opens on the restored device)",
        expect = "pair envelopes from alice did not open on the restored device",
        // Under a crash the final checks do not run, and what refuses the world is one of §15.3's
        // two oracles: alice's answer is `SENT` and never rendered (no loss), or — when the crash
        // left her nothing to answer with before the probe — the probe itself never decrypts.
        expectUnderCrash = listOf(NO_LOSS_FAILURE, LIVENESS_FAILURE),
        rewrite = { sql, args ->
            if (sql == OUT_KEYS_DELETE &&
                calledFrom("ContactStore", "deleteOutPairKeys", "ReceiveStep", "decryptAndApply")
            ) {
                Pair("$OUT_KEYS_DELETE AND 0", args)
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-21 — pair keys erased before ratcheting forward** (§21.3 point 5, CR-13; the suite cases
     * of §22.27).
     *
     * > SWEEP first derives and stores, for every live in-generation, `K_w` for every week up to
     * > `week(now)` from the newest stored key, then erases keys past `start(w + 1) + FRESH`, in one
     * > transaction.
     *
     * `K_{w+1}` is derived from `K_w` and from nothing else, so a sweep that erased first would
     * destroy the only material the derivation starts from: a recipient that did not run for about
     * 52 days erases its newest in-key and has nothing left to ratchet, and every later pair envelope
     * of the conversation is dropped as `unknown_seal` (`PairKeySteps`' own header says so, and names
     * this mutant as the order of the two calls inside `sweep`).
     *
     * **The mechanism: a statement rewrite, scoped to the ratchet's call sites and bound to the
     * device's clock ([rewriteOn]).** A rewrite cannot move a statement, but it can make the
     * ratchet's own read see exactly what an erasure that ran first would have left: the two
     * `dm_pair_key` reads of `PairKeySteps.advance` and `advancingInGenerations`, for the **in**
     * direction, are given `PairKeySteps.eraseIn`'s own survival condition — a row survives while
     * `now_e < start(week + 1) + FRESH` — with `now_e` as `Sweeper` computes it (R-T7:
     * `max(floor_minute(wall), dm_self.expiry_clock_minute)`, the wall half from the device's clock,
     * the stored half read in the SQL). The ratchet then derives from what would have survived an
     * erasure, `eraseIn` erases the rest as it always does, and the transaction commits exactly the
     * state "erase, then ratchet" commits. The same statement from anywhere else — `eraseIn`,
     * `eraseOut`, SEND, RECV — is untouched, and so is the **out** direction: §21.3 point 5 is a rule
     * about in-generations, and the out keys' window is a different rule (§22.8.5 rule 1, whose
     * mutant is MC-33) — erasing them first would lose the sender's key at every week boundary, a
     * different and much louder defect.
     *
     * §15.7 detects it with RS2, and so does this: RS2's check that the recipient holds, for the week
     * it came back in, an in-key of the generation the conversation was sealed under before the
     * absence — in every run, fault-free and under every crash point of the kill. That check is the
     * **only** one any run of the kill reached, and so the only message its crash half accepts: the
     * no-loss oracle and the liveness probe would refuse the same world (the peer's pair-sealed
     * messages `SENT` and never opened), but the runner reads a scenario's own checks before either
     * oracle, and a claim that they stand "behind" the kill was never exercised (§22.27's review).
     *
     * What it changes, measured: only the recipient's first SWEEP after the absence (every earlier
     * sweep reads the same rows through the rewritten text, since no key is past its window yet, and
     * every later one finds nothing left to differ on). That transaction is where the kill crashes
     * it (`DmMutantDetectionTest.detectFaultFreeAndWhereItActs`).
     */
    val MC21 = Mutation(
        id = "MC-21",
        defeats = "§21.3 point 5: SWEEP ratchets every live in-generation to week(now) before it erases the keys past their window",
        detectedBy = "RS2 (after a 61-day absence the recipient holds no in-key of the conversation's generation for the week it came back)",
        expect = "the ratchet did not run before the erasure",
        expectUnderCrash = listOf("the ratchet did not run before the erasure"),
        rewriteOn = { clock ->
            { sql, args ->
                if (sql == PAIR_KEYS_SELECT && args.getOrNull(1) == "in" &&
                    (
                        calledFrom("ContactStore", "pairKeys", "PairKeySteps", "advance") ||
                            calledFrom("ContactStore", "pairKeys", "PairKeySteps", "advancingInGenerations")
                        )
                ) {
                    Pair(PAIR_KEYS_SELECT_AFTER_ERASURE, args + DmTime.floorMinute(clock.now))
                } else {
                    Pair(sql, args)
                }
            }
        },
    )

    /**
     * **MC-24 — `request → changed` attempted** (§21.4 point 5, CR-05; the suite cases of §22.27).
     *
     * > For `trust_state = request`, a PreKey L1 with `OI′ ≠ pinned` under a valid binding is
     * > `drop(request_key_mismatch)` with no state change; a `request → changed` transition does not
     * > exist. … a trigger or CHECK abort inside a DM transaction is a bug, never an expected path.
     *
     * Round 9's defect (3) of §21.4: a requester that sent a second Olm identity drove the key-change
     * path on a contact that was still a request, the schema's `dm_contact_trust` trigger refused
     * the transition, and the untyped abort ended RECV at every offer of the blob — "crashed the
     * process three times per blob" — until the poison guard consumed it.
     *
     * **The mechanism: a statement rewrite scoped to one call site.** The pre-check is Kotlin
     * (`ReceiveStep.intro`, `contact.trust == REQUEST`), and what it reads is the contact row
     * `ContactStore.contactByIdentity` returns. The rewrite reports a `request` row's trust as
     * `unverified` — **only** when the caller is `ReceiveStep.intro`, read off the stack as MC-18
     * does — so the pre-check never sees a request there and the engine goes on to §8.3's hold,
     * whose `setChanged` is the `request → changed` attempt. Nothing else reads a request's trust on
     * that path: the blocked/revoked and `changed` branches are unaffected by the substitution, a
     * brand-new requester is created (and read back) by another statement, and every other caller
     * of the same query — the user's `addContact`, KEYDEC — is untouched.
     *
     * §15.7 detects it with KC12, and so does this: KC12's "no crash" check, which reads what the
     * recipient's passes threw and names the trigger's own words, in every run.
     */
    val MC24 = Mutation(
        id = "MC-24",
        defeats = "§21.4 point 5: a request that sends a second Olm identity is dropped; request → changed is never attempted",
        detectedBy = "KC12 (the recipient's RECV throws on every offer of the second identity's first flight)",
        expect = "attempted request → changed",
        expectUnderCrash = listOf("attempted request → changed"),
        rewrite = { sql, args ->
            if (sql == CONTACT_BY_IDENTITY &&
                calledFrom("ContactStore", "contactByIdentity", "ReceiveStep", "intro")
            ) {
                Pair(
                    CONTACT_BY_IDENTITY.replace(
                        " trust_state,",
                        " CASE trust_state WHEN 'request' THEN 'unverified' ELSE trust_state END,",
                    ),
                    args,
                )
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-26 — `previous` never retired** (§8.7, §10.6; slice S10b).
     *
     * SWEEP deletes a `previous` session at its `retire_day`, 46 days after its demotion; the bound
     * is what T34 relies on for a retired session's skipped keys (§21.3 point 6). The mutation
     * makes the one statement that does it match nothing. §15.7 detects it with "CS-8 bound,
     * structural invariants, T34 retired-session expectation"; here it is the structural half —
     * [DmStructuralInvariants.retiredSessionsGone], run after the last sweep of every run — over
     * SCN-I, which is the scenario whose renewal demotes a session and whose last step takes the
     * world past the day.
     */
    val MC26 = Mutation(
        id = "MC-26",
        defeats = "§8.7: a 'previous' session is deleted at its retire_day",
        detectedBy = "SCN-I (the renewal's demoted session outlives its retire_day)",
        expect = "a 'previous' session past its retire_day after SWEEP",
        // The clause runs at the end of **every** run, faulted or not, so a crash changes nothing
        // about which check kills it.
        expectUnderCrash = listOf("a 'previous' session past its retire_day after SWEEP"),
        rewrite = { sql, args ->
            if (sql.startsWith("DELETE FROM olm_session WHERE slot = ? AND retire_day IS NOT NULL")) {
                Pair("$sql AND 0", args)
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-33 — a FAILED retry without the out key kept for its author week** (§22.8.5 rule 1;
     * slice S10b).
     *
     * SWEEP keeps an earlier week's out pair key while a live retryable item of the contact could
     * still be re-encrypted under it; `MessageStore.retryableItemWeeks` is the query that names
     * those weeks, and the mutation makes it name none. A user retry keeps its author minute and the
     * peer's R9 wants the key of that week, so across a week boundary the retry finds no pair key
     * and re-establishes through a bundle fetch and a PreKey message — the relay-visible event
     * §22.8.5 forbids. §15.7 detects it with "SCN-G week-boundary retry (a bundle fetch or an
     * `unknown_seal` drop)", and so does this: `SCN-G-week`'s check that alice's session survived
     * the retry, which is in its `alwaysChecks` and so runs in faulted runs too.
     */
    val MC33 = Mutation(
        id = "MC-33",
        defeats = "§22.8.5 rule 1: SWEEP keeps the out key of a week a live retryable item was authored in",
        detectedBy = "SCN-G-week (the FAILED retry across a week boundary re-establishes the session)",
        expect = "a FAILED retry across a week boundary re-established the session",
        expectUnderCrash = listOf("a FAILED retry across a week boundary re-established the session"),
        rewrite = { sql, args ->
            if (sql.startsWith("SELECT deadline_hour FROM dm_outbound_item WHERE contact_id = ?")) {
                Pair("$sql AND 0", args)
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-28 — a generation erased before its reuse tuples' last use window** (§5.4; slice S10b).
     *
     * A generation is kept until `superseded_day + 91` — 7 days of validity, 28 of an unanswered
     * initiator session re-sending PreKey messages that name it, 45 of freshness, and slack —
     * because the last first flight that can legitimately name it arrives that late, and its
     * `olm_prekey_used` tuples (D2b) go with it. The mutation erases every generation 70 days
     * early, at `superseded_day + 21`: a retention that remembered the bundle's own validity and
     * forgot the rest. §15.7 detects it with "SCN-H boundary replay"; here it is SCN-H, and what
     * kills it — measured, fault-free and at every crash point the kill test tries — is SCN-H's
     * retention oracle, which sees the generation gone at the first step after the early erasure,
     * weeks before the late first flight the generation exists for is released. That flight would
     * then be `SENT` and never rendered, which the no-loss oracle refuses and `expectUnderCrash`
     * accepts; no run reaches it, because the retention oracle ends the run first, and §22.19 says
     * so rather than counting the second half as a kill it did not observe.
     */
    val MC28 = Mutation(
        id = "MC-28",
        defeats = "§5.4: a superseded generation is kept until superseded_day + 91",
        detectedBy = "SCN-H's retention oracle (a generation erased before superseded_day + 91)",
        expect = "was erased before superseded_day + 91",
        expectUnderCrash = listOf("was erased before superseded_day + 91", NO_LOSS_FAILURE),
        rewrite = { sql, args ->
            if (sql.startsWith("SELECT gen_id FROM olm_prekey_gen g WHERE g.delete_after_day IS NOT NULL")) {
                Pair(sql.replace("g.delete_after_day <= ?", "g.delete_after_day - 70 <= ?"), args)
            } else {
                Pair(sql, args)
            }
        },
    )

    /**
     * **MC-14 — registration rows not re-armed after a rejected own READ credential** (§4.8's
     * healing rule, §21.2 point 8; SCN-E, §22.25).
     *
     * A relay that lost its `keys.redb` refuses the owner's READ credential; KEEPER then sends every
     * `done` row of `(relay, X_0)` from this week on back to pending and re-puts the credential in
     * the same transaction (`OwnerSteps.readCredentialAction`, `HEAL_AND_PUT`), and the work lane
     * registers them again. The mutation makes the one statement that finds those rows
     * (`RegistrationStore.rearm`'s `SELECT`) match nothing: the credential is still re-put, so reads
     * are refused again at once, but no row goes back to pending — the relay never holds the
     * owner's registrations again until a later week's rows are registered for the first time.
     * §15.7 detects it with "SCN-E LOSE_KEYS variant", and so does this: SCN-E/LOSE_KEYS's healing
     * check, six hours after the loss, which is in every run.
     */
    val MC14 = Mutation(
        id = "MC-14",
        defeats = "§4.8, §21.2 point 8: a refused own READ credential re-arms the pair's done registration rows",
        detectedBy = "SCN-E/LOSE_KEYS (6 h after the loss the relay still holds none of the owner's inbox registrations)",
        expect = "(the healing rule, §4.8)",
        expectUnderCrash = listOf("(the healing rule, §4.8)"),
        rewrite = { sql, args ->
            if (sql == REARM_SELECT) Pair("$REARM_SELECT_HEAD AND 0 ORDER BY period_id, kind", args) else Pair(sql, args)
        },
    )

    /**
     * **MC-15 — a refused LOCAL credential re-put on every `CAPABILITIES` hint** (§21.2 point 7;
     * SCN-E, §22.25).
     *
     * A relay that refuses a contact's DEPOSIT credential leaves the row `rejected`, and the contact
     * KEEPER re-puts it as a new generation — which re-arms every parked delivery — at most once per
     * time-triggered pass, so the relay's answer never decides when the sender tries again (§21.2
     * point 7 says "once per relay session start"; §22.25 item 4 records that the engine's bound is
     * per time-triggered pass). The mutation is
     * the trigger §15.7 names: KEEPER's contact half on every `CAPABILITIES` hint, and a refusal
     * commits exactly such a hint. The refused delivery is then due again within the session that
     * was refused, and the relay decides how many times it is refused. §15.7 detects it with "SCN-E
     * bound on refused stores per session"; what detects it here is SCN-E's rule on re-puts as the
     * engine implements the bound (`CredentialWatch`, at the commit of the re-put): a refused
     * credential is re-put only inside a time-triggered pass or a user send, the trigger read from
     * what the wiring **scheduled** and never from a pass's own flag — so the same defect reached
     * through a time-flagged pass on every hint fails as well (`ScnE.Control.TIME_PASS_ON_EVERY_HINT`,
     * the review's second path, §22.25 item 14) — and behind it the relay-side rule (`StoreView`):
     * a deposit refused again under a credential put again needs a time trigger, a user send or a
     * reboot of the sender in between. The per-session count §21.2 point 7 states is not what
     * detects it because the real engine does not meet it either (§22.25 item 4). In
     * SCN-E/LOSE_KEYS, where alice's deposit at the relay that lost its keys is refused until bob
     * has healed.
     */
    val MC15 = Mutation(
        id = "MC-15",
        defeats = "§21.2 point 7: a refused credential is re-put by the device's own schedule, never on the relay's answer",
        detectedBy = "SCN-E/LOSE_KEYS (a refused deposit credential re-put in a process no time trigger, user send or boot of the sender started)",
        expect = "the relay's refusal itself made it retry (§21.2 point 7)",
        expectUnderCrash = listOf("the relay's refusal itself made it retry (§21.2 point 7)"),
        hintKeeper = true,
    )

    /** `RegistrationStore.rearm`'s row query, verbatim: MC-14 matches it exactly. */
    private const val REARM_SELECT_HEAD =
        "SELECT period_id, kind FROM relay_key_registration WHERE relay_id = ?1 AND namespace_id = ?2 " +
            "AND period_id >= ?3 AND state = 'done'"
    private const val REARM_SELECT = "$REARM_SELECT_HEAD ORDER BY period_id, kind"

    /** The no-loss oracle's words (`DmCrashRunner.noMessageTheSenderCallsSentIsMissing`). */
    const val NO_LOSS_FAILURE: String = "marked it sent and no device rendered it"

    /** The liveness oracle's words (`DmCrashRunner.sessionIsStillLive`). */
    const val LIVENESS_FAILURE: String = "the session is not live after the run"

    /** `ContactStore.deleteOutPairKeys`, verbatim: MC-18 matches the statement exactly. */
    private const val OUT_KEYS_DELETE = "DELETE FROM dm_pair_key WHERE contact_id = ? AND direction = 'out'"

    /** `ContactStore.pairKeys`, verbatim: MC-21 matches the statement exactly. */
    private const val PAIR_KEYS_SELECT =
        "SELECT direction, root_gen, week, recog_key, open_env FROM dm_pair_key " +
            "WHERE contact_id = ? AND direction = ? ORDER BY root_gen DESC, week DESC"

    /**
     * [PAIR_KEYS_SELECT] with `PairKeySteps.eraseIn`'s survival condition added: a row is kept while
     * `now_e < start(week + 1) + FRESH`, where `now_e = max(floor_minute(wall), expiry_clock_minute)`
     * (R-T7) and the third `?` is the wall half. `DmTime.weekStart(w)` is `WEEK_ORIGIN + WEEK * w`.
     */
    private val PAIR_KEYS_SELECT_AFTER_ERASURE =
        "SELECT direction, root_gen, week, recog_key, open_env FROM dm_pair_key " +
            "WHERE contact_id = ? AND direction = ? " +
            "AND max(?, coalesce((SELECT expiry_clock_minute FROM dm_self), 0)) < " +
            "${DmTime.WEEK_ORIGIN} + ${DmTime.WEEK} * (week + 1) + ${DmTimers.FRESH_SECONDS} " +
            "ORDER BY root_gen DESC, week DESC"

    /** `ContactStore.contactByIdentity`'s statement (through `contactBy`), verbatim: MC-24 matches it exactly. */
    // Phase 13 §3.6 added name_env to ContactStore.contactColumns; the statement this matches is
    // ContactStore.contactByIdentity's, verbatim (through contactBy) - the mutant must follow the
    // real text, or it rewrites nothing and "survives" by never being applied.
    private const val CONTACT_BY_IDENTITY =
        "SELECT contact_id, identity_pk, card_env, card_index, pinned_identity, pending_identity, " +
            "bundle_week_seen, trust_state, source, establishment, fetch_attempts, " +
            "fetch_listen_until_minute, reset_needed, request_until_day, verified_fp, name_env " +
            "FROM dm_contact WHERE identity_pk = ?"

    /**
     * True when the current thread is inside [storeMethod] of a class named [storeClass], called
     * directly from [callerMethod] of a class named [callerClass]. Simple names, because the
     * packages are the engine's business; the pair is specific enough that no other frame matches.
     */
    private fun calledFrom(
        storeClass: String,
        storeMethod: String,
        callerClass: String,
        callerMethod: String,
    ): Boolean {
        val frames = Thread.currentThread().stackTrace
        val at = frames.indexOfFirst {
            it.className.substringAfterLast('.') == storeClass && it.methodName == storeMethod
        }
        if (at < 0 || at + 1 >= frames.size) return false
        val caller = frames[at + 1]
        return caller.className.substringAfterLast('.') == callerClass && caller.methodName == callerMethod
    }

    /**
     * Every mutant S10, S10b, SCN-E (§22.25) and the suite cases of §22.27 register, in the order the
     * report prints them.
     */
    fun all(): List<Mutation> =
        listOf(
            MC1, MC5, MC7, MC9, MC10, MC12, MC14, MC15, MC16, MC17, MC18, MC20, MC21, MC24, MC26, MC28, MC30, MC33,
            ME7, ME9, ME11, ME16, ME17, ME19, ME20, ME24,
        )
}
