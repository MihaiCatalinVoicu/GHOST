package org.ghost.messaging.harness

import org.ghost.messaging.port.DmEnvelopes

/**
 * The correctness and ephemeral mutants of Phase 9 design §15.7, as far as slice S10 implements
 * them, with the discipline `Mutants.kt` and `t2_mutants.rs` already set in this repository: **a
 * mutant is registered only when a named test kills it.** A registered mutant with no test that
 * detects it is not evidence, it is a claim.
 *
 * §15.7's own set is 97 — 40 privacy (S11's), 33 correctness and 24 ephemeral (this slice's 57).
 * Eleven are here: seven from S10, and four from S10b — MC-18 and MC-26, which S10b's SCN-I makes
 * reachable, MC-28, which its SCN-H does, and MC-33, which its `SCN-G-week` does. The other 46 are
 * listed in §22.15 and §22.19 with the reason each is not, and the gate line says **eleven**, not
 * fifty-seven, for the same reason `dm-report-check.sh` refuses a PASS on an empty sample: a
 * number a run did not measure is worse than no number. The line is built from the kills the run
 * **recorded** ([DmKills]), never from this registry, so an ignored or deleted kill test lowers
 * the count instead of leaving it standing. **S10b's four are held to a stricter kill than S10's seven**: detected fault-free by
 * the check their entry names, *and* at crash points spread over the scenario, each beside the
 * unmutated scenario crashed at the same point ([Mutation.expectUnderCrash]).
 *
 * **What a mutant may be, here.** `:messaging` has no `Steps` seam the way `:sync` does, so a
 * mutation is one of three things: a **statement rewrite** on the device's executor (the same
 * mechanism as the Phase 7 harness's SQL-level mutants M2, M6, M8, M10 and M11), a **decorator**
 * on the `DmEnvelopes` port, or a **transaction split** ([FaultyDmSqlExecutor.defer]) that holds a
 * statement back into a second transaction. The third is new in this slice's review and is what
 * makes MC-1 reachable; §22.15 item 8 had recorded it as out of reach of the first two, and it is.
 * That is what decides which of §15.7's 57 are reachable here, and §22.15 says so per mutant
 * rather than in general.
 */
internal object DmMutants {

    /** One substitution in the armed world. Exactly one of the three mechanisms is set. */
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
        val decorate: ((DmEnvelopes) -> DmEnvelopes)? = null,
        /** The transaction-split seam of [FaultyDmSqlExecutor.defer]; only a crash run kills these. */
        val defer: ((String) -> Boolean)? = null,
        /** True when the mutant is invisible without a crash, so its kill runs the enumeration. */
        val needsACrash: Boolean = false,
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
     */
    val MC5 = Mutation(
        id = "MC-5",
        defeats = "D3: the dm_seen tag makes a re-encrypted copy of a message a duplicate",
        detectedBy = "RP6's retry, refused by the dm_message replace guard before D3's own check",
        expect = "dm_message rows are never replaced",
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
        detectedBy = "the rejected-request replay of §12.3 (a second request appears)",
        expect = "a rejected request came back as a second one",
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

    /** The no-loss oracle's words (`DmCrashRunner.noMessageTheSenderCallsSentIsMissing`). */
    const val NO_LOSS_FAILURE: String = "marked it sent and no device rendered it"

    /** The liveness oracle's words (`DmCrashRunner.sessionIsStillLive`). */
    const val LIVENESS_FAILURE: String = "the session is not live after the run"

    /** `ContactStore.deleteOutPairKeys`, verbatim: MC-18 matches the statement exactly. */
    private const val OUT_KEYS_DELETE = "DELETE FROM dm_pair_key WHERE contact_id = ? AND direction = 'out'"

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

    /** Every mutant S10 and S10b register, in the order the report prints them. */
    fun all(): List<Mutation> =
        listOf(MC1, MC5, MC7, MC10, MC12, MC16, MC18, MC26, MC28, MC33, ME16)
}
