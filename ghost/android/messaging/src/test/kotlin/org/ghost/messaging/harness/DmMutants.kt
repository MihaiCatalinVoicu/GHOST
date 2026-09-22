package org.ghost.messaging.harness

import org.ghost.messaging.port.DmEnvelopes

/**
 * The correctness and ephemeral mutants of Phase 9 design §15.7, as far as slice S10 implements
 * them, with the discipline `Mutants.kt` and `t2_mutants.rs` already set in this repository: **a
 * mutant is registered only when a named test kills it.** A registered mutant with no test that
 * detects it is not evidence, it is a claim.
 *
 * §15.7's own set is 97 — 40 privacy (S11's), 33 correctness and 24 ephemeral (this slice's 57).
 * Six are here. The other 51 are listed in §22.15 with the reason each is not, and the gate line
 * this slice writes says **six**, not fifty-seven, for the same reason `dm-report-check.sh` refuses
 * a PASS on an empty sample: a number a run did not measure is worse than no number.
 *
 * **What a mutant may be, here.** `:messaging` has no `Steps` seam the way `:sync` does, so a
 * mutation is one of two things: a **statement rewrite** on the device's executor (the same
 * mechanism as the Phase 7 harness's SQL-level mutants M2, M6, M8, M10 and M11), or a **decorator**
 * on the `DmEnvelopes` port. That is what decides which of §15.7's 57 are reachable in this slice
 * and which are not, and §22.15 says so per mutant rather than in general.
 */
internal object DmMutants {

    /** One substitution in the armed world. Exactly one of the two fields is set. */
    class Mutation(
        val id: String,
        /** The property §15.7 says this mutant defeats, in its own words. */
        val defeats: String,
        /** Which scenario or suite case §15.7 says detects it, and which one here does. */
        val detectedBy: String,
        val rewrite: ((String, List<Any?>) -> Pair<String, List<Any?>>)? = null,
        val decorate: ((DmEnvelopes) -> DmEnvelopes)? = null,
    ) {
        override fun toString(): String = id
    }

    /**
     * **MC-5 — D3 off.** The `dm_seen` tag of §7.6 is never written, so the fourth dedup layer is
     * gone.
     *
     * §15.7: "detected by SCN-G FAILED retry after a lost receipt; RP2 with D1 expired". The first
     * is what kills it here. Every other duplicate a sender can produce carries identical bytes and
     * dies at D1's tombstone; a **user retry after a wrongly reported FAILED** re-encrypts, so the
     * bytes and the hash differ and the only thing left that says "this is the same message" is the
     * tag over its `message_id`. Without it the recipient renders the message twice, which is CS-2.
     */
    val MC5 = Mutation(
        id = "MC-5",
        defeats = "D3: the dm_seen tag makes a re-encrypted copy of a message a duplicate",
        detectedBy = "RP6 (re-encryption after a wrongly reported FAILED); CS-2 at quiescence",
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

    /** Every mutant this slice registers, in the order the report prints them. */
    fun all(): List<Mutation> = listOf(MC5, MC7, MC10, MC12, MC16, ME16)
}
