package org.ghost.messaging

import org.ghost.crypto.bridge.CredentialV3
import org.ghost.crypto.bridge.RelaySets
import org.ghost.messaging.engine.MessagingEngine
import org.ghost.messaging.engine.OwnerSteps
import org.ghost.messaging.port.EsSlot
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The owner-side transactions of Phase 9 design §7.2 — ACTIVATE, OWNER-WEEK, KEEPER, REGROWS — and
 * `myCard`, over a real migrated v5 database ([OwnerWorld]).
 *
 * Every test names the sentence it proves. The four **idempotence guards** of §7.2's closing line
 * get one test each, because they are what makes a crash and a re-execution safe, and a step that
 * lost its guard would still look right on a first run.
 */
class OwnerStepsTest {

    private val week = 604_800L
    private val day = 86_400L
    private val hour = 3_600L
    private val weekOrigin = 345_600L

    private fun weekStart(w: Long) = weekOrigin + week * w

    private fun weekOf(t: Long) = Math.floorDiv(t - weekOrigin, week)

    /** Activates at a moment safely past this week's publication offset, so OWNER-WEEK is due. */
    private fun OwnerWorld.activateAt(t: Long, restored: Boolean = false): OwnerSteps.Result {
        clock.now = t
        return steps.activate(restored)
    }

    // ------------------------------------------------------------------ myCard

    @Test
    fun myCardIsTheCardAndItsLinkAndNeedsNoDatabase() {
        OwnerWorld().use { world ->
            val card = world.steps.myCard()
            assertNotNull(card)
            assertEquals(131, card!!.card.size)
            assertTrue(card.link.startsWith("ghost://contact/"))
            // §3.3: 16 + 210 = 226 characters. z-base-32 of 131 bytes is ceil(131 * 8 / 5) = 210.
            assertEquals(226, card.link.length)
            // It needed no `dm_self`: the card is a function of the seed alone, so it works before
            // ACTIVATE and after a restore (§3.3, C-1).
            assertNull(world.selfRow())
        }
    }

    @Test
    fun myCardIsCryptoUnavailableWithAClosedContext() {
        OwnerWorld().use { world ->
            world.crypto.available = false
            assertNull(world.steps.myCard())
            assertEquals(OwnerSteps.Result.CRYPTO_UNAVAILABLE, world.steps.activate(restored = false))
        }
    }

    // ---------------------------------------------------------------- ACTIVATE

    @Test
    fun activateWritesTheIdentityRowTheTwoNamespacesAndTheFirstGeneration() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day + 90
            assertEquals(OwnerSteps.Result.DONE, world.activateAt(now))

            val self = world.selfRow()!!
            assertEquals(0L, self["card_index"])
            assertEquals(weekOf(now), self["bundle_week"])
            assertNull("nothing has reported the bundle stored yet", self["bundle_published_week"])
            // `expiry_clock_minute` is this minute, floored: R-T7's clock never runs backwards.
            assertEquals(now - now % 60, self["expiry_clock_minute"])
            assertNull("a plain activation accepts content of any age", self["accept_after_minute"])

            val own = world.crypto.ownCard(0)!!
            val namespaces = world.ownNamespaces()
            assertArrayEquals(own.inboxNamespace, namespaces["inbox"])
            assertArrayEquals(own.bundleNamespace, namespaces["bundle"])

            val generations = world.generations()
            assertEquals(1, generations.size)
            assertEquals(weekOf(now), generations[0]["bundle_week"])
            assertNull("the first generation is current", generations[0]["superseded_day"])
            assertNull(generations[0]["delete_after_day"])
        }
    }

    /**
     * §5.3: an ACTIVATE or restore publication is **off schedule** and uses rank 1, while every
     * OWNER-WEEK bundle uses rank 0. A fetcher orders by `(bundle_week, bundle_rank)` descending,
     * so the restored device's bundle wins over the one the lost device published that week.
     */
    @Test
    fun theFirstBundleIsPublishedOffScheduleAtRankOne() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            assertEquals(1, world.crypto.requestedRanks.size)
            val (bundleWeek, rank, _) = world.crypto.requestedRanks[0]
            assertEquals(weekOf(now), bundleWeek)
            assertEquals(1, rank)
        }
    }

    /**
     * §5.4: the bundle op carries `TtlBucket.DAYS_30` and a deadline of `start(w + 2)` — a bundle
     * is useless once its validity ends, so its operation must not outlive it.
     */
    @Test
    fun theBundleOperationCarriesTheThirtyDayBucketAndTheValidityDeadline() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            val w = weekOf(now)

            val dmOps = world.bundleOps()
            assertEquals(1, dmOps.size)
            assertEquals(w, dmOps[0]["bundle_week"])
            assertEquals(4096L, dmOps[0]["len"])

            val outbox = world.outboxOps()
            assertEquals(1, outbox.size)
            assertEquals(2_592_000L, outbox[0]["ttl_seconds"])
            // The engine floors the deadline to the hour; `start(w + 2)` is already on one.
            assertEquals(weekStart(w + 2), outbox[0]["deadline_hour"])
            // The bundle went to `P_0`, not to the inbox.
            val bundleNs = world.crypto.ownCard(0)!!.bundleNamespace
            assertEquals(bundleNs.toHex(), outbox[0]["ns"])
        }
    }

    /** §7.2: "ACTIVATE per identity". A second call writes nothing at all. */
    @Test
    fun activateIsIdempotentPerIdentity() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            assertEquals(OwnerSteps.Result.DONE, world.activateAt(now))
            val before = world.generations() to world.bundleOps()
            val calls = world.crypto.bundleCreateCalls

            world.clock.now = now + 3 * hour
            assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.activate(restored = false))
            assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.activate(restored = true))

            assertEquals(before.first, world.generations())
            assertEquals(before.second, world.bundleOps())
            assertEquals("no native work happened behind the guard", calls, world.crypto.bundleCreateCalls)
        }
    }

    /**
     * §7.6 "Restore", §8.6: the restore variant sets `accept_after_minute`, so content authored
     * before the restore is refused at `RECV` R9 — `dm_seen` and the pair keys are gone, so it
     * could not be deduplicated.
     */
    @Test
    fun aRestoreRefusesContentAuthoredBeforeIt() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day + 45
            assertEquals(OwnerSteps.Result.DONE, world.activateAt(now, restored = true))
            assertEquals(now - now % 60, world.selfRow()!!["accept_after_minute"])
        }
    }

    /** §5.2: no relay set, no registration. Nothing is written, and §21.12 point 2 retries. */
    @Test
    fun activateWithoutASlotTableWritesNothing() {
        OwnerWorld().use { world ->
            world.slots = emptyList()
            assertEquals(OwnerSteps.Result.NO_RELAYS, world.activateAt(weekStart(2_870)))
            assertNull(world.selfRow())
            assertEquals(0, world.generations().size)
        }
    }

    // -------------------------------------------------------------- OWNER-WEEK

    /**
     * §5.4, §21.9 rule 1, mutants PM-11 and PM-30: the publication happens at `t_pub(w)`, a fixed
     * offset per card, and **not** at the first wake of the week. Before that minute the step is a
     * no-op whatever else has happened.
     */
    @Test
    fun ownerWeekDoesNothingBeforeThePublicationMinuteOfTheWeek() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = 3 * day + 1_200
            world.activateAt(weekStart(2_870) + 4 * day)
            val w = 2_871L

            // Every minute of the new week before `t_pub(w)`: still nothing.
            for (offset in listOf(0L, 60L, day, 3 * day, 3 * day + 1_140)) {
                world.clock.now = weekStart(w) + offset
                assertEquals(
                    "offset $offset is before t_pub",
                    OwnerSteps.Result.UNCHANGED,
                    world.steps.ownerWeek(),
                )
            }
            assertEquals(2_870L, world.selfRow()!!["bundle_week"])

            world.clock.now = weekStart(w) + 3 * day + 1_200
            assertEquals(OwnerSteps.Result.DONE, world.steps.ownerWeek())
            assertEquals(w, world.selfRow()!!["bundle_week"])
        }
    }

    /**
     * §5.4: the rotation. A new generation, the previous one superseded **today** with
     * `delete_after_day = superseded_day + 91`, and the week's bundle at rank 0.
     */
    @Test
    fun ownerWeekRotatesTheGenerationAndPublishesAtRankZero() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = day
            val activation = weekStart(2_870) + 2 * day
            world.activateAt(activation)

            val publication = weekStart(2_871) + day + 30
            world.clock.now = publication
            assertEquals(OwnerSteps.Result.DONE, world.steps.ownerWeek())

            val generations = world.generations()
            assertEquals(2, generations.size)
            val old = generations.first { it["bundle_week"] == 2_870L }
            val new = generations.first { it["bundle_week"] == 2_871L }
            val today = Math.floorDiv(publication, day)
            assertEquals(today, old["superseded_day"])
            assertEquals(today + 91, old["delete_after_day"])
            assertNull("exactly one generation is current", new["superseded_day"])

            assertEquals(listOf(1, 0), world.crypto.requestedRanks.map { it.second })
            assertEquals(2, world.bundleOps().size)
        }
    }

    /** §7.2: "OWNER-WEEK per week". A second pass in the same week changes nothing. */
    @Test
    fun ownerWeekIsIdempotentPerWeek() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = day
            world.activateAt(weekStart(2_870) + 2 * day)
            world.clock.now = weekStart(2_871) + day
            assertEquals(OwnerSteps.Result.DONE, world.steps.ownerWeek())
            val generations = world.generations()
            val calls = world.crypto.bundleCreateCalls

            for (later in listOf(day + 60, 2 * day, 6 * day)) {
                world.clock.now = weekStart(2_871) + later
                assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.ownerWeek())
            }
            assertEquals(generations, world.generations())
            assertEquals(calls, world.crypto.bundleCreateCalls)
            assertEquals(2, world.bundleOps().size)
        }
    }

    /**
     * §5.4: "A missed week publishes at the next time-triggered pass". A device offline for three
     * weeks rotates **once** when it comes back, not once per missed week — the guard is
     * `bundle_week < w`, not `bundle_week + 1 = w`.
     */
    @Test
    fun aMissedWeekPublishesOnceAtTheNextPass() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = day
            world.activateAt(weekStart(2_870) + 2 * day)
            world.clock.now = weekStart(2_874) + 2 * day
            assertEquals(OwnerSteps.Result.DONE, world.steps.ownerWeek())
            assertEquals(2_874L, world.selfRow()!!["bundle_week"])
            assertEquals(2, world.generations().size)
            assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.ownerWeek())
        }
    }

    /**
     * §5.4 "A missed week publishes at the next time-triggered pass", read together with §5.4
     * "Validity": a bundle of week `w′` is valid only in `w′` and `w′ + 1`. An owner back online in
     * week `w` whose newest bundle is of `w − 2` therefore holds **none**, and must publish at that
     * pass — not at `t_pub(w)`, which a late offset puts up to a week further away while every
     * establishment, reset and reconnect fetch against `P_0` fails (§21.7, L7-D10, E-8).
     */
    @Test
    fun aCatchUpPublicationDoesNotWaitForThisWeeksPublicationMinute() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = 6 * day
            world.activateAt(weekStart(2_870) + 6 * day)
            assertEquals(2_870L, world.selfRow()!!["bundle_week"])

            // Offline over the whole of week 2 871; back one hour into 2 872, six days before
            // `t_pub(2 872)`. The bundle of 2 870 stopped being valid at `start(2 872)`.
            world.clock.now = weekStart(2_872) + hour
            assertEquals(OwnerSteps.Result.DONE, world.steps.ownerWeek())
            assertEquals(2_872L, world.selfRow()!!["bundle_week"])
            assertEquals(listOf(1, 0), world.crypto.requestedRanks.map { it.second })

            // And the week is still claimed once: the catch-up does not repeat at `t_pub(2 872)`.
            world.clock.now = weekStart(2_872) + 6 * day
            assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.ownerWeek())
        }
    }

    /**
     * The same rule must not fire while the last bundle is still valid: an owner that published in
     * week `w − 1` waits for `t_pub(w)`, which is the whole of PM-11 and PM-30.
     */
    @Test
    fun aValidBundleOfThePreviousWeekStillWaitsForThePublicationMinute() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = 6 * day
            world.activateAt(weekStart(2_870) + 6 * day)
            for (offset in listOf(hour, day, 5 * day, 6 * day - 60)) {
                world.clock.now = weekStart(2_871) + offset
                assertEquals(
                    "offset $offset is before t_pub and the bundle of 2 870 is still valid",
                    OwnerSteps.Result.UNCHANGED,
                    world.steps.ownerWeek(),
                )
            }
            world.clock.now = weekStart(2_871) + 6 * day
            assertEquals(OwnerSteps.Result.DONE, world.steps.ownerWeek())
        }
    }

    /**
     * §7.2 "atomic", §5.4: an interrupted OWNER-WEEK leaves **nothing** — not the claimed week, not
     * the superseded generation — and the pass that resumes it does the whole rotation once. The
     * interrupt is a real one: `P_0`'s relay set is emptied, so `Outbox.enqueue` refuses under
     * ADR-11 after the week was claimed and the old generation superseded.
     */
    @Test
    fun anInterruptedOwnerWeekRollsBackWholeAndResumes() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = day
            world.activateAt(weekStart(2_870) + 2 * day)
            val bundleNs = org.ghost.sync.api.NamespaceId(world.crypto.ownCard(0)!!.bundleNamespace)
            val relays = world.namespaceRelays(world.crypto.ownCard(0)!!.bundleNamespace)
                .map { org.ghost.sync.api.RelayId(it) }.toSet()
            world.database.transaction { tx -> world.stores.namespaces.setRelays(tx, bundleNs, emptySet()) }

            world.clock.now = weekStart(2_871) + day
            assertThrows(org.ghost.sync.api.InsufficientReplicasException::class.java) {
                world.steps.ownerWeek()
            }
            assertEquals("the week was not claimed", 2_870L, world.selfRow()!!["bundle_week"])
            assertEquals(1, world.generations().size)
            assertNull("the generation was not superseded", world.generations()[0]["superseded_day"])
            assertEquals(1, world.bundleOps().size)

            world.database.transaction { tx -> world.stores.namespaces.setRelays(tx, bundleNs, relays) }
            world.clock.now = weekStart(2_871) + day + hour
            assertEquals(OwnerSteps.Result.DONE, world.steps.ownerWeek())
            assertEquals(2_871L, world.selfRow()!!["bundle_week"])
            assertEquals(2, world.generations().size)
            assertEquals(2, world.bundleOps().size)
            assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.ownerWeek())
        }
    }

    @Test
    fun ownerWeekBeforeActivationIsNotActivated() {
        OwnerWorld().use { world ->
            world.clock.now = weekStart(2_870) + 6 * day
            assertEquals(OwnerSteps.Result.NOT_ACTIVATED, world.steps.ownerWeek())
        }
    }

    // ------------------------------------------------------------------ KEEPER

    /**
     * §4.8: the owner installs its **own READ credential** per relay of `X_0`'s set, an 8-day
     * bearer credential v3 it mints itself. Its bytes are the 67 of §4.3 and its secret is the
     * seed-derived `RX_{0,s}` of the relay's slot.
     */
    @Test
    fun keeperInstallsTheOwnReadCredentialOfEveryRelayOfTheInboxSet() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            assertEquals(OwnerSteps.Result.DONE, world.steps.keeper())

            val own = world.crypto.ownCard(0)!!
            val set = RelaySets.forNamespace(
                own.inboxNamespace,
                world.slots.map { RelaySets.Slot(it.slot, it.relay.value, it.operatorId) },
            )
            val installed = world.capabilities().filter { it["kind"] == "read" }
            assertEquals(set.size, installed.size)
            assertEquals(set.map { it.relay }.toSet(), installed.map { it["relay_id"] }.toSet())
            for (row in installed) {
                assertEquals(own.inboxNamespace.toHex(), row["ns"])
                assertEquals(67L, row["len"])
                assertEquals("usable", row["state"])
                // `ceilHour(now) + 8 d`, floored to the hour by the store (§4.8).
                assertEquals(ceilHour(now) + 8 * day, row["expires_hour"])
            }
        }
    }

    /**
     * §7.2: "KEEPER puts only a differing token". A second pass within the refresh window installs
     * nothing, so the capability generation does not move and no parked delivery is re-armed.
     */
    @Test
    fun keeperPutsNothingWhileTheCredentialIsFresh() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            assertEquals(OwnerSteps.Result.DONE, world.steps.keeper())
            val first = world.capabilities()

            world.clock.now = now + 12 * hour
            assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.keeper())
            assertEquals(first, world.capabilities())
        }
    }

    /** §4.8: "refreshed when fewer than 7 days remain". */
    @Test
    fun keeperRefreshesInsideTheLastSevenDays() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            world.steps.keeper()
            val before = world.capabilities()

            // 6 days and 23 hours later: less than 7 days of the 8-day credential are left.
            world.clock.now = now + 7 * day - hour
            assertEquals(OwnerSteps.Result.DONE, world.steps.keeper())
            val after = world.capabilities()
            assertEquals(before.size, after.size)
            for ((old, fresh) in before.zip(after)) {
                assertEquals(
                    "a refresh is a new generation",
                    (old["generation"] as Long) + 1,
                    fresh["generation"],
                )
                assertTrue((fresh["expires_hour"] as Long) > (old["expires_hour"] as Long))
            }
        }
    }

    /**
     * §5.2 "Slot-table changes": the owner **as a reader** keeps the union of the sets of weeks
     * `w − 5 … w`, because a blob stored in week `w′` may live until `w′ + 6` weeks. The bundle
     * namespace is written, not read, so it takes this week's set alone.
     */
    @Test
    fun keeperKeepsTheReadersUnionForTheInboxAndThisWeeksSetForTheBundle() {
        OwnerWorld().use { world ->
            val activation = weekStart(2_870) + 2 * day
            world.activateAt(activation)
            val own = world.crypto.ownCard(0)!!

            // A slot-table change in week 2 871: four wholly different relays.
            val extra = world.database.transaction { tx ->
                world.stores.relayDirectory.upsert(
                    tx,
                    (10 until 14).map { i ->
                        org.ghost.sync.api.RelayEntry(
                            OwnerWorld.onion(i),
                            OwnerWorld.operatorId(i % 2),
                            org.ghost.sync.api.RelayEntry.Source.CONFIG,
                        )
                    },
                )
            }
            val newSlots = (10 until 14).mapIndexed { i, seed ->
                EsSlot(i, extra.getValue(OwnerWorld.onion(seed)), OwnerWorld.operatorId(seed % 2))
            }
            val oldRelays = world.slots.map { it.relay.value }.toSet()
            // Only week 2 871 changed: the earlier weeks of the union keep the old table, which is
            // what makes the union observable at all.
            world.slotsByWeek[2_871L] = newSlots

            world.crypto.publicationOffsetSeconds = day
            world.clock.now = weekStart(2_871) + 2 * day
            assertEquals(OwnerSteps.Result.DONE, world.steps.ownerWeek())
            assertEquals(OwnerSteps.Result.DONE, world.steps.keeper())

            val inboxRelays = world.namespaceRelays(own.inboxNamespace)
            val bundleRelays = world.namespaceRelays(own.bundleNamespace)
            assertTrue(
                "the reader's union keeps the relays of the earlier weeks",
                inboxRelays.any { it in oldRelays },
            )
            assertTrue(inboxRelays.any { it !in oldRelays })
            assertTrue(
                "the writer's set holds only this week's relays",
                bundleRelays.none { it in oldRelays },
            )
        }
    }

    // ----------------------------------------------------------------- REGROWS

    /**
     * §4.8: for each own namespace, each relay of its set and each kind it needs — `X_0`: DEPOSIT
     * and READ; `P_0`: FETCH — a row for week `w` must exist, and its verifier is the labelled
     * hash of §4.3 over that relay's slot.
     */
    @Test
    fun regrowsKeepsARowPerRelayNamespaceAndKindOfTheWeek() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            assertEquals(OwnerSteps.Result.DONE, world.steps.regrows())

            val own = world.crypto.ownCard(0)!!
            val slots = world.slots.map { RelaySets.Slot(it.slot, it.relay.value, it.operatorId) }
            val inboxSet = RelaySets.forNamespace(own.inboxNamespace, slots)
            val bundleSet = RelaySets.forNamespace(own.bundleNamespace, slots)
            val rows = world.registrations()

            assertEquals(2 * inboxSet.size + bundleSet.size, rows.size)
            assertTrue(rows.all { it["period_id"] == weekOf(now) })
            assertTrue(rows.all { it["state"] == "pending" })
            assertEquals(
                setOf("deposit", "read"),
                rows.filter { it["ns"] == own.inboxNamespace.toHex() }.map { it["kind"] }.toSet(),
            )
            assertEquals(
                setOf("fetch"),
                rows.filter { it["ns"] == own.bundleNamespace.toHex() }.map { it["kind"] }.toSet(),
            )

            // The verifier of one row, recomputed from the secrets the slot really has.
            val slot = inboxSet.first()
            val secrets = world.crypto.ownSecrets(0, slot.slot)!!
            val expected = CredentialV3.verifier(
                CredentialV3.Kind.DEPOSIT,
                slot.slot,
                own.inboxNamespace,
                secrets.deposit,
            )
            val row = rows.first {
                it["relay_id"] == slot.relay && it["kind"] == "deposit"
            }
            assertEquals(expected.toHex(), row["verifier"])
        }
    }

    /**
     * §4.8 and graft G-3: beside `week(now)`, a pair with a usable **write** capability of week
     * `c` also holds rows for `c` and `c + 1`. That `c + 1` row is what buys the offline tolerance
     * of E-8 — a sender presents one static credential with no week choice and no fallback
     * (§21.2), so a registration that lapsed a week earlier would simply refuse it.
     *
     * `c` comes from the capability's **declared expiry**, which is how the relay judges the
     * period too (§4.4 point 3): a capability of week `c` expires at `start(c + 1) + 1 h`.
     */
    @Test
    fun aPairWithAWriteCapabilityAlsoHoldsItsWeekAndTheNext() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            world.steps.regrows()
            assertEquals(setOf(2_870L), world.registrations().map { it["period_id"] }.toSet())

            // A write capability of week 2 870 is redeemed for the inbox on one of its relays.
            val own = world.crypto.ownCard(0)!!
            val relay = world.registrations().first()["relay_id"] as Long
            world.database.transaction { tx ->
                world.stores.capabilities.put(
                    tx,
                    org.ghost.sync.api.RelayId(relay),
                    org.ghost.sync.api.NamespaceId(own.inboxNamespace),
                    org.ghost.sync.api.CapabilityKind.WRITE,
                    ByteArray(64) { 0x21 },
                    weekStart(2_871) + hour,
                )
            }

            assertEquals(OwnerSteps.Result.DONE, world.steps.regrows())
            val forThatRelay = world.registrations()
                .filter { it["relay_id"] == relay && it["ns"] == own.inboxNamespace.toHex() }
            assertEquals(
                "week(now) plus the capability's week and the next",
                setOf(2_870L, 2_871L),
                forThatRelay.map { it["period_id"] }.toSet(),
            )
            // Only that pair grew: a capability of one relay says nothing about another's.
            assertEquals(
                setOf(2_870L),
                world.registrations()
                    .filter { it["relay_id"] != relay }
                    .map { it["period_id"] }
                    .toSet(),
            )
            // And it is idempotent from there on.
            assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.regrows())
        }
    }

    /** §7.2: "REGROWS inserts only missing rows". */
    @Test
    fun regrowsIsIdempotentAndInsertsOnlyMissingRows() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            world.steps.regrows()
            val first = world.registrations()

            world.clock.now = now + 6 * hour
            assertEquals(
                "a pass that inserts no row says so, rather than reporting work it did not do",
                OwnerSteps.Result.UNCHANGED,
                world.steps.regrows(),
            )
            assertEquals(first, world.registrations())
        }
    }

    /**
     * §4.8: a new week adds its own rows, and rows of weeks before `w − 1` are dropped — no
     * capability the relay would accept still names them.
     */
    @Test
    fun regrowsAddsTheNewWeekAndForgetsWeeksBeforeThePreviousOne() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = day
            world.activateAt(weekStart(2_870) + 2 * day)
            world.steps.regrows()
            val perWeek = world.registrations().size

            world.clock.now = weekStart(2_871) + 2 * day
            world.steps.regrows()
            assertEquals(2 * perWeek, world.registrations().size)

            world.clock.now = weekStart(2_872) + 2 * day
            world.steps.regrows()
            // 2 870 is now before `w - 1` and is gone; 2 871 and 2 872 remain.
            assertEquals(2 * perWeek, world.registrations().size)
            assertEquals(
                setOf(2_871L, 2_872L),
                world.registrations().map { it["period_id"] }.toSet(),
            )
        }
    }

    /**
     * §4.8's healing rule: a **rejected** own READ credential means the relay lost its `keys.redb`,
     * so every `done` row of that pair from this week on returns to pending and is registered
     * again. It is KEEPER's, because the re-arm and the re-put that clears the refusal have to be
     * one decision — a step that only re-armed would re-arm again at every later pass, since
     * `rejected` stays set until a new generation is installed.
     */
    @Test
    fun aRejectedReadCredentialSendsTheDoneRowsBackToPending() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            world.steps.keeper()
            world.steps.regrows()
            world.markRegistrationsDone(validUntilHour = ceilHour(now) + 14 * day)
            assertTrue(world.registrations().all { it["state"] == "done" })

            val rejected = world.capabilities().first { it["kind"] == "read" }["relay_id"] as Long
            world.markCapabilityRejected(org.ghost.sync.api.RelayId(rejected))

            assertEquals(OwnerSteps.Result.DONE, world.steps.keeper())
            val pending = world.registrations().filter { it["state"] == "pending" }
            assertTrue("the rejected relay's rows are pending again", pending.isNotEmpty())
            assertEquals(setOf(rejected), pending.map { it["relay_id"] }.toSet())
            // REGROWS does not undo the work that follows: the rows it finds are the ones it keeps.
            assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.regrows())
        }
    }

    /**
     * The other half of the same rule, and the reason it is not REGROWS's: while a refusal is being
     * healed, a row the work lane has just registered must **stay** done. A step that re-armed on
     * the `rejected` level alone would send it back to pending at every pass and the pair would
     * never converge.
     */
    @Test
    fun aRowRegisteredDuringTheHealingIsNotSentBackToPending() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            val engine = MessagingEngine(world.steps)
            engine.runOwnerMaintenance()
            val validUntil = ceilHour(now) + 14 * day
            world.markRegistrationsDone(validUntilHour = validUntil)
            val rejected = world.capabilities().first { it["kind"] == "read" }["relay_id"] as Long
            world.markCapabilityRejected(org.ghost.sync.api.RelayId(rejected))
            world.clock.now = now + hour
            engine.runOwnerMaintenance()
            assertTrue(world.registrations().any { it["state"] == "pending" })

            // The work lane registers one of the re-armed rows, and the relay refuses the
            // credential once more before the other is done.
            world.sql.exec(
                "UPDATE relay_key_registration SET state = 'done', valid_until_hour = ? " +
                    "WHERE state = 'pending' AND kind = 'read'",
                listOf(validUntil),
            )
            world.markCapabilityRejected(org.ghost.sync.api.RelayId(rejected))
            world.clock.now = now + 2 * hour
            engine.runOwnerMaintenance()

            assertEquals(
                "the row the work lane finished stays done while the rest of the pair is pending",
                listOf("done"),
                world.registrations().filter { it["relay_id"] == rejected && it["kind"] == "read" }
                    .map { it["state"] },
            )
        }
    }

    /**
     * §4.8's healing rule **through the pass a device really runs** (`runOwnerMaintenance`, §13.7),
     * not through `regrows()` alone. KEEPER decides whether a refused credential is re-put, so a
     * healing that ran after it would only ever see the credential KEEPER had just made usable
     * again — mutant MC-14, and the reason this rule was dead in the pass order while the test
     * above passed.
     */
    @Test
    fun aRejectedReadCredentialIsHealedByTheMaintenancePass() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            val engine = MessagingEngine(world.steps)
            engine.runOwnerMaintenance()
            world.markRegistrationsDone(validUntilHour = ceilHour(now) + 14 * day)

            val rejected = world.capabilities().first { it["kind"] == "read" }["relay_id"] as Long
            val generationBefore = world.capabilities()
                .first { it["relay_id"] == rejected && it["kind"] == "read" }["generation"] as Long
            world.markCapabilityRejected(org.ghost.sync.api.RelayId(rejected))

            world.clock.now = now + 2 * hour
            assertTrue(engine.runOwnerMaintenance().changed)
            val pending = world.registrations().filter { it["state"] == "pending" }
            assertTrue("the rejected relay's rows are pending again", pending.isNotEmpty())
            assertEquals(setOf(rejected), pending.map { it["relay_id"] }.toSet())
            val healed = world.capabilities().first { it["relay_id"] == rejected && it["kind"] == "read" }
            assertEquals("the re-put clears the refusal in the same transaction", "usable", healed["state"])
            assertEquals(generationBefore + 1, healed["generation"])
        }
    }

    /**
     * §21.2 point 8, mutant MC-15: the re-put is **bounded**. While the pair still has pending
     * rows the healing is under way, reads use the write capability, and a second refusal costs no
     * further capability generation — the credential is re-put once per registration round trip,
     * not once per `CAPABILITIES` hint.
     */
    @Test
    fun aSecondRefusalWhileTheRowsArePendingCostsNoNewGeneration() {
        OwnerWorld().use { world ->
            val now = weekStart(2_870) + 2 * day
            world.activateAt(now)
            val engine = MessagingEngine(world.steps)
            engine.runOwnerMaintenance()
            world.markRegistrationsDone(validUntilHour = ceilHour(now) + 14 * day)
            val rejected = world.capabilities().first { it["kind"] == "read" }["relay_id"] as Long
            world.markCapabilityRejected(org.ghost.sync.api.RelayId(rejected))
            world.clock.now = now + 2 * hour
            engine.runOwnerMaintenance()
            val afterHealing = world.capabilities()

            // The relay refuses the credential again while the rows are still pending.
            world.markCapabilityRejected(org.ghost.sync.api.RelayId(rejected))
            world.clock.now = now + 3 * hour
            assertFalse(engine.runOwnerMaintenance().changed)
            val row = world.capabilities().first { it["relay_id"] == rejected && it["kind"] == "read" }
            assertEquals("still refused: reads fall back to the write capability", "rejected", row["state"])
            assertEquals(
                "no re-put, so no new generation",
                afterHealing.first { it["relay_id"] == rejected && it["kind"] == "read" }["generation"],
                row["generation"],
            )
        }
    }

    /**
     * §5.2 "Slot-table changes" with §21.2 point 2: a verifier binds the relay's **slot number**, a
     * relay may keep a namespace's set while moving to another of its slots, and REGROWS keeps rows
     * for `c` and `c + 1` of an earlier week (graft G-3). The rows of the old slot can then no
     * longer be presented by anyone, and `Registrations.request`'s "a registration keeps the
     * verifier it was created with" would abort the whole owner pass — `forget` loop included — at
     * every pass for as long as those periods lived.
     */
    @Test
    fun regrowsReplacesTheRowsOfARelayThatMovedToAnotherSlot() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = day
            world.activateAt(weekStart(2_870) + 2 * day)
            val own = world.crypto.ownCard(0)!!
            val chosen = RelaySets.forNamespace(
                own.inboxNamespace,
                world.slots.map { RelaySets.Slot(it.slot, it.relay.value, it.operatorId) },
            ).map { it.slot }
            // Two chosen slots of one operator: swapping the relays that serve them leaves every
            // slot's operator — and therefore the chosen slot numbers — exactly as they were.
            val pair = chosen.filter { it % 2 == 0 }.take(2)
                .takeIf { it.size == 2 } ?: chosen.filter { it % 2 == 1 }.take(2)
            assertEquals("the ES shape must offer two chosen slots of one operator", 2, pair.size)
            val (slotA, slotB) = pair
            val moving = world.slots.first { it.slot == slotA }.relay

            // A write capability of week 2 870 on the moving relay, so REGROWS keeps rows for
            // 2 870 and 2 871 there (graft G-3) — rows of the slot it is about to leave.
            world.database.transaction { tx ->
                world.stores.capabilities.put(
                    tx,
                    moving,
                    org.ghost.sync.api.NamespaceId(own.inboxNamespace),
                    org.ghost.sync.api.CapabilityKind.WRITE,
                    ByteArray(64) { 0x21 },
                    weekStart(2_871) + hour,
                )
            }
            assertEquals(OwnerSteps.Result.DONE, world.steps.regrows())
            assertEquals(
                setOf(2_870L, 2_871L),
                world.registrations().filter { it["relay_id"] == moving.value }.map { it["period_id"] }.toSet(),
            )

            // Week 2 871: the relays of the two slots swap places.
            val atA = world.slots.first { it.slot == slotA }
            val atB = world.slots.first { it.slot == slotB }
            world.slotsByWeek[2_871L] = world.slots.map { slot ->
                when (slot.slot) {
                    slotA -> EsSlot(slotA, atB.relay, atB.operatorId)
                    slotB -> EsSlot(slotB, atA.relay, atA.operatorId)
                    else -> slot
                }
            }
            world.clock.now = weekStart(2_871) + 2 * day
            assertEquals(OwnerSteps.Result.DONE, world.steps.regrows())

            // The moving relay's rows now carry the verifier of its new slot, and are to be made.
            val secrets = world.crypto.ownSecrets(0, slotB)!!
            val expected = CredentialV3.verifier(
                CredentialV3.Kind.DEPOSIT,
                slotB,
                own.inboxNamespace,
                secrets.deposit,
            )
            val rows = world.registrations().filter {
                it["relay_id"] == moving.value && it["kind"] == "deposit" &&
                    it["ns"] == own.inboxNamespace.toHex()
            }
            assertTrue(rows.isNotEmpty())
            for (row in rows) {
                assertEquals(expected.toHex(), row["verifier"])
                assertEquals("pending", row["state"])
            }
            // And from there it is idempotent again: the rows are the ones this slot yields.
            assertEquals(OwnerSteps.Result.UNCHANGED, world.steps.regrows())
        }
    }

    @Test
    fun regrowsBeforeActivationIsNotActivated() {
        OwnerWorld().use { world ->
            world.clock.now = weekStart(2_870)
            assertEquals(OwnerSteps.Result.NOT_ACTIVATED, world.steps.regrows())
            assertEquals(OwnerSteps.Result.NOT_ACTIVATED, world.steps.keeper())
        }
    }

    // ------------------------------------------------------------- the facade

    /**
     * §13.7's pass order for the time-triggered steps. The second pass of a quiet week writes
     * nothing at all, which is the whole point of the four guards together.
     */
    @Test
    fun aMaintenancePassIsIdempotentOnAQuietWeek() {
        OwnerWorld().use { world ->
            world.crypto.publicationOffsetSeconds = day
            world.activateAt(weekStart(2_870) + 2 * day)
            val engine = MessagingEngine(world.steps)

            world.clock.now = weekStart(2_871) + 2 * day
            val first = engine.runOwnerMaintenance()
            assertTrue(first.changed)

            val snapshot = listOf(
                world.selfRow(),
                world.generations(),
                world.registrations(),
                world.capabilities(),
                world.bundleOps(),
            )
            world.clock.now = weekStart(2_871) + 3 * day
            val second = engine.runOwnerMaintenance()
            assertFalse(second.changed)
            assertEquals(
                snapshot,
                listOf(
                    world.selfRow(),
                    world.generations(),
                    world.registrations(),
                    world.capabilities(),
                    world.bundleOps(),
                ),
            )
        }
    }

    /**
     * §5.2 and ADR-11: a week whose relays span one operator cannot satisfy the replica rule, and
     * `Outbox.enqueue` refuses. The whole ACTIVATE transaction rolls back — no `dm_self`, no
     * generation, no half-registered namespace — and §21.12 point 2 tries again later.
     */
    @Test
    fun aSingleOperatorWeekRollsTheWholeActivationBack() {
        OwnerWorld(slotCount = 3, operators = 1).use { world ->
            assertThrows(org.ghost.sync.api.InsufficientReplicasException::class.java) {
                world.activateAt(weekStart(2_870) + 2 * day)
            }
            assertNull(world.selfRow())
            assertEquals(0, world.generations().size)
            assertEquals(0, world.ownNamespaces().size)
        }
    }

    /**
     * The other half of the rollback, which §21.12 point 2 is the net for: the activation that
     * rolled back **completes** at the next pass, whole, once the week's ES can satisfy ADR-11.
     * S6 has no actor to run that pass (§22.11 item 9a); the step itself is resumable, and this is
     * what says so.
     */
    @Test
    fun theRolledBackActivationCompletesAtTheNextPass() {
        OwnerWorld(slotCount = 3, operators = 1).use { world ->
            assertThrows(org.ghost.sync.api.InsufficientReplicasException::class.java) {
                world.activateAt(weekStart(2_870) + 2 * day)
            }
            assertNull(world.selfRow())

            // A relay of a second operator joins the ES.
            val joined = world.database.transaction { tx ->
                world.stores.relayDirectory.upsert(
                    tx,
                    listOf(
                        org.ghost.sync.api.RelayEntry(
                            OwnerWorld.onion(20),
                            OwnerWorld.operatorId(1),
                            org.ghost.sync.api.RelayEntry.Source.CONFIG,
                        ),
                    ),
                )
            }
            world.slots = world.slots + EsSlot(3, joined.getValue(OwnerWorld.onion(20)), OwnerWorld.operatorId(1))

            assertEquals(OwnerSteps.Result.DONE, world.activateAt(weekStart(2_870) + 2 * day + hour))
            assertNotNull(world.selfRow())
            assertEquals(1, world.generations().size)
            assertEquals(1, world.bundleOps().size)
            assertEquals(2, world.ownNamespaces().size)
            assertEquals(OwnerSteps.Result.UNCHANGED, world.activateAt(weekStart(2_870) + 2 * day + 2 * hour))
        }
    }

    private fun ceilHour(t: Long): Long = -Math.floorDiv(-t, hour) * hour

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02X".format(it.toInt() and 0xff) }
}
